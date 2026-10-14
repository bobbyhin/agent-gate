// Sending one chat completion to its upstreams: the primary first, then the fallback.
//
// A 5xx answer, a timeout or a connection failure is retried on the same upstream up to `retries`
// more times, waiting backoffMs, 2 x backoffMs, 4 x backoffMs ... before each retry; then the
// fallback (if the route has one) gets the same treatment. Anything else, including a 4xx, is the
// answer: a 4xx would fail the same way again.
// ponytail: bounded and plain. At most (1 + retries) attempts per upstream, retries is capped at 3
// (config.ts), and the backoff has no jitter. Upstream 429s are passed on, not retried.
// ponytail: an upstream's answer is read whole, with no size limit; upstreams are configured by
// the operator and trusted to send answers of a sane size.

import type { ResolvedTarget } from "./routing.js";

export interface UpstreamOptions {
  timeoutMs: number;
  retries: number;
  backoffMs: number;
  /** The upstream's API key, read from its apiKeyEnv. */
  apiKey: (target: ResolvedTarget) => string;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  /** Told about every failed attempt, without bodies or keys. */
  log?: (message: string) => void;
}

export type Failure = "timeout" | "unreachable" | "server_error";

export type UpstreamOutcome =
  | {
      ok: true;
      target: ResolvedTarget;
      status: number;
      /** The upstream's body as text. The caller decides what of it reaches the client. */
      body: string;
      attempts: number;
      /** True when the fallback answered. */
      fallback: boolean;
    }
  /** Every attempt failed; `failure` is how the last one failed. */
  | { ok: false; failure: Failure; status?: number; attempts: number };

export async function callUpstreams(
  targets: readonly ResolvedTarget[],
  body: Record<string, unknown>,
  options: UpstreamOptions,
): Promise<UpstreamOutcome> {
  const doFetch = options.fetch ?? fetch;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  let attempts = 0;
  let last: { failure: Failure; status?: number } = { failure: "unreachable" };

  for (const [index, target] of targets.entries()) {
    for (let retry = 0; retry <= options.retries; retry++) {
      if (retry > 0) await sleep(options.backoffMs * 2 ** (retry - 1));
      attempts++;
      try {
        const response = await doFetch(`${target.upstream.baseUrl}/chat/completions`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${options.apiKey(target)}`,
            "content-type": "application/json",
            accept: "application/json",
          },
          body: JSON.stringify({ ...body, model: target.model }),
          // An API does not redirect; following one could send the key somewhere else.
          redirect: "error",
          // Covers reading the body too.
          signal: AbortSignal.timeout(options.timeoutMs),
        });
        const text = await response.text();
        if (response.status >= 500) {
          last = { failure: "server_error", status: response.status };
          options.log?.(`upstream "${target.upstream.name}" answered ${response.status} (attempt ${attempts})`);
          continue;
        }
        return { ok: true, target, status: response.status, body: text, attempts, fallback: index > 0 };
      } catch (err) {
        const timedOut = err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError");
        last = { failure: timedOut ? "timeout" : "unreachable" };
        options.log?.(`upstream "${target.upstream.name}" ${timedOut ? `timed out after ${options.timeoutMs} ms` : "could not be reached"} (attempt ${attempts})`);
      }
    }
  }
  return { ok: false, ...last, attempts };
}
