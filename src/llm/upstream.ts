// Sending one chat completion to its upstreams: the primary first, then the fallback.
//
// A 5xx answer, a timeout or a connection failure is retried on the same upstream up to `retries`
// more times, waiting backoffMs, 2 x backoffMs, 4 x backoffMs ... before each retry; then the
// fallback (if the route has one) gets the same treatment.
// A 429 (the provider's rate limit or quota) moves on to the fallback at once. On the last upstream
// there is nowhere to go, so it waits for the answer's Retry-After (backoffMs without one), plus up
// to a fifth more at random so that clients refused together do not come back together, and tries
// again, using one of the upstream's `retries`; if Retry-After is longer than rateLimitWaitMs, it does
// not wait at all. A request waits after a 429 at most once.
// Any other 4xx is the answer: it would fail the same way again.
// ponytail: bounded and plain. At most (1 + retries) attempts per upstream, whatever went wrong,
// retries is capped at 3 (config.ts), and the 5xx backoff has no jitter.
// ponytail: an upstream's answer is read whole, with no size limit; upstreams are configured by
// the operator and trusted to send answers of a sane size.

import type { ResolvedTarget } from "./routing.js";

export interface UpstreamOptions {
  timeoutMs: number;
  retries: number;
  backoffMs: number;
  /** The longest the gateway waits after a 429 before its one retry on the last upstream; 0 never waits or retries. */
  rateLimitWaitMs?: number;
  /** Jitter source, 0 <= x < 1 (default Math.random); a test can fix it. */
  random?: () => number;
  /** The upstream's API key, read from its apiKeyEnv. */
  apiKey: (target: ResolvedTarget) => string;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  /** Told about every failed attempt, without bodies or keys. */
  log?: (message: string) => void;
  /** The gateway's own W3C traceparent for this request (its trace id, its span), sent to every upstream. */
  traceparent?: string;
}

export type Failure = "timeout" | "unreachable" | "server_error" | "rate_limited";

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
      /** 429 answers on the way. */
      rateLimited: number;
    }
  /**
   * Every attempt failed; `failure` is how the last one failed. For "rate_limited", the last
   * upstream's Retry-After in seconds, when it gave one.
   */
  | { ok: false; failure: Failure; status?: number; attempts: number; rateLimited: number; retryAfterSeconds?: number };

/** An HTTP date in the one form servers send (IMF-fixdate): Wed, 21 Oct 2026 07:28:00 GMT. */
const HTTP_DATE = /^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/;

/** Retry-After as milliseconds: delta seconds or an HTTP date. Undefined when absent or unreadable. */
export function retryAfterMs(header: string | null, now = Date.now()): number | undefined {
  if (header === null) return undefined;
  const value = header.trim();
  if (/^\d+$/.test(value)) return Number(value) * 1000;
  // Date.parse alone would also read "-3" or "2026" as dates.
  const date = HTTP_DATE.test(value) ? Date.parse(value) : NaN;
  return Number.isNaN(date) ? undefined : Math.max(0, date - now);
}

export async function callUpstreams(
  targets: readonly ResolvedTarget[],
  body: Record<string, unknown>,
  options: UpstreamOptions,
): Promise<UpstreamOutcome> {
  const doFetch = options.fetch ?? fetch;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const random = options.random ?? Math.random;
  const maxWait = options.rateLimitWaitMs ?? 0;
  let attempts = 0;
  let rateLimited = 0;
  let waitedOn429 = false;
  let last: { failure: Failure; status?: number; retryAfterSeconds?: number } = { failure: "unreachable" };

  for (const [index, target] of targets.entries()) {
    const isLast = index === targets.length - 1;
    let failures = 0; // 5xx answers, timeouts and failed connections on this upstream
    let wait429 = 0;
    while (failures <= options.retries) {
      if (wait429 > 0) await sleep(wait429);
      else if (failures > 0) await sleep(options.backoffMs * 2 ** (failures - 1));
      wait429 = 0;
      attempts++;
      try {
        const response = await doFetch(`${target.upstream.baseUrl}/chat/completions`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${options.apiKey(target)}`,
            "content-type": "application/json",
            accept: "application/json",
            ...(options.traceparent ? { traceparent: options.traceparent } : {}),
          },
          body: JSON.stringify({ ...body, model: target.model }),
          // An API does not redirect; following one could send the key somewhere else.
          redirect: "error",
          // Covers reading the body too.
          signal: AbortSignal.timeout(options.timeoutMs),
        });
        const text = await response.text();
        if (response.status === 429) {
          rateLimited++;
          const after = retryAfterMs(response.headers.get("retry-after"));
          last = { failure: "rate_limited", status: 429, ...(after === undefined ? {} : { retryAfterSeconds: Math.ceil(after / 1000) }) };
          options.log?.(`upstream "${target.upstream.name}" answered 429 (attempt ${attempts})`);
          if (!isLast) break; // the fallback, at once
          failures++; // the retry after a 429 is one of this upstream's retries
          const base = after ?? options.backoffMs;
          if (failures > options.retries || maxWait === 0 || waitedOn429 || base > maxWait) break; // one wait per request, never a long one
          waitedOn429 = true;
          wait429 = Math.max(1, Math.min(maxWait, Math.round(base + base * 0.2 * random())));
          continue;
        }
        if (response.status >= 500) {
          last = { failure: "server_error", status: response.status };
          options.log?.(`upstream "${target.upstream.name}" answered ${response.status} (attempt ${attempts})`);
          failures++;
          continue;
        }
        return { ok: true, target, status: response.status, body: text, attempts, fallback: index > 0, rateLimited };
      } catch (err) {
        const timedOut = err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError");
        last = { failure: timedOut ? "timeout" : "unreachable" };
        options.log?.(`upstream "${target.upstream.name}" ${timedOut ? `timed out after ${options.timeoutMs} ms` : "could not be reached"} (attempt ${attempts})`);
        failures++;
      }
    }
  }
  return { ok: false, ...last, attempts, rateLimited };
}
