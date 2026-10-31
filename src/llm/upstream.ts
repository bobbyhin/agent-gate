// Sending one chat completion to its upstreams: the primary first, then the fallback.
//
// A 5xx answer, a 408, a timeout or a connection failure is retried on the same upstream up to
// `retries` more times; then the fallback (if the route has one) gets the same treatment. Before
// retry n the gateway waits a random time between 0 and min(maxBackoffMs, backoffMs x 2^(n-1))
// ("full jitter"), so that clients refused together do not all come back at the same moment.
// A 408 means the server did not get the whole request in time, so it never ran it.
// A 429 (the provider's rate limit or quota) moves on to the fallback at once. On the last upstream
// there is nowhere to go, so it waits for the answer's Retry-After (backoffMs without one), plus up
// to a fifth more at random so that clients refused together do not come back together, and tries
// again, using one of the upstream's `retries`; if Retry-After is longer than rateLimitWaitMs, it does
// not wait at all. A request waits after a 429 at most once.
// Any other 4xx is the answer: it would fail the same way again.
// A streamed request (`stream`) is retried the same way until an upstream answers with a 2xx: then the
// answer's body is handed back unread, and nothing is retried once it starts (server.ts relays it).
// `signal` (the client went away) stops everything at once: no further attempt, no wait, and the
// attempt in flight, body included, is aborted.
// ponytail: bounded and plain. At most (1 + retries) attempts per upstream, whatever went wrong, and
// retries is capped at 3 (config.ts). docs/adr/0010-retries.md has the reasoning.
// ponytail: an upstream's answer is read whole, with no size limit; upstreams are configured by
// the operator and trusted to send answers of a sane size.

import type { ResolvedTarget } from "./routing.js";

export interface UpstreamOptions {
  timeoutMs: number;
  retries: number;
  backoffMs: number;
  /** The longest wait before a retry after a 5xx, a 408 or a timeout (default: no cap). */
  maxBackoffMs?: number;
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
  /** A streamed request: a 2xx answer comes back as `response`, its body unread. */
  stream?: boolean;
  /** Aborts the request: no more attempts, and the one in flight (with its body) is cut off. */
  signal?: AbortSignal;
}

/** "cancelled": `signal` fired (the client went away) before an upstream answered. */
export type Failure = "timeout" | "unreachable" | "server_error" | "rate_limited" | "cancelled";

export type UpstreamOutcome =
  | {
      ok: true;
      target: ResolvedTarget;
      status: number;
      /** The upstream's body as text. The caller decides what of it reaches the client. Empty for a stream. */
      body: string;
      /** A streamed request's 2xx answer, its body not read yet; the attempt's timeout and `signal` still apply to it. */
      response?: Response;
      /** With `response`: the signal that ends the attempt (its timeout, or `signal`), for whatever the caller does while it lasts. */
      attemptSignal?: AbortSignal;
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
  // The default wait ends early when `signal` fires: a client that left does not hold the call for a backoff.
  const sleep = options.sleep ?? ((ms: number) => abortableSleep(ms, options.signal));
  const random = options.random ?? Math.random;
  const maxWait = options.rateLimitWaitMs ?? 0;
  let attempts = 0;
  let rateLimited = 0;
  let waitedOn429 = false;
  let last: { failure: Failure; status?: number; retryAfterSeconds?: number } = { failure: "unreachable" };

  const cancelled = (): UpstreamOutcome => ({ ok: false, failure: "cancelled", attempts, rateLimited });

  for (const [index, target] of targets.entries()) {
    const isLast = index === targets.length - 1;
    let failures = 0; // 5xx answers, timeouts and failed connections on this upstream
    let wait429 = 0;
    while (failures <= options.retries) {
      if (wait429 > 0) await sleep(wait429);
      else if (failures > 0) await sleep(Math.floor(random() * backoffCeiling(options.backoffMs, options.maxBackoffMs, failures)));
      wait429 = 0;
      if (options.signal?.aborted) return cancelled();
      attempts++;
      try {
        const timeout = AbortSignal.timeout(options.timeoutMs);
        const attemptSignal = options.signal ? anySignal([timeout, options.signal]) : timeout;
        const response = await doFetch(`${target.upstream.baseUrl}/chat/completions`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${options.apiKey(target)}`,
            "content-type": "application/json",
            accept: options.stream ? "text/event-stream" : "application/json",
            ...(options.traceparent ? { traceparent: options.traceparent } : {}),
          },
          body: JSON.stringify({ ...body, model: target.model }),
          // An API does not redirect; following one could send the key somewhere else.
          redirect: "error",
          // Covers reading the body too, a stream's included.
          signal: attemptSignal,
        });
        if (options.stream && response.status >= 200 && response.status < 300) {
          return { ok: true, target, status: response.status, body: "", response, attemptSignal, attempts, fallback: index > 0, rateLimited };
        }
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
        if (response.status >= 500 || response.status === 408) {
          last = { failure: "server_error", status: response.status };
          options.log?.(`upstream "${target.upstream.name}" answered ${response.status} (attempt ${attempts})`);
          failures++;
          continue;
        }
        return { ok: true, target, status: response.status, body: text, attempts, fallback: index > 0, rateLimited };
      } catch (err) {
        if (options.signal?.aborted) return cancelled();
        const timedOut = err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError");
        last = { failure: timedOut ? "timeout" : "unreachable" };
        options.log?.(`upstream "${target.upstream.name}" ${timedOut ? `timed out after ${options.timeoutMs} ms` : "could not be reached"} (attempt ${attempts})`);
        failures++;
      }
    }
  }
  return { ok: false, ...last, attempts, rateLimited };
}

/** Waits `ms`, or less when `signal` fires first. */
function abortableSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise<void>((resolve) => {
    if (signal?.aborted) return resolve();
    const done = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal?.addEventListener("abort", done, { once: true });
  });
}

/** A signal that aborts when any of `signals` does, with that one's reason. (AbortSignal.any needs Node 20.3.) */
export function anySignal(signals: readonly AbortSignal[]): AbortSignal {
  const controller = new AbortController();
  for (const signal of signals) {
    if (signal.aborted) {
      controller.abort(signal.reason);
      break;
    }
    signal.addEventListener("abort", () => controller.abort(signal.reason), { once: true });
  }
  return controller.signal;
}

/** The most the wait before retry n (1, 2, 3) can be: backoffMs x 2^(n-1), at most maxBackoffMs. Full jitter waits a random part of it. */
export function backoffCeiling(backoffMs: number, maxBackoffMs: number | undefined, n: number): number {
  const doubled = backoffMs * 2 ** (n - 1);
  return maxBackoffMs === undefined ? doubled : Math.min(maxBackoffMs, doubled);
}
