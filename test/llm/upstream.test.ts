// Tests for retries and the fallback, with a fetch and a sleep the test controls, plus one real
// timeout against a local server that never answers.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { parseLlmConfig } from "../../src/llm/config.js";
import { route, type ResolvedTarget } from "../../src/llm/routing.js";
import { longestCallMs } from "../../src/llm/server.js";
import { backoffCeiling, callUpstreams, retryAfterMs, type UpstreamOptions } from "../../src/llm/upstream.js";

function targets(primaryUrl = "http://primary.test/v1", fallbackUrl = "http://fallback.test/v1"): ResolvedTarget[] {
  const config = parseLlmConfig(
    {
      stateDir: "s",
      policy: "p.json",
      upstreams: [
        { name: "primary", baseUrl: primaryUrl, apiKeyEnv: "PRIMARY_KEY", models: { large: "large-1" }, pricePerMTok: { input: 1, output: 1 } },
        { name: "fallback", baseUrl: fallbackUrl, apiKeyEnv: "FALLBACK_KEY", models: { large: "large-2" }, pricePerMTok: { input: 1, output: 1 } },
      ],
      routes: [{ id: "r", use: { upstream: "primary" }, fallback: { upstream: "fallback" } }],
      keys: [{ name: "k", sha256: "a".repeat(64), dailyUsd: 1, monthlyUsd: 1 }],
    },
    "/srv",
  );
  const chosen = route(config, { model: "large" });
  assert.ok(chosen?.fallback);
  return [chosen.primary, chosen.fallback];
}

type Step = number | "timeout" | "unreachable" | { status: number; retryAfter?: string };

/** A fetch that answers with the next step for each call and records what it was asked. */
function scripted(steps: Step[]) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const sleeps: number[] = [];
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    const step = steps[calls.length - 1];
    if (step === undefined) throw new Error("more calls than the test expected");
    if (step === "timeout") throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
    if (step === "unreachable") throw new TypeError("fetch failed");
    const { status, retryAfter } = typeof step === "number" ? { status: step, retryAfter: undefined } : step;
    return new Response(JSON.stringify({ status }), { status, headers: retryAfter === undefined ? {} : { "retry-after": retryAfter } });
  }) as typeof fetch;
  const options: UpstreamOptions = {
    timeoutMs: 1000,
    retries: 1,
    backoffMs: 100,
    rateLimitWaitMs: 2000,
    random: () => 0.5,
    apiKey: (t) => `key-for-${t.upstream.name}`,
    fetch: fetchImpl,
    sleep: async (ms) => {
      sleeps.push(ms);
    },
  };
  return { calls, sleeps, options };
}

describe("callUpstreams", () => {
  it("returns the primary's answer on the first attempt", async () => {
    const s = scripted([200]);
    const outcome = await callUpstreams(targets(), { model: "large", messages: [] }, s.options);
    assert.deepEqual(outcome.ok && [outcome.target.upstream.name, outcome.status, outcome.attempts, outcome.fallback], ["primary", 200, 1, false]);
    assert.deepEqual(s.sleeps, []);
  });

  it("sends the upstream's model, its own key, and refuses redirects", async () => {
    const s = scripted([500, 500, 200]);
    await callUpstreams(targets(), { model: "large", messages: [{ role: "user", content: "hi" }], max_tokens: 5 }, s.options);
    assert.deepEqual(
      s.calls.map((c) => [c.url, (c.init.headers as Record<string, string>).authorization, JSON.parse(String(c.init.body)).model]),
      [
        ["http://primary.test/v1/chat/completions", "Bearer key-for-primary", "large-1"],
        ["http://primary.test/v1/chat/completions", "Bearer key-for-primary", "large-1"],
        ["http://fallback.test/v1/chat/completions", "Bearer key-for-fallback", "large-2"],
      ],
    );
    assert.deepEqual(JSON.parse(String(s.calls[0]?.init.body)), { model: "large-1", messages: [{ role: "user", content: "hi" }], max_tokens: 5 });
    assert.equal(s.calls[0]?.init.redirect, "error");
    assert.equal(s.calls[0]?.init.method, "POST");
  });

  const table: Array<[name: string, steps: Step[], expected: unknown, sleeps: number[]]> = [
    // random() is 0.5 in these, so a backoff waits half its ceiling: 50 ms before the first retry.
    ["a 500 is retried once on the same upstream", [500, 200], { ok: true, upstream: "primary", status: 200, attempts: 2, fallback: false }, [50]],
    ["a 408 is retried like a 5xx: the server never ran the request", [408, 200], { ok: true, upstream: "primary", status: 200, attempts: 2, fallback: false }, [50]],
    ["two 5xx move on to the fallback", [500, 503, 200], { ok: true, upstream: "fallback", status: 200, attempts: 3, fallback: true }, [50]],
    ["a timeout is retried, then the fallback answers", ["timeout", "timeout", 200], { ok: true, upstream: "fallback", status: 200, attempts: 3, fallback: true }, [50]],
    ["a 4xx is the answer: no retry, no fallback", [400], { ok: true, upstream: "primary", status: 400, attempts: 1, fallback: false }, []],
    ["a 429 moves on to the fallback at once, without waiting", [429, 200], { ok: true, upstream: "fallback", status: 200, attempts: 2, fallback: true }, []],
    ["a 429 on the fallback waits for Retry-After (plus jitter) and tries once more", [429, { status: 429, retryAfter: "1" }, 200], { ok: true, upstream: "fallback", status: 200, attempts: 3, fallback: true }, [1100]],
    [
      "429s everywhere: the answer is rate_limited, with the last Retry-After",
      [{ status: 429, retryAfter: "3" }, { status: 429, retryAfter: "1" }, { status: 429, retryAfter: "7" }],
      { ok: false, failure: "rate_limited", status: 429, attempts: 3, rateLimited: 3, retryAfterSeconds: 7 },
      [1100],
    ],
    ["a Retry-After longer than rateLimitWaitMs is not waited for", [429, { status: 429, retryAfter: "120" }], { ok: false, failure: "rate_limited", status: 429, attempts: 2, rateLimited: 2, retryAfterSeconds: 120 }, []],
    ["without a Retry-After the wait is backoffMs, with jitter", [429, 429, 200], { ok: true, upstream: "fallback", status: 200, attempts: 3, fallback: true }, [110]],
    ["the retry after a 429 is one of the upstream's retries", [500, 500, 500, { status: 429, retryAfter: "1" }], { ok: false, failure: "rate_limited", status: 429, attempts: 4, rateLimited: 1, retryAfterSeconds: 1 }, [50, 50]],
    ["every attempt fails with a 5xx", [500, 500, 502, 503], { ok: false, failure: "server_error", status: 503, attempts: 4, rateLimited: 0 }, [50, 50]],
    ["the last failure decides: timeout", [500, 500, "unreachable", "timeout"], { ok: false, failure: "timeout", attempts: 4, rateLimited: 0 }, [50, 50]],
    ["the last failure decides: unreachable", ["timeout", "timeout", "unreachable", "unreachable"], { ok: false, failure: "unreachable", attempts: 4, rateLimited: 0 }, [50, 50]],
  ];
  for (const [name, steps, expected, sleeps] of table) {
    it(name, async () => {
      const s = scripted(steps);
      const outcome = await callUpstreams(targets(), { model: "large", messages: [] }, s.options);
      const got = outcome.ok
        ? { ok: true, upstream: outcome.target.upstream.name, status: outcome.status, attempts: outcome.attempts, fallback: outcome.fallback }
        : outcome;
      assert.deepEqual(got, expected);
      assert.equal(s.calls.length, steps.length, "no more and no fewer attempts than expected");
      assert.deepEqual(s.sleeps, sleeps);
    });
  }

  it("sends the gateway's traceparent to every upstream it tries, and none when there is none", async () => {
    const parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    const s = scripted([500, 500, 200]);
    await callUpstreams(targets(), { model: "large", messages: [] }, { ...s.options, traceparent: parent });
    assert.deepEqual(s.calls.map((c) => (c.init.headers as Record<string, string>).traceparent), [parent, parent, parent]);
    const plain = scripted([200]);
    await callUpstreams(targets(), { model: "large", messages: [] }, plain.options);
    assert.equal("traceparent" in (plain.calls[0]?.init.headers as Record<string, string>), false);
  });

  it("doubles the backoff's ceiling before each retry, waits a random part of it, and stops after `retries`", async () => {
    const s = scripted([500, 500, 500, 500, 200]);
    const outcome = await callUpstreams(targets(), { model: "large", messages: [] }, { ...s.options, retries: 3 });
    assert.equal(outcome.ok && outcome.target.upstream.name, "fallback");
    assert.deepEqual(s.sleeps, [50, 100, 200]);
    const low = scripted([500, 500, 500, 500, 200]);
    await callUpstreams(targets(), { model: "large", messages: [] }, { ...low.options, retries: 3, random: () => 0 });
    assert.deepEqual(low.sleeps, [0, 0, 0], "full jitter can retry at once");
  });

  it("caps the backoff at maxBackoffMs", async () => {
    const s = scripted([500, 500, 500, 500, 200]);
    await callUpstreams(targets(), { model: "large", messages: [] }, { ...s.options, retries: 3, maxBackoffMs: 150, random: () => 0.999999 });
    assert.deepEqual(s.sleeps, [99, 149, 149]);
    assert.deepEqual([1, 2, 3, 4].map((n) => backoffCeiling(100, 150, n)), [100, 150, 150, 150]);
    assert.deepEqual([1, 2, 3].map((n) => backoffCeiling(100, undefined, n)), [100, 200, 400]);
  });

  it("whatever the jitter, the waits of a call fit inside longestCallMs (what a reservation is sized by)", async () => {
    const config = { timeoutMs: 1000, retries: 3, backoffMs: 400, maxBackoffMs: 1000, rateLimitWaitMs: 2000 };
    const failures: Step[][] = [
      [500, 500, 500, 500, 500, 500, 500, 500],
      ["timeout", 503, 408, 500, 500, 502, 504, { status: 429, retryAfter: "1" }, 500],
      [429, 500, 500, 500, { status: 429 }, 500],
      // the one wait after a 429 on the last upstream, between backoffs
      [500, 500, 500, 500, { status: 429, retryAfter: "1" }, 500, 500, 500],
    ];
    for (const steps of failures) {
      for (const r of [0, 0.25, 0.5, 0.75, 0.999999]) {
        const s = scripted(steps);
        // Each failure is logged with its upstream; the wait after the n-th failure on an upstream is a
        // backoff with ceiling min(maxBackoffMs, backoffMs x 2^(n-1)), or after a 429 the one capped wait.
        const failures = new Map<string, number>();
        let last: { upstream: string; is429: boolean } | undefined;
        const log = (message: string): void => {
          const upstream = /upstream "([^"]+)"/.exec(message)?.[1] ?? "?";
          failures.set(upstream, (failures.get(upstream) ?? 0) + 1);
          last = { upstream, is429: / answered 429 /.test(message) };
        };
        const sleep = async (ms: number): Promise<void> => {
          s.sleeps.push(ms);
          assert.ok(last, "a wait comes after a failure");
          const ceiling = last.is429 ? config.rateLimitWaitMs : backoffCeiling(config.backoffMs, config.maxBackoffMs, failures.get(last.upstream) as number);
          assert.ok(ms <= ceiling, `a wait of ${ms} ms after failure ${failures.get(last.upstream)} on ${last.upstream} is above its ceiling of ${ceiling} ms (random ${r})`);
        };
        const outcome = await callUpstreams(targets(), { model: "large", messages: [] }, { ...s.options, ...config, random: () => r, log, sleep });
        assert.equal(outcome.ok, false);
        // Every attempt timing out is the worst case for the attempts themselves.
        const worst = s.calls.length * config.timeoutMs + s.sleeps.reduce((a, b) => a + b, 0);
        assert.ok(worst <= longestCallMs(config), `${worst} ms > ${longestCallMs(config)} ms with random ${r}`);
      }
    }
    // With the defaults the bound is what Cloud Run's request timeout is set against (test/llm/deploy.test.ts).
    assert.equal(longestCallMs({ timeoutMs: 60_000, retries: 1, backoffMs: 250, maxBackoffMs: 10_000, rateLimitWaitMs: 2000 }), 242_500);
  });

  it("a client that leaves during a wait ends the wait at once: the call does not sleep out its backoff", async () => {
    const controller = new AbortController();
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return new Response("{}", { status: 500 });
    }) as typeof fetch;
    setTimeout(() => controller.abort(), 50);
    const started = Date.now();
    // No sleep is passed in: the gateway's own wait, here up to 5 s, is the one under test.
    const outcome = await callUpstreams(targets().slice(0, 1), { model: "large", messages: [] }, { timeoutMs: 1000, retries: 1, backoffMs: 5000, random: () => 0.99, apiKey: () => "k", fetch: fetchImpl, signal: controller.signal });
    assert.deepEqual([outcome.ok, !outcome.ok && outcome.failure, calls], [false, "cancelled", 1]);
    assert.ok(Date.now() - started < 2000, `the wait was cut short (${Date.now() - started} ms)`);
  });

  it("with no fallback and retries 0, makes exactly one attempt", async () => {
    const s = scripted([500]);
    const outcome = await callUpstreams(targets().slice(0, 1), { model: "large", messages: [] }, { ...s.options, retries: 0 });
    assert.deepEqual(outcome, { ok: false, failure: "server_error", status: 500, attempts: 1, rateLimited: 0 });
  });

  it("with rateLimitWaitMs 0, a 429 on the last upstream is the answer at once", async () => {
    const s = scripted([{ status: 429, retryAfter: "0" }]);
    const outcome = await callUpstreams(targets().slice(0, 1), { model: "large", messages: [] }, { ...s.options, rateLimitWaitMs: 0 });
    assert.deepEqual(outcome, { ok: false, failure: "rate_limited", status: 429, attempts: 1, rateLimited: 1, retryAfterSeconds: 0 });
    assert.deepEqual(s.sleeps, []);
  });

  it("reads Retry-After as seconds or as an HTTP date", () => {
    const now = Date.parse("Wed, 21 Oct 2026 07:27:30 GMT");
    assert.deepEqual(
      [retryAfterMs("5", now), retryAfterMs(" 12 ", now), retryAfterMs("Wed, 21 Oct 2026 07:28:00 GMT", now), retryAfterMs("Wed, 21 Oct 2026 07:00:00 GMT", now), retryAfterMs("soon", now), retryAfterMs(null, now), retryAfterMs("-3", now)],
      [5000, 12000, 30_000, 0, undefined, undefined, undefined],
    );
  });

  it("ends an answer that stalls after its headers at the attempt's timeout, though fetch no longer reacts to the signal", { timeout: 20_000 }, async () => {
    // Node's fetch follows its caller's signal through a weak reference that a garbage collection can drop once the
    // response has been handed back (see readChunk in upstream.ts). This stand-in never reacts to the signal at all,
    // so only the gateway's own read can end the wait.
    let cancelled = false;
    const fetchImpl = (async () =>
      new Response(
        new ReadableStream<Uint8Array>({
          pull: () => new Promise<void>(() => undefined), // headers, then nothing, ever
          cancel: () => {
            cancelled = true;
          },
        }),
        { status: 200 },
      )) as typeof fetch;
    // The signal's timer does not keep Node running, and a stand-in has no socket that would: this does.
    const keepRunning = setInterval(() => undefined, 1000);
    try {
      const outcome = await callUpstreams(targets().slice(0, 1), { model: "large", messages: [] }, { timeoutMs: 100, retries: 0, backoffMs: 0, apiKey: () => "k", fetch: fetchImpl });
      assert.deepEqual(outcome, { ok: false, failure: "timeout", attempts: 1, rateLimited: 0 });
      assert.equal(cancelled, true, "the stalled body was cancelled, so its connection is let go");
    } finally {
      clearInterval(keepRunning);
    }
  });

  it("times out for real against an upstream that never answers", async () => {
    const hanging = http.createServer(() => {
      // never answers
    });
    await new Promise<void>((resolve) => hanging.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(hanging.address() as AddressInfo).port}/v1`;
    try {
      const started = Date.now();
      const outcome = await callUpstreams(targets(url, url).slice(0, 1), { model: "large", messages: [] }, { timeoutMs: 150, retries: 0, backoffMs: 0, apiKey: () => "k" });
      assert.deepEqual(outcome, { ok: false, failure: "timeout", attempts: 1, rateLimited: 0 });
      assert.ok(Date.now() - started < 5000, "the timeout cut the call short");
    } finally {
      hanging.closeAllConnections();
      await new Promise<void>((resolve) => hanging.close(() => resolve()));
    }
  });
});
