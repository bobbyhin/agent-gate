// Tests for retries and the fallback, with a fetch and a sleep the test controls, plus one real
// timeout against a local server that never answers.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { parseLlmConfig } from "../../src/llm/config.js";
import { route, type ResolvedTarget } from "../../src/llm/routing.js";
import { callUpstreams, retryAfterMs, type UpstreamOptions } from "../../src/llm/upstream.js";

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
    ["a 500 is retried once on the same upstream", [500, 200], { ok: true, upstream: "primary", status: 200, attempts: 2, fallback: false }, [100]],
    ["two 5xx move on to the fallback", [500, 503, 200], { ok: true, upstream: "fallback", status: 200, attempts: 3, fallback: true }, [100]],
    ["a timeout is retried, then the fallback answers", ["timeout", "timeout", 200], { ok: true, upstream: "fallback", status: 200, attempts: 3, fallback: true }, [100]],
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
    ["the retry after a 429 is one of the upstream's retries", [500, 500, 500, { status: 429, retryAfter: "1" }], { ok: false, failure: "rate_limited", status: 429, attempts: 4, rateLimited: 1, retryAfterSeconds: 1 }, [100, 100]],
    ["every attempt fails with a 5xx", [500, 500, 502, 503], { ok: false, failure: "server_error", status: 503, attempts: 4, rateLimited: 0 }, [100, 100]],
    ["the last failure decides: timeout", [500, 500, "unreachable", "timeout"], { ok: false, failure: "timeout", attempts: 4, rateLimited: 0 }, [100, 100]],
    ["the last failure decides: unreachable", ["timeout", "timeout", "unreachable", "unreachable"], { ok: false, failure: "unreachable", attempts: 4, rateLimited: 0 }, [100, 100]],
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

  it("doubles the backoff before each retry and stops after `retries`", async () => {
    const s = scripted([500, 500, 500, 500, 200]);
    const outcome = await callUpstreams(targets(), { model: "large", messages: [] }, { ...s.options, retries: 3 });
    assert.equal(outcome.ok && outcome.target.upstream.name, "fallback");
    assert.deepEqual(s.sleeps, [100, 200, 400]);
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
