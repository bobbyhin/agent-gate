// Tests for retries and the fallback, with a fetch and a sleep the test controls, plus one real
// timeout against a local server that never answers.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { parseLlmConfig } from "../../src/llm/config.js";
import { route, type ResolvedTarget } from "../../src/llm/routing.js";
import { callUpstreams, type UpstreamOptions } from "../../src/llm/upstream.js";

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

type Step = number | "timeout" | "unreachable";

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
    return new Response(JSON.stringify({ status: step }), { status: step });
  }) as typeof fetch;
  const options: UpstreamOptions = {
    timeoutMs: 1000,
    retries: 1,
    backoffMs: 100,
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
    ["an upstream 429 is passed on, not retried", [429], { ok: true, upstream: "primary", status: 429, attempts: 1, fallback: false }, []],
    ["every attempt fails with a 5xx", [500, 500, 502, 503], { ok: false, failure: "server_error", status: 503, attempts: 4 }, [100, 100]],
    ["the last failure decides: timeout", [500, 500, "unreachable", "timeout"], { ok: false, failure: "timeout", attempts: 4 }, [100, 100]],
    ["the last failure decides: unreachable", ["timeout", "timeout", "unreachable", "unreachable"], { ok: false, failure: "unreachable", attempts: 4 }, [100, 100]],
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

  it("doubles the backoff before each retry and stops after `retries`", async () => {
    const s = scripted([500, 500, 500, 500, 200]);
    const outcome = await callUpstreams(targets(), { model: "large", messages: [] }, { ...s.options, retries: 3 });
    assert.equal(outcome.ok && outcome.target.upstream.name, "fallback");
    assert.deepEqual(s.sleeps, [100, 200, 400]);
  });

  it("with no fallback and retries 0, makes exactly one attempt", async () => {
    const s = scripted([500]);
    const outcome = await callUpstreams(targets().slice(0, 1), { model: "large", messages: [] }, { ...s.options, retries: 0 });
    assert.deepEqual(outcome, { ok: false, failure: "server_error", status: 500, attempts: 1 });
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
      assert.deepEqual(outcome, { ok: false, failure: "timeout", attempts: 1 });
      assert.ok(Date.now() - started < 5000, "the timeout cut the call short");
    } finally {
      hanging.closeAllConnections();
      await new Promise<void>((resolve) => hanging.close(() => resolve()));
    }
  });
});
