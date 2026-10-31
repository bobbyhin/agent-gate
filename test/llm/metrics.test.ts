// GET /metrics: the Prometheus text, the two ways to read it (a key of its own on the gateway's port,
// or a keyless listener that the config allows only on a loopback address), and the config checks.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { hashKey, isLoopback, parseLlmConfig } from "../../src/llm/config.js";
import { parseLeakPolicy } from "../../src/llm/leak-guard.js";
import { CONTENT_TYPE, Metrics } from "../../src/llm/metrics.js";
import { startLlmGateway, type LlmGateway } from "../../src/llm/server.js";
import { FAKE_GATEWAY_KEYS } from "./fake-secrets.js";
import { startFakeUpstream, type FakeUpstream } from "./fake-upstream.js";

const METRICS_KEY = "fake-metrics-key-for-the-scraper-0001";

function base(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    stateDir: "state",
    policy: "p.json",
    upstreams: [{ name: "up", baseUrl: "http://127.0.0.1:9/v1", apiKeyEnv: "UP_KEY", models: { small: "s" }, pricePerMTok: { input: 1, output: 1 } }],
    routes: [{ id: "all", use: { upstream: "up" } }],
    keys: [{ name: "team-a", sha256: hashKey(FAKE_GATEWAY_KEYS.teamA), dailyUsd: 1, monthlyUsd: 10 }],
    ...extra,
  };
}

describe("Metrics: the text format", () => {
  it("counts requests by route, upstream and status, tokens, cost and a cumulative duration histogram", () => {
    const m = new Metrics();
    m.record({ route: "r", upstream: "u", status: 200, inputTokens: 10, outputTokens: 2, costUsd: 0.000001, latencyMs: 40 });
    m.record({ route: "r", upstream: "u", status: 200, inputTokens: 5, outputTokens: 1, costUsd: 0.000002, latencyMs: 300 });
    m.record({ status: 400, inputTokens: 0, outputTokens: 0, costUsd: 0, latencyMs: 70_000 });
    const text = m.render([{ key: "team-a", day: "2026-10-31", dayUsd: 0.25, dailyUsd: 1, month: "2026-10", monthUsd: 4, monthlyUsd: 10, inFlight: 1, reservedUsd: 0.05 }]);
    const lines = text.trimEnd().split("\n");
    for (const name of ["requests_total", "tokens_total", "cost_usd_total", "request_duration_seconds", "budget_remaining_usd"]) {
      assert.ok(lines.includes(`# TYPE agent_gate_llm_${name} ${name.endsWith("seconds") ? "histogram" : name.startsWith("budget") ? "gauge" : "counter"}`), name);
    }
    for (const sample of [
      'agent_gate_llm_requests_total{route="",upstream="",status="400"} 1',
      'agent_gate_llm_requests_total{route="r",upstream="u",status="200"} 2',
      'agent_gate_llm_tokens_total{direction="input"} 15',
      'agent_gate_llm_tokens_total{direction="output"} 3',
      "agent_gate_llm_cost_usd_total 0.000003",
      'agent_gate_llm_request_duration_seconds_bucket{le="0.05"} 1',
      'agent_gate_llm_request_duration_seconds_bucket{le="0.25"} 1',
      'agent_gate_llm_request_duration_seconds_bucket{le="0.5"} 2',
      'agent_gate_llm_request_duration_seconds_bucket{le="60"} 2',
      'agent_gate_llm_request_duration_seconds_bucket{le="+Inf"} 3',
      "agent_gate_llm_request_duration_seconds_sum 70.34",
      "agent_gate_llm_request_duration_seconds_count 3",
      'agent_gate_llm_budget_remaining_usd{key="team-a",cap="daily"} 0.7',
      'agent_gate_llm_budget_remaining_usd{key="team-a",cap="monthly"} 5.95',
    ]) {
      assert.ok(lines.includes(sample), `missing: ${sample}\n${text}`);
    }
    assert.ok(text.endsWith("\n"));
  });

  it("escapes label values and never reports a budget below zero", () => {
    const m = new Metrics();
    m.record({ route: 'a"b\\c\nd', upstream: "u", status: 200, inputTokens: 0, outputTokens: 0, costUsd: 0, latencyMs: 1 });
    const text = m.render([{ key: "k", day: "d", dayUsd: 2, dailyUsd: 1, month: "m", monthUsd: 0, monthlyUsd: 1, inFlight: 0, reservedUsd: 0 }]);
    assert.ok(text.includes('agent_gate_llm_requests_total{route="a\\"b\\\\c\\nd",upstream="u",status="200"} 1'));
    assert.ok(text.includes('agent_gate_llm_budget_remaining_usd{key="k",cap="daily"} 0\n'));
    assert.equal(text.split("\n").filter((l) => l.startsWith("agent_gate_llm_requests_total")).length, 1, "one sample, one line");
  });
});

describe("config.metrics", () => {
  it("takes a key of its own, a loopback listener, or both", () => {
    const config = parseLlmConfig(base({ metrics: { sha256: hashKey(METRICS_KEY), listen: { port: 9464 } } }), "/srv");
    assert.deepEqual(config.metrics, { sha256: hashKey(METRICS_KEY), listen: { host: "127.0.0.1", port: 9464 } });
    assert.equal(parseLlmConfig(base(), "/srv").metrics, undefined);
  });
  const bad: Array<[string, unknown, RegExp]> = [
    ["neither", {}, /config\.metrics needs "sha256"/],
    ["a keyless listener on every interface", { listen: { host: "0.0.0.0", port: 9464 } }, /must be a loopback address/],
    ["a name instead of an address", { listen: { host: "localhost", port: 9464 } }, /must be a loopback address/],
    ["a listener without a port", { listen: { host: "127.0.0.1" } }, /config\.metrics\.listen\.port must be a whole number/],
    ["a gateway key as the metrics key", { sha256: hashKey(FAKE_GATEWAY_KEYS.teamA) }, /is the hash of a gateway key/],
    ["a key instead of its hash", { sha256: METRICS_KEY }, /64 lowercase hex characters/],
    ["an unknown field", { sha256: hashKey(METRICS_KEY), public: true }, /unknown field "public"/],
  ];
  for (const [what, metrics, error] of bad) it(`refuses ${what}`, () => assert.throws(() => parseLlmConfig(base({ metrics }), "/srv"), error));
  it("knows loopback addresses", () => {
    assert.deepEqual(["127.0.0.1", "127.1.2.3", "::1", "0.0.0.0", "10.0.0.1", "::", "localhost", "127.0.0.1.example"].map(isLoopback), [true, true, true, false, false, false, false, false]);
  });
});

describe("GET /metrics on a running gateway", () => {
  let fake: FakeUpstream;
  let tmp: string;
  let gateway: LlmGateway;
  let plain: LlmGateway;

  before(async () => {
    fake = await startFakeUpstream({ mode: "ok", usage: { prompt_tokens: 100, completion_tokens: 10 } });
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-metrics-"));
    const policy = parseLeakPolicy({ leakGuard: [] });
    const config = (stateDir: string, metrics?: unknown) =>
      parseLlmConfig({ ...base(metrics ? { metrics } : {}), listen: { port: 0 }, stateDir, upstreams: [{ name: "up", baseUrl: `${fake.url}/v1`, apiKeyEnv: "UP_KEY", models: { small: "s" }, pricePerMTok: { input: 1, output: 1 } }] }, tmp);
    const options = { env: { UP_KEY: "fake-upstream-key-metrics" }, log: () => undefined };
    gateway = await startLlmGateway(config("a", { sha256: hashKey(METRICS_KEY), listen: { host: "127.0.0.1", port: 0 } }), policy, options);
    plain = await startLlmGateway(config("b"), policy, options);
  });
  after(async () => {
    await gateway?.close();
    await plain?.close();
    await fake?.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const chat = (url: string) =>
    fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${FAKE_GATEWAY_KEYS.teamA}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "small", messages: [{ role: "user", content: "hi" }], max_tokens: 10 }),
    });

  it("reports the calls made, behind the metrics key on the gateway's port", async () => {
    assert.equal((await chat(gateway.url)).status, 200);
    assert.equal((await chat(gateway.url)).status, 200);
    const res = await fetch(`${gateway.url}/metrics`, { headers: { authorization: `Bearer ${METRICS_KEY}` } });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), CONTENT_TYPE);
    const text = await res.text();
    for (const sample of [
      'agent_gate_llm_requests_total{route="all",upstream="up",status="200"} 2',
      'agent_gate_llm_tokens_total{direction="input"} 200',
      'agent_gate_llm_tokens_total{direction="output"} 20',
      "agent_gate_llm_cost_usd_total 0.00022",
      "agent_gate_llm_request_duration_seconds_count 2",
      'agent_gate_llm_budget_remaining_usd{key="team-a",cap="daily"} 0.99978',
    ]) {
      assert.ok(text.includes(`${sample}\n`), `missing: ${sample}\n${text}`);
    }
  });

  it("refuses the port's /metrics without the metrics key, a gateway key included", async () => {
    for (const authorization of [undefined, `Bearer ${FAKE_GATEWAY_KEYS.teamA}`, `Bearer ${METRICS_KEY}x`]) {
      const res = await fetch(`${gateway.url}/metrics`, { headers: authorization ? { authorization } : {} });
      assert.equal(res.status, 401, String(authorization));
      assert.equal(res.headers.get("www-authenticate"), 'Bearer realm="agent-gate-metrics"');
      assert.equal((await res.text()).includes("agent_gate_llm"), false);
    }
    assert.equal((await fetch(`${gateway.url}/metrics`, { method: "POST", headers: { authorization: `Bearer ${METRICS_KEY}` } })).status, 405);
  });

  it("serves the loopback listener without a key, and nothing else there", async () => {
    assert.match(gateway.metricsUrl ?? "", /^http:\/\/127\.0\.0\.1:\d+$/);
    const res = await fetch(`${gateway.metricsUrl}/metrics`);
    assert.equal(res.status, 200);
    assert.match(await res.text(), /agent_gate_llm_requests_total\{route="all",upstream="up",status="200"\} 2\n/);
    assert.equal((await fetch(`${gateway.metricsUrl}/v1/chat/completions`, { method: "POST" })).status, 404);
    assert.equal((await fetch(`${gateway.metricsUrl}/healthz`)).status, 404);
  });

  it("does not serve /metrics at all without config.metrics", async () => {
    assert.equal(plain.metricsUrl, undefined);
    const res = await fetch(`${plain.url}/metrics`, { headers: { authorization: `Bearer ${METRICS_KEY}` } });
    assert.equal(res.status, 404);
  });
});
