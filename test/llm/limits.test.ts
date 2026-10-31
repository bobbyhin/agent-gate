// Stop rules on a running gateway: a loop that fires fast is cut at call N by maxCallsPerMinute, a
// run (x-run-id) is cut by runMaxCalls and runMaxUsd, and each cut is in the usage log with its reason.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { hashKey, parseLlmConfig } from "../../src/llm/config.js";
import { parseLeakPolicy } from "../../src/llm/leak-guard.js";
import { startLlmGateway, type LlmGateway } from "../../src/llm/server.js";
import { FAKE_GATEWAY_KEYS } from "./fake-secrets.js";
import { startFakeUpstream, type FakeUpstream } from "./fake-upstream.js";
import { RepeatWindow } from "../../src/llm/repeats.js";

const KEY_A = FAKE_GATEWAY_KEYS.teamA;
const KEY_B = FAKE_GATEWAY_KEYS.teamB;

describe("stop rules: calls per minute, and calls and dollars per run", () => {
  let fake: FakeUpstream;
  let tmp: string;
  let gateway: LlmGateway;

  before(async () => {
    // Each call costs (100 + 10) tokens x $1 per million = $0.00011.
    fake = await startFakeUpstream({ mode: "ok", usage: { prompt_tokens: 100, completion_tokens: 10 } });
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-limits-"));
    const config = parseLlmConfig(
      {
        listen: { port: 0 },
        stateDir: "state",
        policy: "p.json",
        upstreams: [{ name: "up", baseUrl: `${fake.url}/v1`, apiKeyEnv: "UP_KEY", models: { small: "s" }, pricePerMTok: { input: 1, output: 1 } }],
        routes: [{ id: "all", use: { upstream: "up" } }],
        keys: [
          { name: "rated", sha256: hashKey(KEY_A), dailyUsd: 1, monthlyUsd: 10, maxCallsPerMinute: 5 },
          { name: "runs", sha256: hashKey(KEY_B), dailyUsd: 1, monthlyUsd: 10, runMaxCalls: 3, runMaxUsd: 0.0003 },
        ],
      },
      tmp,
    );
    gateway = await startLlmGateway(config, parseLeakPolicy({ leakGuard: [] }), { env: { UP_KEY: "fake-upstream-key-limits" }, log: () => undefined });
  });
  after(async () => {
    await gateway?.close();
    await fake?.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const chat = async (key: string, runId?: string, maxTokens = 10) => {
    const res = await fetch(`${gateway.url}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json", ...(runId ? { "x-run-id": runId } : {}) },
      body: JSON.stringify({ model: "small", messages: [{ role: "user", content: "again" }], max_tokens: maxTokens }),
    });
    return { status: res.status, retryAfter: res.headers.get("retry-after"), json: (await res.json()) as { error?: { code: string; message: string; cap: string } } };
  };
  const usageLines = () =>
    fs
      .readFileSync(path.join(tmp, "state", "usage.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, any>);

  it("a loop that fires fast is cut at call 6 of a minute by maxCallsPerMinute, with a Retry-After of its own", async () => {
    const statuses: number[] = [];
    let cut: Awaited<ReturnType<typeof chat>> | undefined;
    for (let i = 0; i < 8; i++) {
      const r = await chat(KEY_A);
      statuses.push(r.status);
      if (r.status === 429 && !cut) cut = r;
    }
    assert.deepEqual(statuses, [200, 200, 200, 200, 200, 429, 429, 429]);
    assert.equal(cut?.json.error?.code, "rate_limited");
    assert.match(cut?.json.error?.message ?? "", /key "rated" has made 5 calls in the last minute, its limit \(maxCallsPerMinute\)/);
    const wait = Number(cut?.retryAfter);
    assert.ok(wait >= 1 && wait <= 60, `retry-after ${cut?.retryAfter}`);
    assert.equal(fake.requests.length, 5, "the cut calls never reached the upstream");
  });

  it("a run is cut at its third call by runMaxCalls; retrying does not help, another run is not cut", async () => {
    const statuses = [];
    for (let i = 0; i < 5; i++) statuses.push((await chat(KEY_B, "loop-1")).status);
    assert.deepEqual(statuses, [200, 200, 200, 429, 429]);
    const cut = await chat(KEY_B, "loop-1");
    assert.deepEqual([cut.status, cut.json.error?.code, cut.json.error?.cap, cut.retryAfter], [429, "run_limit_reached", "runMaxCalls", null]);
    assert.match(cut.json.error?.message ?? "", /run "loop-1" of key "runs" has made 3 calls, its limit \(runMaxCalls\)\. Retrying will not help: the run should stop\./);
    assert.equal((await chat(KEY_B, "loop-2")).status, 200);
    assert.equal((await chat(KEY_B)).status, 200, "no run id: the run caps do not apply");
  });

  it("a run is cut by runMaxUsd before it can pass it, counting what its calls already cost", async () => {
    // $0.00011 settled per call. After two, a call that asks for 100 output tokens could cost
    // $0.000102 (2 + 100 tokens at $1 per million), which would pass $0.0003; one that asks for 10 would not.
    assert.equal((await chat(KEY_B, "spender")).status, 200);
    assert.equal((await chat(KEY_B, "spender")).status, 200);
    const cut = await chat(KEY_B, "spender", 100);
    assert.deepEqual([cut.status, cut.json.error?.code, cut.json.error?.cap], [429, "run_limit_reached", "runMaxUsd"]);
    assert.match(cut.json.error?.message ?? "", /could cost up to \$0\.000102, and run "spender" of key "runs" has \$0\.00008 left of its budget of \$0\.0003 \(\$0\.00022 spent, \$0 held by its calls in flight\)/);
    assert.equal((await chat(KEY_B, "spender", 10)).status, 200, "a smaller call still fits");
  });

  it("writes each cut to the usage log: the error, the rule and the run", () => {
    const cuts = usageLines().filter((l) => l.status === 429);
    assert.deepEqual(
      cuts.map((l) => [l.key, l.error, l.rule, l.runId ?? null, l.costUsd]),
      [
        ["rated", "rate_limited", "maxCallsPerMinute", null, 0],
        ["rated", "rate_limited", "maxCallsPerMinute", null, 0],
        ["rated", "rate_limited", "maxCallsPerMinute", null, 0],
        ["runs", "run_limit_reached", "runMaxCalls", "loop-1", 0],
        ["runs", "run_limit_reached", "runMaxCalls", "loop-1", 0],
        ["runs", "run_limit_reached", "runMaxCalls", "loop-1", 0],
        ["runs", "run_limit_reached", "runMaxUsd", "spender", 0],
      ],
    );
  });

  it("refuses limits that are not whole numbers above zero, or an unknown limit", () => {
    const key = (extra: Record<string, unknown>) => ({ name: "k", sha256: "a".repeat(64), dailyUsd: 1, monthlyUsd: 1, ...extra });
    const config = (extra: Record<string, unknown>) => ({ stateDir: "s", policy: "p", upstreams: [{ name: "u", baseUrl: "http://127.0.0.1:9/v1", apiKeyEnv: "K", models: { m: "m" }, pricePerMTok: { input: 1, output: 1 } }], routes: [{ id: "r", use: { upstream: "u" } }], keys: [key(extra)] });
    assert.throws(() => parseLlmConfig(config({ maxCallsPerMinute: 0 }), "/"), /maxCallsPerMinute must be a whole number from 1/);
    assert.throws(() => parseLlmConfig(config({ runMaxCalls: 2.5 }), "/"), /runMaxCalls must be a whole number/);
    assert.throws(() => parseLlmConfig(config({ runMaxUsd: -1 }), "/"), /runMaxUsd must be a positive number/);
    assert.throws(() => parseLlmConfig(config({ maxTokensPerMinute: 10 }), "/"), /unknown field "maxTokensPerMinute"/);
    assert.throws(() => parseLlmConfig(config({ repeatMax: 5 }), "/"), /repeatMax and repeatWindowSeconds go together/);
    assert.throws(() => parseLlmConfig(config({ repeatWindowSeconds: 60 }), "/"), /repeatMax and repeatWindowSeconds go together/);
    assert.throws(() => parseLlmConfig(config({ repeatMax: 0, repeatWindowSeconds: 60 }), "/"), /repeatMax must be a whole number from 1/);
    assert.throws(() => parseLlmConfig(config({ repeatMax: 5, repeatWindowSeconds: 0.5 }), "/"), /repeatWindowSeconds must be a whole number from 1/);
  });
});

describe("stop rules: the same request again and again (repeatMax)", () => {
  let fake: FakeUpstream;
  let tmp: string;
  let gateway: LlmGateway;
  let clock = Date.parse("2026-10-31T12:00:00.000Z");

  before(async () => {
    fake = await startFakeUpstream({ mode: "ok", usage: { prompt_tokens: 100, completion_tokens: 10 } });
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-repeats-"));
    const config = parseLlmConfig(
      {
        listen: { port: 0 },
        stateDir: "state",
        policy: "p.json",
        upstreams: [{ name: "up", baseUrl: `${fake.url}/v1`, apiKeyEnv: "UP_KEY", models: { small: "s", large: "l" }, pricePerMTok: { input: 1, output: 1 } }],
        routes: [{ id: "all", use: { upstream: "up" } }],
        keys: [
          { name: "looper", sha256: hashKey(KEY_A), dailyUsd: 1, monthlyUsd: 10, repeatMax: 5, repeatWindowSeconds: 60 },
          { name: "free", sha256: hashKey(KEY_B), dailyUsd: 1, monthlyUsd: 10 },
        ],
      },
      tmp,
    );
    gateway = await startLlmGateway(config, parseLeakPolicy({ leakGuard: [] }), { env: { UP_KEY: "fake-upstream-key-repeats" }, log: () => undefined, now: () => clock });
  });
  after(async () => {
    await gateway?.close();
    await fake?.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const chat = async (key: string, content: string, extra: Record<string, unknown> = {}) => {
    const res = await fetch(`${gateway.url}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "small", messages: [{ role: "user", content }], max_tokens: 10, ...extra }),
    });
    return { status: res.status, retryAfter: res.headers.get("retry-after"), json: (await res.json()) as { error?: { code: string; message: string; cap: string } } };
  };

  it("lets the same request through repeatMax times in the window, then refuses it as a loop", async () => {
    const calls = fake.requests.length;
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      statuses.push((await chat(KEY_A, "check the build again")).status);
      clock += 1000;
    }
    assert.deepEqual(statuses, [200, 200, 200, 200, 200, 429]);
    assert.equal(fake.requests.length, calls + 5, "the sixth never reached the upstream");
    const refused = await chat(KEY_A, "check the build again");
    assert.equal(refused.status, 429);
    assert.equal(refused.json.error?.code, "loop_suspected");
    assert.match(refused.json.error?.message ?? "", /has sent this same request 5 times in the last 60 s, its limit \(repeatMax\); that looks like a loop/);
    // The oldest of the five went through 6 s ago, so it leaves the window in 54 s.
    assert.equal(refused.retryAfter, "54");
  });

  it("counts only the same request: other messages, another model or key order changes", async () => {
    assert.equal((await chat(KEY_A, "check the tests instead")).status, 200);
    assert.equal((await chat(KEY_A, "check the build again", { model: "large" })).status, 200);
    // The same fields in another order are the same request.
    const reordered = await fetch(`${gateway.url}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${KEY_A}`, "content-type": "application/json" },
      body: JSON.stringify({ max_tokens: 10, messages: [{ content: "check the build again", role: "user" }], model: "small" }),
    });
    assert.equal(reordered.status, 429);
    // A key without the rule is not held to it.
    for (let i = 0; i < 6; i++) assert.equal((await chat(KEY_B, "check the build again")).status, 200);
  });

  it("lets it through again once the oldest copies leave the window, and logs each refusal", async () => {
    clock += 60_000;
    assert.equal((await chat(KEY_A, "check the build again")).status, 200);
    const lines = fs
      .readFileSync(path.join(tmp, "state", "usage.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    assert.deepEqual(
      lines.filter((l) => l.status === 429).map((l) => [l.key, l.error, l.rule, l.costUsd]),
      [
        ["looper", "loop_suspected", "repeatMax", 0],
        ["looper", "loop_suspected", "repeatMax", 0],
        ["looper", "loop_suspected", "repeatMax", 0],
      ],
    );
  });
});

describe("RepeatWindow: the memory of repeated requests", () => {
  it("forgets the requests of a key that went quiet, not only of the key that is calling", () => {
    const window = new RepeatWindow();
    const windowMs = 60_000;
    for (let i = 0; i < 1000; i++) window.admit("quiet-key", `hash-${i}`, windowMs, 1_000);
    assert.equal(window.size(), 1000);
    // Ten windows later another key calls; the periodic sweep drops what left every key's window.
    const later = 1_000 + 10 * windowMs;
    for (let i = 0; i < 256; i++) window.admit("busy-key", "same-request", windowMs, later + i);
    assert.equal(window.size(), 1, "only the busy key's one request is still held");
    // What is still inside its window is kept, and counted.
    assert.deepEqual(window.check("busy-key", "same-request", 300, windowMs, later + 300), { ok: true });
    assert.equal(window.check("busy-key", "same-request", 256, windowMs, later + 300).ok, false);
  });
});
