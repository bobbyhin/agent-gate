// End to end: the real CLI ("agent-gate llm serve") runs in a child process, in front of two fake
// upstream HTTP servers created here: one healthy, one that answers every call with HTTP 500.
// The test talks to the gateway over HTTP like any OpenAI-compatible client would, and checks
// what reached each upstream and what was written to the state directory.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { hashKey } from "../../src/llm/config.js";
import { FAKE, FAKE_GATEWAY_KEYS, FAKE_PROVIDER_KEYS } from "./fake-secrets.js";
import { startFakeUpstream, type FakeUpstream } from "./fake-upstream.js";

// This file runs from dist/test/llm/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const BIN = path.join(ROOT, "bin", "agent-gate.js");
const KEY_A = FAKE_GATEWAY_KEYS.teamA;
const KEY_B = FAKE_GATEWAY_KEYS.teamB;
// What the healthy fake reports for every call. The settled cost must come from these numbers.
const USAGE = { prompt_tokens: 1234, completion_tokens: 56 };

interface Reply {
  status: number;
  headers: Headers;
  text: string;
  json: any;
}

describe("LLM gateway end to end", () => {
  let healthy: FakeUpstream;
  let failing: FakeUpstream;
  let tmp: string;
  let stateDir: string;
  let configFile: string;
  let gateway: ChildProcess;
  let url = "";
  let stderr = "";
  /** Every response's headers and body, for the provider-key check at the end. */
  const seen: string[] = [];
  let authenticated = 0;
  let marker = 0;

  before(async () => {
    healthy = await startFakeUpstream({ mode: "ok", keys: [FAKE_PROVIDER_KEYS.E2E_CHEAP_KEY, FAKE_PROVIDER_KEYS.E2E_STRONG_KEY], usage: USAGE });
    failing = await startFakeUpstream({ mode: "fail" });
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-llm-e2e-"));
    stateDir = path.join(tmp, "state");
    configFile = path.join(tmp, "llm-gateway.config.json");
    fs.writeFileSync(
      configFile,
      JSON.stringify({
        listen: { host: "127.0.0.1", port: 0 },
        stateDir: "state",
        policy: path.join(ROOT, "llm-policy.example.json"),
        upstreams: [
          { name: "cheap", baseUrl: `${healthy.url}/v1`, apiKeyEnv: "E2E_CHEAP_KEY", models: { small: "fake-small-1" }, pricePerMTok: { input: 0.5, output: 1.5 } },
          { name: "strong", baseUrl: `${healthy.url}/v1`, apiKeyEnv: "E2E_STRONG_KEY", models: { large: "fake-large-1" }, pricePerMTok: { input: 5, output: 15 } },
          { name: "flaky", baseUrl: `${failing.url}/v1`, apiKeyEnv: "E2E_FLAKY_KEY", models: { large: "flaky-large-1" }, pricePerMTok: { input: 4, output: 12 } },
          { name: "misconfigured", baseUrl: `${healthy.url}/v1`, apiKeyEnv: "E2E_WRONG_KEY", models: { small: "fake-small-1" }, pricePerMTok: { input: 0.5, output: 1.5 } },
        ],
        routes: [
          { id: "classify-is-cheap", when: { task: "classify" }, use: { upstream: "cheap", model: "small" } },
          { id: "code-is-strong", when: { task: "code" }, use: { upstream: "flaky", model: "large" }, fallback: { upstream: "strong" } },
          { id: "flaky-only", when: { task: "flaky" }, use: { upstream: "flaky", model: "large" } },
          { id: "wrong-key", when: { task: "wrong-key" }, use: { upstream: "misconfigured", model: "small" } },
          { id: "cheap-models", use: { upstream: "cheap" } },
          { id: "strong-models", use: { upstream: "strong" } },
        ],
        keys: [
          { name: "team-a", sha256: hashKey(KEY_A), dailyUsd: 5, monthlyUsd: 50 },
          { name: "team-b", sha256: hashKey(KEY_B), dailyUsd: 0.0008, monthlyUsd: 1 },
        ],
        defaultMaxTokens: 256,
        timeoutMs: 5000,
        retries: 1,
        backoffMs: 10,
        maxBodyBytes: 4096,
      }),
    );
    gateway = spawn(process.execPath, [BIN, "llm", "serve", "--config", configFile], {
      env: { ...process.env, ...FAKE_PROVIDER_KEYS },
      stdio: ["ignore", "pipe", "pipe"],
    });
    gateway.stderr?.on("data", (chunk) => (stderr += String(chunk)));
    await waitFor(() => /listening on http:\/\/127\.0\.0\.1:\d+/.test(stderr), "the gateway to listen", 10_000);
    url = /listening on (http:\/\/127\.0\.0\.1:\d+)/.exec(stderr)?.[1] ?? "";
  });

  after(async () => {
    if (gateway && gateway.exitCode === null) {
      const exited = new Promise((resolve) => gateway.once("exit", resolve));
      gateway.kill("SIGTERM");
      await exited;
    }
    await healthy?.close();
    await failing?.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  async function waitFor(condition: () => boolean, what: string, ms = 2000): Promise<void> {
    for (let waited = 0; waited < ms && !condition(); waited += 20) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.ok(condition(), `timed out waiting for ${what}; gateway stderr:\n${stderr}`);
  }

  /** A user message with a unique marker, so the test can prove prompts are not logged. */
  function ask(text = "Say hello"): Array<{ role: string; content: string }> {
    return [{ role: "user", content: `${text} [prompt-marker-${++marker}]` }];
  }

  async function post(body: unknown, options: { key?: string | null; task?: string } = {}): Promise<Reply> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    const key = options.key === undefined ? KEY_A : options.key;
    if (key !== null) headers.authorization = `Bearer ${key}`;
    if (options.task !== undefined) headers["x-agent-task"] = options.task;
    const res = await fetch(`${url}/v1/chat/completions`, { method: "POST", headers, body: typeof body === "string" ? body : JSON.stringify(body) });
    const text = await res.text();
    seen.push(JSON.stringify([...res.headers]), text);
    if (res.status !== 401) authenticated++;
    let json: any;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { status: res.status, headers: res.headers, text, json };
  }

  const upstreamCalls = () => healthy.requests.length + failing.requests.length;
  const last = (fake: FakeUpstream) => fake.requests[fake.requests.length - 1]!;

  function usageLines(): Array<Record<string, any>> {
    return fs.readFileSync(path.join(stateDir, "usage.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
  }

  it("answers /healthz without a key", async () => {
    const res = await fetch(`${url}/healthz`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { status: "ok" });
  });

  it("refuses a missing or unknown gateway key with 401, before anything reaches an upstream", async () => {
    for (const key of [null, "not-a-key", `${KEY_A}x`, ""]) {
      const r = await post({ model: "small", messages: ask() }, { key });
      assert.equal(r.status, 401, `key ${JSON.stringify(key)}`);
      assert.equal(r.json.error.code, "invalid_api_key");
      assert.equal(r.headers.get("www-authenticate"), 'Bearer realm="agent-gate"');
    }
    const basic = await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Basic ${Buffer.from(`${KEY_A}:`).toString("base64")}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "small", messages: ask() }),
    });
    assert.equal(basic.status, 401);
    assert.equal(upstreamCalls(), 0);
  });

  it("routes by model alias, with the upstream's own model name and key", async () => {
    const small = await post({ model: "small", messages: ask() });
    assert.equal(small.status, 200, small.text);
    assert.deepEqual([small.headers.get("x-agent-gate-route"), small.headers.get("x-agent-gate-upstream")], ["cheap-models", "cheap"]);
    assert.equal(last(healthy).body.model, "fake-small-1");
    assert.equal(last(healthy).authorization, `Bearer ${FAKE_PROVIDER_KEYS.E2E_CHEAP_KEY}`);
    assert.equal(last(healthy).body.max_tokens, 256, "without a limit from the client, the default is sent");
    assert.deepEqual(Object.keys(small.json), ["id", "object", "created", "model", "choices", "usage"], "the upstream's body comes back as it is");
    assert.equal(small.json.model, "fake-small-1");

    const large = await post({ model: "large", messages: ask() });
    assert.equal(large.status, 200, large.text);
    assert.deepEqual([large.headers.get("x-agent-gate-route"), large.headers.get("x-agent-gate-upstream")], ["strong-models", "strong"]);
    assert.equal(last(healthy).body.model, "fake-large-1");
    assert.equal(last(healthy).authorization, `Bearer ${FAKE_PROVIDER_KEYS.E2E_STRONG_KEY}`);
  });

  it("routes by x-agent-task ahead of the alias, and settles the cost from the upstream's usage", async () => {
    const r = await post({ model: "large", messages: ask("Label: printer on fire"), max_tokens: 20 }, { task: "classify" });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.headers.get("x-agent-gate-route"), "classify-is-cheap");
    assert.equal(last(healthy).body.model, "fake-small-1");
    assert.equal(last(healthy).body.max_tokens, 20, "the client's own limit is kept");
    // 1234 x $0.5 + 56 x $1.5 per million tokens. The estimate was about 13 + 20 tokens: far less.
    assert.equal(r.headers.get("x-agent-gate-cost-usd"), "0.000701");
  });

  it("falls back to the next upstream when the primary answers 500, after one retry", async () => {
    const before = { healthy: healthy.requests.length, failing: failing.requests.length };
    const r = await post({ model: "large", messages: ask("Fix the bug") }, { task: "code" });
    assert.equal(r.status, 200, r.text);
    assert.equal(failing.requests.length - before.failing, 2, "the primary was tried 1 + retries times");
    assert.equal(healthy.requests.length - before.healthy, 1);
    assert.equal(last(failing).authorization, `Bearer ${FAKE_PROVIDER_KEYS.E2E_FLAKY_KEY}`);
    assert.equal(last(failing).body.model, "flaky-large-1");
    assert.equal(last(healthy).body.model, "fake-large-1");
    assert.deepEqual([r.headers.get("x-agent-gate-route"), r.headers.get("x-agent-gate-upstream")], ["code-is-strong", "strong"]);
    assert.equal(r.headers.get("x-agent-gate-cost-usd"), "0.00701", "priced at the upstream that answered");
  });

  it("answers 502 with its own message when every attempt fails, never with the upstream's body", async () => {
    const r = await post({ model: "large", messages: ask() }, { task: "flaky" });
    assert.equal(r.status, 502);
    assert.equal(r.json.error.code, "upstream_error");
    assert.match(r.json.error.message, /no upstream answered \(2 attempts; the last one answered HTTP 500\)\. Nothing was charged to this key\./);
    assert.equal(r.text.includes("exploded"), false);
  });

  it("does not pass on an upstream's auth error, which can quote the key it was sent", async () => {
    const r = await post({ model: "small", messages: ask() }, { task: "wrong-key" });
    assert.equal(r.status, 502);
    assert.equal(r.json.error.code, "upstream_auth_failed");
    assert.match(r.json.error.message, /upstream "misconfigured" refused the gateway's API key \(HTTP 401\)/);
    assert.equal(r.text.includes("Incorrect API key"), false);
  });

  it("passes on an upstream's other 4xx answers, with any quoted upstream key cut out", async () => {
    const r = await post({ model: "small", messages: ask(), max_tokens: 200_000 });
    assert.equal(r.status, 400);
    assert.deepEqual([r.json.error.param, r.json.error.code], ["max_tokens", "invalid_value"]);
    assert.equal(r.json.error.message, "max_tokens is too large for this model (key [REDACTED:upstream-key])");
  });

  it("refuses with 429 once a key's cap is reached, and makes no upstream call", async () => {
    const first = await post({ model: "small", messages: ask("Label: printer on fire"), max_tokens: 100 }, { key: KEY_B });
    assert.equal(first.status, 200, first.text);
    const calls = upstreamCalls();
    const second = await post({ model: "small", messages: ask("Label: paper jam"), max_tokens: 100 }, { key: KEY_B });
    assert.equal(second.status, 429, second.text);
    assert.deepEqual([second.json.error.type, second.json.error.code, second.json.error.cap], ["insufficient_quota", "budget_exceeded", "daily"]);
    assert.match(second.json.error.message, /key "team-b" has \$0\.000099 left of its daily budget of \$0\.0008 \(\$0\.000701 spent, \$0 held by calls in flight\)/);
    assert.ok(Number(second.headers.get("retry-after")) >= 1);
    assert.equal(upstreamCalls(), calls, "no upstream call was made");

    const otherKey = await post({ model: "small", messages: ask() });
    assert.equal(otherKey.status, 200, "another key's budget is separate");
  });

  it("blocks a secret before any upstream call, naming the rule but not the text", async () => {
    const calls = upstreamCalls();
    const aws = await post({ model: "small", messages: ask(`deploy with ${FAKE.awsAccessKeyId}`) });
    assert.equal(aws.status, 400);
    assert.deepEqual([aws.json.error.code, aws.json.error.rule, aws.json.error.param], ["secret_detected", "aws-access-key-id", "messages"]);
    assert.equal(aws.text.includes(FAKE.awsAccessKeyId), false);
    const pem = await post({ model: "small", messages: ask(`why does ssh reject this?\n${FAKE.privateKey}`) });
    assert.equal(pem.json.error.rule, "private-key");
    assert.equal(upstreamCalls(), calls);
  });

  it("redacts what a redact rule matches, and says which rule in a header", async () => {
    const r = await post({ model: "small", messages: ask(`connect with api_key = "${FAKE.apiKeyValue}"`) });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.headers.get("x-agent-gate-redacted"), "api-key-assignment");
    const sent = String((last(healthy).body.messages as Array<{ content: string }>)[0]?.content);
    assert.match(sent, /^connect with api_key = "\[REDACTED:api-key-assignment\]" \[prompt-marker-\d+\]$/);
  });

  it("refuses streaming, unknown models and malformed requests clearly, without calling an upstream", async () => {
    const calls = upstreamCalls();
    const table: Array<[body: unknown, status: number, code: string]> = [
      [{ model: "small", messages: ask(), stream: true }, 400, "stream_not_supported"],
      [{ model: "small", messages: ask(), stream: "yes" }, 400, "stream_not_supported"],
      [{ model: "gpt-9", messages: ask() }, 404, "model_not_found"],
      ["{ not json", 400, "invalid_json"],
      [{ model: "small", messages: [] }, 400, "invalid_request"],
      [{ model: "small", messages: ask(), max_tokens: 0 }, 400, "invalid_request"],
      [{ model: "small", messages: ask("x".repeat(5000)) }, 413, "request_too_large"],
    ];
    for (const [body, status, code] of table) {
      const r = await post(body);
      assert.deepEqual([r.status, r.json?.error?.code], [status, code], JSON.stringify(body).slice(0, 80));
    }
    const wrongMethod = await fetch(`${url}/v1/chat/completions`, { headers: { authorization: `Bearer ${KEY_A}` } });
    assert.deepEqual([wrongMethod.status, wrongMethod.headers.get("allow")], [405, "POST"]);
    const otherPath = await fetch(`${url}/v1/embeddings`, { method: "POST", headers: { authorization: `Bearer ${KEY_A}` }, body: "{}" });
    assert.equal(otherPath.status, 404);
    assert.equal(upstreamCalls(), calls);
  });

  it("writes one usage line per authenticated call, with no prompt or completion text", () => {
    const file = path.join(stateDir, "usage.jsonl");
    const content = fs.readFileSync(file, "utf8");
    const lines = usageLines();
    assert.equal(lines.length, authenticated);
    assert.equal(content.includes("prompt-marker-"), false, "a prompt reached the usage log");
    assert.equal(content.includes("fake answer"), false, "a completion reached the usage log");
    const allowed = ["ts", "id", "key", "route", "upstream", "model", "status", "error", "rule", "inputTokens", "outputTokens", "costUsd", "usage", "attempts", "fallback", "redacted", "latencyMs"];
    for (const line of lines) assert.deepEqual(Object.keys(line).filter((k) => !allowed.includes(k)), [], JSON.stringify(line));

    const classify = lines.find((l) => l.route === "classify-is-cheap");
    assert.deepEqual(
      classify && [classify.key, classify.upstream, classify.model, classify.status, classify.inputTokens, classify.outputTokens, classify.costUsd, classify.usage],
      ["team-a", "cheap", "fake-small-1", 200, 1234, 56, 0.000701, "upstream"],
    );
    const fallback = lines.find((l) => l.route === "code-is-strong");
    assert.deepEqual(fallback && [fallback.upstream, fallback.model, fallback.attempts, fallback.fallback, fallback.costUsd], ["strong", "fake-large-1", 3, true, 0.00701]);
    const refused = lines.find((l) => l.status === 429);
    assert.deepEqual(refused && [refused.key, refused.error, refused.rule, refused.costUsd], ["team-b", "budget_exceeded", "daily", 0]);
    assert.deepEqual(
      lines.filter((l) => l.error === "secret_detected").map((l) => l.rule),
      ["aws-access-key-id", "private-key"],
    );
    assert.deepEqual(lines.find((l) => l.redacted)?.redacted, ["api-key-assignment"]);
    const failed = lines.find((l) => l.route === "flaky-only");
    assert.deepEqual(failed && [failed.status, failed.error, failed.attempts, failed.costUsd], [502, "upstream_error", 2, 0]);
    assert.equal(lines.find((l) => l.route === "wrong-key")?.error, "upstream_auth_failed");
    const rejected = lines.find((l) => l.error === "upstream_rejected");
    assert.deepEqual(rejected && [rejected.status, rejected.upstream, rejected.costUsd], [400, "cheap", 0]);

    if (process.platform !== "win32") {
      assert.equal(fs.statSync(file).mode & 0o777, 0o600);
      assert.equal(fs.statSync(path.join(stateDir, "ledger.json")).mode & 0o777, 0o600);
      assert.equal(fs.statSync(stateDir).mode & 0o777, 0o700);
    }
  });

  it("agent-gate usage shows today's and this month's spend against the caps", () => {
    const run = spawnSync(process.execPath, [BIN, "usage", "--json", "--config", configFile], { encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    const rows: Array<Record<string, any>> = JSON.parse(run.stdout);
    const teamA = rows.find((r) => r.key === "team-a");
    const teamB = rows.find((r) => r.key === "team-b");
    assert.deepEqual(teamB && [teamB.dayUsd, teamB.dailyUsd, teamB.monthUsd, teamB.monthlyUsd, teamB.inFlight], [0.000701, 0.0008, 0.000701, 1, 0]);
    const spentA = usageLines()
      .filter((l) => l.key === "team-a")
      .reduce((sum, l) => sum + l.costUsd, 0);
    assert.ok(teamA && Math.abs(teamA.dayUsd - spentA) < 1e-9, `ledger ${teamA?.dayUsd} vs usage log ${spentA}`);

    const text = spawnSync(process.execPath, [BIN, "usage", "--config", configFile], { encoding: "utf8" });
    assert.equal(text.status, 0, text.stderr);
    assert.match(text.stdout, /^key\s+today \(\d{4}-\d{2}-\d{2} UTC\)\s+this month \(\d{4}-\d{2}\)\s+in flight\n/);
    assert.match(text.stdout, /\nteam-b {2}\$0\.000701 of \$0\.0008\s+\$0\.000701 of \$1\s+0\n/);
  });

  it("never puts a provider key or a gateway key in a response, the state files or the log", () => {
    const files = ["usage.jsonl", "ledger.json"].map((name) => fs.readFileSync(path.join(stateDir, name), "utf8")).join("\n");
    const places: Array<[string, string]> = [
      ["a response", seen.join("\n")],
      ["the state files", files],
      ["the gateway's log", stderr],
    ];
    for (const [name, key] of Object.entries(FAKE_PROVIDER_KEYS)) {
      for (const [where, text] of places) assert.equal(text.includes(key), false, `${where} contains ${name}`);
    }
    for (const key of Object.values(FAKE_GATEWAY_KEYS)) {
      for (const [where, text] of places.slice(1)) assert.equal(text.includes(key), false, `${where} contains a gateway key`);
    }
    // The check means something: the upstreams did receive their keys, and quoted them back.
    assert.ok(failing.requests.some((r) => r.authorization === `Bearer ${FAKE_PROVIDER_KEYS.E2E_FLAKY_KEY}`));
    assert.ok(healthy.requests.some((r) => r.authorization === `Bearer ${FAKE_PROVIDER_KEYS.E2E_WRONG_KEY}`));
  });
});
