// The LLM gateway's CLI commands: "llm serve" and "usage". Exit codes: 0 done, 1 failed, 2 bad usage.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { main } from "../../src/gateway/cli.js";

async function run(...argv: string[]): Promise<{ code: number; out: string; err: string }> {
  let out = "";
  let err = "";
  const code = await main(argv, { out: (t) => (out += t), err: (t) => (err += t) });
  return { code, out, err };
}

describe("agent-gate llm serve and usage", () => {
  let tmp: string;
  let configFile: string;

  before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-llm-cli-"));
    configFile = path.join(tmp, "llm-gateway.config.json");
    fs.writeFileSync(
      configFile,
      JSON.stringify({
        listen: { port: 0 },
        stateDir: "state",
        policy: "policy.json",
        upstreams: [{ name: "only", baseUrl: "http://127.0.0.1:9/v1", apiKeyEnv: "AGENT_GATE_TEST_UNSET_KEY", models: { small: "s" }, pricePerMTok: { input: 1, output: 1 } }],
        routes: [{ id: "all", use: { upstream: "only" } }],
        keys: [
          { name: "search-agent", sha256: "a".repeat(64), dailyUsd: 2, monthlyUsd: 40 },
          { name: "ops", sha256: "b".repeat(64), dailyUsd: 0.5, monthlyUsd: 5 },
        ],
      }),
    );
    fs.writeFileSync(path.join(tmp, "policy.json"), JSON.stringify({ leakGuard: [] }));
  });
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));

  for (const argv of [["llm"], ["llm", "frobnicate"], ["llm", "serve", "now"], ["usage", "extra"], ["usage", "--by"], ["llm", "serve", "--by", "task"]]) {
    it(`exits 2 for: ${argv.join(" ")}`, async () => {
      const r = await run(...argv, "--config", "/nonexistent/llm-gateway.config.json");
      assert.equal(r.code, 2);
      assert.match(r.err, /Usage:/);
    });
  }

  it("lists the LLM commands in --help", async () => {
    const r = await run("--help");
    assert.match(r.out, /agent-gate llm serve \[--config <file>\]/);
    assert.match(r.out, /agent-gate usage \[--json\] \[--config <file>\]/);
  });

  it("refuses to start when an upstream's key variable is not set, naming the variable", async () => {
    assert.equal(process.env.AGENT_GATE_TEST_UNSET_KEY, undefined);
    const r = await run("llm", "serve", "--config", configFile);
    assert.equal(r.code, 1);
    assert.equal(r.err, "agent-gate: set the environment variables named by apiKeyEnv: AGENT_GATE_TEST_UNSET_KEY\n");
  });

  it("usage exits 1 with a clear message when the config cannot be read", async () => {
    const r = await run("usage", "--config", "/nonexistent/llm-gateway.config.json");
    assert.equal(r.code, 1);
    assert.match(r.err, /^agent-gate: cannot read the config file \/nonexistent\/llm-gateway\.config\.json/);
  });

  it("usage --by sums the usage log per task, most expensive first, and counts leak-guard hits", async () => {
    fs.mkdirSync(path.join(tmp, "state"), { recursive: true });
    const line = (fields: Record<string, unknown>) => JSON.stringify({ key: "search-agent", status: 200, inputTokens: 10, outputTokens: 5, costUsd: 0.1, ...fields });
    fs.writeFileSync(
      path.join(tmp, "state", "usage.jsonl"),
      [
        line({ task: "classify", costUsd: 0.000001 }),
        line({ task: "classify", status: 400, error: "secret_detected", rule: "private-key", inputTokens: 0, outputTokens: 0, costUsd: 0 }),
        line({ task: "code", costUsd: 0.2, redacted: ["api-key-assignment"] }),
        line({ task: "code", costUsd: 0.1 }),
        line({ costUsd: 0.05 }),
        "{ broken",
      ].join("\n") + "\n",
    );
    const r = await run("usage", "--by", "task", "--json", "--config", configFile);
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(JSON.parse(r.out), [
      { group: "code", requests: 2, ok: 2, inputTokens: 20, outputTokens: 10, costUsd: 0.3, leakBlocked: 0, leakRedacted: 1 },
      { group: "(none)", requests: 1, ok: 1, inputTokens: 10, outputTokens: 5, costUsd: 0.05, leakBlocked: 0, leakRedacted: 0 },
      { group: "classify", requests: 2, ok: 1, inputTokens: 10, outputTokens: 5, costUsd: 0.000001, leakBlocked: 1, leakRedacted: 0 },
    ]);
    assert.match(r.err, /1 line\(s\) of .*usage\.jsonl are not JSON and were skipped/);
    const text = await run("usage", "--by", "task", "--config", configFile);
    assert.match(text.out, /^task {6}requests {2}ok {2}input tokens {2}output tokens {2}cost {7}leak blocked {2}leak redacted\n/);
    assert.match(text.out, /\nclassify {2}2 {9}1 {3}10 {12}5 {14}\$0\.000001 {2}1 {13}0\n$/);
    const bad = await run("usage", "--by", "colour", "--config", configFile);
    assert.deepEqual([bad.code, bad.err], [2, "agent-gate: --by takes one of task, key, route, upstream, model, session, runId\n"]);
    fs.rmSync(path.join(tmp, "state", "usage.jsonl"));
  });

  it("usage shows every configured key, at zero before any call", async () => {
    const r = await run("usage", "--config", configFile);
    assert.equal(r.code, 0, r.err);
    const lines = r.out.trimEnd().split("\n");
    assert.equal(lines.length, 3);
    assert.match(lines[1] ?? "", /^search-agent {2}\$0 of \$2\s+\$0 of \$40\s+0$/);
    assert.match(lines[2] ?? "", /^ops\s+\$0 of \$0\.5\s+\$0 of \$5\s+0$/);

    const json = await run("usage", "--json", "--config", configFile);
    assert.deepEqual(
      JSON.parse(json.out).map((u: Record<string, unknown>) => [u.key, u.dayUsd, u.dailyUsd, u.monthUsd, u.monthlyUsd, u.inFlight]),
      [
        ["search-agent", 0, 2, 0, 40, 0],
        ["ops", 0, 0.5, 0, 5, 0],
      ],
    );
  });
});
