// Loop limits ("repeat" in the policy): a circuit breaker for calls that would otherwise run
// unattended. The store with a clock the test controls, the config checks, and a loop through a gateway.
import { after, afterEach, before, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { parsePolicy, repeatLimitsFor, type RepeatLimit } from "../../src/gateway/policy.js";
import { RepeatStore } from "../../src/gateway/repeats.js";
import { ConfigError } from "../../src/gateway/validate.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const BIN = path.join(ROOT, "bin", "agent-gate.js");
const FAKE = path.join(__dirname, "fake-downstream.js");

const limitsOf = (repeat: unknown[]): RepeatLimit[] => [...parsePolicy({ default: "allow", repeat }).repeat];

describe("RepeatStore", () => {
  let dir: string;
  let now: number;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-repeats-"));
    now = Date.parse("2026-10-31T10:00:00.000Z");
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  const [perCall] = limitsOf([{ id: "same-call", max: 3, windowSeconds: 60, decision: "ask" }]) as [RepeatLimit];

  it("lets max runs of the same call through in a window, stops the next, and lets it through again once the window moves on", () => {
    const store = new RepeatStore(dir, 60_000, () => now);
    for (let i = 0; i < 3; i++) {
      assert.equal(store.admit([perCall], "demo", "echo", "sha256:a"), undefined, `run ${i + 1}`);
      now += 10_000;
    }
    const hit = store.admit([perCall], "demo", "echo", "sha256:a");
    assert.deepEqual([hit?.limit.id, hit?.count], ["same-call", 3]);
    assert.equal(store.admit([perCall], "demo", "echo", "sha256:b"), undefined, "other arguments are another call");
    now += 31_000; // the first run is now more than 60 s old
    assert.equal(store.admit([perCall], "demo", "echo", "sha256:a"), undefined);
  });

  it("per tool: any arguments count together", () => {
    const [perTool] = limitsOf([{ id: "flood", per: "tool", max: 2, windowSeconds: 60, decision: "block" }]) as [RepeatLimit];
    const store = new RepeatStore(dir, 60_000, () => now);
    assert.equal(store.admit([perTool], "demo", "fail", "sha256:1"), undefined);
    assert.equal(store.admit([perTool], "demo", "fail", "sha256:2"), undefined);
    assert.equal(store.admit([perTool], "demo", "fail", "sha256:3")?.count, 2);
  });

  it("keeps runs as long as the policy's longest window needs, whichever tool's call comes next", () => {
    const limits = limitsOf([
      { id: "short", tool: "echo", max: 5, windowSeconds: 60, decision: "ask" },
      { id: "long", tool: "deploy", max: 1, windowSeconds: 3600, decision: "block" },
    ]);
    const store = new RepeatStore(dir, 3_600_000, () => now);
    const deployLimits = limits.filter((l) => l.id === "long");
    assert.equal(store.admit(deployLimits, "demo", "deploy", "sha256:d"), undefined);
    now += 120_000;
    assert.equal(store.admit(limits.filter((l) => l.id === "short"), "demo", "echo", "sha256:e"), undefined); // rewrites the file
    assert.equal(store.admit(deployLimits, "demo", "deploy", "sha256:d")?.limit.id, "long", "the deploy two minutes ago still counts");
  });

  it("counts each agent and each limit on its own: one agent's calls never use up another's limit", () => {
    const [perTool, other] = limitsOf([
      { id: "flood", per: "tool", max: 2, windowSeconds: 60, decision: "block" },
      { id: "flood-strict", per: "tool", max: 1, windowSeconds: 60, decision: "ask" },
    ]) as [RepeatLimit, RepeatLimit];
    const store = new RepeatStore(dir, 60_000, () => now);
    assert.equal(store.admit([perTool], "demo", "echo", "sha256:1", "alpha"), undefined);
    assert.equal(store.admit([perTool], "demo", "echo", "sha256:2", "alpha"), undefined);
    assert.equal(store.admit([perTool], "demo", "echo", "sha256:3", "alpha")?.count, 2, "alpha has used its limit");
    assert.equal(store.admit([perTool], "demo", "echo", "sha256:4", "beta"), undefined, "beta's first call is beta's own");
    assert.equal(store.admit([perTool], "demo", "echo", "sha256:5"), undefined, "a call with no agent (stdio) counts apart from both");
    assert.equal(store.admit([other], "demo", "echo", "sha256:6", "alpha"), undefined, "another limit has its own count");
    assert.deepEqual(
      Object.keys(JSON.parse(fs.readFileSync(store.file, "utf8")).runs).sort(),
      ['["flood","alpha","demo__echo"]', '["flood","beta","demo__echo"]', '["flood",null,"demo__echo"]', '["flood-strict","alpha","demo__echo"]'],
    );
  });

  it("is shared through the file, counts a run a human let through, and fails closed on a damaged file", () => {
    const store = new RepeatStore(dir, 60_000, () => now);
    const other = new RepeatStore(dir, 60_000, () => now);
    store.admit([perCall], "demo", "echo", "sha256:a");
    store.admit([perCall], "demo", "echo", "sha256:a");
    other.record([perCall], "demo", "echo", "sha256:a");
    assert.equal(store.admit([perCall], "demo", "echo", "sha256:a")?.count, 3);
    if (process.platform !== "win32") assert.equal(fs.statSync(store.file).mode & 0o777, 0o600);
    fs.writeFileSync(store.file, "{ not json");
    assert.throws(() => store.admit([perCall], "demo", "echo", "sha256:a"), /not valid JSON/);
  });
});

describe("policy.repeat", () => {
  it("says which limits a call falls under, by server, tool, words and arguments", () => {
    const policy = parsePolicy({
      default: "allow",
      repeat: [
        { id: "echo-loop", tool: "echo", max: 3, windowSeconds: 60, decision: "ask" },
        { id: "any-search", toolWords: ["search"], args: { query: "*" }, max: 10, windowSeconds: 60, decision: "block" },
      ],
    });
    const ids = (tool: string, args: Record<string, unknown> = {}) => repeatLimitsFor(policy, { server: "demo", tool, args }).map((l) => l.id);
    assert.deepEqual([ids("echo"), ids("search_notes", { query: "x" }), ids("search_notes"), ids("delete_file")], [["echo-loop"], ["any-search"], [], []]);
  });
  const bad: Array<[string, unknown, RegExp]> = [
    ["max 0", { id: "r", max: 0, windowSeconds: 60, decision: "ask" }, /max must be a whole number from 1 to 10000/],
    ["no window", { id: "r", max: 3, decision: "ask" }, /windowSeconds must be more than 0/],
    ["a decision that lets the call run", { id: "r", max: 3, windowSeconds: 60, decision: "allow" }, /decision must be ask or block/],
    ["an unknown counting", { id: "r", max: 3, windowSeconds: 60, decision: "ask", per: "server" }, /per must be "call" or "tool"/],
    ["an id a rule already has", { id: "same", max: 3, windowSeconds: 60, decision: "ask" }, /already used by an earlier rule or limit/],
  ];
  for (const [name, limit, message] of bad) {
    it(`refuses ${name}`, () => {
      const json = { default: "allow", rules: [{ id: "same", tool: "x", decision: "allow", why: "w" }], repeat: [limit] };
      assert.throws(() => parsePolicy(json), (err: unknown) => err instanceof ConfigError && message.test(err.message));
    });
  }
});

describe("a loop through the gateway", () => {
  let tmp: string;
  let configFile: string;
  let receivedLog: string;
  let gateway: Client;

  before(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-loop-"));
    receivedLog = path.join(tmp, "received.jsonl");
    fs.writeFileSync(
      path.join(tmp, "policy.json"),
      JSON.stringify({
        default: "allow",
        rules: [{ id: "red-line-4-delete", toolWords: ["delete"], decision: "ask", why: "Red line 4: deletes." }],
        repeat: [
          { id: "loop-breaker", max: 3, windowSeconds: 60, decision: "ask" },
          { id: "no-floods", tool: "fail", per: "tool", max: 2, windowSeconds: 60, decision: "block", why: "Too many failing calls in a minute." },
        ],
      }),
    );
    configFile = path.join(tmp, "gateway.config.json");
    fs.writeFileSync(configFile, JSON.stringify({ servers: [{ name: "demo", command: process.execPath, args: [FAKE, "--log", receivedLog] }], policy: "policy.json", stateDir: "state" }));
    gateway = new Client({ name: "loop-test", version: "1.0.0" });
    await gateway.connect(new StdioClientTransport({ command: process.execPath, args: [BIN, "serve", "--config", configFile], stderr: "ignore" }));
  });
  after(async () => {
    await gateway?.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const call = async (name: string, args: Record<string, unknown>) => (await gateway.callTool({ name, arguments: args })) as CallToolResult;
  const text = (r: CallToolResult) => (r.content[0] as { text: string }).text;
  const received = () => (fs.existsSync(receivedLog) ? fs.readFileSync(receivedLog, "utf8").trim().split("\n").length : 0);

  it("lets the same call run 3 times, then asks a human; a repeat waits on the same request", async () => {
    for (let i = 0; i < 3; i++) assert.equal(text(await call("demo__echo", { text: "poll status" })), "poll status");
    const fourth = await call("demo__echo", { text: "poll status" });
    assert.equal(fourth.isError, true);
    assert.match(text(fourth), /Reason: loop limit: this same call ran 3 times in the last 60 s, the most rule loop-breaker lets through unattended \(rule loop-breaker\)/);
    const id = /Approval id: (ap-[0-9a-f]{8})/.exec(text(fourth))?.[1];
    assert.equal(/Approval id: (ap-[0-9a-f]{8})/.exec(text(await call("demo__echo", { text: "poll status" })))?.[1], id);
    assert.equal(received(), 3);
    assert.equal(text(await call("demo__echo", { text: "something else" })), "something else", "other arguments are another call");

    assert.ok(id);
    assert.equal(spawnSync(process.execPath, [BIN, "approvals", "approve", id, "--yes", "--config", configFile]).status, 0);
    assert.equal(text(await call("demo__echo", { text: "poll status" })), "poll status", "the human let one more through");
    assert.match(text(await call("demo__echo", { text: "poll status" })), /needs a human decision/, "and only one");
  });

  it("per tool: a third failing call in a minute is blocked, whatever its arguments", async () => {
    assert.equal((await call("demo__fail", { reason: "a" })).isError, true);
    assert.equal((await call("demo__fail", { reason: "b" })).isError, true);
    const before = received();
    const third = await call("demo__fail", { reason: "c" });
    assert.match(text(third), /^agent-gate blocked this call, so it was not run: Too many failing calls in a minute\. \(rule no-floods\)/);
    assert.equal(received(), before);
  });

  it("never touches a call that already needs a human, and says in the audit line which rule a limit overruled", async () => {
    for (let i = 0; i < 5; i++) assert.match(text(await call("demo__delete_file", { path: "x" })), /needs a human decision|still waiting/);
    const lines = fs.readFileSync(path.join(tmp, "state", "audit.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l)).filter((l) => l.event === undefined);
    assert.deepEqual(new Set(lines.filter((l) => l.tool === "delete_file").map((l) => l.rule)), new Set(["red-line-4-delete"]));
    const stopped = lines.find((l) => l.rule === "loop-breaker");
    assert.deepEqual([stopped?.decision, stopped?.forwarded, stopped?.alsoMatched], ["ask", false, ["default"]]);
  });
});
