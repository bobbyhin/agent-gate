"use strict";
// Run with: npm test   (or: node --test)
const { describe, it, after } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { analyze } = require("../src/command-guard");
const cases = require("./cases.json");

const HOOK = path.join(__dirname, "..", "bin", "claude-pretooluse-hook.js");
const EXPECTS = ["pass", "warn", "ask", "block", "ask_or_block"];

describe("test/cases.json", () => {
  it("holds 239 well-formed cases with unique ids", () => {
    assert.equal(cases.length, 239);
    assert.equal(new Set(cases.map((c) => c.id)).size, cases.length, "ids must be unique");
    for (const c of cases) {
      assert.deepEqual(Object.keys(c).sort(), ["category", "cmd", "expect", "id"], `${c.id}: unexpected fields`);
      assert.ok(EXPECTS.includes(c.expect), `${c.id}: unknown expect "${c.expect}"`);
      assert.equal(typeof c.cmd, "string", `${c.id}: cmd must be a string`);
    }
  });
});

describe("analyze() against test/cases.json", () => {
  for (const c of cases) {
    const preview = JSON.stringify(c.cmd).slice(0, 70);
    it(`${c.id} [${c.category}] expect ${c.expect}: ${preview}`, () => {
      const got = analyze(c.cmd).action;
      const ok = c.expect === "ask_or_block" ? got === "ask" || got === "block" : got === c.expect;
      assert.ok(ok, `expected ${c.expect}, got ${got} for ${JSON.stringify(c.cmd)}`);
    });
  }
});

describe("bin/claude-pretooluse-hook.js (child process)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-test-"));
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));

  // Run the hook with `input` on stdin. `log` (optional) is the AGENT_GATE_LOG file.
  function runHook(input, log) {
    const env = { ...process.env };
    delete env.AGENT_GATE_LOG;
    if (log) env.AGENT_GATE_LOG = log;
    const r = spawnSync(process.execPath, [HOOK], { input, encoding: "utf8", env });
    return { status: r.status, stdout: r.stdout, stderr: r.stderr };
  }
  const payload = (command) => JSON.stringify({ tool_name: "Bash", tool_input: { command } });

  it("block: exit 2, reason on stderr, nothing on stdout", () => {
    const r = runHook(payload("git push --force origin main"));
    assert.equal(r.status, 2);
    assert.equal(r.stdout, "");
    assert.equal(r.stderr, "[Hook] BLOCKED: force push\n[Hook] Command: git push --force origin main\n");
  });

  it("ask: exit 0 and a PreToolUse permissionDecision of ask; one line goes to AGENT_GATE_LOG", () => {
    const log = path.join(tmp, "decisions.log");
    const r = runHook(payload("git push origin main"), log);
    assert.equal(r.status, 0);
    assert.equal(r.stderr, "");
    const out = JSON.parse(r.stdout).hookSpecificOutput;
    assert.equal(out.hookEventName, "PreToolUse");
    assert.equal(out.permissionDecision, "ask");
    assert.ok(out.permissionDecisionReason.startsWith("⚠️ git push (any form) — "), out.permissionDecisionReason);
    assert.ok(out.permissionDecisionReason.endsWith("\ngit push origin main"), out.permissionDecisionReason);
    const lines = fs.readFileSync(log, "utf8").trim().split("\n");
    assert.equal(lines.length, 1);
    const entry = JSON.parse(lines[0]);
    assert.equal(entry.action, "ask");
    assert.equal(entry.label, "git push (any form)");
    assert.equal(entry.command, "git push origin main");
    assert.ok(!Number.isNaN(Date.parse(entry.ts)));
  });

  it("pass: exit 0, the payload is echoed on stdout, and nothing is logged", () => {
    const log = path.join(tmp, "pass.log");
    const input = payload("ls -la");
    const r = runHook(input, log);
    assert.equal(r.status, 0);
    assert.equal(r.stdout, input + "\n");
    assert.equal(r.stderr, "");
    assert.equal(fs.existsSync(log), false);
  });

  it("warn: exit 0, a note on stderr, the payload is echoed on stdout", () => {
    const input = payload("kill -9 4242");
    const r = runHook(input);
    assert.equal(r.status, 0);
    assert.equal(r.stdout, input + "\n");
    assert.equal(r.stderr, "[Hook] WARN: kill -9 (SIGKILL) — proceeding\n");
  });

  it("unreadable input is asked about, never passed silently or crashed on", () => {
    const badInputs = ["this is not json", JSON.stringify({ tool_name: "Bash", tool_input: { command: 42 } })];
    for (const input of badInputs) {
      const r = runHook(input);
      assert.equal(r.status, 0, input);
      assert.equal(r.stderr, "", input);
      const out = JSON.parse(r.stdout).hookSpecificOutput;
      assert.equal(out.permissionDecision, "ask", input);
      assert.ok(out.permissionDecisionReason.startsWith("⚠️ agent-gate could not read the command — "), out.permissionDecisionReason);
    }
  });
});
