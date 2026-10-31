// Reading the audit log back: audit verify (the log against the gateway's own rules, with no expected
// answers) and audit trajectory (the calls that ran against an expected list).
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { hashArguments, type Approval } from "../../src/gateway/approvals.js";
import { parseExpected, readAudit, scoreTrajectory, trajectoryOf, verifyAudit, type AuditFile } from "../../src/gateway/audit-tools.js";
import { main } from "../../src/gateway/cli.js";

const H = (n: number) => hashArguments({ n });
const ts = (s: number) => new Date(Date.parse("2026-10-31T10:00:00.000Z") + s * 1000).toISOString();

/** A log as the gateway and the CLI write it: an ask, its approval, the call that ran, a block, a standing approval and its uses. */
function goodLog(): Array<Record<string, unknown>> {
  const call = (seq: number, s: number, fields: Record<string, unknown>) => ({ ts: ts(s), connId: "cn-00000001", seq, server: "demo", ...fields });
  return [
    call(1, 0, { tool: "echo", decision: "allow", rule: "default", why: "w", argsHash: H(1), forwarded: true }),
    { ts: ts(1), event: "call-result", connId: "cn-00000001", seq: 1, server: "demo", tool: "echo", argsHash: H(1), durationMs: 2, isError: false },
    call(2, 2, { tool: "delete_file", decision: "ask", rule: "red-line-4-delete", why: "w", argsHash: H(2), forwarded: false, approvalId: "ap-00000001" }),
    { ts: ts(3), event: "approval-decided", approvalId: "ap-00000001", server: "demo", tool: "delete_file", rule: "red-line-4-delete", argsHash: H(2), decision: "approved", waitMs: 1000 },
    call(3, 4, { tool: "delete_file", decision: "ask", rule: "red-line-4-delete", why: "w", argsHash: H(2), forwarded: true, approvalId: "ap-00000001" }),
    { ts: ts(5), event: "call-result", connId: "cn-00000001", seq: 3, server: "demo", tool: "delete_file", argsHash: H(2), durationMs: 1, isError: false },
    call(4, 6, { tool: "run_command", decision: "block", rule: "shell-guard", why: "w", argsHash: H(4), forwarded: false }),
    { ts: ts(7), event: "standing-approval", id: "sa-00000001", decision: "granted", server: "demo", tool: "execute_sql", args: {}, maxUses: 2, used: 0, expiresAt: ts(3600) },
    call(5, 8, { tool: "execute_sql", decision: "ask", rule: "sql-write", why: "w", argsHash: H(5), forwarded: true, approvalId: "sa-00000001" }),
    call(6, 9, { tool: "execute_sql", decision: "ask", rule: "sql-write", why: "w", argsHash: H(6), forwarded: true, approvalId: "sa-00000001" }),
  ];
}

const asFile = (lines: Array<Record<string, unknown> | string>): AuditFile => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-verify-"));
  const file = path.join(dir, "audit.jsonl");
  fs.writeFileSync(file, `${lines.map((l) => (typeof l === "string" ? l : JSON.stringify(l))).join("\n")}\n`);
  const read = readAudit(file);
  fs.rmSync(dir, { recursive: true, force: true });
  return read;
};

describe("verifyAudit: the log against the gateway's own rules", () => {
  it("finds nothing wrong in a log the gateway and the CLI wrote", () => {
    assert.deepEqual(verifyAudit(asFile(goodLog())), []);
  });

  const edits: Array<[string, (log: Array<Record<string, unknown>>) => void, RegExp]> = [
    ["a blocked call marked as forwarded", (log) => (log[6]!.forwarded = true), /^line 7: a blocked call to demo__run_command was forwarded \(rule shell-guard\)$/],
    ["a call that ran under an approval nobody gave", (log) => (log[4]!.approvalId = "ap-0000beef"), /^line 5: forwarded under ap-0000beef, which no approval-decided line approved before it$/],
    ["an approval used twice", (log) => log.push({ ...log[4], seq: 9, ts: ts(20) }), /^line 11: ap-00000001 let a second call through; it was used on line 5$/],
    ["other arguments than the ones approved", (log) => (log[4]!.argsHash = H(99)), /^line 5: forwarded under ap-00000001, which was approved for other arguments or another tool \(line 4\)$/],
    ["a call that ran before its approval", (log) => (log[4]!.ts = ts(2.5)), /^line 5: forwarded before ap-00000001 was approved \(line 4\)$/],
    ["an approval before any request", (log) => log.splice(2, 1), /^line 3: ap-00000001 was approved before any call asked for it$/],
    ["a result with no forwarded call", (log) => log.push({ ts: ts(30), event: "call-result", connId: "cn-00000001", seq: 77, server: "demo", tool: "echo" }), /^line 11: a call-result line for cn-00000001 77, with no forwarded call before it$/],
    ["a standing approval used past its uses", (log) => log.push({ ...log[9], seq: 7, ts: ts(10) }), /^line 11: sa-00000001 was used 3 times; it allows 2$/],
    ["a standing approval used after it was revoked", (log) => log.splice(9, 0, { ts: ts(8.5), event: "standing-approval", id: "sa-00000001", decision: "revoked", server: "demo", tool: "execute_sql" }), /^line 11: sa-00000001 was used after it was revoked \(line 10\)$/],
    ["an allowed call that was not forwarded", (log) => (log[0]!.forwarded = false), /^line 1: an allowed call to demo__echo was not forwarded$/],
  ];
  for (const [name, edit, expected] of edits) {
    it(`catches ${name}`, () => {
      const log = goodLog();
      edit(log);
      const problems = verifyAudit(asFile(log)).map((p) => `line ${p.line}: ${p.why}`);
      assert.ok(problems.some((p) => expected.test(p)), `got ${JSON.stringify(problems)}`);
    });
  }

  it("catches a line that is not JSON, and an approvals.json that disagrees with the log", () => {
    assert.deepEqual(verifyAudit(asFile([...goodLog(), "{ cut short"])), [{ line: 11, why: "not a JSON object" }]);
    const stillApproved = { id: "ap-00000001", status: "approved", argsHash: H(2) } as Approval;
    assert.deepEqual(verifyAudit(asFile(goodLog()), [stillApproved]), [{ line: 5, why: "forwarded under ap-00000001, but approvals.json says it is approved" }]);
  });
});

describe("scoreTrajectory: the calls that ran against an expected list", () => {
  const actual = [
    { line: 1, tool: "demo__search", argsHash: H(1) },
    { line: 2, tool: "demo__read", argsHash: H(2) },
    { line: 3, tool: "demo__search", argsHash: H(3) },
    { line: 4, tool: "demo__write", argsHash: H(4) },
  ];
  it("exact, in order and in any order, with precision and recall", () => {
    const s = scoreTrajectory(actual, [{ tool: "demo__search" }, { tool: "demo__write", argsHash: H(4) }]);
    assert.deepEqual([s.exact, s.inOrder, s.anyOrder, s.matched, s.precision, s.recall], [false, true, true, 2, 0.5, 1]);
    const all = scoreTrajectory(actual, actual.map(({ tool, argsHash }) => ({ tool, argsHash })));
    assert.deepEqual([all.exact, all.inOrder, all.anyOrder, all.precision, all.recall], [true, true, true, 1, 1]);
    const reversed = scoreTrajectory(actual, [{ tool: "demo__write" }, { tool: "demo__read" }]);
    assert.deepEqual([reversed.inOrder, reversed.anyOrder], [false, true]);
    const missing = scoreTrajectory(actual, [{ tool: "demo__delete" }, { tool: "demo__read" }]);
    assert.deepEqual([missing.anyOrder, missing.matched, missing.recall], [false, 1, 0.5]);
  });

  it("matches calls with arguments before calls that take any, so a wildcard does not steal a specific match", () => {
    const s = scoreTrajectory(actual, [{ tool: "demo__search" }, { tool: "demo__search", argsHash: H(1) }]);
    assert.deepEqual([s.anyOrder, s.matched], [true, 2]);
  });

  it("reads the expected file, and refuses one it cannot use", () => {
    assert.deepEqual(parseExpected({ calls: [{ tool: "demo__echo", args: { text: "hi" } }, { tool: "demo__x", argsHash: "sha256:abc" }, { tool: "demo__y" }] }), [
      { tool: "demo__echo", argsHash: hashArguments({ text: "hi" }) },
      { tool: "demo__x", argsHash: "sha256:abc" },
      { tool: "demo__y" },
    ]);
    assert.throws(() => parseExpected({ calls: [{ tool: "echo" }] }), /must be <server>__<tool>/);
    assert.throws(() => parseExpected({ calls: [{ tool: "a__b", args: {}, argsHash: "x" }] }), /both args and argsHash/);
    assert.throws(() => parseExpected({ steps: [] }), /expected\.calls must be an array/);
  });

  it("takes the calls that ran, or all of them, of one connection or one run, with the agent's own arguments", () => {
    const log = asFile([
      { connId: "cn-a", seq: 1, server: "demo", tool: "echo", decision: "allow", argsHash: H(1), forwarded: true, runId: "r1" },
      { connId: "cn-a", seq: 2, server: "demo", tool: "delete", decision: "ask", argsHash: H(2), forwarded: false, runId: "r1" },
      { connId: "cn-b", seq: 1, server: "demo", tool: "search", decision: "allow", argsHash: H(30), originalArgsHash: H(3), forwarded: true },
      { event: "call-result", connId: "cn-a", seq: 1, server: "demo", tool: "echo" },
    ]);
    const tools = (options: Parameters<typeof trajectoryOf>[1]) => trajectoryOf(log.lines, options).map((c) => c.tool);
    assert.deepEqual(tools({}), ["demo__echo", "demo__search"]);
    assert.deepEqual(tools({ all: true }), ["demo__echo", "demo__delete", "demo__search"]);
    assert.deepEqual(tools({ all: true, run: "r1" }), ["demo__echo", "demo__delete"]);
    assert.deepEqual(tools({ conn: "cn-b" }), ["demo__search"]);
    assert.equal(trajectoryOf(log.lines, { conn: "cn-b" })[0]?.argsHash, H(3), "the agent's arguments, before a rewrite");
  });
});

describe("agent-gate audit verify and audit trajectory", () => {
  let tmp: string;
  let config: string;
  const run = async (...argv: string[]) => {
    let out = "";
    let err = "";
    const code = await main([...argv, "--config", config], { out: (t) => (out += t), err: (t) => (err += t) });
    return { code, out, err };
  };
  before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-audit-cli-"));
    config = path.join(tmp, "gateway.config.json");
    fs.writeFileSync(config, JSON.stringify({ servers: [{ name: "demo", command: "node" }], policy: "policy.json", stateDir: "state" }));
    fs.mkdirSync(path.join(tmp, "state"));
    fs.writeFileSync(path.join(tmp, "state", "audit.jsonl"), `${goodLog().map((l) => JSON.stringify(l)).join("\n")}\n`);
    fs.writeFileSync(path.join(tmp, "expected.json"), JSON.stringify({ calls: [{ tool: "demo__echo" }, { tool: "demo__execute_sql" }] }));
  });
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it("verify: PASS and exit 0 on a good log, the problems and exit 1 on an edited one", async () => {
    const good = await run("audit", "verify");
    assert.deepEqual([good.code, good.out], [0, "PASS: 10 lines checked, no problems\n"]);
    const log = goodLog();
    log[6]!.forwarded = true;
    fs.writeFileSync(path.join(tmp, "state", "audit.jsonl"), `${log.map((l) => JSON.stringify(l)).join("\n")}\n`);
    const bad = await run("audit", "verify");
    assert.deepEqual([bad.code, bad.out], [1, "FAIL line 7: a blocked call to demo__run_command was forwarded (rule shell-guard)\nFAIL: 10 lines checked, 1 problem(s)\n"]);
    fs.writeFileSync(path.join(tmp, "state", "audit.jsonl"), `${goodLog().map((l) => JSON.stringify(l)).join("\n")}\n`);
  });

  it("trajectory: in order by default; exit 1 when the chosen mode fails; usage errors exit 2", async () => {
    const expect = path.join(tmp, "expected.json");
    const inOrder = await run("audit", "trajectory", "--expect", expect);
    assert.equal(inOrder.code, 0, inOrder.out + inOrder.err);
    assert.equal(
      inOrder.out,
      "4 call(s) ran, 2 expected\n  exact      FAIL\n  in order   PASS\n  any order  PASS\n  precision  0.50 (2 of the 4 calls were expected)\n  recall     1.00 (2 of the 2 expected calls happened)\nPASS (in-order)\n",
    );
    assert.equal((await run("audit", "trajectory", "--expect", expect, "--mode", "exact")).code, 1);
    const json = JSON.parse((await run("audit", "trajectory", "--expect", expect, "--all", "--json")).out);
    assert.deepEqual([json.actual.length, json.passed], [6, true]);
    assert.equal((await run("audit", "trajectory")).code, 2, "--expect is required");
    assert.equal((await run("audit", "trajectory", "--expect", expect, "--mode", "fuzzy")).code, 2);
    const missing = await run("audit", "trajectory", "--expect", path.join(tmp, "nope.json"));
    assert.equal(missing.code, 1);
    assert.match(missing.err, /cannot read the expected trajectory/);
  });
});
