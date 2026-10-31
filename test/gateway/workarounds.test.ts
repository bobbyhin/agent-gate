// Red team: the same effect another way. After delete_file on one file is asked about or denied, an
// agent can switch tools, fall back to a shell command, or write the same path another way. Each
// attempt in workarounds.json records what the example policy decided before red-line-4-overwrite
// and what it decides now; the README quotes the summary.
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { ApprovalStore, hashArguments } from "../../src/gateway/approvals.js";
import { evaluate, parsePolicy, type Decision } from "../../src/gateway/policy.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");

interface Attempt {
  id: string;
  tool: string;
  args: Record<string, unknown>;
  before: Decision;
  after: Decision;
}

const fixture = JSON.parse(fs.readFileSync(path.join(ROOT, "test", "gateway", "workarounds.json"), "utf8")) as {
  denied: { tool: string; args: Record<string, unknown> };
  newRules: string[];
  attempts: Attempt[];
  summary: { attempts: number; ranUnattendedBefore: number; ranUnattendedAfter: number };
};
const raw = JSON.parse(fs.readFileSync(path.join(ROOT, "policy.example.json"), "utf8")) as { rules: Array<{ id: string }> };
const now = parsePolicy(raw);
const before = parsePolicy({ ...raw, rules: raw.rules.filter((rule) => !fixture.newRules.includes(rule.id)) });
const unattended = (decision: Decision) => decision === "allow" || decision === "warn";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-workarounds-"));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

describe("red team: the same effect another way, after a delete is asked about or denied", () => {
  it("each attempt gets the recorded decision, before red-line-4-overwrite and now", () => {
    for (const attempt of fixture.attempts) {
      const call = { server: "files", tool: attempt.tool, args: attempt.args };
      assert.deepEqual([evaluate(before, call).decision, evaluate(now, call).decision], [attempt.before, attempt.after], attempt.id);
    }
    assert.deepEqual(
      {
        attempts: fixture.attempts.length,
        ranUnattendedBefore: fixture.attempts.filter((a) => unattended(evaluate(before, { server: "files", tool: a.tool, args: a.args }).decision)).length,
        ranUnattendedAfter: fixture.attempts.filter((a) => unattended(evaluate(now, { server: "files", tool: a.tool, args: a.args }).decision)).length,
      },
      fixture.summary,
    );
  });

  it("the attempts that still run unattended are shell commands, which the shell guard does not ask about", () => {
    const still = fixture.attempts.filter((a) => unattended(evaluate(now, { server: "files", tool: a.tool, args: a.args }).decision));
    assert.ok(still.length > 0 && still.every((a) => a.tool === "run_command" && evaluate(now, { server: "files", tool: a.tool, args: a.args }).rule === "shell-guard"));
  });

  it("a denial binds the exact call: the same path written another way is a new request, not a denied one and not a run", () => {
    const store = new ApprovalStore(tmp, 60 * 60 * 1000);
    const ask = (args: Record<string, unknown>) => {
      const verdict = evaluate(now, { server: "files", tool: fixture.denied.tool, args });
      assert.equal(verdict.decision, "ask");
      return store.resolveCall({ server: "files", tool: fixture.denied.tool, args, argsHash: hashArguments(args), rule: verdict.rule, why: verdict.why });
    };
    const first = ask(fixture.denied.args);
    assert.equal(first.kind, "pending");
    if (first.kind !== "pending") return;
    store.deny(first.approval.id, { note: "Keep that file." });
    assert.equal(ask(fixture.denied.args).kind, "denied");
    for (const attempt of fixture.attempts.filter((a) => a.tool === fixture.denied.tool)) {
      const outcome = ask(attempt.args);
      assert.equal(outcome.kind, "pending", attempt.id);
      assert.notEqual(outcome.kind === "pending" && outcome.approval.id, first.approval.id, attempt.id);
    }
  });
});
