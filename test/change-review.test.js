"use strict";
// The change-review example (examples/change-review/review.js): the graph's routes, the rework limit,
// the escalation into the approval queue, and a timing for every node. Runs after the build (npm test).
const { describe, it, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { review, reviewRound, shellCommand, MAX_REWORK } = require("../examples/change-review/review.js");
const { ApprovalStore } = require("../dist/src/gateway/approvals.js");
// Secret-shaped values are assembled at run time (see test/llm/fake-secrets.ts).
const { FAKE } = require("../dist/test/llm/fake-secrets.js");

const diff = (file, ...added) => [`--- a/${file}`, `+++ b/${file}`, "@@ -0,0 +1 @@", ...added.map((l) => `+${l}`)].join("\n");
const clean = diff("src/greet.js", "export const greet = (name) => `Hello, ${name}!`;");
const withSecret = diff("config/settings.py", `AWS_ACCESS_KEY_ID = "${FAKE.awsAccessKeyId}"`);

describe("examples/change-review: a review as a workflow graph", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-review-"));
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it("a clean change passes, and every node is timed", async () => {
    const r = await reviewRound(clean, 1);
    assert.equal(r.label, "pass");
    assert.deepEqual(r.timings.map((t) => t.node).sort(), ["join", "parse", "router", "secrets", "shell", "size"]);
    for (const t of r.timings) assert.ok(t.ms >= 0 && t.ms < 1000, `${t.node}: ${t.ms} ms`);
  });

  it("a shell line that crosses a red line escalates at once, into the approval queue", async () => {
    const state = path.join(tmp, "escalate");
    const outcome = await review([diff("scripts/release.sh", "git push --force origin main")], state);
    assert.equal(outcome.label, "escalate");
    assert.match(outcome.rounds[0].why, /force push/);
    const queued = new ApprovalStore(state, 1).list();
    assert.deepEqual(queued.map((a) => [a.id, a.server, a.tool, a.rule, a.status]), [[outcome.approval.id, "change-review", "merge", "change-review", "pending"]]);
  });

  it("a secret goes back to the author; removed in the next round, the change passes", async () => {
    const outcome = await review([withSecret, clean], path.join(tmp, "rework"));
    assert.deepEqual(outcome.rounds.map((r) => r.label), ["rework", "pass"]);
    assert.match(outcome.rounds[0].why, /remove the secret \(aws-access-key-id\) from config\/settings\.py/);
  });

  it(`after ${MAX_REWORK} rounds of rework, a secret still there goes to a human`, async () => {
    const outcome = await review([withSecret, withSecret, withSecret], path.join(tmp, "stuck"));
    assert.deepEqual(outcome.rounds.map((r) => r.label), ["rework", "rework", "escalate"]);
    assert.ok(outcome.approval, "queued");
  });

  it("a change too big to review is sent back to be split", async () => {
    const big = diff("src/big.js", ...Array.from({ length: 450 }, (_, i) => `export const v${i} = ${i};`));
    const r = await reviewRound(big, 1);
    assert.equal(r.label, "rework");
    assert.match(r.why, /split the change \(450 lines changed\)/);
  });

  it("reads shell lines from scripts, Dockerfiles, workflows and Makefiles, and nothing else", () => {
    assert.equal(shellCommand("deploy.sh", "rm -rf build"), "rm -rf build");
    assert.equal(shellCommand("deploy.sh", "# rm -rf build"), null);
    assert.equal(shellCommand("Dockerfile", "RUN npm publish"), "npm publish");
    assert.equal(shellCommand(".github/workflows/ci.yml", "      - run: git push"), "git push");
    assert.equal(shellCommand("Makefile", "\tvercel --prod"), "vercel --prod");
    assert.equal(shellCommand("README.md", "git push --force"), null);
  });

  it("the sample diff in the example folder escalates on its deploy line", async () => {
    const sample = fs.readFileSync(path.join(__dirname, "..", "examples", "change-review", "sample.diff"), "utf8");
    const r = await reviewRound(sample, 1);
    assert.equal(r.label, "escalate");
    assert.match(r.why, /gcloud deploy/);
  });
});
