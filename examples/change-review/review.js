#!/usr/bin/env node
"use strict";
// agent-gate example: review a change as a small workflow graph, with the guards as its checks.
//
//            ┌─ secrets: the LLM gateway's leak guard on every added line ─┐
//   diff ──► ├─ shell:   analyze() on added shell lines                     ├─► join ─► router ─┬─► pass
//            └─ size:    lines and files changed                          ─┘                   ├─► rework: back to the author (at most 2 rounds)
//                                                                                              └─► escalate: a request in the approval queue
//
// The router: a shell line that the guard asks about or blocks (a push, a deploy, rm -r) goes to a
// human at once. A secret, or a change too big to review, goes back to the author, who can fix it;
// if it is still there after 2 rounds of rework, it goes to a human too. Anything else passes.
// "Escalate" is a pending request in the same approvals.json that `agent-gate approvals` reads.
//
// Usage, after `npm run build`:
//   node examples/change-review/review.js [--state <dir>] round1.diff [round2.diff ...]
// Each file is the change as the author submitted it in that round; review stops at the first round
// that passes or escalates. The state directory defaults to ./.agent-gate.
// Shell lines read: every added line of a *.sh or *.bash file, RUN lines of a Dockerfile, single-line
// `run:` steps of a GitHub workflow, and tab-indented recipe lines of a Makefile.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const ROOT = path.join(__dirname, "..", "..");
const { analyze } = require(path.join(ROOT, "src", "command-guard.js"));
const { loadLeakPolicy } = require(path.join(ROOT, "dist", "src", "llm", "config.js"));
const { guardMessages } = require(path.join(ROOT, "dist", "src", "llm", "leak-guard.js"));
const { ApprovalStore, hashArguments } = require(path.join(ROOT, "dist", "src", "gateway", "approvals.js"));

const MAX_REWORK = 2;
const MAX_CHANGED_LINES = 400;
const leakPolicy = loadLeakPolicy(path.join(ROOT, "llm-policy.example.json"));

/** The added lines of a unified diff, each with its file, and the counts. */
function parseDiff(text) {
  const lines = [];
  let file = null;
  let removed = 0;
  for (const line of text.split("\n")) {
    if (line.startsWith("+++ ")) file = line.slice(4).replace(/^b\//, "");
    else if (line.startsWith("--- ") || line.startsWith("diff ") || line.startsWith("index ") || line.startsWith("@@")) continue;
    else if (line.startsWith("+")) lines.push({ file, text: line.slice(1) });
    else if (line.startsWith("-")) removed++;
  }
  return { lines, added: lines.length, removed, files: new Set(lines.map((l) => l.file)).size };
}

/** The shell command an added line runs, or null. */
function shellCommand(file, text) {
  const name = path.basename(file || "");
  if (/\.(?:sh|bash)$/.test(name)) return /^\s*(?:#|$)/.test(text) ? null : text;
  if (name === "Dockerfile") return (/^\s*RUN\s+(.+)$/.exec(text) || [])[1] || null;
  if (/^\.github\/workflows\/.+\.ya?ml$/.test(file || "")) return (/^\s*(?:-\s*)?run:\s*([^|>\s].*)$/.exec(text) || [])[1] || null;
  if (name === "Makefile") return text.startsWith("\t") ? text.slice(1) : null;
  return null;
}

// The three checks share nothing, so they are separate nodes that can run side by side.
const CHECKS = {
  secrets(change) {
    const findings = [];
    for (const { file, text } of change.lines) {
      const r = guardMessages(leakPolicy, [{ role: "user", content: text }]);
      if (r.action === "block") findings.push({ file, rule: r.rule });
      else for (const red of r.redactions || []) findings.push({ file, rule: red.rule });
    }
    return findings;
  },
  shell(change) {
    const findings = [];
    for (const { file, text } of change.lines) {
      const command = shellCommand(file, text);
      if (command === null) continue;
      const verdict = analyze(command);
      if (verdict.action === "ask" || verdict.action === "block") findings.push({ file, action: verdict.action, label: verdict.label, command: command.slice(0, 120) });
    }
    return findings;
  },
  size(change) {
    return { added: change.added, removed: change.removed, files: change.files, tooBig: change.added + change.removed > MAX_CHANGED_LINES };
  },
};

/** pass, rework or escalate, and why. `round` counts from 1. */
function router({ secrets, shell, size }, round) {
  if (shell.length) return { label: "escalate", why: `a shell line crosses a red line: ${shell.map((f) => f.label).join(", ")}` };
  const fixable = [...new Set(secrets.map((f) => `remove the secret (${f.rule}) from ${f.file}`)), ...(size.tooBig ? [`split the change (${size.added + size.removed} lines changed)`] : [])];
  if (fixable.length === 0) return { label: "pass", why: "no finding" };
  if (round <= MAX_REWORK) return { label: "rework", why: fixable.join("; ") };
  return { label: "escalate", why: `still after ${MAX_REWORK} rounds of rework: ${fixable.join("; ")}` };
}

async function timed(timings, node, fn) {
  const t0 = process.hrtime.bigint();
  const result = await fn();
  timings.push({ node, ms: Number(process.hrtime.bigint() - t0) / 1e6 });
  return result;
}

/** One round: fan out, join, route. */
async function reviewRound(diffText, round) {
  const timings = [];
  const change = await timed(timings, "parse", () => parseDiff(diffText));
  const [secrets, shell, size] = await Promise.all(["secrets", "shell", "size"].map((name) => timed(timings, name, () => CHECKS[name](change))));
  const joined = await timed(timings, "join", () => ({ secrets, shell, size }));
  const decision = await timed(timings, "router", () => router(joined, round));
  return { round, ...decision, findings: joined, timings, diffSha256: crypto.createHash("sha256").update(diffText).digest("hex") };
}

/** Rounds until one passes or escalates; an escalation is queued for a human in `stateDir`. */
async function review(diffTexts, stateDir) {
  const rounds = [];
  for (let i = 0; i < diffTexts.length; i++) {
    const result = await reviewRound(diffTexts[i], i + 1);
    rounds.push(result);
    if (result.label === "pass") return { rounds, label: "pass" };
    if (result.label === "escalate") {
      const args = { diffSha256: result.diffSha256, round: result.round, why: result.why };
      const outcome = new ApprovalStore(stateDir, 24 * 60 * 60 * 1000).resolveAsk({ server: "change-review", tool: "merge", args, argsHash: hashArguments(args), rule: "change-review", why: result.why });
      return { rounds, label: "escalate", approval: outcome.approval };
    }
  }
  return { rounds, label: "rework", why: "the author has not sent the next round yet" };
}

function print(outcome) {
  for (const r of outcome.rounds) {
    console.log(`round ${r.round}: ${r.label} (${r.why})`);
    for (const t of r.timings) console.log(`  ${t.node.padEnd(8)}${t.ms.toFixed(2).padStart(8)} ms`);
  }
  if (outcome.approval) console.log(`queued for a human: ${outcome.approval.id}\n  agent-gate approvals approve ${outcome.approval.id}`);
}

async function main(argv) {
  let stateDir = path.resolve(".agent-gate");
  const files = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--state") stateDir = path.resolve(argv[++i]);
    else files.push(argv[i]);
  }
  if (files.length === 0) {
    console.error("usage: node examples/change-review/review.js [--state <dir>] round1.diff [round2.diff ...]");
    return 2;
  }
  const outcome = await review(files.map((f) => fs.readFileSync(f, "utf8")), stateDir);
  print(outcome);
  return outcome.label === "pass" ? 0 : 1;
}

module.exports = { parseDiff, shellCommand, router, reviewRound, review, MAX_REWORK };
if (require.main === module) main(process.argv.slice(2)).then((code) => (process.exitCode = code));
