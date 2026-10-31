// Tool lists of real or realistic MCP servers, each tool labelled with the decision it should get,
// run through policy.example.json. Each fixture records what the example policy decides today (the
// decision and the rule), so a change to the policy shows up here as a diff to review, and a summary
// of how often the policy agrees with the labels, is stricter (it asks about a tool that only reads),
// or is looser (it lets through a tool that should have asked). The README quotes these summaries.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { loadPolicy } from "../../src/gateway/config.js";
import { DECISIONS, evaluate, parsePolicy, type Decision } from "../../src/gateway/policy.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const LISTS = path.join(ROOT, "test", "gateway", "tool-lists");
const POLICY = loadPolicy(path.join(ROOT, "policy.example.json"));

interface Tool {
  name: string;
  /** The decision the tool should get. */
  label: Decision;
  why: string;
  /** What policy.example.json decides for the tool's name (with no arguments), and the rule that decides. */
  policy: Decision;
  rule: string;
}

interface ToolList {
  about: string;
  source: string;
  server: string;
  tools: Tool[];
  summary: { tools: number; agree: number; stricter: number; looser: number };
}

const RANK: Readonly<Record<Decision, number>> = { allow: 0, warn: 1, ask: 2, block: 3 };

/** How the policy's decisions compare with the labels. */
function summarize(tools: readonly Tool[]): ToolList["summary"] {
  return {
    tools: tools.length,
    agree: tools.filter((t) => t.policy === t.label).length,
    stricter: tools.filter((t) => RANK[t.policy] > RANK[t.label]).length,
    looser: tools.filter((t) => RANK[t.policy] < RANK[t.label]).length,
  };
}

describe("tool lists through the example policy", () => {
  const files = fs.readdirSync(LISTS).filter((f) => f.endsWith(".json"));
  it("has tool lists", () => assert.ok(files.length > 0));
  for (const file of files) {
    const list = JSON.parse(fs.readFileSync(path.join(LISTS, file), "utf8")) as ToolList;
    it(`${file}: each tool gets the recorded decision, and the summary is what the README quotes`, () => {
      assert.equal(new Set(list.tools.map((t) => t.name)).size, list.tools.length, "no tool is listed twice");
      for (const tool of list.tools) {
        assert.ok(DECISIONS.includes(tool.label) && tool.why.length > 0, `${tool.name}: a label and a reason`);
        const verdict = evaluate(POLICY, { server: list.server, tool: tool.name, args: {} });
        assert.deepEqual([verdict.decision, verdict.rule], [tool.policy, tool.rule], `${file}: ${tool.name}`);
      }
      assert.deepEqual(summarize(list.tools), list.summary);
    });
  }

  it("instavibe.json: before red line 2 named events and invitations, 9 of the 12 tools that should ask ran unattended", () => {
    // The rule's words before that change.
    const raw = JSON.parse(fs.readFileSync(path.join(ROOT, "policy.example.json"), "utf8")) as { rules: Array<{ id: string; toolWords?: string[] }> };
    const rule = raw.rules.find((r) => r.id === "red-line-2-public") as { toolWords: string[] };
    rule.toolWords = ["post", "publish", "send", "tweet", "retweet", "reply", "comment", "email", "share"];
    const before = parsePolicy(raw);
    const list = JSON.parse(fs.readFileSync(path.join(LISTS, "instavibe.json"), "utf8")) as ToolList;
    const shouldAsk = list.tools.filter((t) => t.label === "ask");
    const ranUnattended = shouldAsk.filter((t) => evaluate(before, { server: list.server, tool: t.name, args: {} }).decision === "allow").map((t) => t.name);
    assert.deepEqual([shouldAsk.length, ranUnattended.length], [12, 9], ranUnattended.join(", "));
    assert.ok(ranUnattended.includes("create_event") && ranUnattended.includes("schedule_meeting") && ranUnattended.includes("update_calendar"));
  });
});
