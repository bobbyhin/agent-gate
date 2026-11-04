// Tool lists of real or realistic MCP servers, each tool labelled with the decision it should get,
// run through policy.example.json. Each fixture records what the example policy decides today (the
// decision and the rule), so a change to the policy shows up here as a diff to review, and a summary
// of how often the policy agrees with the labels, is stricter (it asks about a tool that only reads),
// or is looser (it lets through a tool that should have asked). docs/mcp-gateway.md quotes these summaries.
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
  /** The summary with these rules taken out of the example policy: what they changed. */
  without?: { rules: string[]; summary: ToolList["summary"] };
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
    it(`${file}: each tool gets the recorded decision, and the summary is what docs/mcp-gateway.md quotes`, () => {
      assert.equal(new Set(list.tools.map((t) => t.name)).size, list.tools.length, "no tool is listed twice");
      for (const tool of list.tools) {
        assert.ok(DECISIONS.includes(tool.label) && tool.why.length > 0, `${tool.name}: a label and a reason`);
        const verdict = evaluate(POLICY, { server: list.server, tool: tool.name, args: {} });
        assert.deepEqual([verdict.decision, verdict.rule], [tool.policy, tool.rule], `${file}: ${tool.name}`);
      }
      assert.deepEqual(summarize(list.tools), list.summary);
      if (list.without) {
        const raw = JSON.parse(fs.readFileSync(path.join(ROOT, "policy.example.json"), "utf8")) as { rules: Array<{ id: string }> };
        const removed = list.without.rules;
        assert.ok(removed.every((id) => raw.rules.some((rule) => rule.id === id)), `${file}: the rules taken out exist`);
        const smaller = parsePolicy({ ...raw, rules: raw.rules.filter((rule) => !removed.includes(rule.id)) });
        const decided = list.tools.map((t) => ({ ...t, policy: evaluate(smaller, { server: list.server, tool: t.name, args: {} }).decision }));
        assert.deepEqual(summarize(decided), list.without.summary, `${file}: without ${removed.join(", ")}`);
      }
    });
  }

  it("gitea-mcp.json: docs/mcp-gateway.md's rule on the method argument gives a merge red line 3's 30 minutes, and leaves other methods to the red lines", () => {
    const readme = fs.readFileSync(path.join(ROOT, "docs", "mcp-gateway.md"), "utf8");
    const snippet = /```json\n(\{ "id": "gitea-merge"[\s\S]*?)\n```/.exec(readme)?.[1];
    assert.ok(snippet, "docs/mcp-gateway.md shows the rule");
    const raw = JSON.parse(fs.readFileSync(path.join(ROOT, "policy.example.json"), "utf8")) as { rules: unknown[] };
    const withRule = parsePolicy({ ...raw, rules: [JSON.parse(snippet), ...raw.rules] });
    const merge = evaluate(withRule, { server: "gitea", tool: "pull_request_write", args: { method: "merge", index: 7 } });
    assert.deepEqual([merge.decision, merge.rule, merge.ttlMs], ["ask", "gitea-merge", 30 * 60 * 1000]);
    assert.equal(evaluate(withRule, { server: "gitea", tool: "pull_request_write", args: { method: "create" } }).rule, "red-line-4-overwrite");
  });

  it("instavibe.json: before red line 2 named events and invitations, 9 of the 12 tools that should ask ran unattended", () => {
    // The rule's words before that change, and without the rule that came with them for schedule, invite and rsvp.
    const raw = JSON.parse(fs.readFileSync(path.join(ROOT, "policy.example.json"), "utf8")) as { rules: Array<{ id: string; toolWords?: string[] }> };
    const rule = raw.rules.find((r) => r.id === "red-line-2-public") as { toolWords: string[] };
    rule.toolWords = ["post", "publish", "send", "tweet", "retweet", "reply", "comment", "email", "share"];
    raw.rules = raw.rules.filter((r) => r.id !== "red-line-2-events");
    const before = parsePolicy(raw);
    const list = JSON.parse(fs.readFileSync(path.join(LISTS, "instavibe.json"), "utf8")) as ToolList;
    const shouldAsk = list.tools.filter((t) => t.label === "ask");
    const ranUnattended = shouldAsk.filter((t) => evaluate(before, { server: list.server, tool: t.name, args: {} }).decision === "allow").map((t) => t.name);
    assert.deepEqual([shouldAsk.length, ranUnattended.length], [12, 9], ranUnattended.join(", "));
    assert.ok(ranUnattended.includes("create_event") && ranUnattended.includes("schedule_meeting") && ranUnattended.includes("update_calendar"));
  });

  it("calendar-review.json: before the phrases the review led to, 10 of its 12 tools that should ask ran unattended; now 1 does", () => {
    // The phrases added after the review; without them, the rule is as the review found it.
    const added = [
      "cancel event", "cancel meeting", "cancel appointment", "cancel booking", "accept invitation", "accept invite", "decline invitation",
      "decline invite", "create appointment", "book appointment", "book meeting", "book room", "create booking", "add attendee", "add attendees",
      "new event", "new meeting", "create calendar entry", "add calendar entry",
    ];
    const raw = JSON.parse(fs.readFileSync(path.join(ROOT, "policy.example.json"), "utf8")) as { rules: Array<{ id: string; toolWords?: string[] }> };
    const rule = raw.rules.find((r) => r.id === "red-line-2-public") as { toolWords: string[] };
    assert.ok(added.every((phrase) => rule.toolWords.includes(phrase)), "every added phrase is in the rule");
    rule.toolWords = rule.toolWords.filter((phrase) => !added.includes(phrase));
    const before = parsePolicy(raw);
    const list = JSON.parse(fs.readFileSync(path.join(LISTS, "calendar-review.json"), "utf8")) as ToolList;
    const shouldAsk = list.tools.filter((t) => t.label === "ask");
    const unattended = (policy: typeof before) => shouldAsk.filter((t) => evaluate(policy, { server: list.server, tool: t.name, args: {} }).decision === "allow").map((t) => t.name);
    assert.deepEqual([shouldAsk.length, unattended(before).length], [12, 10], unattended(before).join(", "));
    assert.deepEqual(unattended(POLICY), ["set_reminder_for_team"]);
  });

  it("google-workspace-calendar.json: names catch none of the 3 calendar writes; docs/mcp-gateway.md's two rules on the action argument ask about each one", () => {
    const list = JSON.parse(fs.readFileSync(path.join(LISTS, "google-workspace-calendar.json"), "utf8")) as ToolList;
    const writes = list.tools.filter((t) => t.label === "ask").map((t) => t.name);
    assert.deepEqual(writes, ["manage_event", "manage_out_of_office", "manage_focus_time"]);
    assert.ok(writes.every((tool) => evaluate(POLICY, { server: list.server, tool, args: {} }).decision === "allow"), "the example policy lets each one run by its name");

    const readme = fs.readFileSync(path.join(ROOT, "docs", "mcp-gateway.md"), "utf8");
    const snippet = /```json\n *(\[\n *\{ "id": "calendar-list"[\s\S]*?\])\n *```/.exec(readme)?.[1];
    assert.ok(snippet, "docs/mcp-gateway.md shows the two rules");
    const raw = JSON.parse(fs.readFileSync(path.join(ROOT, "policy.example.json"), "utf8")) as { rules: unknown[] };
    const withRules = parsePolicy({ ...raw, rules: [...(JSON.parse(snippet) as unknown[]), ...raw.rules] });
    const decide = (tool: string, args: Record<string, unknown>) => {
      const verdict = evaluate(withRules, { server: "calendar", tool, args });
      return `${verdict.decision} ${verdict.rule}`;
    };
    // The server lowercases and trims the action, so the rule reads it the same way.
    for (const action of ["create", "update", "delete", "rsvp", " RSVP ", "archive"]) assert.equal(decide("manage_event", { action }), "ask calendar-manage", action);
    assert.equal(decide("manage_out_of_office", { action: "list" }), "allow calendar-list");
    assert.equal(decide("manage_focus_time", { action: " List " }), "allow calendar-list");
    assert.equal(decide("manage_focus_time", {}), "ask calendar-manage", "no action: asked");
    assert.equal(decide("manage_focus_time", { action: "list; delete" }), "ask calendar-manage");
    assert.equal(decide("get_events", {}), "allow default");
  });
});
