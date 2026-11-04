// docs/mcp-gateway.md's table of example rules (under "## Policy") mirrors policy.example.json: the same rules
// in the same order, every word a rule matches on named in its row, and each decision, request
// lifetime, standing-approval flag and irreversible flag as the policy file has it.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");

interface RawRule {
  id: string;
  type?: string;
  toolWords?: string[];
  decision?: string;
  ttlMinutes?: number;
  standing?: boolean;
  irreversible?: boolean;
}

const policy = JSON.parse(fs.readFileSync(path.join(ROOT, "policy.example.json"), "utf8")) as { default: string; rules: RawRule[]; repeat?: Array<{ id: string; decision: string }> };
const readme = fs.readFileSync(path.join(ROOT, "docs", "mcp-gateway.md"), "utf8");

/** The rows of the table that follows "`policy.example.json` maps the red lines": [rule, matches, decision]. */
function tableRows(): Array<[string, string, string]> {
  const start = readme.indexOf("`policy.example.json` maps the red lines");
  assert.ok(start >= 0, "docs/mcp-gateway.md introduces the example policy's table");
  const lines = readme.slice(start).split("\n").slice(1);
  const rows: Array<[string, string, string]> = [];
  for (const line of lines.slice(lines.findIndex((l) => l.startsWith("| Rule |")) + 2)) {
    if (!line.startsWith("|")) break;
    const cells = line.split(" | ").map((cell) => cell.replace(/^\| ?| ?\|$/g, ""));
    rows.push([cells[0] as string, cells[1] as string, cells[2] as string]);
  }
  return rows;
}

describe("docs/mcp-gateway.md: the example policy's table mirrors policy.example.json", () => {
  const rows = tableRows();
  const byId = new Map(rows.map(([rule, matches, decision]) => [/^`([^`]+)`/.exec(rule)?.[1] ?? rule, { matches: matches.toLowerCase(), decision }]));

  it("lists every rule in policy order, then the default, then the loop limits", () => {
    const ids = rows.map(([rule]) => /^`([^`]+)`/.exec(rule)?.[1] ?? rule);
    assert.deepEqual(ids, [...policy.rules.map((r) => r.id), "default", ...(policy.repeat ?? []).map((r) => r.id)]);
  });

  it("names every word and phrase a rule matches on", () => {
    for (const rule of policy.rules) {
      for (const phrase of rule.toolWords ?? []) {
        const row = byId.get(rule.id)?.matches ?? "";
        assert.match(row, new RegExp(`(?:^|[^a-z])${phrase}(?:[^a-z]|$)`), `${rule.id}: "${phrase}" is in its row`);
      }
    }
  });

  it("names no word that a plain word-list rule does not match on", () => {
    const checked: string[] = [];
    for (const rule of policy.rules) {
      const row = byId.get(rule.id)?.matches ?? "";
      // Rows that are nothing but a list of the rule's words and phrases (no prose before the first one).
      if (!rule.toolWords || !/^[a-z ,]+$/.test(row) || !rule.toolWords.includes(row.split(", ")[0] as string)) continue;
      assert.deepEqual(row.split(", "), rule.toolWords, rule.id);
      checked.push(rule.id);
    }
    assert.ok(checked.length >= 3, `the plain rows checked: ${checked.join(", ")}`);
  });

  it("gives each rule its decision, request lifetime, standing-approval flag and irreversible flag", () => {
    for (const rule of policy.rules) {
      const cell = byId.get(rule.id)?.decision ?? "";
      assert.ok(cell.startsWith(rule.type === "shell" ? "the guard's decision" : (rule.decision as string)), `${rule.id}: ${cell}`);
      assert.equal(cell.includes(`lives ${rule.ttlMinutes} minutes`), rule.ttlMinutes !== undefined, `${rule.id}: ttlMinutes`);
      assert.equal(cell.includes("standing approvals allowed"), rule.standing === true, `${rule.id}: standing`);
      assert.equal(cell.includes("irreversible (action token)"), rule.irreversible === true, `${rule.id}: irreversible`);
    }
    // Red lines 1 to 4 cannot be undone, so each of their rules says so (ADR 0013); red line 5, memory, can be corrected.
    assert.deepEqual(
      policy.rules.filter((r) => r.irreversible).map((r) => r.id),
      policy.rules.filter((r) => /^red-line-[1-4]-/.test(r.id)).map((r) => r.id),
    );
    assert.equal(byId.get("default")?.decision, policy.default);
  });
});
