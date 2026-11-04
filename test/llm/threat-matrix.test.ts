// The threat matrix: 32 risky prompts and what the leak guard does with each, including the ones it
// is not the layer for. A row's outcome may not change without the matrix saying so.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { loadLeakPolicy } from "../../src/llm/config.js";
import { guardMessages } from "../../src/llm/leak-guard.js";
import { PII } from "./fake-pii.js";
import { FAKE } from "./fake-secrets.js";

// This file runs from dist/test/llm/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const policy = loadLeakPolicy(path.join(ROOT, "llm-policy.example.json"));

interface Row {
  id: string;
  category: string;
  prompt?: string;
  messages?: string[];
  expect: string;
  covered: boolean;
  reason: string;
}
const matrix = JSON.parse(fs.readFileSync(path.join(ROOT, "test", "llm", "threat-matrix.json"), "utf8")) as { rows: Row[] };
const half = Math.floor(FAKE.githubToken.length / 2);
const VALUES: Record<string, string> = {
  ...(Object.fromEntries(Object.entries(FAKE).map(([name, value]) => [name, typeof value === "string" ? value : JSON.stringify(value)])) as Record<string, string>),
  ...(PII as Record<string, string>),
  githubTokenBase64: Buffer.from(FAKE.githubToken).toString("base64"),
  githubTokenFirstHalf: FAKE.githubToken.slice(0, half),
  githubTokenSecondHalf: FAKE.githubToken.slice(half),
};
const fill = (text: string): string =>
  text.replace(/\{\{(\w+)\}\}/g, (_, name: string) => {
    const value = VALUES[name];
    if (value === undefined) throw new Error(`threat-matrix.json names an unknown value {{${name}}}`);
    return value;
  });

function outcome(row: Row): string {
  const messages = (row.messages ?? [row.prompt as string]).map((content) => ({ role: "user", content: fill(content) }));
  const result = guardMessages(policy, messages);
  if (result.action === "block") return `block:${result.rule}`;
  return result.redactions.length > 0 ? `redact:${result.redactions.map((r) => r.rule).join(",")}` : "pass";
}

describe("the threat matrix (test/llm/threat-matrix.json)", () => {
  it("is well formed: 32 rows, unique ids, known categories, a reason for each", () => {
    assert.equal(matrix.rows.length, 32);
    assert.equal(new Set(matrix.rows.map((r) => r.id)).size, matrix.rows.length);
    for (const row of matrix.rows) {
      assert.ok(["secret", "pii", "injection", "jailbreak", "dangerous"].includes(row.category), row.id);
      assert.ok(row.reason.length > 10, row.id);
      assert.ok((row.prompt === undefined) !== (row.messages === undefined), `${row.id}: prompt or messages`);
      if (!row.covered) assert.equal(row.expect, "pass", `${row.id}: a row the leak guard does not cover must pass, and say why`);
    }
  });

  for (const row of matrix.rows) {
    it(`${row.category}: ${row.id} -> ${row.expect}${row.covered ? "" : " (not covered)"}`, () => {
      assert.equal(outcome(row), row.expect);
    });
  }

  it("docs/llm-gateway.md gives the same counts", () => {
    const covered = matrix.rows.filter((r) => r.covered).length;
    const readme = fs.readFileSync(path.join(ROOT, "docs", "llm-gateway.md"), "utf8");
    assert.match(readme, new RegExp(`\`test/llm/threat-matrix\\.json\`\\) holds ${matrix.rows.length} prompts`));
    assert.match(readme, new RegExp(`the leak guard covers ${covered} of them`));
  });
});
