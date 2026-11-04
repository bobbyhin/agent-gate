// Indirect prompt injections in tool results (test/gateway/result-injections.json) through the result
// guard with the example leak policy. Each case says what the guard does; the misses are part of the
// fixture, so the test fails when the guard starts or stops catching one, and docs/mcp-gateway.md's counts are
// checked against the file.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { guardResult, type ResultGuard } from "../../src/gateway/result-guard.js";
import { loadLeakPolicy } from "../../src/llm/config.js";
import { guardMessages } from "../../src/llm/leak-guard.js";
import { PII } from "../llm/fake-pii.js";
import { FAKE } from "../llm/fake-secrets.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const FILE = path.join(ROOT, "test", "gateway", "result-injections.json");
const RAW = fs.readFileSync(FILE, "utf8");
const LEAK = loadLeakPolicy(path.join(ROOT, "llm-policy.example.json"));
const GUARD: ResultGuard = { leak: LEAK, flagInstructions: true };

interface Case {
  id: string;
  source: string;
  injection: boolean;
  result: CallToolResult;
  expect: { withheld?: string; flags: string[]; redacted: string[] };
  caught: boolean;
  reason: string;
}
const CASES = (JSON.parse(RAW) as { cases: Case[] }).cases;

/** Fills {{FAKE.name}} and {{PII.name}} in every string; an unknown name is an error. */
function fill<T>(value: T): T {
  const tables: Record<string, Record<string, string>> = { FAKE: FAKE as unknown as Record<string, string>, PII };
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") {
      return v.replace(/\{\{(FAKE|PII)\.([A-Za-z0-9]+)\}\}/g, (_, table: string, name: string) => {
        const found = tables[table]?.[name];
        if (typeof found !== "string") throw new Error(`no ${table}.${name}`);
        return found;
      });
    }
    if (Array.isArray(v)) return v.map(walk);
    if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, item]) => [k, walk(item)]));
    return v;
  };
  return walk(value) as T;
}

describe("indirect prompt injections in tool results", () => {
  it("is a well-formed fixture with no secret or personal number in the file itself", () => {
    assert.ok(CASES.length >= 12 && CASES.length <= 15, `${CASES.length} cases`);
    assert.equal(new Set(CASES.map((c) => c.id)).size, CASES.length, "ids are unique");
    for (const c of CASES) assert.ok(c.source && c.reason, `${c.id} says where it comes from and why`);
    const scanned = guardMessages(LEAK, [{ role: "user", content: RAW }]);
    assert.deepEqual(scanned.action === "pass" ? scanned.redactions : scanned, [], "the leak guard finds nothing in the raw file");
  });

  for (const c of CASES) {
    it(`${c.id}: ${c.caught ? (c.injection ? "caught" : "a false alarm") : c.injection ? "missed" : "left alone"}`, () => {
      const input = fill(c.result);
      const guarded = guardResult(GUARD, input);
      assert.deepEqual({ ...(guarded.withheld ? { withheld: guarded.withheld } : {}), flags: guarded.flags, redacted: guarded.redacted }, c.expect);
      assert.equal(guarded.withheld !== undefined || guarded.flags.length > 0, c.caught, "caught means flagged or withheld");
      if (guarded.withheld) {
        assert.equal(guarded.result.isError, true);
        assert.equal(JSON.stringify(guarded.result).includes(FAKE.githubToken), false, "nothing of a withheld result reaches the model");
      } else if (guarded.redacted.length === 0) {
        // A flag changes nothing but _meta; a result with nothing found is returned as it is.
        assert.deepEqual(guarded.result.content, input.content);
        if (guarded.flags.length === 0) assert.equal(guarded.result, input);
        else assert.deepEqual(guarded.result._meta, { "agent-gate/flags": guarded.flags });
      }
    });
  }

  it("docs/mcp-gateway.md's counts are this file's", () => {
    const injections = CASES.filter((c) => c.injection);
    const benign = CASES.filter((c) => !c.injection);
    const caught = injections.filter((c) => c.caught).length;
    const falseAlarms = benign.filter((c) => c.caught).length;
    const readme = fs.readFileSync(path.join(ROOT, "docs", "mcp-gateway.md"), "utf8").replace(/\s+/g, " ");
    assert.ok(
      readme.includes(`Of the ${injections.length} results that carry an injection, the guard flags or withholds ${caught} and misses ${injections.length - caught}`),
      "docs/mcp-gateway.md states the injection counts",
    );
    assert.ok(readme.includes(`of the ${benign.length} ordinary documents, it flags ${falseAlarms}`), "docs/mcp-gateway.md states the false alarms");
  });
});
