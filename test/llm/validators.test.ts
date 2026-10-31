// The PII rules' validators, on their own and through the leak guard: a number counts only when its
// checksum or its ranges say it can be one. Every number here is built at run time (fake-pii.ts).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { guardResult } from "../../src/gateway/result-guard.js";
import { loadLeakPolicy } from "../../src/llm/config.js";
import { guardMessages, parseLeakPolicy } from "../../src/llm/leak-guard.js";
import { luhnCheckDigit, luhnValid, myNumberCheckDigit, VALIDATORS } from "../../src/llm/validators.js";
import { PII } from "./fake-pii.js";

// This file runs from dist/test/llm/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const policy = loadLeakPolicy(path.join(ROOT, "llm-policy.example.json"));
const redacted = (content: string) => {
  const result = guardMessages(policy, [{ role: "user", content }]);
  assert.equal(result.action, "pass");
  return result.action === "pass" ? { text: (result.messages[0] as { content: string }).content, rules: result.redactions.map((r) => r.rule) } : { text: "", rules: [] };
};

describe("validators", () => {
  it("Luhn: the check digit completes the sum, and changing any one digit breaks it", () => {
    assert.equal(luhnValid(PII.card), true);
    for (let i = 0; i < PII.card.length; i++) {
      const changed = `${PII.card.slice(0, i)}${(Number(PII.card[i]) + 5) % 10}${PII.card.slice(i + 1)}`;
      assert.equal(luhnValid(changed), false, `digit ${i}`);
    }
    assert.equal(luhnCheckDigit(PII.card.slice(0, -1)), Number(PII.card.slice(-1)));
    assert.equal(VALIDATORS.luhn(PII.cardSpaced), true);
    assert.equal(VALIDATORS.luhn(PII.cardBadCheck), false);
    assert.equal(VALIDATORS.luhn(PII.card.slice(0, 12)), false, "fewer than 13 digits is not a card number");
  });

  it("My Number: the check digit follows the ordinance's weights, and a remainder of 0 or 1 gives 0", () => {
    // Weights from the right of the first 11 digits: 2, 3, 4, 5, 6, 7, then 2, 3, 4, 5, 6.
    const one = (position: number) => "0".repeat(11 - position) + "1" + "0".repeat(position - 1);
    assert.deepEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].map((n) => 11 - myNumberCheckDigit(one(n))), [2, 3, 4, 5, 6, 7, 2, 3, 4, 5, 6]);
    assert.equal(myNumberCheckDigit("0".repeat(11)), 0, "remainder 0");
    assert.equal(myNumberCheckDigit(`${"0".repeat(8)}3${"0".repeat(2)}`), 0, "3 at the third place from the right: 3 x 4 = 12, remainder 1");
    assert.equal(VALIDATORS["jp-my-number"](PII.myNumber), true);
    assert.equal(VALIDATORS["jp-my-number"](PII.myNumberSpaced), true);
    assert.equal(VALIDATORS["jp-my-number"](PII.myNumberBadCheck), false);
  });

  it("SSN and ITIN: only the ranges that can be assigned", () => {
    assert.deepEqual([PII.ssn, PII.ssnArea666, PII.ssnGroup00, PII.itin].map(VALIDATORS["us-ssn"]), [true, false, false, false]);
    assert.deepEqual([PII.itin, PII.itinGroup89, PII.ssn].map(VALIDATORS["us-itin"]), [true, false, false]);
  });
});

describe("the PII rules of llm-policy.example.json", () => {
  it("redacts each kind in every way it is written, and leaves look-alikes that fail their check", () => {
    for (const [value, rule] of [
      [PII.card, "credit-card"],
      [PII.cardSpaced, "credit-card"],
      [PII.cardDashed, "credit-card"],
      [PII.myNumber, "jp-my-number"],
      [PII.myNumberSpaced, "jp-my-number"],
      [PII.ssn, "us-ssn"],
      [PII.itin, "us-itin"],
    ] as const) {
      const r = redacted(`please update the record: ${value}, thanks`);
      assert.deepEqual(r, { text: `please update the record: [REDACTED:${rule}], thanks`, rules: [rule] }, value);
    }
    for (const value of [PII.cardBadCheck, PII.myNumberBadCheck, PII.ssnArea666, PII.ssnGroup00, PII.itinGroup89]) {
      const text = `order ${value} shipped`;
      assert.deepEqual(redacted(text), { text, rules: [] }, value);
    }
  });

  it("reads a number only when it stands on its own, not as the tail of a UUID or another hyphenated id", () => {
    for (const text of [`request ${["123e4567", "e89b", "12d3", "a456", PII.myNumber].join("-")} failed`, `ticket INC-${PII.ssn} closed`, `build v2-${PII.card}-rc1`]) {
      assert.deepEqual(redacted(text), { text, rules: [] }, text);
    }
    // The same numbers after a space, a colon or a parenthesis are found.
    assert.deepEqual(redacted(`id:${PII.myNumber} (${PII.ssn})`).rules, ["jp-my-number", "us-ssn"]);
  });

  it("a validator applies to block rules too, and to the MCP gateway's result guard, which reads the same rules", () => {
    const blocking = parseLeakPolicy({ leakGuard: [{ id: "card", action: "block", regex: "\\b[2-6](?:[ -]?\\d){12,18}\\b", validator: "luhn" }] });
    assert.deepEqual(guardMessages(blocking, [{ role: "user", content: `card ${PII.cardSpaced}` }]), { action: "block", rule: "card" });
    assert.equal(guardMessages(blocking, [{ role: "user", content: `card ${PII.cardBadCheck}` }]).action, "pass");
    // The rule's own regex test() honours the validator, so code that only calls test() does too.
    assert.equal(blocking.rules[0]!.pattern.test(`x ${PII.cardBadCheck} y`), false);
    assert.equal(blocking.rules[0]!.pattern.test(`x ${PII.cardBadCheck} y ${PII.card}`), true);
    const withheld = guardResult({ leak: blocking, flagInstructions: false }, { content: [{ type: "text", text: `on file: ${PII.card}` }] });
    assert.equal(withheld.withheld, "card");
    const kept = guardResult({ leak: blocking, flagInstructions: false }, { content: [{ type: "text", text: `on file: ${PII.cardBadCheck}` }] });
    assert.equal(kept.withheld, undefined);
    const edited = guardResult({ leak: policy, flagInstructions: false }, { content: [{ type: "text", text: `ITIN ${PII.itin}` }] });
    assert.deepEqual([edited.redacted, (edited.result.content[0] as { text: string }).text], [["us-itin"], "ITIN [REDACTED:us-itin]"]);
  });

  it("refuses an unknown validator", () => {
    assert.throws(() => parseLeakPolicy({ leakGuard: [{ id: "x", action: "redact", regex: "\\d{4}", validator: "mod97" }] }), /validator must be one of luhn, jp-my-number, us-ssn, us-itin/);
  });

  it("README.md's leak-guard table lists every rule of llm-policy.example.json, in order, with its action", () => {
    const readme = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");
    const section = readme.slice(readme.indexOf("`llm-policy.example.json` ships"), readme.indexOf("The formats that are surely secrets block"));
    const rows = [...section.matchAll(/^\| `([^`]+)` \| .* \| (block|redact) \|$/gm)].map((m) => [m[1], m[2]]);
    assert.deepEqual(rows, policy.rules.map((r) => [r.id, r.action]));
    const count = /ships (\w+) rules/.exec(section)?.[1];
    assert.equal(count, ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen"][policy.rules.length]);
  });
});
