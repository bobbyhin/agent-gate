"use strict";
// The LLM gateway under concurrent load over real HTTP: a small run of scripts/loadtest.js (npm run
// loadtest is the full one). 200 requests, 50 at a time, against a key whose daily cap fits about half
// of them. However the calls interleave, the ledger must never pass the cap, must book exactly what the
// answers let through cost, must agree with the usage log and must hold nothing in flight at the end;
// every refusal must be a 429 with a named stop rule, never a 5xx. Nothing here depends on timing.
// Runs after the build (the script loads dist/).
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { runInProcess, percentile } = require("../scripts/loadtest.js");

describe("loadtest: the budget holds under concurrent load", () => {
  it("200 requests, 50 at a time: never overspent, booked exactly, no 5xx, part of the load refused by the cap", async () => {
    const r = await runInProcess({ requests: 200, concurrency: 50, direct: false });
    assert.deepEqual(
      r.checks.filter((c) => !c.ok).map((c) => c.what),
      [],
    );
    assert.equal(r.ok + r.refused, 200);
    assert.ok(r.spentUsd <= r.capUsd, `spent $${r.spentUsd} of a $${r.capUsd} cap`);
    // Each call reserves more than it settles, so the calls let through cost exactly ok x settle.
    assert.equal(Math.round(r.spentUsd * 1e9), Math.round(r.ok * r.settleUsd * 1e9));
    assert.deepEqual(Object.keys(r.counts).sort(), ["200", "429 budget_exceeded"]);
  });

  it("percentiles are nearest-rank", () => {
    const sorted = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    assert.deepEqual([percentile(sorted, 50), percentile(sorted, 95), percentile(sorted, 100), percentile([], 50)], [5, 10, 10, null]);
  });
});
