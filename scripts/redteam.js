#!/usr/bin/env node
"use strict";
// npm run redteam [-- --list]
//
// Scores the shell guard on test/cases-heldout.json: 163 commands that a red team wrote against a
// later, broader version of the hook (see test/HELDOUT.md). None of them was used to build or tune
// this analyzer, so the score says how it does on attacks it has not seen, unlike the 239 cases in
// test/cases.json, which it was repaired against until all of them passed.
//
//   recall      of the commands that should be stopped (expect "ask"), how many get ask or block
//   false asks  of the commands that should pass, how many get ask or block
//
// test/heldout-baseline.json holds the current score. test/command-guard.test.js fails when recall
// falls below it or false asks rise above it, so a change cannot quietly make the guard worse; a
// change that improves the score updates the baseline.
const path = require("node:path");
const { analyze } = require("../src/command-guard");

const STOPPED = new Set(["ask", "block"]);

/** Counts per category and in total. `run` is analyze() or a stand-in. */
function score(cases, run = analyze) {
  const rows = new Map();
  const total = { category: "total", cases: 0, shouldAsk: 0, caught: 0, shouldPass: 0, falseAsks: 0, slowestMs: 0 };
  const missed = [];
  const falseAsks = [];
  for (const c of cases) {
    if (!rows.has(c.category)) rows.set(c.category, { category: c.category, cases: 0, shouldAsk: 0, caught: 0, shouldPass: 0, falseAsks: 0, slowestMs: 0 });
    const row = rows.get(c.category);
    const t0 = process.hrtime.bigint();
    const got = run(c.cmd).action;
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    for (const r of [row, total]) {
      r.cases++;
      r.slowestMs = Math.max(r.slowestMs, ms);
      if (c.expect === "ask") {
        r.shouldAsk++;
        if (STOPPED.has(got)) r.caught++;
      } else {
        r.shouldPass++;
        if (STOPPED.has(got)) r.falseAsks++;
      }
    }
    if (c.expect === "ask" && !STOPPED.has(got)) missed.push(c.id);
    if (c.expect !== "ask" && STOPPED.has(got)) falseAsks.push(`${c.id} (${got})`);
  }
  return { rows: [...rows.values()], total, missed, falseAsks };
}

function main(argv) {
  const cases = require(path.join(__dirname, "..", "test", "cases-heldout.json"));
  const { rows, total, missed, falseAsks } = score(cases);
  const pct = (a, b) => (b === 0 ? "-" : `${Math.round((100 * a) / b)}%`);
  const table = [
    ["category", "cases", "recall", "false asks", "slowest"],
    ...[...rows, total].map((r) => [r.category, String(r.cases), `${r.caught}/${r.shouldAsk} ${pct(r.caught, r.shouldAsk)}`, `${r.falseAsks}/${r.shouldPass}`, `${r.slowestMs.toFixed(1)} ms`]),
  ];
  const widths = table[0].map((_, i) => Math.max(...table.map((row) => row[i].length)));
  for (const row of table) console.log(row.map((cell, i) => cell.padEnd(widths[i])).join("  ").trimEnd());
  const baseline = require(path.join(__dirname, "..", "test", "heldout-baseline.json"));
  console.log(`\nbaseline: recall ${baseline.caught}/${baseline.shouldAsk}, false asks ${baseline.falseAsks}/${baseline.shouldPass} (test/heldout-baseline.json)`);
  if (argv.includes("--list")) {
    console.log(`\nmissed (${missed.length}): ${missed.join(" ")}`);
    console.log(`\nfalse asks (${falseAsks.length}): ${falseAsks.join(" ")}`);
  } else {
    console.log("--list prints the ids of the misses and the false asks.");
  }
  return total.caught < baseline.caught || total.falseAsks > baseline.falseAsks ? 1 : 0;
}

module.exports = { score };
if (require.main === module) process.exitCode = main(process.argv.slice(2));
