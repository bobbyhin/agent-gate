// Tests for budget math and the ledger, with a clock the test controls.
import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { costUsd, estimateInputTokens, formatUsd, Ledger, roundUsd, type ReserveOutcome } from "../../src/llm/budget.js";
import type { GatewayKey } from "../../src/llm/config.js";

const KEY: GatewayKey = { name: "team-a", sha256: "a".repeat(64), dailyUsd: 1, monthlyUsd: 3 };
const TTL = 60_000;

function ok(outcome: ReserveOutcome): string {
  assert.equal(outcome.ok, true, JSON.stringify(outcome));
  return (outcome as { id: string }).id;
}

function refused(outcome: ReserveOutcome): Extract<ReserveOutcome, { ok: false }> {
  assert.equal(outcome.ok, false, JSON.stringify(outcome));
  return outcome as Extract<ReserveOutcome, { ok: false }>;
}

describe("budget math", () => {
  it("estimates input tokens as characters / 4, rounded up", () => {
    assert.deepEqual([0, 1, 4, 5, 400, 401].map(estimateInputTokens), [0, 1, 1, 2, 100, 101]);
  });

  it("prices tokens per million, to a billionth of a dollar", () => {
    assert.equal(costUsd({ input: 3, output: 15 }, 1000, 500), 0.0105);
    assert.equal(costUsd({ input: 0.15, output: 0.6 }, 21, 9), 0.00000855);
    assert.equal(costUsd({ input: 0.5, output: 1.5 }, 1234, 56), 0.000701);
    assert.equal(costUsd({ input: 0, output: 0 }, 1e6, 1e6), 0);
    assert.equal(roundUsd(0.1 + 0.2), 0.3);
  });

  it("formats dollars without exponents or trailing zeros", () => {
    assert.deepEqual([0.00000855, 2, 0, 0.5, 1.5e-7, 0.015015].map(formatUsd), ["0.00000855", "2", "0", "0.5", "0.00000015", "0.015015"]);
  });
});

describe("Ledger", () => {
  let dir: string;
  let now: number;
  let ledger: Ledger;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-ledger-"));
    now = Date.parse("2026-10-14T10:00:00.000Z");
    ledger = new Ledger(dir, TTL, () => now);
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  const usage = () => ledger.usage([KEY])[0]!;

  it("reserves an estimate, then settles the real cost", () => {
    const id = ok(ledger.reserve(KEY, 0.4));
    assert.match(id, /^rs-[0-9a-f]{8}$/);
    assert.deepEqual([usage().dayUsd, usage().inFlight, usage().reservedUsd], [0, 1, 0.4]);
    ledger.settle(KEY.name, id, 0.25);
    assert.deepEqual([usage().dayUsd, usage().monthUsd, usage().inFlight, usage().reservedUsd], [0.25, 0.25, 0, 0]);
  });

  it("releases a failed call without booking anything", () => {
    ledger.release(KEY.name, ok(ledger.reserve(KEY, 0.4)));
    assert.deepEqual([usage().dayUsd, usage().monthUsd, usage().inFlight], [0, 0, 0]);
  });

  it("counts calls in flight: concurrent reservations cannot pass the cap together", () => {
    const first = ok(ledger.reserve(KEY, 0.5));
    ok(ledger.reserve(KEY, 0.4));
    const no = refused(ledger.reserve(KEY, 0.2));
    assert.deepEqual([no.cap, no.capUsd, no.spentUsd, no.reservedUsd, no.requestedUsd], ["daily", 1, 0, 0.9, 0.2]);
    assert.equal(no.retryAfterSeconds, 1, "calls in flight are what is in the way, so it may fit soon");
    ledger.release(KEY.name, first);
    ok(ledger.reserve(KEY, 0.2));
  });

  it("lets a call reach the cap exactly, but not pass it", () => {
    ledger.settle(KEY.name, ok(ledger.reserve(KEY, 0.6)), 0.6);
    ok(ledger.reserve(KEY, 0.4));
    refused(ledger.reserve(KEY, 0.000000001));
  });

  it("refuses once settled spend leaves no room, until the next UTC day", () => {
    ledger.settle(KEY.name, ok(ledger.reserve(KEY, 0.1)), 0.95);
    const no = refused(ledger.reserve(KEY, 0.1));
    assert.deepEqual([no.cap, no.spentUsd, no.reservedUsd], ["daily", 0.95, 0]);
    assert.equal(no.retryAfterSeconds, 14 * 60 * 60, "10:00 UTC to midnight");
  });

  it("applies the monthly cap across days, and names it", () => {
    for (const day of ["2026-10-01", "2026-10-02", "2026-10-03"]) {
      now = Date.parse(`${day}T12:00:00.000Z`);
      ledger.settle(KEY.name, ok(ledger.reserve(KEY, 0.9)), 0.9);
    }
    now = Date.parse("2026-10-04T12:00:00.000Z");
    assert.deepEqual([usage().dayUsd, usage().monthUsd], [0, 2.7]);
    const no = refused(ledger.reserve(KEY, 0.4));
    assert.deepEqual([no.cap, no.capUsd, no.spentUsd], ["monthly", 3, 2.7]);
    assert.equal(no.retryAfterSeconds, (Date.parse("2026-11-01T00:00:00.000Z") - now) / 1000);
    ok(ledger.reserve(KEY, 0.3));
  });

  it("starts a new day at 00:00 UTC and keeps the month", () => {
    now = Date.parse("2026-10-14T23:59:00.000Z");
    ledger.settle(KEY.name, ok(ledger.reserve(KEY, 0.9)), 0.9);
    assert.equal(refused(ledger.reserve(KEY, 0.2)).retryAfterSeconds, 60);
    now = Date.parse("2026-10-15T00:00:00.000Z");
    ok(ledger.reserve(KEY, 0.2));
    assert.deepEqual([usage().day, usage().dayUsd, usage().month, usage().monthUsd], ["2026-10-15", 0, "2026-10", 0.9]);
  });

  it("starts a new month on the 1st, 00:00 UTC", () => {
    now = Date.parse("2026-10-31T23:30:00.000Z");
    ledger.settle(KEY.name, ok(ledger.reserve(KEY, 0.5)), 0.5);
    now = Date.parse("2026-11-01T00:00:00.000Z");
    assert.deepEqual([usage().day, usage().dayUsd, usage().month, usage().monthUsd], ["2026-11-01", 0, "2026-11", 0]);
  });

  it("books a call that ends after midnight on the day it ends", () => {
    now = Date.parse("2026-10-14T23:59:59.000Z");
    const id = ok(ledger.reserve(KEY, 0.2));
    now = Date.parse("2026-10-15T00:00:01.000Z");
    ledger.settle(KEY.name, id, 0.15);
    assert.deepEqual([usage().day, usage().dayUsd, usage().monthUsd, usage().inFlight], ["2026-10-15", 0.15, 0.15, 0]);
  });

  it("drops a reservation left behind by a process that died, after its TTL", () => {
    ok(ledger.reserve(KEY, 0.9));
    refused(ledger.reserve(KEY, 0.9));
    now += TTL + 1;
    assert.equal(usage().inFlight, 0);
    ok(ledger.reserve(KEY, 0.9));
  });

  it("is shared through the file: a second process sees the first one's reservations", () => {
    const other = new Ledger(dir, TTL, () => now);
    ok(ledger.reserve(KEY, 0.6));
    assert.equal(refused(other.reserve(KEY, 0.6)).reservedUsd, 0.6);
  });

  it("keeps each key's budget separate", () => {
    const other: GatewayKey = { ...KEY, name: "team-b", sha256: "b".repeat(64) };
    ledger.settle(KEY.name, ok(ledger.reserve(KEY, 1)), 1);
    ok(ledger.reserve(other, 1));
    assert.deepEqual(
      ledger.usage([KEY, other]).map((u) => [u.key, u.dayUsd, u.inFlight]),
      [
        ["team-a", 1, 0],
        ["team-b", 0, 1],
      ],
    );
  });

  it("does not drift when many small costs add up", () => {
    for (let i = 0; i < 10; i++) ledger.settle(KEY.name, ok(ledger.reserve(KEY, 0.1)), 0.1);
    assert.equal(usage().dayUsd, 1);
  });

  it("reports zero for a key it has never seen", () => {
    assert.deepEqual(usage(), { key: "team-a", day: "2026-10-14", dayUsd: 0, dailyUsd: 1, month: "2026-10", monthUsd: 0, monthlyUsd: 3, inFlight: 0, reservedUsd: 0 });
  });

  it("writes a private, versioned file atomically and leaves no temporary files", () => {
    ok(ledger.reserve(KEY, 0.1));
    assert.deepEqual(fs.readdirSync(dir), ["ledger.json"]);
    const file = JSON.parse(fs.readFileSync(ledger.file, "utf8"));
    assert.equal(file.version, 1);
    assert.deepEqual(Object.keys(file.keys["team-a"]), ["day", "dayUsd", "month", "monthUsd", "reservations"]);
    if (process.platform !== "win32") assert.equal(fs.statSync(ledger.file).mode & 0o777, 0o600);
  });

  it("fails closed on a damaged ledger instead of starting from zero", () => {
    fs.writeFileSync(ledger.file, "{ not json");
    assert.throws(() => ledger.reserve(KEY, 0.1), /not valid JSON/);
    assert.equal(fs.readFileSync(ledger.file, "utf8"), "{ not json");
    fs.writeFileSync(ledger.file, JSON.stringify({ version: 99, keys: {} }));
    assert.throws(() => ledger.usage([KEY]), /not a version 1 ledger file/);
  });
});
