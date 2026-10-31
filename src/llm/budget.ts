// Budgets: a daily and a monthly cap in US dollars for every gateway key, and three optional stop
// rules per key: calls per minute (maxCallsPerMinute), and calls and dollars per run (runMaxCalls,
// runMaxUsd), where a run is what a client names in its x-run-id header.
//
// Before a call, the gateway reserves an estimate of its cost; the reservation is refused if the
// key's settled spend plus everything still reserved plus this estimate would pass a cap. After
// the call, the reservation is settled with the real cost from the upstream's "usage", or released
// if the call failed. Concurrent calls each hold their reservation while they run, so together
// they cannot pass a cap by more than their estimates were off. Why reserve-then-settle:
// docs/adr/0002-reserve-then-settle-budgets.md.
//
// Each reservation is settled at most once: the ledger remembers settled reservation ids for as long as
// a reservation lives, so a second settle of the same id books nothing ("duplicate"), and a settle
// whose reservation is gone (it expired first) books the cost once and says so ("orphan").
//
// The ledger is one JSON file, <stateDir>/ledger.json, changed with the same locked
// read-modify-write and atomic rename as the MCP gateway's approvals.json (state-file.ts).
// ponytail: days and months are UTC calendar days and months; caps reset at 00:00 UTC.
// ponytail: one file and one lock on one host. Several gateway hosts sharing a budget would need
// a shared store with atomic increments (a database, Redis).

import { randomBytes } from "node:crypto";
import * as path from "node:path";
import { readIfExists, withLock, writeAtomic } from "../gateway/state-file.js";
import type { GatewayKey, Price } from "./config.js";

const FILE_VERSION = 1;

export type Cap = "daily" | "monthly";

/** How long a run's calls and spend are remembered after its last call. */
export const RUN_MEMORY_MS = 24 * 60 * 60 * 1000;
const MINUTE_MS = 60_000;

export interface KeySpend {
  /** The UTC day that dayUsd belongs to, "YYYY-MM-DD". */
  day: string;
  dayUsd: number;
  /** The UTC month that monthUsd belongs to, "YYYY-MM". */
  month: string;
  monthUsd: number;
  /** Calls in flight: reservation id to its estimate. */
  reservations: Record<string, Reservation>;
  /** Reservations settled lately: id to when it is forgotten. A second settle of one books nothing. */
  settled?: Record<string, string>;
  /** maxCallsPerMinute: when the calls of the last minute were let through (ms since the epoch). */
  recent?: number[];
  /** runMaxCalls and runMaxUsd: each run's calls and settled dollars, by the client's run id. */
  runs?: Record<string, RunSpend>;
}

export interface Reservation {
  usd: number;
  /** After this the reservation is dropped, in case the process that made it died mid-call. */
  expiresAt: string;
  /** The run the call belongs to, when the key has a run cap. */
  runId?: string;
}

export interface RunSpend {
  calls: number;
  usd: number;
  /** The run is forgotten RUN_MEMORY_MS after this. */
  lastSeen: string;
}

/** What settle() did: booked the reservation; booked one it no longer had ("orphan"); or nothing, because it was settled before. */
export type SettleOutcome = "booked" | "orphan" | "duplicate";

export type ReserveOutcome =
  | { ok: true; id: string; usd: number }
  | {
      ok: false;
      cap: Cap;
      capUsd: number;
      /** Settled spend in the cap's period. */
      spentUsd: number;
      /** Held by other calls that are still running. */
      reservedUsd: number;
      requestedUsd: number;
      /** Seconds until the request could fit: the end of the period, or 1 when in-flight calls are what is in the way. */
      retryAfterSeconds: number;
    }
  /** The key made maxCallsPerMinute calls in the last 60 seconds. */
  | { ok: false; cap: "maxCallsPerMinute"; limit: number; retryAfterSeconds: number }
  /** The run made runMaxCalls calls. Waiting does not help: the run has to stop. */
  | { ok: false; cap: "runMaxCalls"; runId: string; limit: number; calls: number }
  /** The run's settled spend, plus what its calls in flight hold, plus this call, would pass runMaxUsd. */
  | { ok: false; cap: "runMaxUsd"; runId: string; limit: number; spentUsd: number; reservedUsd: number; requestedUsd: number };

export interface KeyUsage {
  key: string;
  day: string;
  dayUsd: number;
  dailyUsd: number;
  month: string;
  monthUsd: number;
  monthlyUsd: number;
  inFlight: number;
  reservedUsd: number;
}

/**
 * Input tokens are estimated as characters / 4, rounded up: the usual rule of thumb for English
 * text and code with GPT-style tokenizers.
 * ponytail: not a tokenizer. Other languages and unusual text can take more tokens per character;
 * the settled cost always comes from the upstream's own count.
 */
export function estimateInputTokens(promptChars: number): number {
  return Math.ceil(promptChars / 4);
}

export function costUsd(price: Price, inputTokens: number, outputTokens: number): number {
  return roundUsd((inputTokens * price.input + outputTokens * price.output) / 1_000_000);
}

/** To a billionth of a dollar, so sums stay readable in the ledger file. */
export function roundUsd(usd: number): number {
  return Math.round(usd * 1e9) / 1e9;
}

/** 0.000701, 2, 0.5: never an exponent, no trailing zeros. */
export function formatUsd(usd: number): string {
  return usd.toFixed(9).replace(/\.?0+$/, "");
}

export function utcDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

export function utcMonth(ms: number): string {
  return new Date(ms).toISOString().slice(0, 7);
}

export class Ledger {
  readonly file: string;
  private readonly lockDir: string;

  /** `now` is injectable so that tests can move the clock across days and months. */
  constructor(
    readonly dir: string,
    /** How long a reservation may stay in flight; longer than any call can take. */
    readonly reservationTtlMs: number,
    private readonly now: () => number = Date.now,
  ) {
    this.file = path.join(dir, "ledger.json");
    this.lockDir = path.join(dir, "ledger.lock");
  }

  /**
   * Holds `usd` for a call, or refuses it. In this order: the key's calls per minute, the run's
   * calls, the run's dollars, the key's daily cap, its monthly cap. `runId` counts only for a key
   * with a run cap; a client that sends none is held to the other limits only.
   */
  reserve(key: GatewayKey, usd: number, runId?: string): ReserveOutcome {
    return this.update((spend, now): ReserveOutcome => {
      const entry = account(spend, key.name, now);
      const recent = (entry.recent ?? []).filter((t) => t > now - MINUTE_MS);
      if (key.maxCallsPerMinute !== undefined && recent.length >= key.maxCallsPerMinute) {
        const oldest = recent[recent.length - key.maxCallsPerMinute] ?? now;
        return { ok: false, cap: "maxCallsPerMinute", limit: key.maxCallsPerMinute, retryAfterSeconds: Math.max(1, Math.ceil((oldest + MINUTE_MS - now) / 1000)) };
      }
      const capsRun = runId !== undefined && (key.runMaxCalls !== undefined || key.runMaxUsd !== undefined);
      const run = capsRun && entry.runs && Object.prototype.hasOwnProperty.call(entry.runs, runId) ? entry.runs[runId] : undefined;
      if (capsRun) {
        const calls = run?.calls ?? 0;
        if (key.runMaxCalls !== undefined && calls >= key.runMaxCalls) return { ok: false, cap: "runMaxCalls", runId, limit: key.runMaxCalls, calls };
        if (key.runMaxUsd !== undefined) {
          const held = roundUsd(Object.values(entry.reservations).reduce((sum, r) => sum + (r.runId === runId ? r.usd : 0), 0));
          const spent = run?.usd ?? 0;
          if (roundUsd(spent + held + usd) > key.runMaxUsd) {
            return { ok: false, cap: "runMaxUsd", runId, limit: key.runMaxUsd, spentUsd: spent, reservedUsd: held, requestedUsd: usd };
          }
        }
      }
      const reservedUsd = roundUsd(Object.values(entry.reservations).reduce((sum, r) => sum + r.usd, 0));
      const checks: Array<[Cap, number, number, number]> = [
        ["daily", key.dailyUsd, entry.dayUsd, nextUtcDay(now)],
        ["monthly", key.monthlyUsd, entry.monthUsd, nextUtcMonth(now)],
      ];
      for (const [cap, capUsd, spentUsd, periodEnd] of checks) {
        if (roundUsd(spentUsd + reservedUsd + usd) > capUsd) {
          // If the settled spend alone leaves no room, only the next period helps.
          const retryAfterSeconds = roundUsd(spentUsd + usd) > capUsd ? Math.max(1, Math.ceil((periodEnd - now) / 1000)) : 1;
          return { ok: false, cap, capUsd, spentUsd, reservedUsd, requestedUsd: usd, retryAfterSeconds };
        }
      }
      const id = newId(entry.reservations);
      entry.reservations[id] = { usd, expiresAt: new Date(now + this.reservationTtlMs).toISOString(), ...(capsRun ? { runId } : {}) };
      if (key.maxCallsPerMinute !== undefined) entry.recent = [...recent, now];
      if (capsRun) {
        entry.runs ??= {};
        entry.runs[runId] = { calls: (run?.calls ?? 0) + 1, usd: run?.usd ?? 0, lastSeen: new Date(now).toISOString() };
      }
      return { ok: true, id, usd };
    });
  }

  /**
   * Books the real cost of a finished call and drops its reservation, once per reservation id. A
   * second settle of the same id books nothing ("duplicate"). A settle whose reservation is gone, because
   * it expired before the call ended, books the cost (it was spent) and says "orphan" so it can be flagged.
   */
  settle(keyName: string, reservationId: string, usd: number): SettleOutcome {
    return this.update((spend, now): SettleOutcome => {
      const entry = account(spend, keyName, now);
      entry.settled ??= {};
      if (Object.prototype.hasOwnProperty.call(entry.settled, reservationId)) return "duplicate";
      const reservation = Object.prototype.hasOwnProperty.call(entry.reservations, reservationId) ? entry.reservations[reservationId] : undefined;
      delete entry.reservations[reservationId];
      entry.dayUsd = roundUsd(entry.dayUsd + usd);
      entry.monthUsd = roundUsd(entry.monthUsd + usd);
      entry.settled[reservationId] = new Date(now + this.reservationTtlMs).toISOString();
      const run = reservation?.runId !== undefined && entry.runs ? entry.runs[reservation.runId] : undefined;
      if (run) run.usd = roundUsd(run.usd + usd);
      return reservation ? "booked" : "orphan";
    });
  }

  /** Drops the reservation of a call that failed, without booking anything. */
  release(keyName: string, reservationId: string): void {
    this.update((spend, now) => {
      delete account(spend, keyName, now).reservations[reservationId];
    });
  }

  /** What the CLI shows. Reads without the lock: writes are atomic renames. */
  usage(keys: readonly GatewayKey[]): KeyUsage[] {
    const spend = this.read();
    const now = this.now();
    return keys.map((key) => {
      const entry = Object.prototype.hasOwnProperty.call(spend, key.name) ? spend[key.name] : undefined;
      const live = Object.values(entry?.reservations ?? {}).filter((r) => Date.parse(r.expiresAt) > now);
      return {
        key: key.name,
        day: utcDay(now),
        dayUsd: entry?.day === utcDay(now) ? entry.dayUsd : 0,
        dailyUsd: key.dailyUsd,
        month: utcMonth(now),
        monthUsd: entry?.month === utcMonth(now) ? entry.monthUsd : 0,
        monthlyUsd: key.monthlyUsd,
        inFlight: live.length,
        reservedUsd: roundUsd(live.reduce((sum, r) => sum + r.usd, 0)),
      };
    });
  }

  private read(): Record<string, KeySpend> {
    const content = readIfExists(this.file);
    if (content === undefined) return {};
    let data: unknown;
    try {
      data = JSON.parse(content);
    } catch (err) {
      throw new Error(`${this.file} is not valid JSON (${(err as Error).message}); fix or remove it`);
    }
    // Fail closed: a damaged ledger is an error, never an empty one, because an empty ledger would
    // hand every key its whole budget again.
    const file = data as { version?: unknown; keys?: unknown } | null;
    if (typeof file !== "object" || file === null || file.version !== FILE_VERSION || typeof file.keys !== "object" || file.keys === null) {
      throw new Error(`${this.file} is not a version ${FILE_VERSION} ledger file; fix or remove it`);
    }
    return file.keys as Record<string, KeySpend>;
  }

  private update<T>(change: (spend: Record<string, KeySpend>, now: number) => T): T {
    return withLock(this.dir, this.lockDir, () => {
      const spend = this.read();
      const now = this.now();
      const result = change(spend, now);
      writeAtomic(this.file, `${JSON.stringify({ version: FILE_VERSION, keys: spend }, null, 2)}\n`);
      return result;
    });
  }
}

/** The key's entry, created if needed, rolled over to the current day and month, and with expired reservations dropped. */
function account(spend: Record<string, KeySpend>, name: string, now: number): KeySpend {
  const day = utcDay(now);
  const month = utcMonth(now);
  if (!Object.prototype.hasOwnProperty.call(spend, name)) spend[name] = { day, dayUsd: 0, month, monthUsd: 0, reservations: {} };
  const entry = spend[name] as KeySpend;
  if (entry.day !== day) {
    entry.day = day;
    entry.dayUsd = 0;
  }
  if (entry.month !== month) {
    entry.month = month;
    entry.monthUsd = 0;
  }
  for (const [id, r] of Object.entries(entry.reservations)) {
    if (!(Date.parse(r.expiresAt) > now)) delete entry.reservations[id];
  }
  // The other memories are kept only while they can still matter, and left out when empty.
  if (entry.settled) {
    for (const [id, until] of Object.entries(entry.settled)) if (!(Date.parse(until) > now)) delete entry.settled[id];
    if (Object.keys(entry.settled).length === 0) delete entry.settled;
  }
  if (entry.recent) {
    entry.recent = entry.recent.filter((t) => t > now - MINUTE_MS);
    if (entry.recent.length === 0) delete entry.recent;
  }
  if (entry.runs) {
    for (const [id, run] of Object.entries(entry.runs)) if (!(Date.parse(run.lastSeen) + RUN_MEMORY_MS > now)) delete entry.runs[id];
    if (Object.keys(entry.runs).length === 0) delete entry.runs;
  }
  return entry;
}

function nextUtcDay(now: number): number {
  const d = new Date(now);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1);
}

function nextUtcMonth(now: number): number {
  const d = new Date(now);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1);
}

function newId(taken: Record<string, Reservation>): string {
  for (;;) {
    const id = `rs-${randomBytes(4).toString("hex")}`;
    if (!Object.prototype.hasOwnProperty.call(taken, id)) return id;
  }
}
