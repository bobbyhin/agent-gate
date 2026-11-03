// Budgets: a daily and a monthly cap in US dollars for every gateway key, and optional stop rules per
// key: calls per minute (maxCallsPerMinute), and limits per run, where a run is what a client names in
// its x-run-id header: calls, dollars, seconds and tokens (runMaxCalls, runMaxUsd, runMaxSeconds,
// runMaxTokens).
//
// Loop exits. A loop that grades its own rounds (propose, judge, repeat) reports each round's score
// (POST /v1/runs/score, src/llm/server.ts) and the ledger decides, in this order: SHIP when the score
// reaches runShipScore; STOP on budget when the run has used its scored rounds (runMaxRounds) or any of
// the limits above; STOP on a flat line after runFlatRounds rounds in a row that gain no more than
// runMinGain over the best score. A run that has stopped stays stopped: every later call in it is
// refused, and a later score changes nothing. The key's limits are hard caps: a client may lower them
// for its own run (x-run-budget, kept as the lowest it ever declared), never raise them. The score is
// the client's claim, so it can only end a run early; the limits the gateway counts itself (calls,
// seconds, tokens, dollars) bound a run whatever it reports.
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
  /** The run limits and exits: each run's calls, settled dollars and the rest, by the client's run id. */
  runs?: Record<string, RunSpend>;
}

export interface Reservation {
  usd: number;
  /** After this the reservation is dropped, in case the process that made it died mid-call. */
  expiresAt: string;
  /** The run the call belongs to, when the key has a run cap. */
  runId?: string;
  /** The call's estimated tokens, held against its run's runMaxTokens while it is in flight. */
  tokens?: number;
}

export interface RunSpend {
  calls: number;
  usd: number;
  /** The run is forgotten RUN_MEMORY_MS after this: its last call, admitted or refused, or its last score. */
  lastSeen: string;
  /** When the ledger first saw the run: runMaxSeconds counts from here. */
  startedAt?: string;
  /** Input and output tokens booked: runMaxTokens. */
  tokens?: number;
  /** Scores reported: how many (runMaxRounds), the best one that counted as a gain, and the rounds since it (runFlatRounds). */
  rounds?: number;
  best?: number;
  flat?: number;
  /** The lowest limits the run declared for itself (x-run-budget). They can go down, never up. */
  budget?: RunBudget;
  /** Set once, by a score report that ended the run. Every later call in the run is refused. */
  stopped?: RunStop;
}

/** What a client may declare for its own run with x-run-budget: limits under the key's, never over. */
export interface RunBudget {
  calls?: number;
  rounds?: number;
  seconds?: number;
  tokens?: number;
  usd?: number;
}

export const RUN_BUDGET_FIELDS = ["calls", "rounds", "seconds", "tokens", "usd"] as const;
export type RunBudgetField = (typeof RUN_BUDGET_FIELDS)[number];

/** How a run ended: ship (good enough), budget (a limit used up) or flat_line (no gain any more). */
export type RunExit = "ship" | "budget" | "flat_line";

export interface RunStop {
  exit: RunExit;
  /** The config field that ended it: runShipScore, runFlatRounds, runMaxRounds, runMaxCalls and so on. */
  rule: string;
  /** In words, from the gateway: the round, the score, the limit. */
  why: string;
  at: string;
}

/** The limits a run is held to now: the key's, each lowered by what the run declared. */
export interface RunLimits {
  calls?: number;
  rounds?: number;
  seconds?: number;
  tokens?: number;
  usd?: number;
  shipScore?: number;
  flatRounds?: number;
  minGain: number;
}

/** True when the key has any per-run limit or exit, so its runs are counted. */
export function hasRunRules(key: GatewayKey): boolean {
  return [key.runMaxCalls, key.runMaxUsd, key.runMaxSeconds, key.runMaxTokens, key.runMaxRounds, key.runShipScore, key.runFlatRounds].some((v) => v !== undefined);
}

/** The key's caps, each lowered by every declared budget that sets it lower. Nothing here can raise a cap. */
export function runLimits(key: GatewayKey, ...declared: Array<RunBudget | undefined>): RunLimits {
  const caps: Record<RunBudgetField, number | undefined> = { calls: key.runMaxCalls, rounds: key.runMaxRounds, seconds: key.runMaxSeconds, tokens: key.runMaxTokens, usd: key.runMaxUsd };
  const limits: RunLimits = { minGain: key.runMinGain ?? 0 };
  for (const field of RUN_BUDGET_FIELDS) {
    let limit = caps[field];
    for (const budget of declared) {
      const value = budget?.[field];
      if (value !== undefined && (limit === undefined || value < limit)) limit = value;
    }
    if (limit !== undefined) limits[field] = limit;
  }
  if (key.runShipScore !== undefined) limits.shipScore = key.runShipScore;
  if (key.runFlatRounds !== undefined) limits.flatRounds = key.runFlatRounds;
  return limits;
}

/** The fields of a declared budget that ask for more than the key allows: clamped to the key's cap, and worth a line in the log. */
export function overCaps(key: GatewayKey, budget: RunBudget | undefined): RunBudgetField[] {
  const caps = runLimits(key);
  return RUN_BUDGET_FIELDS.filter((field) => budget?.[field] !== undefined && caps[field] !== undefined && (budget[field] as number) > (caps[field] as number));
}

/**
 * Reads an x-run-budget header: "calls=12, rounds=4, seconds=600, tokens=50000, usd=0.25", any of the
 * five, each once. Counts are whole numbers from 1; usd is a positive number. Returns an error message
 * for anything else: a budget that cannot be read is refused, not ignored.
 */
export function parseRunBudget(header: string): RunBudget | { error: string } {
  const budget: RunBudget = {};
  const parts = header.split(",").map((part) => part.trim());
  if (parts.length === 0 || parts.some((part) => part === "")) return { error: 'x-run-budget must be a list such as "calls=12, rounds=4, seconds=600, tokens=50000, usd=0.25"' };
  for (const part of parts) {
    const m = /^([a-z]+)\s*=\s*([0-9]+(?:\.[0-9]+)?)$/.exec(part);
    const field = m?.[1] as RunBudgetField | undefined;
    if (!m || !field || !(RUN_BUDGET_FIELDS as readonly string[]).includes(field)) {
      return { error: `x-run-budget: ${JSON.stringify(part.slice(0, 40))} is not one of ${RUN_BUDGET_FIELDS.map((f) => `${f}=<number>`).join(", ")}` };
    }
    if (budget[field] !== undefined) return { error: `x-run-budget sets ${field} twice` };
    const value = Number(m[2]);
    const whole = field !== "usd";
    if (!(value > 0) || (whole && (!Number.isSafeInteger(value) || value > 1_000_000_000)) || !Number.isFinite(value)) {
      return { error: `x-run-budget: ${field} must be ${whole ? "a whole number from 1 to 1000000000" : "a positive number"}` };
    }
    budget[field] = value;
  }
  return budget;
}

/** Field by field, the lower of two declared budgets: a run's declaration only ever goes down. */
function lowerOf(a: RunBudget | undefined, b: RunBudget | undefined): RunBudget | undefined {
  if (!a) return b && { ...b };
  if (!b) return { ...a };
  const out: RunBudget = { ...a };
  for (const field of RUN_BUDGET_FIELDS) {
    const value = b[field];
    if (value !== undefined && (out[field] === undefined || value < (out[field] as number))) out[field] = value;
  }
  return out;
}

/** What a call brings to reserve() for its run: its estimated tokens, and the budget its x-run-budget declares. */
export interface RunCall {
  tokens?: number;
  budget?: RunBudget;
}

/** What the gateway answers a score report with (POST /v1/runs/score). */
export interface ScoreOutcome {
  runId: string;
  /** continue: another round; ship: use the last result; stop: give up, a limit or the flat line ended it. */
  decision: "continue" | "ship" | "stop";
  /** How the run ended, when it has. */
  stop?: RunStop;
  /** The run had ended before this score came in, so the score was not counted. */
  already?: true;
  score: number;
  /** Scored rounds so far. */
  round: number;
  best?: number;
  /** Scored rounds in a row without a gain. */
  flat: number;
  spent: { calls: number; seconds: number; tokens: number; usd: number };
  limits: RunLimits;
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
  /**
   * The run made runMaxCalls calls. Waiting does not help: the run has to stop. For each run limit,
   * `declared` is set when the run's own x-run-budget set it, lower than the key's cap.
   */
  | { ok: false; cap: "runMaxCalls"; runId: string; limit: number; calls: number; declared?: true }
  /** The run's settled spend, plus what its calls in flight hold, plus this call, would pass runMaxUsd. */
  | { ok: false; cap: "runMaxUsd"; runId: string; limit: number; spentUsd: number; reservedUsd: number; requestedUsd: number; declared?: true }
  /** runMaxSeconds have passed since the run's first call. */
  | { ok: false; cap: "runMaxSeconds"; runId: string; limit: number; seconds: number; declared?: true }
  /** The run's booked tokens, plus what its calls in flight hold, plus this call's estimate, would pass runMaxTokens. */
  | { ok: false; cap: "runMaxTokens"; runId: string; limit: number; spentTokens: number; reservedTokens: number; requestedTokens: number; declared?: true }
  /** A score report ended the run (ship, budget, flat line): it stays ended. */
  | { ok: false; cap: "runStopped"; runId: string; stop: RunStop };

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
   * Holds `usd` for a call, or refuses it. In this order: the key's calls per minute; then, for a run,
   * whether a score report ended it, its calls, seconds, tokens and dollars; then the key's daily cap
   * and its monthly cap. `runId` counts only for a key with a run limit, or a run that declared a
   * budget (`call.budget`, from x-run-budget); a client that sends none is held to the other limits.
   */
  reserve(key: GatewayKey, usd: number, runId?: string, call: RunCall = {}): ReserveOutcome {
    return this.update((spend, now): ReserveOutcome => {
      const entry = account(spend, key.name, now);
      const recent = (entry.recent ?? []).filter((t) => t > now - MINUTE_MS);
      if (key.maxCallsPerMinute !== undefined && recent.length >= key.maxCallsPerMinute) {
        const oldest = recent[recent.length - key.maxCallsPerMinute] ?? now;
        return { ok: false, cap: "maxCallsPerMinute", limit: key.maxCallsPerMinute, retryAfterSeconds: Math.max(1, Math.ceil((oldest + MINUTE_MS - now) / 1000)) };
      }
      const known = runId !== undefined && entry.runs !== undefined && Object.prototype.hasOwnProperty.call(entry.runs, runId);
      const capsRun = runId !== undefined && (hasRunRules(key) || call.budget !== undefined || known);
      let run = known ? (entry.runs as Record<string, RunSpend>)[runId as string] : undefined;
      if (capsRun) {
        const at = new Date(now).toISOString();
        // A run that declares a budget is remembered from that call on, admitted or refused, with the
        // lowest budget it ever declared: a declaration on a refused call still holds the next call.
        if (!run && call.budget !== undefined) {
          entry.runs ??= {};
          run = { calls: 0, usd: 0, lastSeen: at, startedAt: at };
          entry.runs[runId as string] = run;
        }
        if (run) {
          // A refused call keeps its run in memory as well: a loop that keeps knocking stays stopped.
          run.lastSeen = at;
          const budget = lowerOf(run.budget, call.budget);
          if (budget) run.budget = budget;
        }
        if (run?.stopped) return { ok: false, cap: "runStopped", runId, stop: run.stopped };
        const limits = runLimits(key, run?.budget);
        const caps = runLimits(key);
        const declared = (field: RunBudgetField): { declared?: true } => ((limits[field] as number) < (caps[field] ?? Infinity) ? { declared: true } : {});
        const calls = run?.calls ?? 0;
        if (limits.calls !== undefined && calls >= limits.calls) return { ok: false, cap: "runMaxCalls", runId, limit: limits.calls, calls, ...declared("calls") };
        if (limits.seconds !== undefined && run?.startedAt !== undefined) {
          const seconds = Math.floor((now - Date.parse(run.startedAt)) / 1000);
          if (!(seconds < limits.seconds)) return { ok: false, cap: "runMaxSeconds", runId, limit: limits.seconds, seconds, ...declared("seconds") };
        }
        if (limits.tokens !== undefined) {
          const held = Object.values(entry.reservations).reduce((sum, r) => sum + (r.runId === runId ? (r.tokens ?? 0) : 0), 0);
          const spentTokens = run?.tokens ?? 0;
          const requestedTokens = call.tokens ?? 0;
          if (spentTokens + held + requestedTokens > limits.tokens) {
            return { ok: false, cap: "runMaxTokens", runId, limit: limits.tokens, spentTokens, reservedTokens: held, requestedTokens, ...declared("tokens") };
          }
        }
        if (limits.usd !== undefined) {
          const held = roundUsd(Object.values(entry.reservations).reduce((sum, r) => sum + (r.runId === runId ? r.usd : 0), 0));
          const spent = run?.usd ?? 0;
          if (roundUsd(spent + held + usd) > limits.usd) {
            return { ok: false, cap: "runMaxUsd", runId, limit: limits.usd, spentUsd: spent, reservedUsd: held, requestedUsd: usd, ...declared("usd") };
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
      entry.reservations[id] = {
        usd,
        expiresAt: new Date(now + this.reservationTtlMs).toISOString(),
        ...(capsRun ? { runId } : {}),
        ...(capsRun && call.tokens !== undefined ? { tokens: call.tokens } : {}),
      };
      if (key.maxCallsPerMinute !== undefined) entry.recent = [...recent, now];
      if (capsRun) {
        entry.runs ??= {};
        const at = new Date(now).toISOString();
        const next: RunSpend = run ?? { calls: 0, usd: 0, lastSeen: at };
        next.calls += 1;
        next.lastSeen = at;
        next.startedAt ??= at;
        entry.runs[runId as string] = next;
      }
      return { ok: true, id, usd };
    });
  }

  /**
   * Books the real cost of a finished call and drops its reservation, once per reservation id. A
   * second settle of the same id books nothing ("duplicate"). A settle whose reservation is gone, because
   * it expired before the call ended, books the cost (it was spent) and says "orphan" so it can be flagged.
   * `tokens` (input plus output) are booked to the call's run, for runMaxTokens.
   */
  settle(keyName: string, reservationId: string, usd: number, tokens?: number): SettleOutcome {
    return this.update((spend, now): SettleOutcome => {
      const entry = account(spend, keyName, now);
      entry.settled ??= {};
      if (Object.prototype.hasOwnProperty.call(entry.settled, reservationId)) return "duplicate";
      const reservation = Object.prototype.hasOwnProperty.call(entry.reservations, reservationId) ? entry.reservations[reservationId] : undefined;
      delete entry.reservations[reservationId];
      entry.dayUsd = roundUsd(entry.dayUsd + usd);
      entry.monthUsd = roundUsd(entry.monthUsd + usd);
      entry.settled[reservationId] = new Date(now + this.reservationTtlMs).toISOString();
      const runId = reservation?.runId;
      const run = runId !== undefined && entry.runs && Object.prototype.hasOwnProperty.call(entry.runs, runId) ? entry.runs[runId] : undefined;
      if (run) {
        run.usd = roundUsd(run.usd + usd);
        if (tokens !== undefined) run.tokens = (run.tokens ?? 0) + tokens;
      }
      return reservation ? "booked" : "orphan";
    });
  }

  /**
   * A loop reports the score of its latest round, and the run's exits decide, in this order: ship
   * (the score reaches runShipScore), budget (the run has used its scored rounds, or any limit the
   * gateway counts: calls, seconds, tokens, dollars), flat line (runFlatRounds rounds in a row without
   * a gain of more than runMinGain over the best score). A decision other than continue ends the run
   * for good. A run that has already ended keeps its first decision: the score is not counted.
   * undefined: the key has no such run. A run starts with its first call (for a key with run limits, or
   * one that declares a budget), so a report, which costs nothing, cannot fill the ledger with runs.
   */
  score(key: GatewayKey, runId: string, score: number, budget?: RunBudget): ScoreOutcome | undefined {
    return this.update((spend, now): ScoreOutcome | undefined => {
      const entry = account(spend, key.name, now);
      if (!entry.runs || !Object.prototype.hasOwnProperty.call(entry.runs, runId)) return undefined;
      const at = new Date(now).toISOString();
      const run = entry.runs[runId] as RunSpend;
      run.lastSeen = at;
      run.startedAt ??= at;
      const declared = lowerOf(run.budget, budget);
      if (declared) run.budget = declared;
      const limits = runLimits(key, run.budget);
      const seconds = Math.floor((now - Date.parse(run.startedAt)) / 1000);
      const result = (already: boolean): ScoreOutcome => ({
        runId,
        decision: run.stopped === undefined ? "continue" : run.stopped.exit === "ship" ? "ship" : "stop",
        ...(run.stopped ? { stop: run.stopped } : {}),
        ...(already ? { already: true as const } : {}),
        score,
        round: run.rounds ?? 0,
        ...(run.best !== undefined ? { best: run.best } : {}),
        flat: run.flat ?? 0,
        spent: { calls: run.calls, seconds, tokens: run.tokens ?? 0, usd: run.usd },
        limits,
      });
      if (run.stopped) return result(true);

      const round = (run.rounds ?? 0) + 1;
      run.rounds = round;
      if (run.best === undefined || score > run.best + limits.minGain) {
        run.best = score;
        run.flat = 0;
      } else run.flat = (run.flat ?? 0) + 1;

      const stop = (exit: RunExit, rule: string, why: string): void => {
        run.stopped = { exit, rule, why, at };
      };
      const ownBudget = (field: RunBudgetField): string => ((limits[field] as number) < (runLimits(key)[field] ?? Infinity) ? " (its own x-run-budget)" : "");
      if (limits.shipScore !== undefined && score >= limits.shipScore) {
        stop("ship", "runShipScore", `round ${round} scored ${score}, at or above the ship score ${limits.shipScore}`);
      } else if (limits.rounds !== undefined && round >= limits.rounds) {
        stop("budget", "runMaxRounds", `${round} scored rounds, the run's limit${ownBudget("rounds")}`);
      } else if (limits.calls !== undefined && run.calls >= limits.calls) {
        stop("budget", "runMaxCalls", `${run.calls} calls, the run's limit${ownBudget("calls")}`);
      } else if (limits.seconds !== undefined && seconds >= limits.seconds) {
        stop("budget", "runMaxSeconds", `${seconds} s since the run's first call, its limit is ${limits.seconds} s${ownBudget("seconds")}`);
      } else if (limits.tokens !== undefined && (run.tokens ?? 0) >= limits.tokens) {
        stop("budget", "runMaxTokens", `${run.tokens ?? 0} tokens booked, the run's limit is ${limits.tokens}${ownBudget("tokens")}`);
      } else if (limits.usd !== undefined && run.usd >= limits.usd) {
        stop("budget", "runMaxUsd", `$${formatUsd(run.usd)} booked, the run's limit is $${formatUsd(limits.usd)}${ownBudget("usd")}`);
      } else if (limits.flatRounds !== undefined && (run.flat ?? 0) >= limits.flatRounds) {
        const gain = limits.minGain > 0 ? ` of more than ${limits.minGain}` : "";
        stop("flat_line", "runFlatRounds", `${run.flat ?? 0} scored rounds in a row without a gain${gain} over the best score ${run.best}`);
      }
      return result(false);
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
