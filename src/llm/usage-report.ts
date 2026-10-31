// Reading the usage log back: what "agent-gate usage --by <field>" and "usage --verify" print.
//
// The usage log has one line per authenticated call (usage-log.ts). Grouping it by the x-agent-task
// header answers "which kind of work spends the money, and which one trips the leak guard"; by key,
// route, upstream, model, session or run, the same question for those.
//
// --verify adds up the log's dollars for today and this month, per key, and compares them with the
// ledger, which is what the caps are enforced from. The two are written separately (the ledger when a
// call is settled, the log line just after), so they should agree to the billionth of a dollar; a
// difference means a line was lost, a cost was booked twice, or a file was edited.

import * as fs from "node:fs";
import { roundUsd, type KeyUsage } from "./budget.js";

export const GROUP_FIELDS = ["task", "key", "route", "upstream", "model", "session", "runId"] as const;
export type GroupField = (typeof GROUP_FIELDS)[number];

/** What a group's lines add up to. */
export interface UsageGroup {
  /** The field's value, or "(none)" for lines without it (a call with no x-agent-task header, say). */
  group: string;
  requests: number;
  /** Calls answered with a 2xx. */
  ok: number;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  /** Calls the leak guard refused, on the request or on the answer. */
  leakBlocked: number;
  /** Calls in which the leak guard redacted something, in the request or the answer. */
  leakRedacted: number;
}

export interface UsageFile {
  lines: Array<Record<string, unknown>>;
  /** Line numbers of lines that are not a JSON object. */
  unreadable: number[];
}

export function readUsageLog(file: string): UsageFile {
  const content = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  const lines: Array<Record<string, unknown>> = [];
  const unreadable: number[] = [];
  content.split("\n").forEach((text, i) => {
    if (text.trim() === "") return;
    try {
      const value: unknown = JSON.parse(text);
      if (typeof value === "object" && value !== null && !Array.isArray(value)) lines.push(value as Record<string, unknown>);
      else unreadable.push(i + 1);
    } catch {
      unreadable.push(i + 1);
    }
  });
  return { lines, unreadable };
}

/** Sums the lines per value of `by`, most expensive group first. */
export function groupUsage(lines: ReadonlyArray<Record<string, unknown>>, by: GroupField): UsageGroup[] {
  const groups = new Map<string, UsageGroup>();
  const number = (value: unknown): number => (typeof value === "number" && Number.isFinite(value) ? value : 0);
  for (const line of lines) {
    const value = line[by];
    const name = typeof value === "string" && value !== "" ? value : "(none)";
    let g = groups.get(name);
    if (!g) groups.set(name, (g = { group: name, requests: 0, ok: 0, inputTokens: 0, outputTokens: 0, costUsd: 0, leakBlocked: 0, leakRedacted: 0 }));
    g.requests++;
    const status = number(line.status);
    if (status >= 200 && status < 300) g.ok++;
    g.inputTokens += number(line.inputTokens);
    g.outputTokens += number(line.outputTokens);
    g.costUsd = roundUsd(g.costUsd + number(line.costUsd));
    if (line.error === "secret_detected" || line.error === "response_blocked") g.leakBlocked++;
    if ((Array.isArray(line.redacted) && line.redacted.length > 0) || (Array.isArray(line.responseRedacted) && line.responseRedacted.length > 0)) g.leakRedacted++;
  }
  return [...groups.values()].sort((a, b) => b.costUsd - a.costUsd || a.group.localeCompare(b.group));
}

export interface VerifyRow {
  key: string;
  day: string;
  ledgerDayUsd: number;
  logDayUsd: number;
  month: string;
  ledgerMonthUsd: number;
  logMonthUsd: number;
  /** Both pairs agree. */
  ok: boolean;
}

/** Each configured key's spend today and this month: in the ledger (`ledger`), and summed from the usage log. */
export function verifyUsage(lines: ReadonlyArray<Record<string, unknown>>, ledger: readonly KeyUsage[]): VerifyRow[] {
  return ledger.map((row) => {
    let logDayUsd = 0;
    let logMonthUsd = 0;
    for (const line of lines) {
      if (line.key !== row.key || typeof line.ts !== "string" || typeof line.costUsd !== "number") continue;
      if (line.ts.startsWith(row.month)) logMonthUsd = roundUsd(logMonthUsd + line.costUsd);
      if (line.ts.startsWith(row.day)) logDayUsd = roundUsd(logDayUsd + line.costUsd);
    }
    const same = (a: number, b: number) => Math.abs(a - b) < 1e-9;
    return {
      key: row.key,
      day: row.day,
      ledgerDayUsd: row.dayUsd,
      logDayUsd,
      month: row.month,
      ledgerMonthUsd: row.monthUsd,
      logMonthUsd,
      ok: same(row.dayUsd, logDayUsd) && same(row.monthUsd, logMonthUsd),
    };
  });
}
