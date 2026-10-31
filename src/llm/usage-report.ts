// Reading the usage log back: what "agent-gate usage --by <field>" prints.
//
// The usage log has one line per authenticated call (usage-log.ts). Grouping it by the x-agent-task
// header answers "which kind of work spends the money, and which one trips the leak guard"; by key,
// route, upstream, model, session or run, the same question for those.

import * as fs from "node:fs";
import { roundUsd } from "./budget.js";

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
  /** Calls the leak guard refused. */
  leakBlocked: number;
  /** Calls in which the leak guard redacted something. */
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
    if (line.error === "secret_detected") g.leakBlocked++;
    if (Array.isArray(line.redacted) && line.redacted.length > 0) g.leakRedacted++;
  }
  return [...groups.values()].sort((a, b) => b.costUsd - a.costUsd || a.group.localeCompare(b.group));
}
