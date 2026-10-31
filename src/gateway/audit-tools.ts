// Reading the audit log back: what "agent-gate audit ..." prints.
//
//   auditStats()  per tool: calls, what the policy did with them, errors, and how long forwarded
//                 calls took (p50, p95, max) from their call-result lines
//
// These functions only read. A line that is not JSON is counted and skipped; the log is
// append-only, so a damaged line is evidence to keep, not something to repair here.

import * as fs from "node:fs";

/** One line of audit.jsonl, parsed, with its 1-based line number. */
export interface AuditLine {
  line: number;
  value: Record<string, unknown>;
}

export interface AuditFile {
  lines: AuditLine[];
  /** Line numbers of lines that are not a JSON object. */
  unreadable: number[];
}

export function readAudit(file: string): AuditFile {
  const content = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  const lines: AuditLine[] = [];
  const unreadable: number[] = [];
  content.split("\n").forEach((text, i) => {
    if (text.trim() === "") return;
    try {
      const value: unknown = JSON.parse(text);
      if (typeof value === "object" && value !== null && !Array.isArray(value)) lines.push({ line: i + 1, value: value as Record<string, unknown> });
      else unreadable.push(i + 1);
    } catch {
      unreadable.push(i + 1);
    }
  });
  return { lines, unreadable };
}

/** A call line (written before forwarding): it has no "event" field. */
export function isCallLine(value: Record<string, unknown>): boolean {
  return value.event === undefined;
}

export interface ToolStats {
  /** "<server>__<tool>", as the agent sees it. */
  tool: string;
  /** Call lines: every call the agent made to the tool. */
  calls: number;
  forwarded: number;
  /** Held for a human (decision ask, not forwarded). */
  asked: number;
  blocked: number;
  /** Forwarded calls that came back (call-result lines). */
  results: number;
  /** Results with isError, and calls that failed without a result. */
  errors: number;
  /** Nearest-rank percentiles of durationMs over the results; null before the first result. */
  p50Ms: number | null;
  p95Ms: number | null;
  maxMs: number | null;
}

export function auditStats(lines: readonly AuditLine[]): ToolStats[] {
  const tools = new Map<string, { calls: number; forwarded: number; asked: number; blocked: number; errors: number; durations: number[] }>();
  const of = (value: Record<string, unknown>) => {
    const name = `${String(value.server)}__${String(value.tool)}`;
    let s = tools.get(name);
    if (!s) tools.set(name, (s = { calls: 0, forwarded: 0, asked: 0, blocked: 0, errors: 0, durations: [] }));
    return s;
  };
  for (const { value } of lines) {
    if (typeof value.server !== "string" || typeof value.tool !== "string") continue;
    if (isCallLine(value)) {
      const s = of(value);
      s.calls++;
      if (value.forwarded === true) s.forwarded++;
      else if (value.decision === "ask") s.asked++;
      else if (value.decision === "block") s.blocked++;
    } else if (value.event === "call-result") {
      const s = of(value);
      if (typeof value.durationMs === "number" && Number.isFinite(value.durationMs)) s.durations.push(value.durationMs);
      if (value.isError === true) s.errors++;
    }
  }
  return [...tools]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([tool, s]) => {
      const sorted = [...s.durations].sort((a, b) => a - b);
      return {
        tool,
        calls: s.calls,
        forwarded: s.forwarded,
        asked: s.asked,
        blocked: s.blocked,
        results: sorted.length,
        errors: s.errors,
        p50Ms: percentile(sorted, 0.5),
        p95Ms: percentile(sorted, 0.95),
        maxMs: sorted.length === 0 ? null : (sorted[sorted.length - 1] ?? null),
      };
    });
}

/** Nearest rank: the smallest value with at least p of the values at or below it. */
export function percentile(sorted: readonly number[], p: number): number | null {
  if (sorted.length === 0) return null;
  return sorted[Math.min(sorted.length, Math.max(1, Math.ceil(p * sorted.length))) - 1] ?? null;
}
