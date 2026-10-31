// Reading the audit log back: what "agent-gate audit ..." prints.
//
//   auditStats()       per tool: calls, what the policy did with them, errors, and how long forwarded
//                      calls took (p50, p95, max) from their call-result lines
//   verifyAudit()      checks the log against the gateway's own rules, with no expected answers: a
//                      blocked call never ran; a call that ran after an ask was approved first, by a
//                      human, for exactly these arguments, and used its approval once
//   scoreTrajectory()  compares the calls that ran with an expected list of calls: exact, in order,
//                      in any order, with precision and recall
//
// These functions only read. A line that is not JSON is counted and skipped; the log is
// append-only, so a damaged line is evidence to keep, not something to repair here.

import * as fs from "node:fs";
import { hashArguments, type Approval } from "./approvals.js";
import { array, ConfigError, fail, object, text } from "./validate.js";

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

// ── verify ──────────────────────────────────────────────────────────────────────────────────

export interface Problem {
  line: number;
  why: string;
}

/**
 * Checks every line against what the gateway and the CLI are meant to write. `approvals` is the
 * current approvals.json, when there is one: a record still in it must agree with the log. The log
 * itself is the lasting record (approvals.json forgets requests a week after they expire).
 */
export function verifyAudit(file: AuditFile, approvals: readonly Approval[] = []): Problem[] {
  const problems: Problem[] = file.unreadable.map((line) => ({ line, why: "not a JSON object" }));
  const asked = new Map<string, number>(); // approval id -> line of its first held request
  const approved = new Map<string, { line: number; value: Record<string, unknown> }>();
  const used = new Map<string, number>();
  const grants = new Map<string, { line: number; value: Record<string, unknown>; revokedAt?: number; uses: number }>();
  const forwardedCalls = new Map<string, number>(); // "connId seq" -> line
  const results = new Set<string>();
  const records = new Map(approvals.map((a) => [a.id, a]));

  for (const { line, value: v } of file.lines) {
    const event = v.event;
    if (event === undefined) {
      const id = typeof v.approvalId === "string" ? v.approvalId : undefined;
      const call = `${String(v.server)}__${String(v.tool)}`;
      if (v.forwarded === true && typeof v.connId === "string") forwardedCalls.set(`${v.connId} ${String(v.seq)}`, line);
      if (v.decision === "block" && v.forwarded !== false) problems.push({ line, why: `a blocked call to ${call} was forwarded (rule ${String(v.rule)})` });
      if ((v.decision === "allow" || v.decision === "warn") && v.forwarded !== true) problems.push({ line, why: `an allowed call to ${call} was not forwarded` });
      if (v.decision !== "ask") continue;
      if (v.forwarded !== true) {
        if (id && !asked.has(id)) asked.set(id, line);
        continue;
      }
      // A call that ran after an ask: an approval let it through.
      if (!id) {
        problems.push({ line, why: `a call to ${call} that needed a human was forwarded without an approval id` });
      } else if (id.startsWith("sa-")) {
        const grant = grants.get(id);
        if (!grant) problems.push({ line, why: `forwarded under ${id}, which no standing-approval line granted before it` });
        else {
          grant.uses++;
          if (grant.value.server !== v.server || grant.value.tool !== v.tool) problems.push({ line, why: `${id} was granted for ${String(grant.value.server)}__${String(grant.value.tool)}, not ${call}` });
          if (grant.revokedAt !== undefined) problems.push({ line, why: `${id} was used after it was revoked (line ${grant.revokedAt})` });
          if (typeof grant.value.maxUses === "number" && grant.uses > grant.value.maxUses) problems.push({ line, why: `${id} was used ${grant.uses} times; it allows ${grant.value.maxUses}` });
          if (typeof v.ts === "string" && typeof grant.value.expiresAt === "string" && v.ts >= grant.value.expiresAt) problems.push({ line, why: `${id} was used after it expired (${grant.value.expiresAt})` });
        }
      } else {
        const yes = approved.get(id);
        if (!yes) problems.push({ line, why: `forwarded under ${id}, which no approval-decided line approved before it` });
        else {
          if (yes.value.server !== v.server || yes.value.tool !== v.tool || yes.value.argsHash !== v.argsHash) {
            problems.push({ line, why: `forwarded under ${id}, which was approved for other arguments or another tool (line ${yes.line})` });
          }
          if (typeof v.ts === "string" && typeof yes.value.ts === "string" && v.ts < yes.value.ts) problems.push({ line, why: `forwarded before ${id} was approved (line ${yes.line})` });
        }
        const before = used.get(id);
        if (before !== undefined) problems.push({ line, why: `${id} let a second call through; it was used on line ${before}` });
        else used.set(id, line);
        const record = records.get(id);
        if (record && record.status !== "used") problems.push({ line, why: `forwarded under ${id}, but approvals.json says it is ${record.status}` });
        if (record && record.argsHash !== v.argsHash) problems.push({ line, why: `forwarded under ${id}, but approvals.json has other arguments for it` });
      }
    } else if (event === "approval-decided" && typeof v.approvalId === "string") {
      if (v.decision === "approved") {
        if (!asked.has(v.approvalId)) problems.push({ line, why: `${v.approvalId} was approved before any call asked for it` });
        approved.set(v.approvalId, { line, value: v });
      }
    } else if (event === "standing-approval" && typeof v.id === "string") {
      if (v.decision === "granted") grants.set(v.id, { line, value: v, uses: 0 });
      else if (v.decision === "revoked") {
        const grant = grants.get(v.id);
        if (grant) grant.revokedAt = line;
      }
    } else if (event === "call-result") {
      const key = `${String(v.connId)} ${String(v.seq)}`;
      if (!forwardedCalls.has(key)) problems.push({ line, why: `a call-result line for ${key}, with no forwarded call before it` });
      else if (results.has(key)) problems.push({ line, why: `a second call-result line for ${key}` });
      results.add(key);
    }
  }
  return problems.sort((a, b) => a.line - b.line);
}

// ── trajectory ──────────────────────────────────────────────────────────────────────────────

/** One expected call: the tool as the agent sees it, and optionally its arguments (or their hash). */
export interface ExpectedCall {
  tool: string;
  argsHash?: string;
}

export interface TrajectoryScore {
  /** The calls compared: "<server>__<tool>" and the hash of the agent's arguments. */
  actual: Array<{ line: number; tool: string; argsHash: string }>;
  expected: ExpectedCall[];
  exact: boolean;
  inOrder: boolean;
  anyOrder: boolean;
  /** Expected calls that happened: the largest one-to-one match between the two lists. */
  matched: number;
  /** matched / actual (1 when nothing ran); matched / expected (1 when nothing was expected). */
  precision: number;
  recall: number;
}

/** Reads { "calls": [ { "tool": "<server>__<tool>", "args"?: {...} | "argsHash"?: "sha256:..." } ] }. */
export function parseExpected(json: unknown): ExpectedCall[] {
  const spec = object(json, "expected");
  const calls = array(spec.calls, "expected.calls").map((raw, i) => {
    const at = `expected.calls[${i}]`;
    const call = object(raw, at);
    for (const key of Object.keys(call)) if (!["tool", "args", "argsHash"].includes(key)) fail(`${at} has an unknown field "${key}" (allowed: tool, args, argsHash)`);
    const tool = text(call.tool, `${at}.tool`);
    if (!tool.includes("__")) fail(`${at}.tool must be <server>__<tool>, as the agent sees it`);
    if (call.args !== undefined && call.argsHash !== undefined) fail(`${at} has both args and argsHash; give one`);
    if (call.args !== undefined) return { tool, argsHash: hashArguments(object(call.args, `${at}.args`)) };
    if (call.argsHash !== undefined) return { tool, argsHash: text(call.argsHash, `${at}.argsHash`) };
    return { tool };
  });
  return calls;
}

export function loadExpected(file: string): ExpectedCall[] {
  let json: unknown;
  try {
    json = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (err) {
    throw new ConfigError(`cannot read the expected trajectory ${file}: ${(err as Error).message}`);
  }
  return parseExpected(json);
}

/**
 * The calls of the log, in order: by default those that ran (forwarded), with `all` also the refused
 * ones; only one connection or one run when asked. A call's arguments are the agent's own
 * (originalArgsHash when a rewrite rule edited them).
 */
export function trajectoryOf(lines: readonly AuditLine[], options: { all?: boolean; conn?: string; run?: string } = {}): TrajectoryScore["actual"] {
  return lines
    .filter(({ value: v }) => isCallLine(v) && (options.all || v.forwarded === true))
    .filter(({ value: v }) => (options.conn === undefined || v.connId === options.conn) && (options.run === undefined || v.runId === options.run))
    .map(({ line, value: v }) => ({ line, tool: `${String(v.server)}__${String(v.tool)}`, argsHash: String(v.originalArgsHash ?? v.argsHash) }));
}

export function scoreTrajectory(actual: TrajectoryScore["actual"], expected: readonly ExpectedCall[]): TrajectoryScore {
  const fits = (e: ExpectedCall, a: { tool: string; argsHash: string }) => e.tool === a.tool && (e.argsHash === undefined || e.argsHash === a.argsHash);
  const exact = actual.length === expected.length && expected.every((e, i) => fits(e, actual[i] as { tool: string; argsHash: string }));
  // In order: the expected calls are a subsequence of the actual ones. Taking the earliest fit is enough.
  let next = 0;
  for (const a of actual) if (next < expected.length && fits(expected[next] as ExpectedCall, a)) next++;
  const inOrder = next === expected.length;
  // Any order: a one-to-one match. Calls with arguments first, then the ones that take any arguments;
  // that order finds the largest match, because a call without arguments fits whatever is left.
  const free = actual.map(() => true);
  let matched = 0;
  for (const e of [...expected].sort((x, y) => Number(x.argsHash === undefined) - Number(y.argsHash === undefined))) {
    const at = actual.findIndex((a, i) => free[i] && fits(e, a));
    if (at >= 0) {
      free[at] = false;
      matched++;
    }
  }
  return {
    actual: [...actual],
    expected: [...expected],
    exact,
    inOrder,
    anyOrder: matched === expected.length,
    matched,
    precision: actual.length === 0 ? 1 : matched / actual.length,
    recall: expected.length === 0 ? 1 : matched / expected.length,
  };
}
