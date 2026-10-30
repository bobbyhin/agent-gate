// The agent-gate command line: run the MCP gateway and let a human answer approval requests; run
// the LLM gateway and show what each gateway key has spent.

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { parseArgs } from "node:util";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { formatUsd } from "../llm/budget.js";
import { loadLeakPolicy, loadLlmConfig } from "../llm/config.js";
import { openLedger, startLlmGateway } from "../llm/server.js";
import { ApprovalError, ApprovalStore, canonicalJson, cleanNote, isLive, type Approval } from "./approvals.js";
import { AuditLog, type ApprovalEvent } from "./audit.js";
import { loadConfig, loadPolicy } from "./config.js";
import { createGateway, SEPARATOR } from "./server.js";
import { ConfigError } from "./validate.js";

const USAGE = `Usage:
  agent-gate serve [--config <file>]                  run the MCP gateway on stdin/stdout
  agent-gate approvals list [--all] [--json] [--config <file>]
  agent-gate approvals show <id> [--config <file>]    print one request in full
  agent-gate approvals approve <id> [--note <text>] [--config <file>]
  agent-gate approvals deny <id> [--reason <text>] [--config <file>]
  agent-gate approvals stats [--json] [--config <file>]   decisions per rule: counts, wait, deny rate
  agent-gate llm serve [--config <file>]              run the LLM gateway (HTTP)
  agent-gate usage [--json] [--config <file>]         LLM spend per gateway key: today, this month, caps

"list" shows the requests that are waiting; --all also shows decided, used and expired ones.
A deny --reason is shown to the agent the next time it makes the call; an approve --note is kept
with the approval. Both are stored, with the OS user who ran the command, in approvals.json and
in the audit log.
The MCP gateway's config file is --config, else $AGENT_GATE_CONFIG, else ./gateway.config.json.
The LLM gateway's ("llm serve", "usage") is --config, else $AGENT_GATE_LLM_CONFIG, else
./llm-gateway.config.json.
`;

export interface Io {
  out: (text: string) => void;
  err: (text: string) => void;
}

const processIo: Io = {
  out: (text) => process.stdout.write(text),
  err: (text) => process.stderr.write(text),
};

/** Runs one command and returns the exit code: 0 done, 1 failed, 2 bad usage. */
export async function main(argv: string[], io: Io = processIo): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        config: { type: "string" },
        all: { type: "boolean", default: false },
        json: { type: "boolean", default: false },
        reason: { type: "string" },
        note: { type: "string" },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (err) {
    io.err(`agent-gate: ${(err as Error).message}\n\n${USAGE}`);
    return 2;
  }
  const { values, positionals } = parsed;
  if (values.help) {
    io.out(USAGE);
    return 0;
  }
  const configFile = values.config ?? process.env.AGENT_GATE_CONFIG ?? "gateway.config.json";
  const llmConfigFile = values.config ?? process.env.AGENT_GATE_LLM_CONFIG ?? "llm-gateway.config.json";
  const [command, action, id, ...extra] = positionals;
  const isServe = command === "serve" && action === undefined;
  const isApprovals =
    command === "approvals" &&
    extra.length === 0 &&
    (action === "list" || action === "stats" ? id === undefined : ["show", "approve", "deny"].includes(action ?? "") && id !== undefined) &&
    (values.reason === undefined || action === "deny") &&
    (values.note === undefined || action === "approve");
  const isLlmServe = command === "llm" && action === "serve" && id === undefined;
  const isUsage = command === "usage" && action === undefined;
  if (!isServe && !isApprovals && !isLlmServe && !isUsage) {
    io.err(USAGE);
    return 2;
  }

  try {
    if (isServe) return await serve(configFile);
    if (isLlmServe) return await serveLlm(llmConfigFile);
    if (isUsage) return usage(llmConfigFile, values.json, io);
    const config = loadConfig(configFile);
    const store = new ApprovalStore(config.stateDir, config.approvalTtlMs);
    const audit = new AuditLog(path.join(config.stateDir, "audit.jsonl"));
    if (action === "list") return list(store, values.all, values.json, io);
    if (action === "stats") return stats(store, audit.file, values.json, io);
    if (action === "show") {
      io.out(`${JSON.stringify(store.get(id as string), null, 2)}\n`);
    } else if (action === "approve") {
      const approval = decide(store, audit, id as string, "approved", values.note);
      io.out(`approved ${describeCall(approval)}\nThe agent can now make this exact call once, until ${approval.expiresAt}.\n`);
    } else {
      const approval = decide(store, audit, id as string, "denied", values.reason);
      const reason = approval.decisionNote ? `It is also shown your reason: ${JSON.stringify(approval.decisionNote)}\n` : "";
      io.out(`denied ${describeCall(approval)}\nIf the agent makes this call again, it is told that a human said no.\n${reason}`);
    }
    return 0;
  } catch (err) {
    if (err instanceof ApprovalError || err instanceof ConfigError) {
      io.err(`agent-gate: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
}

async function serve(configFile: string): Promise<number> {
  const config = loadConfig(configFile);
  const gateway = await createGateway(config, loadPolicy(config.policyFile));
  await gateway.server.connect(new StdioServerTransport());
  // The SDK's stdio transport does not notice when the client goes away, so watch stdin here.
  await new Promise<void>((resolve) => {
    process.stdin.once("end", resolve);
    process.stdin.once("close", resolve);
    process.once("SIGINT", resolve);
    process.once("SIGTERM", resolve);
  });
  await gateway.close();
  return 0;
}

async function serveLlm(configFile: string): Promise<number> {
  const config = loadLlmConfig(configFile);
  const gateway = await startLlmGateway(config, loadLeakPolicy(config.policyFile));
  await new Promise<void>((resolve) => {
    process.once("SIGINT", resolve);
    process.once("SIGTERM", resolve);
  });
  await gateway.close();
  return 0;
}

function usage(configFile: string, json: boolean, io: Io): number {
  const config = loadLlmConfig(configFile);
  const rows = openLedger(config).usage(config.keys);
  if (json) {
    io.out(`${JSON.stringify(rows, null, 2)}\n`);
    return 0;
  }
  const first = rows[0];
  const table = [
    ["key", `today (${first?.day ?? ""} UTC)`, `this month (${first?.month ?? ""})`, "in flight"],
    ...rows.map((r) => [
      r.key,
      `$${formatUsd(r.dayUsd)} of $${formatUsd(r.dailyUsd)}`,
      `$${formatUsd(r.monthUsd)} of $${formatUsd(r.monthlyUsd)}`,
      r.inFlight === 0 ? "0" : `${r.inFlight} ($${formatUsd(r.reservedUsd)} reserved)`,
    ]),
  ];
  const widths = (table[0] ?? []).map((_, column) => Math.max(...table.map((row) => (row[column] ?? "").length)));
  for (const row of table) io.out(`${row.map((cell, column) => cell.padEnd(widths[column] ?? 0)).join("  ").trimEnd()}\n`);
  return 0;
}

function list(store: ApprovalStore, all: boolean, json: boolean, io: Io): number {
  const now = Date.now();
  const shown = store.list().filter((a) => all || (a.status === "pending" && isLive(a, now)));
  if (json) {
    io.out(`${JSON.stringify(shown.map((a) => ({ ...a, expired: a.status !== "used" && !isLive(a, now) })), null, 2)}\n`);
    return 0;
  }
  if (shown.length === 0) {
    io.out(all ? "No approval requests.\n" : "No requests are waiting for a decision.\n");
    return 0;
  }
  for (const a of shown) {
    const state = a.status !== "used" && !isLive(a, now) ? `${a.status}, expired` : a.status;
    io.out(
      [
        `${a.id}  ${state}  ${a.server}${SEPARATOR}${a.tool}`,
        `  why:     ${a.why} (rule ${a.rule})`,
        `  args:    ${preview(canonicalJson(a.args))}`,
        `  created: ${a.createdAt}  expires: ${a.expiresAt}`,
        ...(a.decidedAt ? [`  decided: ${a.decidedAt}${a.decidedBy ? ` by ${a.decidedBy}` : ""}`] : []),
        ...(a.decisionNote ? [`  note:    ${a.decisionNote}`] : []),
        "",
      ].join("\n"),
    );
  }
  return 0;
}

/** The OS user running the CLI, recorded as who decided. */
function currentUser(): string | undefined {
  try {
    return cleanNote(os.userInfo().username, 64);
  } catch {
    return undefined;
  }
}

/** Records a human's decision in approvals.json, then as an approval-decided line in the audit log. */
function decide(store: ApprovalStore, audit: AuditLog, id: string, decision: "approved" | "denied", note: string | undefined): Approval {
  const by = currentUser();
  let approval: Approval;
  try {
    approval = decision === "approved" ? store.approve(id, { by, note }) : store.deny(id, { by, note });
  } catch (err) {
    // A request found expired is worth a line too: it shows how long requests wait unanswered.
    if (err instanceof ApprovalError && err.expired) {
      try {
        writeEvent(audit, err.expired, "expired", by);
      } catch {
        // the expiry error below is what the human needs to see
      }
    }
    throw err;
  }
  try {
    writeEvent(audit, approval, decision, approval.decidedBy);
  } catch (err) {
    throw new ApprovalError(`${id} is ${decision}, but the audit log could not be written: ${(err as Error).message}`);
  }
  return approval;
}

function writeEvent(audit: AuditLog, a: Approval, decision: ApprovalEvent["decision"], by: string | undefined): void {
  const end = Date.parse(decision === "expired" ? a.expiresAt : (a.decidedAt ?? ""));
  audit.writeEvent({
    approvalId: a.id,
    server: a.server,
    tool: a.tool,
    rule: a.rule,
    argsHash: a.argsHash,
    decision,
    waitMs: Math.max(0, end - Date.parse(a.createdAt)) || 0,
    ...(by ? { decidedBy: by } : {}),
    ...(decision !== "expired" && a.decisionNote ? { note: a.decisionNote } : {}),
  });
}

export interface RuleStats {
  rule: string;
  approved: number;
  denied: number;
  /** Found expired by the CLI, or still in approvals.json as an expired request nobody answered. */
  expired: number;
  /** Pending and not expired yet. */
  waiting: number;
  /** Median time from request to approve or deny, in milliseconds; null before the first decision. */
  medianWaitMs: number | null;
  /** denied / (approved + denied); null before the first decision. */
  denyRate: number | null;
}

/**
 * Decisions per rule, from the approval-decided lines in the audit log plus approvals.json.
 * ponytail: a request that expired with nobody answering leaves no audit line, and approvals.json
 * drops it a week after it expires, so older unanswered requests are not counted as expired.
 */
function stats(store: ApprovalStore, auditFile: string, json: boolean, io: Io): number {
  const now = Date.now();
  const rules = new Map<string, { approved: number; denied: number; expired: Set<string>; waiting: number; waits: number[] }>();
  const of = (rule: string) => {
    let s = rules.get(rule);
    if (!s) rules.set(rule, (s = { approved: 0, denied: 0, expired: new Set(), waiting: 0, waits: [] }));
    return s;
  };
  let unreadable = 0;
  const content = fs.existsSync(auditFile) ? fs.readFileSync(auditFile, "utf8") : "";
  for (const line of content.split("\n")) {
    if (line.trim() === "") continue;
    let entry: Partial<ApprovalEvent>;
    try {
      entry = JSON.parse(line) as Partial<ApprovalEvent>;
    } catch {
      unreadable++;
      continue;
    }
    if (entry.event !== "approval-decided" || typeof entry.rule !== "string") continue;
    const s = of(entry.rule);
    if (entry.decision === "expired") s.expired.add(String(entry.approvalId));
    else if (entry.decision === "approved" || entry.decision === "denied") {
      s[entry.decision]++;
      if (typeof entry.waitMs === "number") s.waits.push(entry.waitMs);
    }
  }
  for (const a of store.list()) {
    if (a.status !== "pending") continue;
    if (isLive(a, now)) of(a.rule).waiting++;
    else of(a.rule).expired.add(a.id);
  }
  const rows: RuleStats[] = [...rules].sort(([x], [y]) => x.localeCompare(y)).map(([rule, s]) => ({
    rule,
    approved: s.approved,
    denied: s.denied,
    expired: s.expired.size,
    waiting: s.waiting,
    medianWaitMs: median(s.waits),
    denyRate: s.approved + s.denied === 0 ? null : s.denied / (s.approved + s.denied),
  }));
  if (json) {
    io.out(`${JSON.stringify(rows, null, 2)}\n`);
    return 0;
  }
  if (rows.length === 0) io.out("No approval requests or decisions recorded yet.\n");
  else {
    const table = [
      ["rule", "approved", "denied", "expired", "waiting", "deny rate", "median wait"],
      ...rows.map((r) => [r.rule, `${r.approved}`, `${r.denied}`, `${r.expired}`, `${r.waiting}`, r.denyRate === null ? "-" : `${Math.round(r.denyRate * 100)}%`, r.medianWaitMs === null ? "-" : duration(r.medianWaitMs)]),
    ];
    const widths = (table[0] ?? []).map((_, column) => Math.max(...table.map((row) => (row[column] ?? "").length)));
    for (const row of table) io.out(`${row.map((cell, column) => cell.padEnd(widths[column] ?? 0)).join("  ").trimEnd()}\n`);
  }
  if (unreadable > 0) io.err(`agent-gate: ${unreadable} line(s) of ${auditFile} are not JSON and were skipped\n`);
  return 0;
}

function median(values: number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? (sorted[mid] ?? 0) : Math.round(((sorted[mid - 1] ?? 0) + (sorted[mid] ?? 0)) / 2);
}

/** 4m 12s · 1h 05m · 2d 03h */
export function duration(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${String(Math.floor((s % 3600) / 60)).padStart(2, "0")}m`;
  return `${Math.floor(s / 86400)}d ${String(Math.floor((s % 86400) / 3600)).padStart(2, "0")}h`;
}

function describeCall(a: Approval): string {
  return `${a.id}: ${a.server}${SEPARATOR}${a.tool} ${preview(canonicalJson(a.args))}`;
}

const PREVIEW_CHARS = 300;
function preview(json: string): string {
  return json.length <= PREVIEW_CHARS ? json : `${json.slice(0, PREVIEW_CHARS)}... (${json.length} characters; "approvals show <id>" prints all of it)`;
}
