// The agent-gate command line: run the MCP gateway and let a human answer approval requests; run
// the LLM gateway and show what each gateway key has spent.

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as readline from "node:readline";
import { parseArgs } from "node:util";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { formatUsd } from "../llm/budget.js";
import { loadLeakPolicy, loadLlmConfig } from "../llm/config.js";
import { openLedger, startLlmGateway } from "../llm/server.js";
import { GROUP_FIELDS, groupUsage, readUsageLog, verifyUsage, type GroupField } from "../llm/usage-report.js";
import { ApprovalError, ApprovalStore, canonicalJson, cleanNote, isLive, type Approval, type Confirmation, type StandingApproval } from "./approvals.js";
import { AuditLog, type ApprovalEvent } from "./audit.js";
import { auditStats, loadExpected, readAudit, scoreTrajectory, trajectoryOf, verifyAudit } from "./audit-tools.js";
import { loadConfig, loadPolicy, type GatewayConfig } from "./config.js";
import { bindFiles } from "./files.js";
import { startHttpGateway } from "./http-server.js";
import { createGateway, SEPARATOR } from "./server.js";
import { downstreamCandidates, openApiCandidates, suggest, type Candidate } from "./suggest.js";
import { ToolPins } from "./tool-pins.js";
import { ConfigError } from "./validate.js";

const USAGE = `Usage:
  agent-gate serve [--profile <name>] [--config <file>]
                                                      run the MCP gateway on stdin/stdout; with a profile
                                                      from the config, the agent sees only its tools
  agent-gate serve --http [--config <file>]           serve the agents in the config's "http" section over
                                                      Streamable HTTP at /mcp, each with its own key
  agent-gate approvals list [--all] [--json] [--config <file>]
  agent-gate approvals show <id> [--config <file>]    print one request in full
  agent-gate approvals approve <id> [--note <text>] [--yes] [--config <file>]
  agent-gate approvals deny <id> [--reason <text>] [--config <file>]
  agent-gate approvals stats [--json] [--config <file>]   decisions per rule: counts, wait, deny rate
  agent-gate approvals grant <server>__<tool> --uses <n> --hours <h> [--arg <name>=<glob>]... [--agent <name>] [--note <text>] [--config <file>]
  agent-gate approvals grants [--all] [--json] [--config <file>]   standing approvals
  agent-gate llm serve [--config <file>]              run the LLM gateway (HTTP)
  agent-gate usage [--json] [--config <file>]         LLM spend per gateway key: today, this month, caps
  agent-gate usage --by <field> [--json] [--config <file>]
                                                      the usage log summed by task, key, route, upstream,
                                                      model, session or runId
  agent-gate usage --verify [--json] [--config <file>] the usage log's dollars against the ledger, per
                                                      key, today and this month (exit 1 if they differ)
  agent-gate audit stats [--json] [--config <file>]   per tool: calls, decisions, errors, p50/p95 time
  agent-gate audit verify [--json] [--config <file>]  check the log: nothing blocked ran, every approval
                                                      came first, matched and was used once (exit 1 if not)
  agent-gate audit trajectory --expect <file> [--mode exact|in-order|any-order] [--all] [--conn <id>]
                             [--run <id>] [--json] [--config <file>]
                                                      score the calls that ran against an expected list
  agent-gate tools list [--json] [--config <file>]    pinned tool definitions, and the changed ones withheld
  agent-gate tools show <server>__<tool> [--config <file>]    the pinned and the changed definition
  agent-gate tools accept <server>__<tool> [--config <file>]  pin the changed definition: the tool is listed again
  agent-gate policy suggest [--openapi <spec.json>] [--json] [--config <file>]  each tool's decision, and a draft policy

"list" shows the requests that are waiting; --all also shows decided, used and expired ones.
"approve" reads the call back to you and asks you to type the last 4 characters of its id;
--yes skips that, for scripts.
"grant" makes a standing approval: up to <n> calls to one tool within <h> hours, whose listed
arguments match their globs; only policy rules with "standing": true use it. "deny sa-..." revokes it.
With --agent it covers that HTTP agent's calls only; without, only calls that come with no agent (stdio).
A deny --reason is shown to the agent the next time it makes the call; an approve --note is kept
with the approval. Both are stored, with the OS user who ran the command, in approvals.json and
in the audit log.
The MCP gateway's config file is --config, else $AGENT_GATE_CONFIG, else ./gateway.config.json.
The LLM gateway's ("llm serve", "usage") is --config, else $AGENT_GATE_LLM_CONFIG, else
./llm-gateway.config.json.
`;

/** Every command: the options it takes, the ones it needs, and whether it takes an id after the action word. */
const COMMANDS: Readonly<Record<string, { options: readonly string[]; required?: readonly string[]; id?: true }>> = {
  serve: { options: ["profile", "http"] },
  "approvals list": { options: ["all", "json"] },
  "approvals show": { options: [], id: true },
  "approvals approve": { options: ["note", "yes"], id: true },
  "approvals deny": { options: ["reason"], id: true },
  "approvals stats": { options: ["json"] },
  "approvals grant": { options: ["uses", "hours", "arg", "note", "agent"], required: ["uses", "hours"], id: true },
  "approvals grants": { options: ["all", "json"] },
  "llm serve": { options: [] },
  usage: { options: ["json", "by", "verify"] },
  "audit stats": { options: ["json"] },
  "audit verify": { options: ["json"] },
  "audit trajectory": { options: ["json", "expect", "mode", "all", "conn", "run"], required: ["expect"] },
  "tools list": { options: ["json"] },
  "tools show": { options: [], id: true },
  "tools accept": { options: [], id: true },
  "policy suggest": { options: ["json", "openapi"] },
};

export interface Io {
  out: (text: string) => void;
  err: (text: string) => void;
  /** One line typed by the human, or undefined at end of input. Without it, approve needs --yes. */
  readLine?: () => Promise<string | undefined>;
}

const processIo: Io = {
  out: (text) => process.stdout.write(text),
  err: (text) => process.stderr.write(text),
  readLine: () =>
    new Promise((resolve) => {
      const rl = readline.createInterface({ input: process.stdin, terminal: false });
      let line: string | undefined;
      rl.once("line", (text) => {
        line = text;
        rl.close();
      });
      rl.once("close", () => resolve(line));
    }),
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
        yes: { type: "boolean", default: false },
        uses: { type: "string" },
        hours: { type: "string" },
        arg: { type: "string", multiple: true },
        by: { type: "string" },
        verify: { type: "boolean", default: false },
        expect: { type: "string" },
        mode: { type: "string" },
        conn: { type: "string" },
        run: { type: "string" },
        openapi: { type: "string" },
        profile: { type: "string" },
        http: { type: "boolean", default: false },
        agent: { type: "string" },
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
  // "serve" and "usage" take no action word; every other command does.
  const single = command === "serve" || command === "usage";
  const name = single ? command : `${command} ${action}`;
  const spec = Object.prototype.hasOwnProperty.call(COMMANDS, name) ? COMMANDS[name] : undefined;
  const given = Object.entries(values)
    .filter(([option, value]) => option !== "config" && option !== "help" && value !== undefined && value !== false && !(Array.isArray(value) && value.length === 0))
    .map(([option]) => option);
  const positionalsFit = single ? action === undefined : spec?.id ? id !== undefined && extra.length === 0 : id === undefined;
  if (!spec || !positionalsFit || given.some((option) => !spec.options.includes(option)) || (spec.required ?? []).some((option) => !given.includes(option))) {
    io.err(USAGE);
    return 2;
  }

  try {
    if (name === "serve") {
      if (values.http && values.profile !== undefined) {
        io.err(`agent-gate: --profile is for one stdio client; with --http each agent's profile is set in the config\n\n${USAGE}`);
        return 2;
      }
      return values.http ? await serveHttp(configFile) : await serve(configFile, values.profile);
    }
    if (name === "llm serve") return await serveLlm(llmConfigFile);
    if (name === "usage") {
      if (values.by !== undefined && values.verify) {
        io.err(`agent-gate: --by and --verify are two different reports; pick one\n\n${USAGE}`);
        return 2;
      }
      if (values.verify) return usageVerify(llmConfigFile, values.json, io);
      return values.by === undefined ? usage(llmConfigFile, values.json, io) : usageBy(llmConfigFile, values.by, values.json, io);
    }
    if (name === "policy suggest") return await policySuggest(configFile, values.openapi, values.json, io);
    const config = loadConfig(configFile);
    const store = new ApprovalStore(config.stateDir, config.approvalTtlMs);
    const audit = new AuditLog(path.join(config.stateDir, "audit.jsonl"));
    if (name === "audit stats") return auditStatsCommand(audit.file, values.json, io);
    if (name === "audit verify") return auditVerifyCommand(audit.file, store, values.json, io);
    if (name === "audit trajectory") return auditTrajectoryCommand(audit.file, values, io);
    if (command === "tools") return toolsCommand(action as string, id, config, audit, values.json, io);
    if (action === "list") return list(store, values.all, values.json, io);
    if (action === "stats") return stats(store, audit.file, values.json, io);
    if (action === "grants") return grants(store, values.all, values.json, io);
    if (action === "grant") return grant(store, audit, config, id as string, values, io);
    if (action === "show") {
      io.out(`${JSON.stringify((id as string).startsWith("sa-") ? store.getStanding(id as string) : store.get(id as string), null, 2)}\n`);
    } else if (action === "deny" && (id as string).startsWith("sa-")) {
      const revoked = store.revoke(id as string, { by: currentUser(), note: values.reason });
      writeStanding(audit, revoked, "revoked");
      io.out(`revoked ${revoked.id}: it allows nothing more (${revoked.used} of ${revoked.maxUses} uses were spent).\n`);
    } else if (action === "approve") {
      const request = store.get(id as string);
      let confirmation: Confirmation = "--yes";
      // Read back what is being approved, and wait for the human to type the end of its id. A request
      // that is no longer pending or has expired skips this: decide() refuses it with the reason.
      if (!values.yes && request.status === "pending" && isLive(request, Date.now())) {
        const code = request.id.slice(-4);
        io.out(`${readBack(request, config)}Type the last 4 characters of the id (${code}) to approve it, anything else to stop: `);
        const typed = io.readLine ? await io.readLine() : undefined;
        io.out("\n");
        if (typed === undefined) {
          io.err(`agent-gate: nothing was typed, so ${request.id} was not approved. In a script, pass --yes.\n`);
          return 1;
        }
        if (typed.trim() !== code && typed.trim() !== request.id) {
          io.err(`agent-gate: ${JSON.stringify(typed.trim().slice(0, 40))} is not ${code}, so ${request.id} was not approved.\n`);
          return 1;
        }
        confirmation = "typed";
      }
      const approval = decide(store, audit, id as string, "approved", values.note, confirmation);
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

async function serve(configFile: string, profile: string | undefined): Promise<number> {
  const config = loadConfig(configFile);
  const gateway = await createGateway(config, loadPolicy(config.policyFile), undefined, profile === undefined ? {} : { profile });
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

async function serveHttp(configFile: string): Promise<number> {
  const config = loadConfig(configFile);
  const gateway = await startHttpGateway(config);
  await new Promise<void>((resolve) => {
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
  printTable(
    [
      ["key", `today (${first?.day ?? ""} UTC)`, `this month (${first?.month ?? ""})`, "in flight"],
      ...rows.map((r) => [
        r.key,
        `$${formatUsd(r.dayUsd)} of $${formatUsd(r.dailyUsd)}`,
        `$${formatUsd(r.monthUsd)} of $${formatUsd(r.monthlyUsd)}`,
        r.inFlight === 0 ? "0" : `${r.inFlight} ($${formatUsd(r.reservedUsd)} reserved)`,
      ]),
    ],
    io,
  );
  return 0;
}

/** usage --by <field>: the usage log summed per task (or key, route, ...), most expensive first. */
function usageBy(configFile: string, by: string, json: boolean, io: Io): number {
  if (!(GROUP_FIELDS as readonly string[]).includes(by)) {
    io.err(`agent-gate: --by takes one of ${GROUP_FIELDS.join(", ")}\n`);
    return 2;
  }
  const config = loadLlmConfig(configFile);
  const file = path.join(config.stateDir, "usage.jsonl");
  const { lines, unreadable } = readUsageLog(file);
  const rows = groupUsage(lines, by as GroupField);
  if (json) io.out(`${JSON.stringify(rows, null, 2)}\n`);
  else if (rows.length === 0) io.out("No calls recorded yet.\n");
  else {
    printTable(
      [
        [by, "requests", "ok", "input tokens", "output tokens", "cost", "leak blocked", "leak redacted"],
        ...rows.map((r) => [r.group, `${r.requests}`, `${r.ok}`, `${r.inputTokens}`, `${r.outputTokens}`, `$${formatUsd(r.costUsd)}`, `${r.leakBlocked}`, `${r.leakRedacted}`]),
      ],
      io,
    );
  }
  if (unreadable.length > 0) io.err(`agent-gate: ${unreadable.length} line(s) of ${file} are not JSON and were skipped\n`);
  return 0;
}

/** usage --verify: the usage log's dollars against the ledger, per key; exit 1 when any differ. */
function usageVerify(configFile: string, json: boolean, io: Io): number {
  const config = loadLlmConfig(configFile);
  const file = path.join(config.stateDir, "usage.jsonl");
  const { lines, unreadable } = readUsageLog(file);
  const rows = verifyUsage(lines, openLedger(config).usage(config.keys));
  if (json) io.out(`${JSON.stringify(rows, null, 2)}\n`);
  else {
    printTable(
      [
        ["key", "day", "ledger", "usage log", "month", "ledger", "usage log", "result"],
        ...rows.map((r) => [r.key, r.day, `$${formatUsd(r.ledgerDayUsd)}`, `$${formatUsd(r.logDayUsd)}`, r.month, `$${formatUsd(r.ledgerMonthUsd)}`, `$${formatUsd(r.logMonthUsd)}`, r.ok ? "ok" : "DIFFERENT"]),
      ],
      io,
    );
  }
  if (unreadable.length > 0) io.err(`agent-gate: ${unreadable.length} line(s) of ${file} are not JSON and were skipped\n`);
  const different = rows.filter((r) => !r.ok);
  if (different.length > 0) {
    io.err(`agent-gate: the usage log and the ledger differ for ${different.map((r) => `"${r.key}"`).join(", ")}: a usage line was lost, a cost was booked twice, or a file was edited\n`);
    return 1;
  }
  return 0;
}

/** Columns padded to their widest cell, two spaces apart. */
function printTable(table: string[][], io: Io): void {
  const widths = (table[0] ?? []).map((_, column) => Math.max(...table.map((row) => (row[column] ?? "").length)));
  for (const row of table) io.out(`${row.map((cell, column) => cell.padEnd(widths[column] ?? 0)).join("  ").trimEnd()}\n`);
}

/** audit stats: per tool, from the call and call-result lines of the audit log. */
function auditStatsCommand(file: string, json: boolean, io: Io): number {
  const { lines, unreadable } = readAudit(file);
  const rows = auditStats(lines);
  if (json) io.out(`${JSON.stringify(rows, null, 2)}\n`);
  else if (rows.length === 0) io.out("No tool calls recorded yet.\n");
  else {
    printTable(
      [
        ["tool", "calls", "forwarded", "asked", "blocked", "errors", "p50", "p95", "max"],
        ...rows.map((r) => [r.tool, `${r.calls}`, `${r.forwarded}`, `${r.asked}`, `${r.blocked}`, `${r.errors}`, formatMs(r.p50Ms), formatMs(r.p95Ms), formatMs(r.maxMs)]),
      ],
      io,
    );
  }
  if (unreadable.length > 0) io.err(`agent-gate: ${unreadable.length} line(s) of ${file} are not JSON and were skipped (line ${unreadable.slice(0, 5).join(", ")}${unreadable.length > 5 ? ", ..." : ""})\n`);
  return 0;
}

/** tools list / show / accept: the pinned tool definitions (src/gateway/tool-pins.ts). */
function toolsCommand(action: string, name: string | undefined, config: GatewayConfig, audit: AuditLog, json: boolean, io: Io): number {
  const pins = new ToolPins(config.stateDir);
  if (action === "list") {
    const servers = pins.list();
    if (json) {
      io.out(`${JSON.stringify(servers, null, 2)}\n`);
      return 0;
    }
    const rows = Object.entries(servers).flatMap(([server, tools]) => Object.entries(tools).map(([tool, record]) => ({ name: `${server}${SEPARATOR}${tool}`, record })));
    if (rows.length === 0) io.out(config.pinTools ? "No tools pinned yet: they are pinned the first time the gateway lists them.\n" : "Tool pinning is off (pinTools: false).\n");
    for (const { name: tool, record } of rows.sort((a, b) => a.name.localeCompare(b.name))) {
      io.out(
        record.changed
          ? `${tool}  CHANGED, withheld  pinned ${record.pinned.sha256.slice(0, 19)}... at ${record.pinned.at}; seen ${record.changed.sha256.slice(0, 19)}... at ${record.changed.at}\n`
          : `${tool}  pinned  ${record.pinned.sha256.slice(0, 19)}... at ${record.pinned.at}${record.pinned.acceptedBy ? ` by ${record.pinned.acceptedBy}` : ""}\n`,
      );
    }
    return 0;
  }
  const at = (name ?? "").indexOf(SEPARATOR);
  if (at <= 0) {
    io.err(`agent-gate: name the tool as <server>${SEPARATOR}<tool>, as the agent sees it\n`);
    return 2;
  }
  const server = (name as string).slice(0, at);
  const tool = (name as string).slice(at + SEPARATOR.length);
  if (action === "show") {
    const record = pins.get(server, tool);
    if (!record) throw new ApprovalError(`no pinned tool ${name}`);
    io.out(`${JSON.stringify(record, null, 2)}\n`);
    return 0;
  }
  let accepted;
  try {
    accepted = pins.accept(server, tool, currentUser());
  } catch (err) {
    throw new ApprovalError((err as Error).message);
  }
  audit.writeTool({ event: "tool-accepted", server, tool, sha256: accepted.pinned.sha256, ...(accepted.pinned.acceptedBy ? { decidedBy: accepted.pinned.acceptedBy } : {}) });
  io.out(`accepted ${name}: its new definition (${accepted.pinned.sha256}) is pinned, and the agent sees the tool again the next time it lists tools.\n`);
  return 0;
}

/** audit verify: the log against the gateway's rules; exit 1 with the problems when there are any. */
function auditVerifyCommand(file: string, store: ApprovalStore, json: boolean, io: Io): number {
  const audit = readAudit(file);
  const problems = verifyAudit(audit, store.list());
  const checked = audit.lines.length + audit.unreadable.length;
  if (json) io.out(`${JSON.stringify({ lines: checked, problems }, null, 2)}\n`);
  else {
    for (const p of problems) io.out(`FAIL line ${p.line}: ${p.why}\n`);
    io.out(problems.length === 0 ? `PASS: ${checked} lines checked, no problems\n` : `FAIL: ${checked} lines checked, ${problems.length} problem(s)\n`);
  }
  return problems.length === 0 ? 0 : 1;
}

const MODES = ["exact", "in-order", "any-order"] as const;

/** audit trajectory --expect <file>: exit 0 when the chosen mode (default in-order) passes. */
function auditTrajectoryCommand(file: string, values: { expect?: string; mode?: string; all?: boolean; conn?: string; run?: string; json?: boolean }, io: Io): number {
  const mode = values.mode ?? "in-order";
  if (!(MODES as readonly string[]).includes(mode)) {
    io.err(`agent-gate: --mode takes ${MODES.join(", ")}\n`);
    return 2;
  }
  const expected = loadExpected(values.expect as string);
  const actual = trajectoryOf(readAudit(file).lines, { all: values.all ?? false, ...(values.conn ? { conn: values.conn } : {}), ...(values.run ? { run: values.run } : {}) });
  const score = scoreTrajectory(actual, expected);
  const passed = mode === "exact" ? score.exact : mode === "in-order" ? score.inOrder : score.anyOrder;
  if (values.json) io.out(`${JSON.stringify({ mode, passed, ...score }, null, 2)}\n`);
  else {
    const verdict = (ok: boolean) => (ok ? "PASS" : "FAIL");
    io.out(
      [
        `${score.actual.length} call(s) ${values.all ? "recorded" : "ran"}, ${score.expected.length} expected`,
        `  exact      ${verdict(score.exact)}`,
        `  in order   ${verdict(score.inOrder)}`,
        `  any order  ${verdict(score.anyOrder)}`,
        `  precision  ${score.precision.toFixed(2)} (${score.matched} of the ${score.actual.length} calls were expected)`,
        `  recall     ${score.recall.toFixed(2)} (${score.matched} of the ${score.expected.length} expected calls happened)`,
        `${verdict(passed)} (${mode})`,
        "",
      ].join("\n"),
    );
  }
  return passed ? 0 : 1;
}

/** 7 ms · 1.2 s · - for none */
function formatMs(ms: number | null): string {
  if (ms === null) return "-";
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
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
        ...(a.alsoMatched ?? []).map((m) => `  also:    ${m.rule} (${m.decision}: ${m.why})`),
        ...(a.rewrittenBy ? [`  edited:  by ${a.rewrittenBy.join(", ")}; the args below are what will run`] : []),
        ...(a.agent !== undefined ? [`  agent:   ${a.agent} (its key; only its own call can use this approval)`] : []),
        ...(a.agentPath ? [`  agents:  ${a.agentPath}`] : []),
        `  args:    ${preview(canonicalJson(a.args))}`,
        ...(a.files ?? []).map((f) => `  file:    ${f.path} ${f.sha256 ?? "(did not exist)"}`),
        `  created: ${a.createdAt}  expires: ${a.expiresAt}`,
        ...(a.decidedAt ? [`  decided: ${a.decidedAt}${a.decidedBy ? ` by ${a.decidedBy}` : ""}`] : []),
        ...(a.decisionNote ? [`  note:    ${a.decisionNote}`] : []),
        "",
      ].join("\n"),
    );
  }
  return 0;
}

/** approvals grant <server>__<tool> --uses <n> --hours <h> [--arg name=glob]... : a standing approval (ADR 0006). */
function grant(store: ApprovalStore, audit: AuditLog, config: GatewayConfig, name: string, values: { uses?: string; hours?: string; arg?: string[]; note?: string; agent?: string }, io: Io): number {
  const at = name.indexOf(SEPARATOR);
  if (at <= 0 || at + SEPARATOR.length === name.length) {
    io.err(`agent-gate: name the tool as <server>${SEPARATOR}<tool>, as the agent sees it\n`);
    return 2;
  }
  const server = name.slice(0, at);
  const tool = name.slice(at + SEPARATOR.length);
  if (!config.servers.some((s) => s.name === server)) throw new ApprovalError(`the config has no server named "${server}"`);
  if (values.agent !== undefined && !config.http?.agents.some((a) => a.name === values.agent)) throw new ApprovalError(`the config has no HTTP agent named "${values.agent}"`);
  const args: Record<string, string> = {};
  for (const spec of values.arg ?? []) {
    const eq = spec.indexOf("=");
    if (eq <= 0 || eq === spec.length - 1) {
      io.err(`agent-gate: --arg takes <name>=<glob>, for example --arg "repo=octo/agent-gate"\n`);
      return 2;
    }
    args[spec.slice(0, eq)] = spec.slice(eq + 1);
  }
  const granted = store.grant({ server, tool, args, ...(values.agent !== undefined ? { agent: values.agent } : {}), maxUses: Number(values.uses), ttlMs: Number(values.hours) * 3_600_000, by: currentUser(), note: values.note });
  writeStanding(audit, granted, "granted");
  const pattern = Object.entries(args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ");
  io.out(
    `granted ${granted.id}: up to ${granted.maxUses} call(s) to ${server}${SEPARATOR}${tool}${pattern ? ` with ${pattern}` : " with any arguments"}${granted.agent !== undefined ? ` from agent "${granted.agent}"` : ""}, until ${granted.expiresAt}.\n` +
      `Only rules with "standing": true in the policy use it, and a denial of a call still wins. Revoke it with: agent-gate approvals deny ${granted.id}\n`,
  );
  return 0;
}

function grants(store: ApprovalStore, all: boolean, json: boolean, io: Io): number {
  const now = Date.now();
  const live = (g: StandingApproval) => g.status === "active" && g.used < g.maxUses && now < Date.parse(g.expiresAt);
  const shown = store.standing().filter((g) => all || live(g));
  if (json) {
    io.out(`${JSON.stringify(shown, null, 2)}\n`);
    return 0;
  }
  if (shown.length === 0) io.out(all ? "No standing approvals.\n" : "No standing approvals are in force.\n");
  for (const g of shown) {
    const state = live(g) ? "active" : g.status === "revoked" ? "revoked" : g.used >= g.maxUses ? "used up" : "expired";
    const pattern = Object.entries(g.args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ") || "any arguments";
    io.out(`${g.id}  ${state}  ${g.server}${SEPARATOR}${g.tool}  ${pattern}\n${g.agent !== undefined ? `  agent:   ${g.agent}\n` : ""}  uses:    ${g.used} of ${g.maxUses}\n  until:   ${g.expiresAt}${g.decidedBy ? `  by ${g.decidedBy}` : ""}\n${g.decisionNote ? `  note:    ${g.decisionNote}\n` : ""}\n`);
  }
  return 0;
}

function writeStanding(audit: AuditLog, g: StandingApproval, decision: "granted" | "revoked"): void {
  audit.writeStanding({
    id: g.id,
    decision,
    server: g.server,
    tool: g.tool,
    args: g.args,
    ...(g.agent !== undefined ? { agent: g.agent } : {}),
    maxUses: g.maxUses,
    used: g.used,
    expiresAt: g.expiresAt,
    ...(g.decidedBy ? { decidedBy: g.decidedBy } : {}),
    ...(g.decisionNote ? { note: g.decisionNote } : {}),
  });
}

/** The OS user running the CLI, recorded as who decided. */
function currentUser(): string | undefined {
  try {
    return cleanNote(os.userInfo().username, 64);
  } catch {
    return undefined;
  }
}

/**
 * What the human is approving, in full: the call, every argument, the rule and its reason, the files
 * the request is bound to (hashed again now, to show whether they still match), and the time left.
 */
export function readBack(a: Approval, config: Pick<GatewayConfig, "fileBinding">, now = Date.now()): string {
  const args = JSON.stringify(JSON.parse(canonicalJson(a.args)), null, 2).split("\n");
  const current = a.files && config.fileBinding ? bindFiles(a.args, config.fileBinding) : [];
  const files = (a.files ?? []).map((f) => {
    const again = current.find((c) => c.argument === f.argument);
    const state = again && again.path === f.path && again.sha256 === f.sha256 ? "unchanged since the request" : "CHANGED since the request: the agent will be asked again";
    return `  file:     ${f.path} ${f.sha256 ?? "(did not exist)"}, ${state}`;
  });
  return [
    `Approve this call? ${a.id}`,
    `  call:     ${a.server}${SEPARATOR}${a.tool}`,
    ...(a.agent !== undefined ? [`  agent:    ${a.agent} (known by its key; only its own call can use this approval)`] : []),
    ...(a.agentPath ? [`  agents:   ${a.agentPath} (as the client states it)`] : []),
    `  args:     ${args[0]}`,
    ...args.slice(1).map((line) => `            ${line}`),
    `  rule:     ${a.rule}: ${a.why}`,
    ...(a.alsoMatched ?? []).map((m) => `  also:     ${m.rule} (${m.decision}: ${m.why})`),
    ...(a.rewrittenBy ? [`  edited:   by ${a.rewrittenBy.join(", ")}; these args are what will run, not what the agent sent`] : []),
    ...files,
    `  expires:  ${a.expiresAt} (in ${duration(Math.max(0, Date.parse(a.expiresAt) - now))})`,
    "",
  ].join("\n");
}

/** Records a human's decision in approvals.json, then as an approval-decided line in the audit log. */
function decide(store: ApprovalStore, audit: AuditLog, id: string, decision: "approved" | "denied", note: string | undefined, confirmation?: Confirmation): Approval {
  const by = currentUser();
  let approval: Approval;
  try {
    approval = decision === "approved" ? store.approve(id, { by, note, ...(confirmation ? { confirmation } : {}) }) : store.deny(id, { by, note });
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
    ...(decision === "approved" && a.confirmation ? { confirmation: a.confirmation } : {}),
    ...(a.agent !== undefined ? { agent: a.agent } : {}),
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
    printTable(
      [
        ["rule", "approved", "denied", "expired", "waiting", "deny rate", "median wait"],
        ...rows.map((r) => [r.rule, `${r.approved}`, `${r.denied}`, `${r.expired}`, `${r.waiting}`, r.denyRate === null ? "-" : `${Math.round(r.denyRate * 100)}%`, r.medianWaitMs === null ? "-" : duration(r.medianWaitMs)]),
      ],
      io,
    );
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

/** policy suggest: each tool's decision under the config's policy, the tools no rule names, and a draft policy. */
async function policySuggest(configFile: string, openapi: string | undefined, json: boolean, io: Io): Promise<number> {
  const config = loadConfig(configFile);
  const policy = loadPolicy(config.policyFile);
  const raw = JSON.parse(fs.readFileSync(config.policyFile, "utf8")) as unknown;
  let candidates: Candidate[];
  let failures: string[] = [];
  if (openapi === undefined) ({ candidates, failures } = await downstreamCandidates(config));
  else {
    let spec: unknown;
    try {
      spec = JSON.parse(fs.readFileSync(openapi, "utf8"));
    } catch (err) {
      throw new ConfigError(`cannot read ${openapi} as JSON (a YAML document has to be converted to JSON first): ${(err as Error).message}`);
    }
    candidates = openApiCandidates(spec);
  }
  const report = suggest(policy, raw, candidates, new Map(config.servers.flatMap((s) => (s.expose ? [[s.name, s.expose] as const] : []))));
  for (const failure of failures) io.err(`agent-gate: ${failure}\n`);
  if (json) {
    io.out(`${JSON.stringify({ ...report, failures }, null, 2)}\n`);
    return failures.length > 0 ? 1 : 0;
  }
  const table = [["tool", "now", "rule", "draft", "note"]];
  for (const s of report.suggestions) {
    const notes = [
      s.http ? `${s.http.method.toUpperCase()} ${s.http.path}` : "",
      s.dependsOn.length > 0 ? `arguments can change it (${s.dependsOn.join(", ")})` : "",
      s.hints ? `the server says: ${s.hints.join(", ")}` : "",
    ].filter(Boolean);
    table.push([`${s.server}${SEPARATOR}${s.tool}`, s.decision, s.rule, s.draft, notes.join("; ")]);
  }
  io.out(`${report.suggestions.length} tools, decided from their names by ${path.basename(config.policyFile)} ("now") and by the draft below ("draft"):\n`);
  printTable(table, io);
  if (report.argumentRules.length > 0) io.out(`\nRules that look only at arguments can change any of these when the arguments match: ${report.argumentRules.join(", ")}.\n`);
  io.out(
    report.unmatched.length === 0
      ? "\nEvery tool matched a rule.\n"
      : `\nNo rule names ${report.unmatched.length} of them, so the policy's default (${policy.default}) decides: ${report.unmatched.join(", ")}\n`,
  );
  // One rule per line, so the draft can be read and edited.
  const { rules, repeat } = report.draft;
  const draft = [
    "{",
    '  "default": "ask",',
    '  "rules": [',
    rules.map((rule) => `    ${JSON.stringify(rule)}`).join(",\n"),
    `  ]${repeat ? "," : ""}`,
    ...(repeat ? [`  "repeat": ${JSON.stringify(repeat)}`] : []),
    "}",
  ].join("\n");
  io.out(`\nDraft policy: the same rules, an allow rule for the tools whose names read, and "default": "ask". Check every line before you use it:\n${draft}\n`);
  return failures.length > 0 ? 1 : 0;
}
