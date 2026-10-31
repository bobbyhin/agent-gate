// The MCP gateway: one MCP server for the agent, in front of one or more downstream MCP servers.
//
// It lists every downstream tool as "<server>__<tool>", decides every call with the policy, and
// forwards the calls that may run. Forwarded calls get the downstream result back unchanged, except
// that a call whose arguments a rewrite rule edited says so in the result's _meta.
// Every call is written to the audit log before anything is forwarded; a forwarded call gets a
// second line when it comes back, with its duration and a hash of its result (audit.ts).
//
//   allow  forward, audit
//   warn   forward, audit, and a note on stderr
//   ask    do not forward; queue an approval for a human and return an error result naming it.
//          Once a human approves, the same call (same arguments) is forwarded exactly once.
//   block  do not forward and do not queue; return an error result
//
// tools/list shows a server's tools minus three kinds: those its "expose" globs leave out (a call to
// one is blocked), those the policy blocks whatever the arguments, and those whose definition changed
// since it was pinned (a call to one asks; src/gateway/tool-pins.ts).
//
// ponytail: only tools are proxied. Resources, prompts, and requests from a downstream server
// back to the client (sampling, elicitation) are not.

import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { performance } from "node:perf_hooks";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  CallToolResultSchema,
  ErrorCode,
  ListToolsRequestSchema,
  ListToolsResultSchema,
  McpError,
  ToolListChangedNotificationSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { ApprovalStore, hashArguments, type Approval } from "./approvals.js";
import { AuditLog, hashJson } from "./audit.js";
import type { GatewayConfig } from "./config.js";
import { contextFromMeta, type CallContext } from "./context.js";
import { bindFiles } from "./files.js";
import { alwaysBlocked, evaluate, globToRegExp, repeatLimitsFor, type Policy, type ToolCall, type Verdict } from "./policy.js";
import { loadLeakPolicy } from "../llm/config.js";
import { RepeatStore } from "./repeats.js";
import { guardResult, type ResultGuard } from "./result-guard.js";
import { ToolPins } from "./tool-pins.js";

export const VERSION = "0.1.0";
export const SEPARATOR = "__";
// ponytail: a server that keeps returning a nextCursor is cut off after this many pages.
const MAX_LIST_PAGES = 100;

export interface Gateway {
  /** Not yet connected to a transport: the caller connects it (the CLI uses stdio). */
  server: Server;
  close(): Promise<void>;
}

export type Log = (message: string) => void;
const stderrLog: Log = (message) => process.stderr.write(`[agent-gate] ${message}\n`);

export async function createGateway(config: GatewayConfig, policy: Policy, log: Log = stderrLog): Promise<Gateway> {
  fs.mkdirSync(config.stateDir, { recursive: true, mode: 0o700 });
  const approvals = new ApprovalStore(config.stateDir, config.approvalTtlMs);
  const audit = new AuditLog(path.join(config.stateDir, "audit.jsonl"), config.auditArguments);
  const repeats = policy.repeat.length > 0 ? new RepeatStore(config.stateDir, Math.max(...policy.repeat.map((limit) => limit.windowMs))) : undefined;
  const pins = config.pinTools ? new ToolPins(config.stateDir) : undefined;
  const resultGuard: ResultGuard | undefined = config.resultGuard
    ? { ...(config.resultGuard.leakPolicyFile ? { leak: loadLeakPolicy(config.resultGuard.leakPolicyFile) } : {}), flagInstructions: config.resultGuard.flagInstructions }
    : undefined;
  const exposeTests = new Map(config.servers.flatMap((s) => (s.expose ? [[s.name, s.expose.map(globToRegExp)] as const] : [])));
  const isExposed = (server: string, tool: string): boolean => exposeTests.get(server)?.some((re) => re.test(tool)) ?? true;
  // One connection per gateway process: the stdio transport serves exactly one client.
  const connId = `cn-${randomBytes(4).toString("hex")}`;
  let seq = 0;

  // The low-level Server rather than McpServer (the SDK marks Server deprecated for ordinary
  // servers): a proxy republishes tools whose JSON Schemas come from other servers, while
  // McpServer only registers tools that it describes with zod itself.
  const server = new Server({ name: "agent-gate", version: VERSION }, { capabilities: { tools: { listChanged: true } } });
  const downstream = await connectAll(config, () => server.sendToolListChanged().catch(() => undefined));

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const lists = await Promise.all([...downstream].map(([name, client]) => visibleTools(name, client)));
    return { tools: lists.flat() };
  });

  /** A server's tools as the agent sees them: exposed, not always blocked, not changed since pinned; with the prefix. */
  async function visibleTools(name: string, client: Client): Promise<Tool[]> {
    let shown = (await listTools(name, client, log)).filter((tool) => isExposed(name, tool.name) && !alwaysBlocked(policy, name, tool.name));
    if (pins) {
      try {
        const checked = pins.check(name, shown);
        for (const p of checked.pinned) recordTool({ event: "tool-pinned", server: name, tool: p.tool, sha256: p.sha256 });
        for (const c of checked.changed) {
          recordTool({ event: "tool-changed", server: name, tool: c.tool, sha256: c.sha256, pinnedSha256: c.pinnedSha256 });
          log(`${name}${SEPARATOR}${c.tool} changed since it was pinned, so it is withheld; compare with: agent-gate tools show ${name}${SEPARATOR}${c.tool}`);
        }
        shown = checked.visible;
      } catch (err) {
        // Fail closed: without the pins, none of this server's tools is shown.
        log(`could not check the pinned tools of "${name}", so none of its tools are listed: ${errorText(err)}`);
        return [];
      }
    }
    return shown.map((tool) => ({ ...tool, name: `${name}${SEPARATOR}${tool.name}` }));
  }

  function recordTool(event: Parameters<AuditLog["writeTool"]>[0]): void {
    try {
      audit.writeTool(event);
    } catch (err) {
      log(`could not write a ${event.event} line to the audit log: ${errorText(err)}`);
    }
  }

  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const { name, arguments: rawArgs } = request.params;
    const route = splitName(name);
    const client = route && downstream.get(route.server);
    if (!route || !client) throw new McpError(ErrorCode.InvalidParams, `Unknown tool: ${name}`);

    const n = ++seq;
    const context = contextFromMeta(request.params._meta);
    const call: ToolCall = { server: route.server, tool: route.tool, args: rawArgs ?? {} };
    let decided: Decided;
    try {
      // A tool the gateway has not listed yet is listed now, so that its definition is pinned (or found changed) first.
      if (pins && isExposed(call.server, call.tool) && pins.status(call.server, call.tool) === "unknown") await visibleTools(call.server, client);
      decided = decide(call, n, context);
    } catch (err) {
      // The policy, the approval file or the audit log failed: the call is not run.
      // ponytail: such a failure goes to stderr only; the audit log may be what failed.
      log(`could not check or record a call to ${name}: ${errorText(err)}`);
      return errorResult(`agent-gate could not check or record this call, so it was not run: ${errorText(err)}`);
    }
    if (decided.refusal) return decided.refusal;
    // A rewritten call goes on with its edited arguments; any other exactly as the agent sent it.
    const forwardArgs = decided.rewrittenBy ? decided.args : rawArgs;
    return forwardAndRecord(client, { ...call, args: decided.args }, n, decided.argsHash, forwardArgs, extra.signal, decided.rewrittenBy);
  });

  /** What decide() found: an error result when the call must not run, and the arguments it runs with. */
  interface Decided {
    refusal?: CallToolResult;
    args: Record<string, unknown>;
    argsHash: string;
    rewrittenBy?: string[];
  }

  function decide(call: ToolCall, n: number, context: CallContext): Decided {
    let verdict: Verdict = isExposed(call.server, call.tool)
      ? evaluate(policy, call)
      : { decision: "block", rule: "not-exposed", why: `the gateway config's "expose" list for server "${call.server}" leaves this tool out` };
    // A tool whose definition changed since it was pinned does not run unattended.
    if (pins && (verdict.decision === "allow" || verdict.decision === "warn") && pins.status(call.server, call.tool) === "changed") {
      verdict = {
        decision: "ask",
        rule: "tool-changed",
        why: `the definition of this tool (its description or schema) changed since it was pinned, so it is withheld from the agent; compare the two with "agent-gate tools show ${call.server}${SEPARATOR}${call.tool}" before letting it run`,
        alsoMatched: [{ rule: verdict.rule, decision: verdict.decision, why: verdict.why }, ...(verdict.alsoMatched ?? [])],
        ...(verdict.rewrittenBy ? { args: verdict.args as Record<string, unknown>, rewrittenBy: verdict.rewrittenBy } : {}),
      };
    }
    // Rewrite rules may have edited the arguments: what runs, what is hashed and what a human approves is the edited call.
    const args = verdict.args ?? call.args;
    const argsHash = hashArguments(args);
    // Loop limits apply to calls that would run unattended; past one, a human is asked (or the call is blocked).
    const limits = repeats ? repeatLimitsFor(policy, { ...call, args }) : [];
    let limited = false;
    if (repeats && limits.length > 0 && (verdict.decision === "allow" || verdict.decision === "warn")) {
      const hit = repeats.admit(limits, call.server, call.tool, argsHash);
      if (hit) {
        limited = true;
        const what = hit.limit.per === "tool" ? "this tool was called" : "this same call ran";
        verdict = {
          decision: hit.limit.decision,
          rule: hit.limit.id,
          why: hit.limit.why ?? `loop limit: ${what} ${hit.count} times in the last ${hit.limit.windowMs / 1000} s, the most rule ${hit.limit.id} lets through unattended`,
          alsoMatched: [{ rule: verdict.rule, decision: verdict.decision, why: verdict.why }, ...(verdict.alsoMatched ?? [])],
          ...(verdict.rewrittenBy ? { args: verdict.args as Record<string, unknown>, rewrittenBy: verdict.rewrittenBy } : {}),
        };
      }
    }
    const rewritten = verdict.rewrittenBy ? { originalArgsHash: hashArguments(call.args), rewrittenBy: verdict.rewrittenBy } : {};
    const record = (forwarded: boolean, approvalId?: string) =>
      audit.write(
        {
          connId,
          seq: n,
          server: call.server,
          tool: call.tool,
          decision: verdict.decision,
          rule: verdict.rule,
          why: verdict.why,
          argsHash,
          forwarded,
          ...(approvalId ? { approvalId } : {}),
          ...rewritten,
          ...(verdict.alsoMatched ? { alsoMatched: verdict.alsoMatched.map((m) => m.rule) } : {}),
          ...context,
        },
        args,
      );
    const run = (): Decided => ({ args, argsHash, ...(verdict.rewrittenBy ? { rewrittenBy: verdict.rewrittenBy } : {}) });
    const refuse = (refusal: CallToolResult): Decided => ({ refusal, args, argsHash });
    if (verdict.rewrittenBy) log(`REWRITE ${call.server}${SEPARATOR}${call.tool}: arguments edited by ${verdict.rewrittenBy.join(", ")}`);

    switch (verdict.decision) {
      case "allow":
        record(true);
        return run();
      case "warn":
        record(true);
        log(`WARN ${call.server}${SEPARATOR}${call.tool}: ${verdict.why} (rule ${verdict.rule})`);
        return run();
      case "block":
        record(false);
        return refuse(errorResult(blockedText(verdict)));
      case "ask": {
        const files = config.fileBinding ? bindFiles(args, config.fileBinding) : undefined;
        const outcome = approvals.resolveCall({
          ...call,
          args,
          argsHash,
          rule: verdict.rule,
          why: verdict.why,
          ...(verdict.ttlMs !== undefined ? { ttlMs: verdict.ttlMs } : {}),
          ...(files ? { files } : {}),
          ...(verdict.standing ? { standing: true } : {}),
          ...(context.agentPath ? { agentPath: context.agentPath } : {}),
          ...(verdict.alsoMatched ? { alsoMatched: verdict.alsoMatched } : {}),
          ...(verdict.rewrittenBy ? { rewrittenBy: verdict.rewrittenBy } : {}),
        });
        if (outcome.kind === "approved" || outcome.kind === "standing") {
          // the audit line names the approval, or the standing approval, that let it through
          record(true, outcome.kind === "approved" ? outcome.approval.id : outcome.grant.id);
          if (repeats && limited) repeats.record(limits, call.server, call.tool, argsHash);
          return run();
        }
        record(false, outcome.approval.id);
        return refuse(errorResult(outcome.kind === "denied" ? deniedText(outcome.approval) : pendingText(outcome.approval, outcome.created, outcome.replaced)));
      }
    }
  }

  /** Forwards a call that may run, then writes its call-result line: duration, error flag, result hash and size. */
  async function forwardAndRecord(
    client: Client,
    call: ToolCall,
    n: number,
    argsHash: string,
    rawArgs: Record<string, unknown> | undefined,
    signal: AbortSignal,
    rewrittenBy?: string[],
  ): Promise<CallToolResult> {
    const started = performance.now();
    const record = (outcome: Omit<Parameters<AuditLog["writeResult"]>[0], "connId" | "seq" | "server" | "tool" | "argsHash" | "durationMs">): void => {
      try {
        audit.writeResult({ connId, seq: n, server: call.server, tool: call.tool, argsHash, durationMs: Math.round(performance.now() - started), ...outcome });
      } catch (err) {
        // ponytail: the call has already run, so a result line that cannot be written is reported
        // on stderr only, and the agent still gets its result.
        log(`could not record the result of call ${n} to ${call.server}${SEPARATOR}${call.tool}: ${errorText(err)}`);
      }
    };
    let result: CallToolResult;
    try {
      result = await forward(client, call.server, call.tool, rawArgs, signal);
    } catch (err) {
      record({ isError: true, errorCode: err instanceof McpError ? err.code : ErrorCode.InternalError });
      throw err;
    }
    const sent = result;
    const notes: { withheld?: string; redacted?: string[]; flags?: string[] } = {};
    if (resultGuard) {
      const guarded = guardResult(resultGuard, result);
      result = guarded.result;
      if (guarded.withheld) {
        notes.withheld = guarded.withheld;
        log(`WITHHELD ${call.server}${SEPARATOR}${call.tool}: its result matched leak-guard rule ${guarded.withheld}`);
      }
      if (guarded.redacted.length > 0) notes.redacted = guarded.redacted;
      if (guarded.flags.length > 0) {
        notes.flags = guarded.flags;
        log(`WARN ${call.server}${SEPARATOR}${call.tool}: its result reads like instructions to the model (${guarded.flags.join(", ")}); it is passed on as data`);
      }
    }
    // The agent learns that its arguments were edited, in the result's _meta, not in its content.
    if (rewrittenBy) result = { ...result, _meta: { ...(result._meta ?? {}), "agent-gate/rewritten-by": rewrittenBy } };
    const { hash, bytes } = hashJson(result);
    record({ isError: result.isError === true, resultHash: hash, resultBytes: bytes, ...(result === sent ? {} : { originalResultHash: hashJson(sent).hash }), ...notes });
    return result;
  }

  function splitName(name: string): { server: string; tool: string } | undefined {
    const at = name.indexOf(SEPARATOR);
    if (at <= 0 || at + SEPARATOR.length === name.length) return undefined;
    return { server: name.slice(0, at), tool: name.slice(at + SEPARATOR.length) };
  }

  log(`ready: ${downstream.size} downstream server(s) (${[...downstream.keys()].join(", ")}), state in ${config.stateDir}, connection ${connId}`);
  return {
    server,
    async close() {
      await server.close().catch(() => undefined);
      await Promise.allSettled([...downstream.values()].map((client) => client.close()));
    },
  };
}

// ponytail: every downstream server is started once, at startup. If one fails to start, the
// gateway does not start; if one dies later, its calls fail until the gateway is restarted.
async function connectAll(config: GatewayConfig, onToolListChanged: () => void): Promise<Map<string, Client>> {
  const results = await Promise.allSettled(
    config.servers.map(async (s) => {
      const client = new Client({ name: "agent-gate", version: VERSION });
      client.setNotificationHandler(ToolListChangedNotificationSchema, async () => onToolListChanged());
      await client.connect(new StdioClientTransport({ command: s.command, args: s.args, env: s.env, stderr: "inherit" }));
      return [s.name, client] as const;
    }),
  );
  const connected = new Map<string, Client>();
  const failures: string[] = [];
  results.forEach((result, i) => {
    if (result.status === "fulfilled") connected.set(result.value[0], result.value[1]);
    else failures.push(`"${config.servers[i]?.name}": ${errorText(result.reason)}`);
  });
  if (failures.length > 0) {
    await Promise.allSettled([...connected.values()].map((client) => client.close()));
    throw new Error(`could not start downstream server ${failures.join("; ")}`);
  }
  return connected;
}

async function listTools(name: string, client: Client, log: Log): Promise<Tool[]> {
  const tools: Tool[] = [];
  try {
    let cursor: string | undefined;
    for (let page = 0; page < MAX_LIST_PAGES; page++) {
      const result = await client.request({ method: "tools/list", params: cursor === undefined ? {} : { cursor } }, ListToolsResultSchema);
      tools.push(...result.tools); // the server's own names; visibleTools() adds the prefix
      cursor = result.nextCursor;
      if (cursor === undefined) break;
    }
  } catch (err) {
    // One broken server should not hide the tools of the others.
    log(`could not list the tools of "${name}": ${errorText(err)}`);
  }
  return tools;
}

async function forward(client: Client, server: string, tool: string, args: Record<string, unknown> | undefined, signal: AbortSignal): Promise<CallToolResult> {
  // client.request rather than client.callTool: callTool would also check the result against the
  // tool's output schema. The gateway passes results through as they are; checking them is the
  // job of the agent's own client.
  // ponytail: the SDK's default 60 s request timeout applies and progress notifications are not
  // relayed, so a tool that runs longer than a minute fails through the gateway.
  try {
    return await client.request(
      { method: "tools/call", params: args === undefined ? { name: tool } : { name: tool, arguments: args } },
      CallToolResultSchema,
      { signal },
    );
  } catch (err) {
    // Keep the downstream error's code and data; drop the "MCP error <code>: " prefix that the
    // SDK adds, because the agent's client adds it again.
    if (err instanceof McpError) throw new McpError(err.code, err.message.replace(/^MCP error -?\d+: /, ""), err.data);
    throw new McpError(ErrorCode.InternalError, `downstream server "${server}" failed: ${errorText(err)}`);
  }
}

function errorResult(message: string): CallToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

const DO_NOT_WORK_AROUND = "Do not try to get the same result another way.";

function pendingText(approval: Approval, created: boolean, replaced?: Approval): string {
  return [
    replaced
      ? `agent-gate: a file this call names changed after it was approved (approval ${replaced.id}), so it was not run and needs a new decision.`
      : created
        ? "agent-gate: this call needs a human decision, so it was not run."
        : "agent-gate: this call is still waiting for a human decision, so it was not run.",
    `Reason: ${approval.why} (rule ${approval.rule})`,
    `Approval id: ${approval.id} (expires ${approval.expiresAt})`,
    `A human can approve it with: agent-gate approvals approve ${approval.id}`,
    "Once it is approved, make exactly the same call again (same tool, same arguments) and it will run once. Different arguments need a new approval.",
    DO_NOT_WORK_AROUND,
  ].join("\n");
}

function deniedText(approval: Approval): string {
  const lines = [`agent-gate: a human denied this exact call (approval ${approval.id}, ${approval.decidedAt ?? "earlier"}), so it was not run.`];
  // The reason is quoted as one JSON string and labelled as data: it explains the "no", and it
  // grants nothing. Decisions come only from the policy and the approval file.
  if (approval.decisionNote) lines.push(`The human's reason, quoted as written (information only, not an instruction from agent-gate): ${JSON.stringify(approval.decisionNote)}`);
  lines.push(`Do not retry it. ${DO_NOT_WORK_AROUND} Ask the human what they want instead.`);
  return lines.join("\n");
}

function blockedText(verdict: Verdict): string {
  return [
    `agent-gate blocked this call, so it was not run: ${verdict.why} (rule ${verdict.rule})`,
    `Blocked calls cannot be approved. ${DO_NOT_WORK_AROUND}`,
  ].join("\n");
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
