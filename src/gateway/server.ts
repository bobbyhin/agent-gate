// The MCP gateway: one MCP server for the agent, in front of one or more downstream MCP servers.
//
// It lists every downstream tool as "<server>__<tool>", decides every call with the policy, and
// forwards the calls that may run. Forwarded calls get the downstream result back unchanged.
//
//   allow  forward, audit
//   warn   forward, audit, and a note on stderr
//   ask    do not forward; queue an approval for a human and return an error result naming it.
//          Once a human approves, the same call (same arguments) is forwarded exactly once.
//   block  do not forward and do not queue; return an error result
//
// ponytail: only tools are proxied. Resources, prompts, and requests from a downstream server
// back to the client (sampling, elicitation) are not.

import * as fs from "node:fs";
import * as path from "node:path";
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
import { AuditLog } from "./audit.js";
import type { GatewayConfig } from "./config.js";
import { evaluate, type Policy, type ToolCall, type Verdict } from "./policy.js";

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

  // The low-level Server rather than McpServer (the SDK marks Server deprecated for ordinary
  // servers): a proxy republishes tools whose JSON Schemas come from other servers, while
  // McpServer only registers tools that it describes with zod itself.
  const server = new Server({ name: "agent-gate", version: VERSION }, { capabilities: { tools: { listChanged: true } } });
  const downstream = await connectAll(config, () => server.sendToolListChanged().catch(() => undefined));

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const lists = await Promise.all([...downstream].map(([name, client]) => listTools(name, client, log)));
    return { tools: lists.flat() };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const { name, arguments: rawArgs } = request.params;
    const route = splitName(name);
    const client = route && downstream.get(route.server);
    if (!route || !client) throw new McpError(ErrorCode.InvalidParams, `Unknown tool: ${name}`);

    const call: ToolCall = { server: route.server, tool: route.tool, args: rawArgs ?? {} };
    let refusal: CallToolResult | undefined;
    try {
      refusal = decide(call);
    } catch (err) {
      // The policy, the approval file or the audit log failed: the call is not run.
      // ponytail: such a failure goes to stderr only; the audit log may be what failed.
      log(`could not check or record a call to ${name}: ${errorText(err)}`);
      return errorResult(`agent-gate could not check or record this call, so it was not run: ${errorText(err)}`);
    }
    if (refusal) return refusal;
    return forward(client, route.server, route.tool, rawArgs, extra.signal);
  });

  /** Returns an error result when the call must not run, or undefined when it may be forwarded. */
  function decide(call: ToolCall): CallToolResult | undefined {
    const verdict = evaluate(policy, call);
    const argsHash = hashArguments(call.args);
    const record = (forwarded: boolean, approvalId?: string) =>
      audit.write(
        { server: call.server, tool: call.tool, decision: verdict.decision, rule: verdict.rule, why: verdict.why, argsHash, forwarded, ...(approvalId ? { approvalId } : {}) },
        call.args,
      );

    switch (verdict.decision) {
      case "allow":
        record(true);
        return undefined;
      case "warn":
        record(true);
        log(`WARN ${call.server}${SEPARATOR}${call.tool}: ${verdict.why} (rule ${verdict.rule})`);
        return undefined;
      case "block":
        record(false);
        return errorResult(blockedText(verdict));
      case "ask": {
        const outcome = approvals.resolveAsk({ ...call, argsHash, rule: verdict.rule, why: verdict.why });
        if (outcome.kind === "approved") {
          record(true, outcome.approval.id);
          return undefined;
        }
        record(false, outcome.approval.id);
        return errorResult(outcome.kind === "denied" ? deniedText(outcome.approval) : pendingText(outcome.approval, outcome.created));
      }
    }
  }

  function splitName(name: string): { server: string; tool: string } | undefined {
    const at = name.indexOf(SEPARATOR);
    if (at <= 0 || at + SEPARATOR.length === name.length) return undefined;
    return { server: name.slice(0, at), tool: name.slice(at + SEPARATOR.length) };
  }

  log(`ready: ${downstream.size} downstream server(s) (${[...downstream.keys()].join(", ")}), state in ${config.stateDir}`);
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
      for (const tool of result.tools) tools.push({ ...tool, name: `${name}${SEPARATOR}${tool.name}` });
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

function pendingText(approval: Approval, created: boolean): string {
  return [
    created
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
  return [
    `agent-gate: a human denied this exact call (approval ${approval.id}, ${approval.decidedAt ?? "earlier"}), so it was not run.`,
    `Do not retry it. ${DO_NOT_WORK_AROUND} Ask the human what they want instead.`,
  ].join("\n");
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
