// The MCP gateway: one MCP server for the agent, in front of one or more downstream MCP servers.
//
// It lists every downstream tool as "<server>__<tool>", decides every call with the policy, and
// forwards the calls that may run. Forwarded calls get the downstream result back unchanged, except
// that the optional result guard may withhold or redact it (result-guard.ts), and a call whose
// arguments a rewrite rule edited says so in the result's _meta.
// Every call is written to the audit log before anything is forwarded; a forwarded call gets a
// second line when it comes back, with its duration and a hash of its result (audit.ts).
//
//   allow  forward, audit
//   warn   forward, audit, and a note on stderr
//   ask    do not forward; queue an approval for a human and return an error result naming it.
//          Once a human approves, the same call (same arguments) is forwarded exactly once.
//   block  do not forward and do not queue; return an error result
//
// tools/list shows a server's tools minus four kinds: those its "expose" globs leave out and those
// the connection's profile leaves out (a call to one is blocked), those the policy blocks whatever the
// arguments, and those whose definition changed since it was pinned (a call to one asks;
// src/gateway/tool-pins.ts).
//
// The downstream servers are kept connected by src/gateway/downstream.ts: one that goes away is
// started again, an optional one may be missing at startup, and a call to a server that is not up is
// refused with the reason (rule server-down).
//
// ponytail: only tools are proxied. Resources, prompts, and requests from a downstream server
// back to the client (sampling, elicitation) are not.

import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { performance } from "node:perf_hooks";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  CallToolResultSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { ApprovalStore, hashArguments, type Approval } from "./approvals.js";
import { AuditLog, hashJson } from "./audit.js";
import type { GatewayConfig } from "./config.js";
import { contextFromMeta, type CallContext } from "./context.js";
import { ConfigError } from "./validate.js";
import { bindFiles } from "./files.js";
import { alwaysBlocked, evaluate, globToRegExp, repeatLimitsFor, type Policy, type ToolCall, type Verdict } from "./policy.js";
import { loadLeakPolicy } from "../llm/config.js";
import { RepeatStore } from "./repeats.js";
import { guardResult, type ResultGuard } from "./result-guard.js";
import { ToolPins } from "./tool-pins.js";
import { Downstreams, listTools, VERSION } from "./downstream.js";
import { StatusFile } from "./status.js";

// Where they lived before src/gateway/downstream.ts; other modules import them from here.
export { listTools, transportFor, VERSION } from "./downstream.js";
export const SEPARATOR = "__";

export interface Gateway {
  /** Not yet connected to a transport: the caller connects it (the CLI uses stdio). */
  server: Server;
  close(): Promise<void>;
}

export type Log = (message: string) => void;
export const stderrLog: Log = (message) => process.stderr.write(`[agent-gate] ${message}\n`);

export interface GatewayOptions {
  /** Where headersFromEnv values are read from (default: process.env). */
  env?: NodeJS.ProcessEnv;
  /** A profile from the config's "profiles": this connection sees and may call only its tools. */
  profile?: string;
  /** The first wait before a server that went away is started again (default 1000 ms; tests shorten it). */
  restartBackoffMs?: number;
}

/** Who a connection is: the policy that decides its calls, its profile, and the HTTP agent behind it. */
export interface SessionSpec {
  policy: Policy;
  /** A profile from the config's "profiles". */
  profile?: string;
  /** The agent known by its key (serve --http); absent over stdio, where a process serves one client. */
  agent?: string;
}

/** One client connection: an SDK Server of its own, with its own connId and call numbers. */
export interface Session {
  /** Not yet connected to a transport. */
  server: Server;
  /** "cn-" and 8 hex digits (16 for an HTTP session): names the connection in the audit log. */
  connId: string;
  close(): Promise<void>;
}

/**
 * What every connection of one gateway process shares: the downstream servers (connected once) and
 * the state directory (approvals, audit log, pins, loop counts). The stdio gateway opens one session;
 * the HTTP gateway (src/gateway/http-server.ts) one per client session.
 */
export interface GatewayCore {
  openSession(spec: SessionSpec): Session;
  close(): Promise<void>;
}

/** The stdio gateway: the shared core and one session, for the one client of this process. */
export async function createGateway(config: GatewayConfig, policy: Policy, log: Log = stderrLog, options: GatewayOptions = {}): Promise<Gateway> {
  // An unknown profile is a config mistake: found before any downstream server is started.
  if (options.profile !== undefined) profileTests(config, options.profile);
  const core = await createCore(config, [policy], log, { ...options, mode: "stdio" });
  let session: Session;
  try {
    session = core.openSession({ policy, ...(options.profile !== undefined ? { profile: options.profile } : {}) });
  } catch (err) {
    await core.close();
    throw err;
  }
  log(`ready: connection ${session.connId}${options.profile !== undefined ? `, profile ${options.profile}` : ""}`);
  return {
    server: session.server,
    async close() {
      await session.close();
      await core.close();
    },
  };
}

/** A profile's globs, compiled per server; throws a ConfigError for a profile the config does not have. */
function profileTests(config: GatewayConfig, name: string): Map<string, RegExp[]> {
  const profile = config.profiles?.get(name);
  if (!profile) throw new ConfigError(`the config has no profile "${name}"${config.profiles ? ` (it has ${[...config.profiles.keys()].join(", ")})` : " (it has no \"profiles\")"}`);
  return new Map([...profile].map(([server, globs]) => [server, globs.map(globToRegExp)] as const));
}

/**
 * Connects the downstream servers and opens the state directory, once per process. `policies` are
 * every policy a session may use: the loop-limit counts are kept as long as the longest window needs.
 */
export async function createCore(
  config: GatewayConfig,
  policies: readonly Policy[],
  log: Log = stderrLog,
  options: Pick<GatewayOptions, "env" | "restartBackoffMs"> & { mode?: "stdio" | "http" } = {},
): Promise<GatewayCore> {
  fs.mkdirSync(config.stateDir, { recursive: true, mode: 0o700 });
  const approvals = new ApprovalStore(config.stateDir, config.approvalTtlMs);
  const audit = new AuditLog(path.join(config.stateDir, "audit.jsonl"), config.auditArguments);
  const windows = policies.flatMap((p) => p.repeat.map((limit) => limit.windowMs));
  const repeats = windows.length > 0 ? new RepeatStore(config.stateDir, Math.max(...windows)) : undefined;
  const pins = config.pinTools ? new ToolPins(config.stateDir) : undefined;
  const resultGuard: ResultGuard | undefined = config.resultGuard
    ? { ...(config.resultGuard.leakPolicyFile ? { leak: loadLeakPolicy(config.resultGuard.leakPolicyFile) } : {}), flagInstructions: config.resultGuard.flagInstructions }
    : undefined;
  const exposeTests = new Map(config.servers.flatMap((s) => (s.expose ? [[s.name, s.expose.map(globToRegExp)] as const] : [])));
  const isExposed = (server: string, tool: string): boolean => exposeTests.get(server)?.some((re) => re.test(tool)) ?? true;

  // Header values for remote servers, read once: a missing variable stops the gateway, naming it.
  const env = options.env ?? process.env;
  const missing = config.servers.flatMap((s) => Object.values(s.headersFromEnv ?? {}).filter((variable) => !env[variable]));
  if (missing.length > 0) throw new ConfigError(`set the environment variables named by headersFromEnv: ${[...new Set(missing)].join(", ")}`);
  const headers = new Map(config.servers.map((s) => [s.name, Object.fromEntries(Object.entries(s.headersFromEnv ?? {}).map(([header, variable]) => [header, env[variable] as string]))]));
  // Secrets that must not appear in a log line or an error the agent sees, should a server quote them.
  const secrets = [...headers.values()].flatMap((h) => Object.values(h)).filter((value) => value.length >= 4);
  const scrub = (message: string): string => secrets.reduce((text, secret) => text.split(secret).join("[REDACTED:header]"), message);
  const servers = new Map(config.servers.map((s) => [s.name, s]));
  // The sessions' servers, told when a downstream server's tool list changes, or a server comes or goes.
  const sessions = new Set<Server>();
  const status = new StatusFile(config.stateDir, { mode: options.mode ?? "stdio", startedAt: new Date().toISOString() });
  const downstream = new Downstreams(
    config,
    headers,
    scrub,
    log,
    () => {
      for (const s of sessions) s.sendToolListChanged().catch(() => undefined);
    },
    { status, ...(options.restartBackoffMs !== undefined ? { backoffMs: options.restartBackoffMs } : {}) },
  );
  await downstream.start();
  log(`${downstream.names().length} downstream server(s) (${downstream.names().join(", ")}), state in ${config.stateDir}`);

  function recordTool(event: Parameters<AuditLog["writeTool"]>[0]): void {
    try {
      audit.writeTool(event);
    } catch (err) {
      log(`could not write a ${event.event} line to the audit log: ${errorText(err)}`);
    }
  }

  function openSession(spec: SessionSpec): Session {
    const { policy } = spec;
    // A profile narrows what this connection sees on top of "expose"; a server it does not name shows nothing.
    const profile = spec.profile === undefined ? undefined : profileTests(config, spec.profile);
    const inProfile = (server: string, tool: string): boolean => !profile || (profile.get(server)?.some((re) => re.test(tool)) ?? false);
    // An HTTP gateway opens many sessions over its life, and the audit log keeps them all: 64 random bits
    // keep two sessions from sharing an id. A stdio gateway serves one client per process.
    const connId = `cn-${randomBytes(options.mode === "http" ? 8 : 4).toString("hex")}`;
    let seq = 0;

    // The low-level Server rather than McpServer (the SDK marks Server deprecated for ordinary
    // servers): a proxy republishes tools whose JSON Schemas come from other servers, while
    // McpServer only registers tools that it describes with zod itself.
    const server = new Server({ name: "agent-gate", version: VERSION }, { capabilities: { tools: { listChanged: true } } });
    sessions.add(server);

    server.setRequestHandler(ListToolsRequestSchema, async () => {
      // A server that is not up lists nothing (an optional one due for a try is tried first).
      const lists = await Promise.all(
        downstream.names().map(async (name) => {
          const client = await downstream.client(name);
          return client ? visibleTools(name, client) : [];
        }),
      );
      return { tools: lists.flat() };
    });

    /** A server's tools as this connection sees them: exposed, in its profile, not always blocked, not changed since pinned; with the prefix. */
    async function visibleTools(name: string, client: Client): Promise<Tool[]> {
      let shown = (await listTools(name, client, log, servers.get(name)?.timeoutMs, scrub)).filter((tool) => isExposed(name, tool.name) && inProfile(name, tool.name) && !alwaysBlocked(policy, name, tool.name));
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

    server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const { name, arguments: rawArgs } = request.params;
      const route = splitName(name);
      if (!route || !downstream.has(route.server)) throw new McpError(ErrorCode.InvalidParams, `Unknown tool: ${name}`);
      const client = await downstream.client(route.server);

      const n = ++seq;
      const context = contextFromMeta(request.params._meta);
      const call: ToolCall = { server: route.server, tool: route.tool, args: rawArgs ?? {} };
      let decided: Decided;
      try {
        // A tool the gateway has not listed yet is listed now, so that its definition is pinned (or found changed) first.
        if (client && pins && isExposed(call.server, call.tool) && inProfile(call.server, call.tool) && pins.status(call.server, call.tool) === "unknown") await visibleTools(call.server, client);
        // A server that is not up cannot run the call: it is refused, and recorded, with the reason.
        decided = decide(call, n, context, client ? undefined : downstream.whyDown(call.server));
      } catch (err) {
        // The policy, the approval file or the audit log failed: the call is not run.
        // ponytail: such a failure goes to stderr only; the audit log may be what failed.
        log(`could not check or record a call to ${name}: ${errorText(err)}`);
        return errorResult(`agent-gate could not check or record this call, so it was not run: ${errorText(err)}`);
      }
      if (decided.refusal) return decided.refusal;
      // A rewritten call goes on with its edited arguments; any other exactly as the agent sent it.
      const forwardArgs = decided.rewrittenBy ? decided.args : rawArgs;
      return forwardAndRecord(client as Client, { ...call, args: decided.args }, n, decided.argsHash, forwardArgs, extra.signal, decided.rewrittenBy);
    });

    /** What decide() found: an error result when the call must not run, and the arguments it runs with. */
    interface Decided {
      refusal?: CallToolResult;
      args: Record<string, unknown>;
      argsHash: string;
      rewrittenBy?: string[];
    }

    /** `down`: why the call's server is not up, when it is not. */
    function decide(call: ToolCall, n: number, context: CallContext, down?: string): Decided {
      let verdict: Verdict = !isExposed(call.server, call.tool)
        ? { decision: "block", rule: "not-exposed", why: `the gateway config's "expose" list for server "${call.server}" leaves this tool out` }
        : !inProfile(call.server, call.tool)
          ? { decision: "block", rule: "not-in-profile", why: `profile "${spec.profile}" leaves this tool out, so this connection may not call it` }
          : down !== undefined
            ? { decision: "block", rule: "server-down", why: down }
            : evaluate(policy, call);
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
        const hit = repeats.admit(limits, call.server, call.tool, argsHash, spec.agent);
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
            ...(servers.get(call.server)?.url ? { transport: "http" as const } : {}),
            ...(spec.agent !== undefined ? { agent: spec.agent } : {}),
            ...(spec.profile !== undefined ? { profile: spec.profile } : {}),
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
            ...(spec.agent !== undefined ? { agent: spec.agent } : {}),
          });
          if (outcome.kind === "approved" || outcome.kind === "standing") {
            // the audit line names the approval, or the standing approval, that let it through
            record(true, outcome.kind === "approved" ? outcome.approval.id : outcome.grant.id);
            if (repeats && limited) repeats.record(limits, call.server, call.tool, argsHash, spec.agent);
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
        result = await forward(client, call.server, call.tool, rawArgs, signal, servers.get(call.server)?.timeoutMs, scrub);
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

    let closed = false;
    return {
      server,
      connId,
      // Once: closing the server closes its transport, whose onclose may come back here.
      async close() {
        if (closed) return;
        closed = true;
        sessions.delete(server);
        await server.close().catch(() => undefined);
      },
    };
  }

  return {
    openSession,
    async close() {
      await Promise.allSettled([...sessions].map((s) => s.close()));
      sessions.clear();
      await downstream.close();
      try {
        status.remove();
      } catch (err) {
        log(`could not update the status file: ${errorText(err)}`);
      }
    },
  };
}

function splitName(name: string): { server: string; tool: string } | undefined {
  const at = name.indexOf(SEPARATOR);
  if (at <= 0 || at + SEPARATOR.length === name.length) return undefined;
  return { server: name.slice(0, at), tool: name.slice(at + SEPARATOR.length) };
}

async function forward(
  client: Client,
  server: string,
  tool: string,
  args: Record<string, unknown> | undefined,
  signal: AbortSignal,
  timeoutMs: number | undefined,
  scrub: (message: string) => string,
): Promise<CallToolResult> {
  // client.request rather than client.callTool: callTool would also check the result against the
  // tool's output schema. The gateway passes results through as they are; checking them is the
  // job of the agent's own client.
  // ponytail: the request timeout is the server's timeoutSeconds, else the SDK's default 60 s, and
  // progress notifications are not relayed, so a tool that runs longer than that fails through the gateway.
  try {
    return await client.request(
      { method: "tools/call", params: args === undefined ? { name: tool } : { name: tool, arguments: args } },
      CallToolResultSchema,
      { signal, ...(timeoutMs === undefined ? {} : { timeout: timeoutMs }) },
    );
  } catch (err) {
    // Keep the downstream error's code and data; drop the "MCP error <code>: " prefix that the
    // SDK adds, because the agent's client adds it again.
    if (err instanceof McpError) throw new McpError(err.code, scrub(err.message.replace(/^MCP error -?\d+: /, "")), err.data);
    throw new McpError(ErrorCode.InternalError, `downstream server "${server}" failed: ${scrub(errorText(err))}`);
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
  // Not a decision about the call: the server cannot take it now. The agent may try later.
  if (verdict.rule === "server-down") return `agent-gate could not run this call: ${verdict.why}. (rule server-down) Try again later.`;
  return [
    `agent-gate blocked this call, so it was not run: ${verdict.why} (rule ${verdict.rule})`,
    `Blocked calls cannot be approved. ${DO_NOT_WORK_AROUND}`,
  ].join("\n");
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
