// The MCP gateway for agents that connect over the network: "agent-gate serve --http".
//
// It listens on Streamable HTTP at /mcp (the MCP transport for remote servers) and serves many agents
// from one process. Every request carries an agent's key ("Authorization: Bearer <key>"); the config
// holds only each key's SHA-256 ("http.agents"), looked up by its hash as the LLM gateway does. An
// agent may have its own policy file and profile. Each MCP session gets an SDK Server of its own (its
// own connId and call numbers in the audit log), bound to the agent that opened it: another agent's
// key cannot use that session id. The downstream servers and the state directory are shared
// (src/gateway/server.ts, createCore), and so is the one-process rule of ADR 0003. An approval is
// bound to the agent whose call asked for it (approvals.ts), so one agent's yes never lets another
// agent's identical call run.
//
// Before anything else, the Host header must be one of the listen address's own names, or one of
// "http.allowedHosts" (DNS rebinding: a web page that makes a browser send requests to 127.0.0.1),
// and so must an Origin header when there is one. Then the key, then the session.
// Sessions are bounded: an agent may hold "maxSessionsPerAgent" open sessions (default 16; a new one
// closes that agent's least recently used), and the gateway "maxSessions" in all (default 256; past
// that a new session is refused with 503), so no key holder can grow the shared process without end.
// A session nobody used for "sessionIdleMinutes" is closed, on a timer and whenever a session opens.
// ponytail: plain HTTP and static keys. Bind it to 127.0.0.1 (the default) or put a TLS proxy in front
// (docs/adr/0012-an-http-endpoint-for-agents.md); there is no OAuth flow. Sessions live in memory: a
// restart ends them, and clients start new ones.

import { randomUUID } from "node:crypto";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { hashKey } from "../llm/config.js";
import { isLocalHost, loadPolicy, type GatewayConfig, type HttpAgent, type HttpConfig } from "./config.js";
import type { Policy } from "./policy.js";
import { createCore, stderrLog, type GatewayOptions, type Log, type Session } from "./server.js";
import { ConfigError } from "./validate.js";

export interface HttpGateway {
  /** For example http://127.0.0.1:8788 ; the endpoint is this plus /mcp. */
  url: string;
  close(): Promise<void>;
}

/** The most a request body may be: tool arguments can be long, but not unbounded. */
const MAX_BODY_BYTES = 4 * 1024 * 1024;

interface Open {
  transport: StreamableHTTPServerTransport;
  session: Session;
  agent: string;
  lastSeen: number;
}

export async function startHttpGateway(config: GatewayConfig, log: Log = stderrLog, options: Pick<GatewayOptions, "env" | "restartBackoffMs"> & { now?: () => number } = {}): Promise<HttpGateway> {
  if (!config.http) throw new ConfigError('this config has no "http" section; "serve --http" needs one: { "listen": { "host", "port" }, "agents": [...] }');
  const spec: HttpConfig = config.http;
  const now = options.now ?? Date.now;
  // Each agent's policy, read once; agents that name the same file share it.
  const policies = new Map<string, Policy>();
  const policyOf = (file: string): Policy => {
    let policy = policies.get(file);
    if (!policy) policies.set(file, (policy = loadPolicy(file)));
    return policy;
  };
  const agents = new Map(spec.agents.map((a) => [a.sha256, { ...a, policy: policyOf(a.policyFile ?? config.policyFile) }] as const));
  const core = await createCore(config, [...policies.values()], log, { ...options, mode: "http" });
  const open = new Map<string, Open>();

  /** Closes a session the gateway gives up on: idle too long, or the oldest of an agent at its cap. */
  function closeSession(id: string, why: string): void {
    const o = open.get(id);
    if (!o) return;
    open.delete(id);
    log(`session ${o.session.connId} of agent "${o.agent}" closed: ${why}`);
    void o.transport.close();
  }

  /** Closes the sessions nobody used for sessionIdleMs. */
  function sweep(): void {
    const before = now() - spec.sessionIdleMs;
    for (const [id, o] of [...open]) if (o.lastSeen < before) closeSession(id, `unused for ${spec.sessionIdleMs / 60_000} min`);
  }

  /**
   * Room for one more session of this agent: at its own cap, its least recently used session is closed
   * (its client gets 404 and starts a new one); at the gateway's cap, nothing is closed for it, because
   * one agent must not end another's sessions. False: refuse.
   */
  function makeRoom(agent: string): boolean {
    sweep();
    const own = [...open].filter(([, o]) => o.agent === agent).sort(([, a], [, b]) => a.lastSeen - b.lastSeen);
    if (own.length >= spec.maxSessionsPerAgent) {
      for (const [id] of own.slice(0, own.length - spec.maxSessionsPerAgent + 1)) closeSession(id, `agent "${agent}" opened more than maxSessionsPerAgent (${spec.maxSessionsPerAgent}); this was its least recently used`);
    }
    return open.size < spec.maxSessions;
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if ((req.url ?? "/").split("?")[0] !== "/mcp") return reply(res, 404, -32000, "agent-gate serves MCP at /mcp");
    // DNS rebinding: a browser tricked into calling this address sends a Host (and an Origin) of the attacker's name.
    const host = (req.headers.host ?? "").toLowerCase();
    if (!allowedHosts.has(host)) return reply(res, 403, -32000, `agent-gate: Host ${JSON.stringify(host.slice(0, 100))} is not one this gateway answers to`);
    const origin = req.headers.origin;
    if (origin !== undefined && !allowedOrigin(origin)) return reply(res, 403, -32000, "agent-gate: requests from this Origin are not accepted");

    const agent = authenticate(req.headers.authorization);
    if (!agent) {
      log(`401 ${req.method ?? ""} /mcp: missing or unknown agent key`);
      return reply(res, 401, -32000, "agent-gate: missing or unknown agent key; send it as Authorization: Bearer <key>", { "www-authenticate": 'Bearer realm="agent-gate-mcp"' });
    }

    const sessionId = req.headers["mcp-session-id"];
    let body: unknown;
    if (req.method === "POST") {
      try {
        body = JSON.parse(await readBody(req));
      } catch (err) {
        if (err instanceof BodyTooLarge) return reply(res, 413, -32000, `agent-gate: the request body is larger than ${MAX_BODY_BYTES} bytes`, { connection: "close" });
        return reply(res, 400, -32700, "agent-gate: the request body is not JSON");
      }
    }
    if (typeof sessionId === "string") {
      const found = open.get(sessionId);
      // Another agent's session is answered like one that does not exist: its id is not a key.
      if (!found || found.agent !== agent.name) return reply(res, 404, -32001, "Session not found");
      found.lastSeen = now();
      return found.transport.handleRequest(req, res, body);
    }
    // No session yet: only an initialize request may start one.
    if (req.method !== "POST" || !isInitializeRequest(body)) return reply(res, 400, -32000, "Bad Request: send an initialize request first, then the mcp-session-id header it returns");
    if (!makeRoom(agent.name)) {
      log(`503 initialize from agent "${agent.name}": ${open.size} sessions open, maxSessions is ${spec.maxSessions}`);
      return reply(res, 503, -32000, `agent-gate: the gateway has ${spec.maxSessions} sessions open, the most it keeps (maxSessions); try again later`, { "retry-after": "60" });
    }
    const session = core.openSession({ policy: agent.policy, ...(agent.profile !== undefined ? { profile: agent.profile } : {}), agent: agent.name });
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      // One JSON answer per request: the gateway relays no progress or server-to-client requests.
      enableJsonResponse: true,
      onsessioninitialized: (id) => {
        open.set(id, { transport, session, agent: agent.name, lastSeen: now() });
        log(`session ${session.connId} opened for agent "${agent.name}"`);
      },
    });
    transport.onclose = () => {
      const id = transport.sessionId;
      if (id !== undefined && open.delete(id)) log(`session ${session.connId} of agent "${agent.name}" closed`);
      void session.close();
    };
    await session.server.connect(transport);
    await transport.handleRequest(req, res, body);
    // An initialize that failed opened nothing.
    if (transport.sessionId === undefined || !open.has(transport.sessionId)) await transport.close();
  }

  function authenticate(header: string | undefined): (HttpAgent & { policy: Policy }) | undefined {
    const match = /^Bearer[ \t]+(\S+)[ \t]*$/i.exec(header ?? "");
    return match?.[1] === undefined ? undefined : agents.get(hashKey(match[1]));
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      log(`request failed: ${err instanceof Error ? err.message : String(err)}`);
      if (!res.headersSent) reply(res, 500, -32603, "agent-gate failed while handling this request");
      else res.destroy();
    });
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(spec.port, spec.host, () => {
        server.off("error", reject);
        resolve();
      });
    });
  } catch (err) {
    // A port in use, or an address this machine does not have: stop the downstream servers and drop
    // this process's status entry, so nothing keeps the process alive or claims it is serving.
    await core.close();
    throw err;
  }
  const address = server.address() as AddressInfo;
  const url = `http://${address.family === "IPv6" ? `[${address.address}]` : address.address}:${address.port}`;
  const allowedHosts = hostNames(spec.host, address.port, spec.allowedHosts);
  const allowedOrigin = (origin: string): boolean => {
    try {
      return allowedHosts.has(new URL(origin).host.toLowerCase());
    } catch {
      return false;
    }
  };

  // Sessions a client left without closing them are closed after a while.
  const sweeper = setInterval(sweep, Math.min(60_000, spec.sessionIdleMs));
  sweeper.unref();

  log(`listening on ${url}/mcp for ${agents.size} agent(s), as ${[...allowedHosts].join(", ")}`);
  return {
    url,
    async close() {
      clearInterval(sweeper);
      await Promise.allSettled([...open.values()].map((o) => o.transport.close()));
      open.clear();
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      });
      await core.close();
    },
  };
}

/**
 * The Host header values this listener answers to: the address as configured (bracketed for IPv6),
 * every loopback spelling when that address is a loopback one, and the operator's own (a proxy's
 * public name). Lowercase.
 */
export function hostNames(host: string, port: number, extra: readonly string[] = []): Set<string> {
  const configured = host.replace(/^\[|\]$/g, "");
  return new Set([
    `${configured.includes(":") ? `[${configured}]` : configured}:${port}`.toLowerCase(),
    ...(isLocalHost(host) ? [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`] : []),
    ...extra.map((h) => h.toLowerCase()),
  ]);
}

/** A JSON-RPC error answer, in the shape the SDK's transport uses for its own refusals. */
function reply(res: http.ServerResponse, status: number, code: number, message: string, headers: Record<string, string> = {}): void {
  const text = JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id: null });
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text), ...headers });
  res.end(text);
}

class BodyTooLarge extends Error {}

/**
 * The body, at most MAX_BODY_BYTES of it. A larger one is read to its end without being kept, so the
 * client is still listening when the 413 comes (an answer sent while it is still sending can be lost
 * to a connection reset); past twice the limit the connection is cut instead.
 */
function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size <= MAX_BODY_BYTES) chunks.push(chunk);
      else if (size > 2 * MAX_BODY_BYTES) {
        reject(new BodyTooLarge());
        req.destroy();
      }
    });
    req.on("end", () => (size > MAX_BODY_BYTES ? reject(new BodyTooLarge()) : resolve(Buffer.concat(chunks).toString("utf8"))));
    req.on("error", reject);
  });
}
