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
// ponytail: plain HTTP and static keys. Bind it to 127.0.0.1 (the default) or put a TLS proxy in front
// (docs/adr/0012-an-http-endpoint-for-agents.md); there is no OAuth flow. Sessions live in memory: a
// restart ends them, and clients start new ones.

import { randomUUID } from "node:crypto";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { hashKey } from "../llm/config.js";
import { isLocalHost, loadPolicy, type GatewayConfig, type HttpAgent } from "./config.js";
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
  const spec = config.http;
  if (!spec) throw new ConfigError('this config has no "http" section; "serve --http" needs one: { "listen": { "host", "port" }, "agents": [...] }');
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
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(spec.port, spec.host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address() as AddressInfo;
  const url = `http://${address.family === "IPv6" ? `[${address.address}]` : address.address}:${address.port}`;
  // The names a client may use for this listener: every loopback spelling for a loopback address, else
  // the address as configured; plus the operator's own (a proxy's public name).
  const port = address.port;
  const allowedHosts = new Set([
    ...(isLocalHost(spec.host) ? [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`] : [`${spec.host.includes(":") ? `[${spec.host}]` : spec.host}:${port}`.toLowerCase()]),
    ...spec.allowedHosts,
  ]);
  const allowedOrigin = (origin: string): boolean => {
    try {
      return allowedHosts.has(new URL(origin).host.toLowerCase());
    } catch {
      return false;
    }
  };

  // Sessions a client left without closing them are closed after a while.
  const sweep = setInterval(() => {
    const before = now() - spec.sessionIdleMs;
    for (const [id, o] of open) if (o.lastSeen < before) void o.transport.close().then(() => open.delete(id));
  }, Math.min(60_000, spec.sessionIdleMs));
  sweep.unref();

  log(`listening on ${url}/mcp for ${agents.size} agent(s), as ${[...allowedHosts].join(", ")}`);
  return {
    url,
    async close() {
      clearInterval(sweep);
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

/** A JSON-RPC error answer, in the shape the SDK's transport uses for its own refusals. */
function reply(res: http.ServerResponse, status: number, code: number, message: string, headers: Record<string, string> = {}): void {
  const text = JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id: null });
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text), ...headers });
  res.end(text);
}

class BodyTooLarge extends Error {}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) reject(new BodyTooLarge());
      else chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
