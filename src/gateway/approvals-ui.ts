// The approvals page: "agent-gate approvals ui" (docs/adr/0014-approvals-web-page.md).
//
// A small web server for the human, on 127.0.0.1 only, that shows the approval queue and takes the
// decisions of "agent-gate approvals approve|deny" through the same code (src/gateway/decisions.ts):
// the same records in approvals.json, the same audit lines, and for an irreversible call the same action
// token (ADR 0013), checked here, on the server, never in the page. It is a process the human starts in
// their own terminal, like the CLI; never part of "agent-gate serve", whose output an agent's client
// can read.
//
// Who can use it: whoever opens the link it prints once, at start, in the terminal that started it.
//   - The link carries a launch key in its fragment (#key=...), which a browser does not send to any
//     server. The page trades it, once, for a session: a session token and a CSRF token, kept in that
//     tab's sessionStorage (scoped to this host and port). A second trade is refused, so a copy of the
//     link found later (history, scrollback) opens nothing; a wrong key does not spend it.
//   - No cookies: a cookie for 127.0.0.1 goes to every port on 127.0.0.1, a server an agent started
//     included; a header that only this page's script sends does not.
//   - Every request: a Host header that names this listener (DNS rebinding). Every API request: the
//     session token (Authorization: Bearer), and Sec-Fetch-Site, when the browser sends it, same-origin.
//     Every state-changing request also: the session's CSRF token (x-agent-gate-csrf), an Origin that is
//     this listener's own, and a JSON body of at most 16 KiB.
//   - The page runs under a Content-Security-Policy that allows only its own script and style (by hash)
//     and requests to this listener, and it puts what the agent sent into the page only as text.
//   - A new port every start, unless --port names one: the page's origin (http://127.0.0.1:<port>) is then
//     new too, so nothing a server that held a port before left in the browser (a service worker, a
//     cached page) can be waiting there to read the link's key.
// What it never does: show an action token anywhere but the read-back of one pending request, to the
// session; fill one in; log one; grant or revoke a standing approval (that stays at the CLI). What it
// prints to the terminal has every control, invisible and direction-changing character escaped.
// ponytail: one session per start. When it ends (60 minutes without a human's request: the page's
// background polls do not count), the link is spent: start it again.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import * as path from "node:path";
import { ApprovalError, ApprovalStore, canonicalJson, cleanNote, isLive, type Approval, type StandingApproval } from "./approvals.js";
import { approvalsPage, HIDDEN_CHARS, pageCsp } from "./approvals-page.js";
import { AuditLog } from "./audit.js";
import type { GatewayConfig } from "./config.js";
import { checkIrreversible, confirmIrreversible, currentUser, decide, describeCall, preview, readBack, refuseToken, TokenRefused, withToken } from "./decisions.js";
import { hostNames } from "./http-server.js";
import { SEPARATOR } from "./server.js";

/** The only address it listens on: this machine. */
const HOST = "127.0.0.1";
const MAX_BODY_BYTES = 16 * 1024;
const SESSION_IDLE_MS = 60 * 60 * 1000;
const APPROVAL_PATH = /^\/api\/approvals\/([A-Za-z0-9-]{1,40})(?:\/(approve|deny))?$/;
const APPROVAL_ID = /^ap-[0-9a-f]{8}$/;

export interface ApprovalsUiOptions {
  /** The port on 127.0.0.1. Default 0: a free one, new every start (a fixed port keeps the same origin). */
  port?: number;
  /** Where it reports decisions and refusals: the human's terminal. It is never given a secret. */
  log?: (line: string) => void;
  /** For tests: the clock of the session's idle time and of the approval store. */
  now?: () => number;
  /** A session with no request from the human (polls do not count) for this long ends. Default 60 minutes. */
  sessionIdleMs?: number;
}

export interface ApprovalsUi {
  /** http://127.0.0.1:<port> */
  url: string;
  /** The link with the launch key: printed once, to the terminal that started the page. */
  launchUrl: string;
  close(): Promise<void>;
}

interface UiSession {
  token: string;
  csrf: string;
  lastSeen: number;
}

/** What a handler answers: a status and a JSON body. */
interface Answer {
  status: number;
  body: Record<string, unknown>;
}

const COMMON_HEADERS: Readonly<Record<string, string>> = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
};

export async function startApprovalsUi(config: GatewayConfig, options: ApprovalsUiOptions = {}): Promise<ApprovalsUi> {
  const now = options.now ?? Date.now;
  const print = options.log ?? (() => undefined);
  /** Everything it prints is one line, with what an agent or a request could have put in it escaped. */
  const log = (line: string): void => print(terminalSafe(line));
  const idleMs = options.sessionIdleMs ?? SESSION_IDLE_MS;
  const store = new ApprovalStore(config.stateDir, config.approvalTtlMs, now);
  const audit = new AuditLog(path.join(config.stateDir, "audit.jsonl"));
  const page = approvalsPage({ mode: "live" });
  const pageHeaders = { ...COMMON_HEADERS, "content-type": "text/html; charset=utf-8", "content-security-policy": pageCsp("live"), "content-length": String(Buffer.byteLength(page)) };
  const firstKey = secret();
  /** The launch key until the page trades it for a session; then undefined, for good. */
  let launchKey: string | undefined = firstKey;
  let session: UiSession | undefined;
  let allowedHosts = new Set<string>();

  function send(res: http.ServerResponse, answer: Answer): void {
    const text = JSON.stringify(answer.body);
    res.writeHead(answer.status, {
      ...COMMON_HEADERS,
      "content-type": "application/json; charset=utf-8",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      "content-length": Buffer.byteLength(text),
    });
    res.end(text);
  }

  /** Refuses a request, and tells the terminal: a refusal is the human's business. Nothing secret is in `why`. */
  function refuse(req: http.IncomingMessage, res: http.ServerResponse, status: number, why: string, extra: Record<string, unknown> = {}): void {
    log(`refused ${cleanNote(req.method ?? "", 10) ?? "?"} ${cleanNote((req.url ?? "").split("?")[0], 80) ?? "/"}: ${why} (${status})`);
    send(res, { status, body: { error: why, ...extra } });
  }

  /**
   * The session the request carries, or undefined. A session with no request from the human for idleMs
   * has ended; the page's background polls (x-agent-gate-poll) are checked but do not count as one.
   */
  function sessionOf(req: http.IncomingMessage): UiSession | undefined {
    const match = /^Bearer[ \t]+(\S+)[ \t]*$/i.exec(req.headers.authorization ?? "");
    if (!session || match?.[1] === undefined || !sameSecret(match[1], session.token)) return undefined;
    if (now() - session.lastSeen > idleMs) {
      session = undefined;
      log(`the page's session ended: unused for ${Math.round(idleMs / 60_000)} minutes. Start agent-gate approvals ui again for a new link.`);
      return undefined;
    }
    if (req.headers["x-agent-gate-poll"] !== "1") session.lastSeen = now();
    return session;
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const pathname = (req.url ?? "/").split("?")[0] ?? "/";
    // DNS rebinding: a page that gets a browser to send requests here sends its own name as Host.
    const host = (req.headers.host ?? "").toLowerCase();
    if (!allowedHosts.has(host)) return refuse(req, res, 403, `Host ${JSON.stringify(host.slice(0, 100))} is not one this page answers to`);
    if (pathname === "/") {
      if (req.method !== "GET" && req.method !== "HEAD") return refuse(req, res, 405, "the page is read with GET");
      res.writeHead(200, pageHeaders);
      res.end(req.method === "HEAD" ? undefined : page);
      return;
    }
    if (pathname === "/favicon.ico") return send(res, { status: 404, body: { error: "no icon" } });
    if (!pathname.startsWith("/api/")) return refuse(req, res, 404, "not found");
    // A browser says where a request comes from; this API answers only its own page.
    const site = req.headers["sec-fetch-site"];
    if (site !== undefined && site !== "same-origin") return refuse(req, res, 403, "requests from other sites are not accepted");

    if (req.method === "POST") {
      const origin = req.headers.origin;
      if (origin === undefined || !ownOrigin(origin)) return refuse(req, res, 403, "a request that changes anything must come from this page: the Origin header is missing or not this page's");
      if (!/^application\/json(?:\s*;.*)?$/i.test(req.headers["content-type"] ?? "")) return refuse(req, res, 415, "send JSON (content-type: application/json)");
      let body: Record<string, unknown>;
      try {
        body = await readJsonBody(req);
      } catch (err) {
        if (err instanceof BodyTooLarge) return refuse(req, res, 413, `the body is larger than ${MAX_BODY_BYTES} bytes`);
        return refuse(req, res, 400, "the body is not a JSON object");
      }
      if (pathname === "/api/session") return send(res, openSession(req, body));
      const current = sessionOf(req);
      if (!current) return refuse(req, res, 401, "no session: open the link that agent-gate approvals ui printed in its terminal", { session: "none" });
      const csrf = req.headers["x-agent-gate-csrf"];
      if (typeof csrf !== "string" || !sameSecret(csrf, current.csrf)) return refuse(req, res, 403, "the CSRF token is missing or not this session's, so nothing was changed");
      const match = APPROVAL_PATH.exec(pathname);
      if (!match?.[2]) return refuse(req, res, 404, "not found");
      return send(res, decision(match[1] as string, match[2] as "approve" | "deny", body));
    }
    if (req.method !== "GET") return refuse(req, res, 405, "this API takes GET and POST only");
    if (!sessionOf(req)) return refuse(req, res, 401, "no session: open the link that agent-gate approvals ui printed in its terminal", { session: "none" });
    if (pathname === "/api/approvals") return send(res, { status: 200, body: queue() });
    const match = APPROVAL_PATH.exec(pathname);
    if (!match || match[2] !== undefined) return refuse(req, res, 404, "not found");
    return send(res, readOne(match[1] as string));
  }

  /** POST /api/session: the launch key, traded once for a session. A wrong key does not spend it. */
  function openSession(req: http.IncomingMessage, body: Record<string, unknown>): Answer {
    if (launchKey === undefined) {
      log("refused POST /api/session: the link was used already (403)");
      return { status: 403, body: { error: "This link was used already: it opens one session, in the tab that opened it first. Start agent-gate approvals ui again for a new link." } };
    }
    if (!sameSecret(body.key, launchKey)) {
      log(`refused POST /api/session from ${cleanNote(req.headers["user-agent"] ?? "?", 60) ?? "?"}: not the key of this page's link (401)`);
      return { status: 401, body: { error: "That is not the key of the link agent-gate approvals ui printed." } };
    }
    launchKey = undefined;
    session = { token: secret(), csrf: secret(), lastSeen: now() };
    log("the link was opened: one browser session; the link is now spent.");
    return { status: 200, body: { session: session.token, csrf: session.csrf, idleMinutes: Math.round(idleMs / 60_000) } };
  }

  /** GET /api/approvals: the requests waiting for a decision, and the standing approvals in force. Never a token. */
  function queue(): Record<string, unknown> {
    const t = now();
    const pending = store
      .list()
      .filter((a) => a.status === "pending" && isLive(a, t))
      .map((a) => summary(a, t));
    const standing = store
      .standing()
      .filter((g) => g.status === "active" && g.used < g.maxUses && t < Date.parse(g.expiresAt))
      .map(grantSummary);
    return { now: new Date(t).toISOString(), pending, standing };
  }

  /** GET /api/approvals/<id>: the read-back, as the CLI prints it, and for a pending irreversible request its action token. */
  function readOne(id: string): Answer {
    if (!APPROVAL_ID.test(id)) return { status: 404, body: { error: `no approval with id ${id}` } };
    let a: Approval;
    try {
      a = store.get(id);
    } catch (err) {
      if (err instanceof ApprovalError) return { status: 404, body: { error: err.message } };
      throw err;
    }
    const t = now();
    // The token only for a request that can still be confirmed with it; withToken() leaves it out otherwise.
    const shown: { actionToken?: string | null; actionTokenError?: string } = a.status === "pending" && isLive(a, t) ? withToken(a, config) : {};
    return {
      status: 200,
      body: {
        approval: { ...summary(a, t), args: a.args },
        readBack: readBack(a, config, t),
        confirm: a.irreversible ? "token" : "typed",
        ...(a.irreversible ? {} : { code: a.id.slice(-4) }),
        ...(shown.actionToken !== undefined ? { actionToken: shown.actionToken } : {}),
        ...(shown.actionTokenError !== undefined ? { actionTokenError: shown.actionTokenError } : {}),
      },
    };
  }

  /**
   * POST /api/approvals/<id>/approve|deny. The body names the call that was read back (argsHash): a
   * record that changed since is not decided. Approve takes what the CLI's read-back asks for: the
   * action token for an irreversible request, else the last 4 characters of the id.
   */
  function decision(id: string, action: "approve" | "deny", body: Record<string, unknown>): Answer {
    if (id.startsWith("sa-")) return { status: 400, body: { error: "standing approvals are granted and revoked at the CLI (approvals grant, approvals deny sa-...)" } };
    if (!APPROVAL_ID.test(id)) return { status: 404, body: { error: `no approval with id ${id}` } };
    const note = action === "approve" ? body.note : body.reason;
    if (note !== undefined && typeof note !== "string") return { status: 400, body: { error: `${action === "approve" ? "note" : "reason"} must be text` } };
    if (typeof body.argsHash !== "string") return { status: 400, body: { error: "send the argsHash of the call you read back, so that only that call is decided" } };
    const by = currentUser();
    try {
      const request = store.get(id);
      const changed = `${id} is not the call you read back: its arguments are not the ones you saw, so nothing was decided; read it back again`;
      // An irreversible approval first passes the CLI's checks, in the CLI's order (used, not pending, expired,
      // a record that is not its call, no key); only then does a call other than the one read back count as "changed".
      // Anything else is compared while it can still be decided (a pending request; for a denial, also an approval not
      // used yet); otherwise decide() says why, as at the CLI.
      const tokens = action === "approve" && request.irreversible ? checkIrreversible(audit, config, request, by, now()).tokens : undefined;
      if (body.argsHash !== request.argsHash) {
        if (tokens) throw refuseToken(audit, request, "changed", changed, by);
        const decidable = isLive(request, now()) && (request.status === "pending" || (action === "deny" && request.status === "approved"));
        if (decidable) return { status: 409, body: { error: changed } };
      }
      if (action === "deny") {
        const denied = decide(store, audit, id, "denied", note);
        log(`denied ${describeCall(denied)}${denied.decisionNote ? `; the agent is shown the reason ${JSON.stringify(denied.decisionNote)}` : ""}`);
        const reason = denied.decisionNote ? ` It is also shown your reason: ${JSON.stringify(denied.decisionNote)}` : "";
        return { status: 200, body: { decided: summary(denied, now()), message: `denied ${describeCall(denied)}. If the agent makes this call again, it is told that a human said no.${reason}` } };
      }
      let approved: Approval;
      if (tokens) {
        const typed = typeof body.token === "string" ? body.token : "";
        if (typed.trim() === "") {
          throw refuseToken(audit, request, "no-token", `${id} is for an irreversible action (rule ${request.rule}), so a yes is not enough: type its action token, shown under the call in the read-back`, by);
        }
        approved = confirmIrreversible(store, audit, request, tokens, typed, note, by);
      } else {
        if (body.token !== undefined && body.token !== "") return { status: 400, body: { error: `${id} is not for an irreversible action, so it has no action token; approve it with the last 4 characters of its id` } };
        // As at the CLI: a request that is no longer pending or has expired skips this, and decide() says why.
        if (request.status === "pending" && isLive(request, now())) {
          const code = id.slice(-4);
          const typed = typeof body.confirm === "string" ? body.confirm.trim() : "";
          if (typed !== code && typed !== id) return { status: 400, body: { error: `${JSON.stringify(typed.slice(0, 40))} is not ${code}, so ${id} was not approved` } };
        }
        approved = decide(store, audit, id, "approved", note, "typed");
      }
      log(`approved ${describeCall(approved)}${approved.confirmation === "token" ? ", confirmed with its action token" : ""}`);
      return { status: 200, body: { decided: summary(approved, now()), message: `approved ${describeCall(approved)}. The agent can now make this exact call once, until ${approved.expiresAt}.` } };
    } catch (err) {
      if (err instanceof TokenRefused) {
        log(`refused to approve ${id}: ${err.reason}`);
        return { status: 409, body: { error: err.message, refused: err.reason } };
      }
      if (err instanceof ApprovalError) return { status: err.message.startsWith("no approval with id") ? 404 : 409, body: { error: err.message } };
      throw err;
    }
  }

  function ownOrigin(origin: string): boolean {
    try {
      const url = new URL(origin);
      return url.protocol === "http:" && allowedHosts.has(url.host.toLowerCase());
    } catch {
      return false;
    }
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      log(`a request failed: ${cleanNote(err instanceof Error ? err.message : String(err), 300) ?? "?"}`);
      if (!res.headersSent) send(res, { status: 500, body: { error: `agent-gate failed while handling this request: ${err instanceof Error ? err.message : String(err)}` } });
      else res.destroy();
    });
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, HOST, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const { port } = server.address() as AddressInfo;
  allowedHosts = hostNames(HOST, port);
  const url = `http://${HOST}:${port}`;
  return {
    url,
    launchUrl: `${url}/#key=${firstKey}`,
    async close() {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      });
    },
  };
}

/**
 * A field of a record as text. approvals.json is read as it is, so a field may hold anything; the page is
 * handed text, never an object whose own toString it would call.
 */
function plain(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return "?";
  }
}

/** A request as the page lists it: its arguments as one line, cut like "approvals list" cuts them. */
function summary(a: Approval, now: number): Record<string, unknown> {
  return {
    id: plain(a.id),
    call: `${plain(a.server)}${SEPARATOR}${plain(a.tool)}`,
    server: plain(a.server),
    tool: plain(a.tool),
    rule: plain(a.rule),
    why: plain(a.why),
    status: plain(a.status),
    expired: a.status !== "used" && !isLive(a, now),
    irreversible: a.irreversible === true,
    ...(a.agent !== undefined ? { agent: plain(a.agent) } : {}),
    ...(a.agentPath ? { agentPath: plain(a.agentPath) } : {}),
    argsPreview: preview(canonicalJson(a.args)),
    argsHash: plain(a.argsHash),
    ...(a.files ? { files: a.files.map((f) => ({ argument: f.argument, path: f.path, sha256: f.sha256 })) } : {}),
    ...(a.alsoMatched ? { alsoMatched: a.alsoMatched } : {}),
    ...(a.rewrittenBy ? { rewrittenBy: a.rewrittenBy } : {}),
    createdAt: a.createdAt,
    expiresAt: a.expiresAt,
    ...(a.decidedAt ? { decidedAt: a.decidedAt } : {}),
    ...(a.decidedBy ? { decidedBy: a.decidedBy } : {}),
    ...(a.decisionNote ? { decisionNote: a.decisionNote } : {}),
    ...(a.confirmation ? { confirmation: a.confirmation } : {}),
  };
}

function grantSummary(g: StandingApproval): Record<string, unknown> {
  return {
    id: plain(g.id),
    call: `${plain(g.server)}${SEPARATOR}${plain(g.tool)}`,
    args: g.args,
    ...(g.agent !== undefined ? { agent: plain(g.agent) } : {}),
    used: typeof g.used === "number" ? g.used : plain(g.used),
    maxUses: typeof g.maxUses === "number" ? g.maxUses : plain(g.maxUses),
    expiresAt: plain(g.expiresAt),
    ...(g.decidedBy ? { decidedBy: plain(g.decidedBy) } : {}),
    ...(g.decisionNote ? { decisionNote: plain(g.decisionNote) } : {}),
  };
}

/** One line for the terminal: line breaks, tabs, and control, invisible and direction-changing characters as \uXXXX. */
export function terminalSafe(text: string): string {
  const escape = (found: string): string => found.split("").map((unit) => `\\u${unit.charCodeAt(0).toString(16).padStart(4, "0")}`).join("");
  return text.replace(HIDDEN_CHARS, escape).replace(/[\t\n]/g, escape);
}

/** 32 random bytes, base64url: a launch key, a session token or a CSRF token. */
function secret(): string {
  return randomBytes(32).toString("base64url");
}

/** Compares a presented secret with the real one in constant time, whatever its length or type. */
function sameSecret(given: unknown, expected: string): boolean {
  if (typeof given !== "string") return false;
  return timingSafeEqual(createHash("sha256").update(given).digest(), createHash("sha256").update(expected).digest());
}

class BodyTooLarge extends Error {}

/** The body as a JSON object, at most MAX_BODY_BYTES of it. */
function readJsonBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
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
    req.on("end", () => {
      if (size > MAX_BODY_BYTES) return reject(new BodyTooLarge());
      try {
        const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("not an object");
        resolve(value as Record<string, unknown>);
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}
