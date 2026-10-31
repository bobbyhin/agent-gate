// The LLM gateway: an OpenAI-compatible HTTP endpoint in front of one or more upstream providers.
//
//   POST /v1/chat/completions   Authorization: Bearer <gateway key>, optional x-agent-task header
//   GET  /healthz
//   GET  /metrics               only with "metrics" in the config (metrics.ts): behind a key of its
//                               own here, or without one on a loopback listener of its own
//
// Every chat completion goes through these steps, in this order:
//   1. authenticate the gateway key                        401 if it is missing or unknown
//   2. read and check the body                             400, or 413 if it is too large
//   3. route: upstream + model from alias and task         404 if no route applies
//   4. leak guard: block or redact secrets                 400 if a block rule matches
//   5. reserve the estimated cost against the key's caps   429 if it does not fit
//   6. call the upstream; retries, then the fallback       502 or 504 if every attempt fails,
//                                                          429 if the upstreams are rate limiting
//   7. settle the real cost from "usage" (or release it)
//   8. leak guard on the answer (scanResponses)             502 if a block rule matches; it was paid for
//   9. write one usage line, answer
// Nothing is sent upstream until steps 1 to 5 have passed. Upstream API keys are read from the
// environment once, at startup; each is sent only to its own upstream and is never logged or
// returned, and client headers (including the client's Authorization) are never forwarded.
// Tracing: a valid W3C traceparent from the client puts the call in the client's trace; without
// one, the call starts a new trace. Either way the gateway sends upstream a traceparent of its own
// (the trace id, the gateway's span id), returns the trace id as x-agent-gate-trace-id, and writes
// both to the usage line.

import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import * as path from "node:path";
import { performance } from "node:perf_hooks";
import { cleanNote } from "../gateway/approvals.js";
import { contextFromHeaders, parseTraceparent } from "../gateway/context.js";
import { ConfigError } from "../gateway/validate.js";
import { costUsd, estimateInputTokens, formatUsd, Ledger, roundUsd, type ReserveOutcome, type SettleOutcome } from "./budget.js";
import { hashKey, type GatewayKey, type LlmConfig } from "./config.js";
import { guardMessages, guardResponse, messageTexts, type LeakPolicy } from "./leak-guard.js";
import { CONTENT_TYPE, Metrics } from "./metrics.js";
import { route } from "./routing.js";
import { callUpstreams } from "./upstream.js";
import { UsageLog, type UsageEntry } from "./usage-log.js";

export interface LlmGatewayOptions {
  /** Where the upstream API keys are read from (default: process.env). */
  env?: NodeJS.ProcessEnv;
  log?: (message: string) => void;
  /** The clock for budgets and usage timestamps (default: Date.now). */
  now?: () => number;
  fetch?: typeof fetch;
}

export interface LlmGateway {
  /** For example http://127.0.0.1:8787 */
  url: string;
  /** The keyless metrics listener (config metrics.listen), for example http://127.0.0.1:9464 */
  metricsUrl?: string;
  close(): Promise<void>;
}

type ExtraHeaders = Record<string, string | number>;
type Outcome = Partial<Pick<UsageEntry, "error" | "rule" | "side" | "inputTokens" | "outputTokens" | "costUsd" | "usage" | "attempts" | "fallback" | "upstream429" | "settle" | "responseRedacted">>;

/** The x-agent-task header is kept in the usage line on one line, at most this long. */
const TASK_MAX_CHARS = 100;

const stderrLog = (message: string): void => {
  process.stderr.write(`[agent-gate] ${message}\n`);
};

export async function startLlmGateway(config: LlmConfig, policy: LeakPolicy, options: LlmGatewayOptions = {}): Promise<LlmGateway> {
  const env = options.env ?? process.env;
  const log = options.log ?? stderrLog;
  const now = options.now ?? Date.now;

  // A missing key stops the gateway now, instead of failing calls later. The error names the
  // variable, never a value.
  const apiKeys = new Map<string, string>();
  const missing = new Set<string>();
  for (const upstream of config.upstreams.values()) {
    const value = env[upstream.apiKeyEnv];
    if (value === undefined || value === "") missing.add(upstream.apiKeyEnv);
    else apiKeys.set(upstream.name, value);
  }
  if (missing.size > 0) throw new ConfigError(`set the environment variables named by apiKeyEnv: ${[...missing].join(", ")}`);

  fs.mkdirSync(config.stateDir, { recursive: true, mode: 0o700 });
  const ledger = openLedger(config, now);
  const usageLog = new UsageLog(path.join(config.stateDir, "usage.jsonl"));
  const keysByHash = new Map(config.keys.map((key) => [key.sha256, key]));
  const metrics = new Metrics();

  /** GET /metrics. On the gateway's port it needs the metrics key; on its own loopback listener it does not. */
  function serveMetrics(req: http.IncomingMessage, res: http.ServerResponse, withKey: boolean): void {
    if (withKey && config.metrics?.sha256 === undefined) return send(res, 404, apiError("not_found", "agent-gate serves POST /v1/chat/completions and GET /healthz"));
    if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, apiError("method_not_allowed", "use GET /metrics"), { allow: "GET, HEAD" });
    if (withKey) {
      const match = /^Bearer[ \t]+(\S+)[ \t]*$/i.exec(req.headers.authorization ?? "");
      if (match?.[1] === undefined || hashKey(match[1]) !== config.metrics?.sha256) {
        return send(res, 401, apiError("invalid_api_key", "agent-gate: GET /metrics needs the metrics key, as Authorization: Bearer <key>"), {
          "www-authenticate": 'Bearer realm="agent-gate-metrics"',
        });
      }
    }
    let text: string;
    try {
      text = metrics.render(ledger.usage(config.keys));
    } catch (err) {
      log(`could not read the ledger for /metrics: ${errorText(err)}`);
      return send(res, 500, apiError("gateway_error", "agent-gate could not read the budget ledger, so it has no metrics to give"));
    }
    res.writeHead(200, { "content-type": CONTENT_TYPE, "content-length": Buffer.byteLength(text) });
    res.end(req.method === "HEAD" ? undefined : text);
  }

  /**
   * Looking a key up by its SHA-256 also means secrets are never compared byte by byte: timing
   * could at most tell how much of a hash matched, which says nothing about the key.
   */
  function authenticate(header: string | undefined): GatewayKey | undefined {
    const match = /^Bearer[ \t]+(\S+)[ \t]*$/i.exec(header ?? "");
    return match?.[1] === undefined ? undefined : keysByHash.get(hashKey(match[1]));
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const started = performance.now();
    const id = `req-${randomBytes(4).toString("hex")}`;
    res.setHeader("x-agent-gate-request-id", id);
    const pathname = (req.url ?? "/").split("?")[0];

    if (pathname === "/healthz") {
      // ponytail: liveness only. It does not call the upstreams; a probe that did would spend money.
      if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, apiError("method_not_allowed", "use GET /healthz"), { allow: "GET, HEAD" });
      return send(res, 200, { status: "ok" });
    }
    if (pathname === "/metrics") return serveMetrics(req, res, true);
    if (pathname !== "/v1/chat/completions") return send(res, 404, apiError("not_found", "agent-gate serves POST /v1/chat/completions and GET /healthz"));
    if (req.method !== "POST") return send(res, 405, apiError("method_not_allowed", "use POST /v1/chat/completions"), { allow: "POST" });

    const key = authenticate(req.headers.authorization);
    if (!key) {
      log(`401 ${id}: missing or unknown gateway key`);
      return send(res, 401, apiError("invalid_api_key", "agent-gate: missing or unknown gateway key; send it as Authorization: Bearer <key>"), {
        "www-authenticate": 'Bearer realm="agent-gate"',
      });
    }

    // The client's correlation headers, checked (src/gateway/context.ts), and this call's trace.
    const context = contextFromHeaders(req.headers);
    const traceId = context.traceId ?? randomBytes(16).toString("hex");
    const spanId = randomBytes(8).toString("hex");
    const traceparent = `00-${traceId}-${spanId}-${parseTraceparent(req.headers.traceparent)?.flags ?? "00"}`;
    res.setHeader("x-agent-gate-trace-id", traceId);
    const taskHeader = req.headers["x-agent-task"];
    const task = typeof taskHeader === "string" ? cleanNote(taskHeader, TASK_MAX_CHARS) : undefined;

    // From here on, every answer also writes a usage line.
    const where: { route?: string; upstream?: string; model?: string; redacted?: string[] } = {};
    const finish = (status: number, body: unknown, outcome: Outcome = {}, headers: ExtraHeaders = {}): void => {
      const entry: Omit<UsageEntry, "ts"> = {
        id,
        key: key.name,
        ...(task === undefined ? {} : { task }),
        ...(where.route === undefined ? {} : { route: where.route, upstream: where.upstream, model: where.model }),
        status,
        ...(outcome.error === undefined ? {} : { error: outcome.error }),
        ...(outcome.rule === undefined ? {} : { rule: outcome.rule }),
        ...(outcome.side === undefined ? {} : { side: outcome.side }),
        inputTokens: outcome.inputTokens ?? 0,
        outputTokens: outcome.outputTokens ?? 0,
        costUsd: outcome.costUsd ?? 0,
        ...(outcome.usage === undefined ? {} : { usage: outcome.usage }),
        ...(outcome.attempts === undefined ? {} : { attempts: outcome.attempts, fallback: outcome.fallback ?? false }),
        ...(outcome.upstream429 ? { upstream429: outcome.upstream429 } : {}),
        ...(outcome.settle === undefined ? {} : { settle: outcome.settle }),
        ...(where.redacted === undefined ? {} : { redacted: where.redacted }),
        ...(outcome.responseRedacted === undefined ? {} : { responseRedacted: outcome.responseRedacted }),
        latencyMs: Math.round(performance.now() - started),
        traceId,
        spanId,
        ...(context.parentSpanId ? { parentSpanId: context.parentSpanId } : {}),
        ...(context.session ? { session: context.session } : {}),
        ...(context.runId ? { runId: context.runId } : {}),
        ...(context.contextDropped ? { contextDropped: context.contextDropped } : {}),
      };
      metrics.record(entry);
      try {
        usageLog.write(entry, new Date(now()));
      } catch (err) {
        // ponytail: the call has been answered or refused either way; a usage line that cannot be
        // written is reported here, and the budget ledger (not this log) is what enforces caps.
        log(`could not write the usage log: ${errorText(err)}`);
      }
      log(
        `${status} ${id} key=${key.name}${where.route ? ` route=${where.route} upstream=${where.upstream} model=${where.model}` : ""}` +
          ` cost=$${formatUsd(entry.costUsd)}${outcome.error ? ` error=${outcome.error}` : ""} ${entry.latencyMs}ms`,
      );
      send(res, status, body, headers);
    };

    try {
      await chat(req, key, where, finish, traceparent, context.runId);
    } catch (err) {
      log(`${id} failed: ${errorText(err)}`);
      if (res.headersSent) res.destroy();
      else finish(500, apiError("gateway_error", "agent-gate failed while handling this request; the gateway log has the details"), { error: "gateway_error" });
    }
  }

  async function chat(
    req: http.IncomingMessage,
    key: GatewayKey,
    where: { route?: string; upstream?: string; model?: string; redacted?: string[] },
    finish: (status: number, body: unknown, outcome?: Outcome, headers?: ExtraHeaders) => void,
    traceparent: string,
    runId: string | undefined,
  ): Promise<void> {
    let raw: string;
    try {
      raw = await readBody(req, config.maxBodyBytes);
    } catch (err) {
      if (!(err instanceof BodyTooLarge)) throw err;
      return finish(413, apiError("request_too_large", `agent-gate: the request body is larger than ${config.maxBodyBytes} bytes`), { error: "request_too_large" }, { connection: "close" });
    }

    let body: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("not an object");
      body = parsed as Record<string, unknown>;
    } catch {
      return finish(400, apiError("invalid_json", "agent-gate: the request body must be a JSON object"), { error: "invalid_json" });
    }
    const problem = checkRequest(body);
    if (problem) return finish(400, apiError(problem.code, `agent-gate: ${problem.message}`, { param: problem.param }), { error: problem.code });
    const model = body.model as string;
    const messages = body.messages as unknown[];

    // 3. Route.
    const taskHeader = req.headers["x-agent-task"];
    const task = typeof taskHeader === "string" ? taskHeader : undefined;
    const chosen = route(config, task === undefined ? { model } : { model, task });
    if (!chosen) {
      const forTask = task === undefined ? "" : ` and x-agent-task ${JSON.stringify(clip(task))}`;
      return finish(404, apiError("model_not_found", `agent-gate: no route for model ${JSON.stringify(clip(model))}${forTask}`, { param: "model" }), { error: "model_not_found" });
    }
    Object.assign(where, { route: chosen.rule, upstream: chosen.primary.upstream.name, model: chosen.primary.model });

    // 4. Leak guard. The error names the rule, never the text it matched.
    const guarded = guardMessages(policy, messages);
    if (guarded.action === "block") {
      return finish(
        400,
        apiError(
          "secret_detected",
          `agent-gate: the messages contain text that looks like a secret (rule ${guarded.rule}), so the request was not sent. Remove it and try again; if it was a real secret, rotate it.`,
          { param: "messages", rule: guarded.rule },
        ),
        { error: "secret_detected", rule: guarded.rule, side: "prompt" },
      );
    }
    if (guarded.redactions.length > 0) where.redacted = guarded.redactions.map((r) => r.rule);

    // 5. Reserve the most this call can cost on any upstream it may reach.
    const promptChars = messageTexts(guarded.messages).reduce((sum, t) => sum + t.length, 0) + (body.tools === undefined ? 0 : JSON.stringify(body.tools).length);
    const inputTokens = estimateInputTokens(promptChars);
    const outputLimit = (body.max_completion_tokens ?? body.max_tokens ?? config.defaultMaxTokens) as number;
    const outputTokens = outputLimit * ((body.n ?? 1) as number);
    const targets = chosen.fallback ? [chosen.primary, chosen.fallback] : [chosen.primary];
    const estimate = Math.max(...targets.map((t) => costUsd(t.upstream.pricePerMTok, inputTokens, outputTokens)));

    const reservation = ledger.reserve(key, estimate, runId);
    if (!reservation.ok) {
      const refused = refusal(reservation, key.name);
      return finish(429, refused.body, refused.outcome, refused.headers);
    }

    // 6. Call. Without a limit from the client, the default is sent, so the reservation covers the answer.
    const forward: Record<string, unknown> = { ...body, messages: guarded.messages };
    if (body.max_tokens == null && body.max_completion_tokens == null) forward.max_tokens = config.defaultMaxTokens;
    let open = true;
    const release = (): void => {
      open = false;
      ledger.release(key.name, reservation.id);
    };
    try {
      const outcome = await callUpstreams(targets, forward, {
        timeoutMs: config.timeoutMs,
        retries: config.retries,
        backoffMs: config.backoffMs,
        rateLimitWaitMs: config.rateLimitWaitMs,
        apiKey: (target) => apiKeys.get(target.upstream.name) as string,
        ...(options.fetch ? { fetch: options.fetch } : {}),
        log,
        traceparent,
      });
      if (!outcome.ok && outcome.failure === "rate_limited") {
        release();
        // The provider's own body is not passed on (it can quote the key); its Retry-After is.
        return finish(
          429,
          apiError(
            "upstream_rate_limited",
            `agent-gate: the upstream is rate limiting this gateway (${outcome.attempts} attempts${targets.length > 1 ? ", the fallback included" : ""}; the last one answered HTTP 429). Nothing was charged to this key.`,
            { type: "rate_limit_error" },
          ),
          { error: "upstream_rate_limited", attempts: outcome.attempts, fallback: targets.length > 1, upstream429: outcome.rateLimited },
          outcome.retryAfterSeconds === undefined ? {} : { "retry-after": outcome.retryAfterSeconds },
        );
      }
      if (!outcome.ok) {
        release();
        const timedOut = outcome.failure === "timeout";
        const last = outcome.failure === "server_error" ? `answered HTTP ${outcome.status}` : timedOut ? "timed out" : "could not be reached";
        return finish(
          timedOut ? 504 : 502,
          apiError(timedOut ? "upstream_timeout" : "upstream_error", `agent-gate: no upstream answered (${outcome.attempts} attempts; the last one ${last}). Nothing was charged to this key.`, {
            type: "api_error",
          }),
          { error: timedOut ? "upstream_timeout" : "upstream_error", attempts: outcome.attempts, fallback: targets.length > 1, upstream429: outcome.rateLimited },
        );
      }

      Object.assign(where, { upstream: outcome.target.upstream.name, model: outcome.target.model });
      const via = { attempts: outcome.attempts, fallback: outcome.fallback, upstream429: outcome.rateLimited };
      if (outcome.status >= 400) {
        release();
        if (outcome.status === 401 || outcome.status === 403) {
          // Not passed on: a provider's auth error can quote part of the key it was given.
          return finish(
            502,
            apiError("upstream_auth_failed", `agent-gate: upstream "${outcome.target.upstream.name}" refused the gateway's API key (HTTP ${outcome.status}); this is a gateway configuration problem.`, {
              type: "api_error",
            }),
            { error: "upstream_auth_failed", ...via },
          );
        }
        // Other 4xx answers say what is wrong with the request, so they are passed on.
        return finish(outcome.status, scrub(outcome.body, apiKeys), { error: "upstream_rejected", ...via });
      }

      // 7. A 2xx answer is paid for: with its own usage when it reports one, else with the estimate.
      let json: unknown;
      try {
        json = JSON.parse(outcome.body);
      } catch {
        json = undefined;
      }
      const used = readUsage(json);
      const cost = used ? costUsd(outcome.target.upstream.pricePerMTok, used.input, used.output) : reservation.usd;
      open = false;
      let settled: SettleOutcome = "booked";
      try {
        settled = ledger.settle(key.name, reservation.id, cost);
      } catch (err) {
        log(`could not settle ${reservation.id} for key "${key.name}" ($${formatUsd(cost)}): ${errorText(err)}; its reservation stays until it expires`);
      }
      // "orphan": the call outlived its reservation, so the cost was booked without one.
      if (settled !== "booked") log(`settled ${reservation.id} for key "${key.name}" ($${formatUsd(cost)}) as ${settled}`);
      const spent: Outcome = {
        inputTokens: used?.input ?? inputTokens,
        outputTokens: used?.output ?? outputTokens,
        costUsd: cost,
        usage: used ? "upstream" : "estimate",
        ...via,
        ...(settled === "booked" ? {} : { settle: settled }),
      };
      if (typeof json !== "object" || json === null || Array.isArray(json)) {
        return finish(502, apiError("bad_upstream_response", "agent-gate: the upstream's answer was not JSON", { type: "api_error" }), { ...spent, error: "bad_upstream_response" });
      }

      // 8. The answer goes through the same leak guard. Its text is never echoed, and it is booked either way.
      let answer = outcome.body;
      let responseRedacted: string[] | undefined;
      if (config.scanResponses) {
        const scanned = guardResponse(policy, json as Record<string, unknown>);
        if (scanned.action === "block") {
          return finish(
            502,
            apiError(
              "response_blocked",
              `agent-gate: the model's answer contains text that looks like a secret (rule ${scanned.rule}), so it was not passed on. The call was paid for; if the secret is real, rotate it.`,
              { type: "api_error", rule: scanned.rule },
            ),
            { ...spent, error: "response_blocked", rule: scanned.rule, side: "response" },
          );
        }
        if (scanned.redactions.length > 0) {
          responseRedacted = scanned.redactions.map((r) => r.rule);
          answer = JSON.stringify(scanned.body);
        }
      }
      return finish(outcome.status, scrub(answer, apiKeys), { ...spent, ...(responseRedacted ? { responseRedacted } : {}) }, {
        "x-agent-gate-route": chosen.rule,
        "x-agent-gate-upstream": outcome.target.upstream.name,
        "x-agent-gate-cost-usd": formatUsd(cost),
        ...(where.redacted ? { "x-agent-gate-redacted": where.redacted.join(",") } : {}),
        ...(responseRedacted ? { "x-agent-gate-response-redacted": responseRedacted.join(",") } : {}),
      });
    } finally {
      if (open) {
        try {
          release();
        } catch (err) {
          log(`could not release ${reservation.id} for key "${key.name}": ${errorText(err)}; it expires on its own`);
        }
      }
    }
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      log(`request failed: ${errorText(err)}`);
      if (!res.headersSent) send(res, 500, apiError("gateway_error", "agent-gate failed while handling this request"));
      else res.destroy();
    });
  });
  const url = await listen(server, config.port, config.host);
  let metricsServer: http.Server | undefined;
  let metricsUrl: string | undefined;
  if (config.metrics?.listen) {
    metricsServer = http.createServer((req, res) => {
      if ((req.url ?? "/").split("?")[0] !== "/metrics") return send(res, 404, apiError("not_found", "this listener serves GET /metrics only"));
      serveMetrics(req, res, false);
    });
    try {
      metricsUrl = await listen(metricsServer, config.metrics.listen.port, config.metrics.listen.host);
    } catch (err) {
      await closeServer(server);
      throw err;
    }
    log(`metrics on ${metricsUrl}/metrics (no key: a loopback address only)`);
  }
  log(`listening on ${url}: ${config.upstreams.size} upstreams, ${config.routes.length} routes, ${config.keys.length} keys, state in ${config.stateDir}`);
  return {
    url,
    ...(metricsUrl ? { metricsUrl } : {}),
    close: async () => {
      await Promise.all([closeServer(server), metricsServer ? closeServer(metricsServer) : Promise.resolve()]);
    },
  };
}

async function listen(server: http.Server, port: number, host: string): Promise<string> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address() as AddressInfo;
  return `http://${address.family === "IPv6" ? `[${address.address}]` : address.address}:${address.port}`;
}

function closeServer(server: http.Server): Promise<void> {
  return new Promise<void>((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections();
  });
}

/** The 429 for a call the ledger refused: which limit, in words the caller can act on. */
function refusal(r: Extract<ReserveOutcome, { ok: false }>, keyName: string): { body: unknown; outcome: Outcome; headers: ExtraHeaders } {
  const stop = "Retrying will not help: the run should stop.";
  switch (r.cap) {
    case "maxCallsPerMinute":
      return {
        body: apiError("rate_limited", `agent-gate: key "${keyName}" has made ${r.limit} calls in the last minute, its limit (maxCallsPerMinute). Try again in ${r.retryAfterSeconds} s.`, {
          type: "rate_limit_error",
          cap: r.cap,
        }),
        outcome: { error: "rate_limited", rule: r.cap },
        headers: { "retry-after": r.retryAfterSeconds },
      };
    case "runMaxCalls":
      return {
        body: apiError("run_limit_reached", `agent-gate: run ${JSON.stringify(r.runId)} of key "${keyName}" has made ${r.calls} calls, its limit (runMaxCalls). ${stop}`, {
          type: "insufficient_quota",
          cap: r.cap,
        }),
        outcome: { error: "run_limit_reached", rule: r.cap },
        headers: {},
      };
    case "runMaxUsd": {
      const left = Math.max(0, roundUsd(r.limit - r.spentUsd - r.reservedUsd));
      return {
        body: apiError(
          "run_limit_reached",
          `agent-gate: this call could cost up to $${formatUsd(r.requestedUsd)}, and run ${JSON.stringify(r.runId)} of key "${keyName}" has $${formatUsd(left)} left of its ` +
            `budget of $${formatUsd(r.limit)} ($${formatUsd(r.spentUsd)} spent, $${formatUsd(r.reservedUsd)} held by its calls in flight). ${stop}`,
          { type: "insufficient_quota", cap: r.cap },
        ),
        outcome: { error: "run_limit_reached", rule: r.cap },
        headers: {},
      };
    }
    default: {
      const left = Math.max(0, roundUsd(r.capUsd - r.spentUsd - r.reservedUsd));
      return {
        body: apiError(
          "budget_exceeded",
          `agent-gate: this call could cost up to $${formatUsd(r.requestedUsd)}, and key "${keyName}" has $${formatUsd(left)} left ` +
            `of its ${r.cap} budget of $${formatUsd(r.capUsd)} ($${formatUsd(r.spentUsd)} spent, ` +
            `$${formatUsd(r.reservedUsd)} held by calls in flight). Try again later, or with a lower max_tokens.`,
          { type: "insufficient_quota", cap: r.cap },
        ),
        outcome: { error: "budget_exceeded", rule: r.cap },
        headers: { "retry-after": r.retryAfterSeconds },
      };
    }
  }
}

/** The ledger in the config's stateDir. A reservation outlives the longest possible call by a minute. */
export function openLedger(config: LlmConfig, now: () => number = Date.now): Ledger {
  return new Ledger(config.stateDir, longestCallMs(config) + 60_000, now);
}

/**
 * The longest a call can take: every attempt on both upstreams timing out, plus the backoff, plus the
 * one wait after a 429 (it takes a retry's place, so it adds no attempt). With the defaults: 242.5 s.
 */
export function longestCallMs(config: Pick<LlmConfig, "timeoutMs" | "retries" | "backoffMs" | "rateLimitWaitMs">): number {
  const perUpstream = (config.retries + 1) * config.timeoutMs + config.backoffMs * (2 ** config.retries - 1);
  return 2 * perUpstream + config.rateLimitWaitMs;
}

function checkRequest(body: Record<string, unknown>): { code: string; param: string; message: string } | undefined {
  // ponytail: non-streaming only. A streamed answer has to be relayed chunk by chunk and its usage
  // read from the last chunk; until that exists, "stream": true is refused rather than half done.
  if (body.stream != null && body.stream !== false) {
    return { code: "stream_not_supported", param: "stream", message: 'streaming is not supported by this gateway; leave "stream" out or set it to false' };
  }
  if (typeof body.model !== "string" || body.model === "") return { code: "invalid_request", param: "model", message: "model must be a non-empty string (a model alias)" };
  if (!Array.isArray(body.messages) || body.messages.length === 0) return { code: "invalid_request", param: "messages", message: "messages must be a non-empty array" };
  for (const field of ["max_tokens", "max_completion_tokens"]) {
    const value = body[field];
    if (value != null && !(Number.isInteger(value) && (value as number) > 0)) return { code: "invalid_request", param: field, message: `${field} must be a positive whole number` };
  }
  if (body.n != null && !(Number.isInteger(body.n) && (body.n as number) >= 1 && (body.n as number) <= 128)) {
    return { code: "invalid_request", param: "n", message: "n must be a whole number from 1 to 128" };
  }
  return undefined;
}

/** prompt_tokens and completion_tokens from an OpenAI-style answer, if both are there. */
function readUsage(json: unknown): { input: number; output: number } | undefined {
  const usage = typeof json === "object" && json !== null ? (json as { usage?: unknown }).usage : undefined;
  if (typeof usage !== "object" || usage === null) return undefined;
  const { prompt_tokens: input, completion_tokens: output } = usage as Record<string, unknown>;
  const count = (n: unknown): n is number => Number.isInteger(n) && (n as number) >= 0;
  return count(input) && count(output) ? { input, output } : undefined;
}

/** Cuts the upstream API keys out of a body that is passed on, in case an upstream quotes one. */
function scrub(body: string, apiKeys: ReadonlyMap<string, string>): string {
  let out = body;
  for (const key of apiKeys.values()) out = out.split(key).join("[REDACTED:upstream-key]");
  return out;
}

class BodyTooLarge extends Error {}

function readBody(req: http.IncomingMessage, limit: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      // Past the limit, keep reading (so the 413 can be sent) but stop keeping anything.
      if (size > limit) reject(new BodyTooLarge());
      else chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function apiError(code: string, message: string, extra: { type?: string; param?: string; [field: string]: unknown } = {}): unknown {
  const { type = "invalid_request_error", param = null, ...rest } = extra;
  return { error: { message, type, param, code, ...rest } };
}

function send(res: http.ServerResponse, status: number, body: unknown, headers: ExtraHeaders = {}): void {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text), ...headers });
  res.end(text);
}

function clip(value: string): string {
  return value.length <= 100 ? value : `${value.slice(0, 100)}...`;
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
