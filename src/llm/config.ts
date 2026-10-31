// The LLM gateway config file, for example llm-gateway.config.example.json:
//
//   {
//     "listen": { "host": "127.0.0.1", "port": 8787 },
//     "stateDir": ".agent-gate",
//     "policy": "llm-policy.example.json",
//     "upstreams": [{ "name": "cheap", "baseUrl": "https://llm.example/v1", "apiKeyEnv": "CHEAP_API_KEY",
//                     "models": { "small": "provider-small-2" }, "pricePerMTok": { "input": 0.15, "output": 0.6 } }],
//     "routes": [{ "id": "classify-is-cheap", "when": { "task": "classify" }, "use": { "upstream": "cheap", "model": "small" } }],
//     "keys": [{ "name": "search-agent", "sha256": "<64 hex characters>", "dailyUsd": 2, "monthlyUsd": 40 }]
//   }
//
// Optional fields and their defaults are in DEFAULTS below. Relative "policy" and "stateDir" paths
// are resolved against the config file's directory. Upstream API keys are never in this file:
// "apiKeyEnv" names the environment variable that holds the key. Gateway keys are not in it either,
// only their SHA-256: a gateway key is a long random string, so its hash cannot be guessed back,
// and the file can be read (or committed) without handing out access.

import { createHash } from "node:crypto";
import * as path from "node:path";
import { readJson } from "../gateway/config.js";
import { globToRegExp } from "../gateway/policy.js";
import { array, fail, integerIn, nonNegativeNumber, object, onlyKeys, positiveNumber, text } from "../gateway/validate.js";
import { parseLeakPolicy, type LeakPolicy } from "./leak-guard.js";

/** US dollars per million tokens. */
export interface Price {
  input: number;
  output: number;
}

export interface Upstream {
  name: string;
  /** Without a trailing slash; the gateway posts to `${baseUrl}/chat/completions`. */
  baseUrl: string;
  /** The name of the environment variable that holds this upstream's API key. */
  apiKeyEnv: string;
  /** Model alias (what clients ask for) to the model name the upstream knows. */
  models: ReadonlyMap<string, string>;
  pricePerMTok: Price;
}

/** Where a route sends a call: an upstream and, optionally, a fixed alias on it. */
export interface Target {
  upstream: string;
  /** An alias in that upstream's "models". Left out: the alias the client asked for. */
  model?: string;
}

export interface RouteRule {
  id: string;
  /** Matches the model alias in the request. Left out: any alias. */
  model?: (alias: string) => boolean;
  /** Matches the x-agent-task header. Left out: any request, with or without the header. */
  task?: (task: string) => boolean;
  use: Target;
  fallback?: Target;
}

export interface GatewayKey {
  name: string;
  /** Lowercase hex SHA-256 of the key that clients send as "Authorization: Bearer <key>". */
  sha256: string;
  dailyUsd: number;
  monthlyUsd: number;
  /** Stop rules (optional): calls in any 60 seconds, and calls and dollars per run (x-run-id). */
  maxCallsPerMinute?: number;
  runMaxCalls?: number;
  runMaxUsd?: number;
  /** The same request let through at most repeatMax times in any repeatWindowMs (src/llm/repeats.ts). */
  repeatMax?: number;
  repeatWindowMs?: number;
}

/** Who may read GET /metrics (src/llm/metrics.ts). Absent: nobody, it is not served. */
export interface MetricsConfig {
  /** SHA-256 of a key of its own: GET /metrics on the gateway's port, with Authorization: Bearer <key>. */
  sha256?: string;
  /** A listener of its own that serves only GET /metrics, without a key. Its host must be a loopback address. */
  listen?: { host: string; port: number };
}

export interface LlmConfig {
  host: string;
  port: number;
  stateDir: string;
  policyFile: string;
  upstreams: ReadonlyMap<string, Upstream>;
  routes: readonly RouteRule[];
  keys: readonly GatewayKey[];
  /** Output tokens to reserve, and to send as max_tokens, when a request sets no limit itself. */
  defaultMaxTokens: number;
  /** Per attempt, not per request. */
  timeoutMs: number;
  /** Extra attempts on the same upstream after a 5xx or a timeout, before the fallback. */
  retries: number;
  /** The wait before retry n is a random time up to backoffMs * 2^(n-1), at most maxBackoffMs (full jitter). */
  backoffMs: number;
  maxBackoffMs: number;
  /** After a 429 on the last upstream: the longest the gateway waits (Retry-After, capped) before its one retry. 0: never. */
  rateLimitWaitMs: number;
  maxBodyBytes: number;
  /** Run the leak guard over the answers too (default true). A streamed answer is then held until it is complete. */
  scanResponses: boolean;
  /** A stream that sends nothing for this long is stopped (default 30 s). */
  streamIdleMs: number;
  /** Send the upstreams a traceparent header (default true); some providers may refuse unknown headers. */
  sendTraceparent: boolean;
  metrics?: MetricsConfig;
}

export const DEFAULTS = {
  host: "127.0.0.1",
  port: 8787,
  defaultMaxTokens: 1024,
  timeoutMs: 60_000,
  retries: 1,
  backoffMs: 250,
  maxBackoffMs: 10_000,
  rateLimitWaitMs: 2000,
  maxBodyBytes: 1024 * 1024,
  streamIdleMs: 30_000,
} as const;

// ponytail: at most 3 retries per upstream. Each one costs the caller a timeout; past that, the
// fallback (or an error the client can retry on its own schedule) is the better answer.
export const MAX_RETRIES = 3;

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;

/** The SHA-256 the config stores for a gateway key. */
export function hashKey(key: string): string {
  return createHash("sha256").update(key, "utf8").digest("hex");
}

export function loadLlmConfig(file: string): LlmConfig {
  const absolute = path.resolve(file);
  return parseLlmConfig(readJson(absolute, "config"), path.dirname(absolute));
}

export function loadLeakPolicy(file: string): LeakPolicy {
  return parseLeakPolicy(readJson(file, "policy"));
}

export function parseLlmConfig(json: unknown, baseDir: string): LlmConfig {
  const config = object(json, "config");
  onlyKeys(
    config,
    ["listen", "stateDir", "policy", "upstreams", "routes", "keys", "defaultMaxTokens", "timeoutMs", "retries", "backoffMs", "maxBackoffMs", "rateLimitWaitMs", "maxBodyBytes", "scanResponses", "streamIdleMs", "sendTraceparent", "metrics"],
    "config",
  );

  const listen = object(config.listen ?? {}, "config.listen");
  onlyKeys(listen, ["host", "port"], "config.listen");

  const upstreams = new Map<string, Upstream>();
  array(config.upstreams, "config.upstreams").forEach((raw, i) => {
    const upstream = parseUpstream(raw, `config.upstreams[${i}]`);
    if (upstreams.has(upstream.name)) fail(`config.upstreams: the name "${upstream.name}" is used twice`);
    upstreams.set(upstream.name, upstream);
  });
  if (upstreams.size === 0) fail("config.upstreams must list at least one upstream");

  const routeIds = new Set<string>();
  const routes = array(config.routes, "config.routes").map((raw, i) => parseRoute(raw, `config.routes[${i}]`, upstreams, routeIds));
  if (routes.length === 0) fail("config.routes must list at least one route");

  const keyNames = new Set<string>();
  const keyHashes = new Set<string>();
  const keys = array(config.keys, "config.keys").map((raw, i) => {
    const key = parseKey(raw, `config.keys[${i}]`);
    if (keyNames.has(key.name)) fail(`config.keys: the name "${key.name}" is used twice`);
    if (keyHashes.has(key.sha256)) fail(`config.keys[${i}].sha256 is the same as an earlier key's`);
    keyNames.add(key.name);
    keyHashes.add(key.sha256);
    return key;
  });
  if (keys.length === 0) fail("config.keys must list at least one gateway key");

  return {
    host: listen.host === undefined ? DEFAULTS.host : text(listen.host, "config.listen.host"),
    port: listen.port === undefined ? DEFAULTS.port : integerIn(listen.port, "config.listen.port", 0, 65535),
    stateDir: path.resolve(baseDir, text(config.stateDir, "config.stateDir")),
    policyFile: path.resolve(baseDir, text(config.policy, "config.policy")),
    upstreams,
    routes,
    keys,
    defaultMaxTokens: optionalInteger(config.defaultMaxTokens, "config.defaultMaxTokens", 1, 1_000_000, DEFAULTS.defaultMaxTokens),
    timeoutMs: optionalInteger(config.timeoutMs, "config.timeoutMs", 1, 600_000, DEFAULTS.timeoutMs),
    retries: optionalInteger(config.retries, "config.retries", 0, MAX_RETRIES, DEFAULTS.retries),
    backoffMs: optionalInteger(config.backoffMs, "config.backoffMs", 0, 60_000, DEFAULTS.backoffMs),
    maxBackoffMs: optionalInteger(config.maxBackoffMs, "config.maxBackoffMs", 0, 60_000, DEFAULTS.maxBackoffMs),
    rateLimitWaitMs: optionalInteger(config.rateLimitWaitMs, "config.rateLimitWaitMs", 0, 60_000, DEFAULTS.rateLimitWaitMs),
    maxBodyBytes: optionalInteger(config.maxBodyBytes, "config.maxBodyBytes", 1024, 32 * 1024 * 1024, DEFAULTS.maxBodyBytes),
    scanResponses: config.scanResponses === undefined ? true : config.scanResponses === true ? true : config.scanResponses === false ? false : fail("config.scanResponses must be true or false"),
    streamIdleMs: optionalInteger(config.streamIdleMs, "config.streamIdleMs", 100, 600_000, DEFAULTS.streamIdleMs),
    sendTraceparent: config.sendTraceparent === undefined ? true : config.sendTraceparent === true ? true : config.sendTraceparent === false ? false : fail("config.sendTraceparent must be true or false"),
    ...(config.metrics === undefined ? {} : { metrics: parseMetrics(config.metrics, keyHashes) }),
  };
}

/** A loopback IP address: 127.0.0.0/8 or ::1. Names are not accepted, because a name can resolve elsewhere. */
export function isLoopback(host: string): boolean {
  return host === "::1" || /^127\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})$/.test(host);
}

function parseMetrics(raw: unknown, keyHashes: ReadonlySet<string>): MetricsConfig {
  const at = "config.metrics";
  const m = object(raw, at);
  onlyKeys(m, ["sha256", "listen"], at);
  if (m.sha256 === undefined && m.listen === undefined) {
    fail(`${at} needs "sha256" (a key for GET /metrics on the gateway's port), "listen" (a listener of its own on a loopback address), or both`);
  }
  const metrics: MetricsConfig = {};
  if (m.sha256 !== undefined) {
    const sha256 = text(m.sha256, `${at}.sha256`);
    if (!SHA256_HEX.test(sha256)) fail(`${at}.sha256 must be 64 lowercase hex characters (the SHA-256 of the metrics key, not the key)`);
    // An agent's key must not also read every key's spend.
    if (keyHashes.has(sha256)) fail(`${at}.sha256 is the hash of a gateway key; the metrics key must be a key of its own`);
    metrics.sha256 = sha256;
  }
  if (m.listen !== undefined) {
    const listen = object(m.listen, `${at}.listen`);
    onlyKeys(listen, ["host", "port"], `${at}.listen`);
    const host = listen.host === undefined ? "127.0.0.1" : text(listen.host, `${at}.listen.host`);
    if (!isLoopback(host)) fail(`${at}.listen.host must be a loopback address (127.0.0.1 or ::1): this listener has no key`);
    metrics.listen = { host, port: integerIn(listen.port, `${at}.listen.port`, 0, 65535) };
  }
  return metrics;
}

function parseUpstream(raw: unknown, at: string): Upstream {
  const u = object(raw, at);
  onlyKeys(u, ["name", "baseUrl", "apiKeyEnv", "models", "pricePerMTok"], at);
  const name = text(u.name, `${at}.name`);
  if (!NAME.test(name)) fail(`${at}.name must be 1 to 64 letters, digits, ".", "_" or "-", starting with a letter or digit`);

  const baseUrl = text(u.baseUrl, `${at}.baseUrl`).replace(/\/+$/, "");
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    fail(`${at}.baseUrl is not a valid URL`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") fail(`${at}.baseUrl must start with http:// or https://`);
  if (url.username || url.password) fail(`${at}.baseUrl must not contain credentials; use apiKeyEnv`);

  const apiKeyEnv = text(u.apiKeyEnv, `${at}.apiKeyEnv`);
  if (!ENV_NAME.test(apiKeyEnv)) fail(`${at}.apiKeyEnv must be the name of an environment variable, such as OPENAI_API_KEY`);

  const models = new Map<string, string>();
  for (const [alias, model] of Object.entries(object(u.models, `${at}.models`))) {
    models.set(alias, text(model, `${at}.models.${alias}`));
  }
  if (models.size === 0) fail(`${at}.models must map at least one alias to a model`);

  const price = object(u.pricePerMTok, `${at}.pricePerMTok`);
  onlyKeys(price, ["input", "output"], `${at}.pricePerMTok`);
  return {
    name,
    baseUrl,
    apiKeyEnv,
    models,
    pricePerMTok: {
      input: nonNegativeNumber(price.input, `${at}.pricePerMTok.input`),
      output: nonNegativeNumber(price.output, `${at}.pricePerMTok.output`),
    },
  };
}

function parseRoute(raw: unknown, at: string, upstreams: ReadonlyMap<string, Upstream>, ids: Set<string>): RouteRule {
  const r = object(raw, at);
  onlyKeys(r, ["id", "when", "use", "fallback"], at);
  const id = text(r.id, `${at}.id`);
  if (ids.has(id)) fail(`${at}.id "${id}" is already used by an earlier route`);
  ids.add(id);

  const rule: RouteRule = { id, use: parseTarget(r.use, `${at}.use`, upstreams) };
  if (r.when !== undefined) {
    const when = object(r.when, `${at}.when`);
    onlyKeys(when, ["model", "task"], `${at}.when`);
    if (when.model !== undefined) rule.model = globs(when.model, `${at}.when.model`);
    if (when.task !== undefined) rule.task = globs(when.task, `${at}.when.task`);
  }
  if (r.fallback !== undefined) {
    const fallback = parseTarget(r.fallback, `${at}.fallback`, upstreams);
    // When the primary alias is fixed, the fallback's alias is known now, so check it now.
    const alias = fallback.model ?? rule.use.model;
    if (alias !== undefined && !upstreams.get(fallback.upstream)?.models.has(alias)) {
      fail(`${at}.fallback: upstream "${fallback.upstream}" has no model alias "${alias}"`);
    }
    rule.fallback = fallback;
  }
  return rule;
}

function parseTarget(raw: unknown, at: string, upstreams: ReadonlyMap<string, Upstream>): Target {
  const t = object(raw, at);
  onlyKeys(t, ["upstream", "model"], at);
  const upstream = upstreams.get(text(t.upstream, `${at}.upstream`));
  if (!upstream) fail(`${at}.upstream "${String(t.upstream)}" is not one of the upstreams`);
  if (t.model === undefined) return { upstream: upstream.name };
  const model = text(t.model, `${at}.model`);
  if (!upstream.models.has(model)) fail(`${at}.model: upstream "${upstream.name}" has no model alias "${model}"`);
  return { upstream: upstream.name, model };
}

/** A glob (see policy.ts: whole value, any case, "*" and "?") or a non-empty list of them. */
function globs(value: unknown, at: string): (candidate: string) => boolean {
  const list = Array.isArray(value) ? value : [value];
  if (list.length === 0) fail(`${at} must not be an empty list`);
  const res = list.map((one, i) => globToRegExp(text(one, Array.isArray(value) ? `${at}[${i}]` : at)));
  return (candidate) => res.some((re) => re.test(candidate));
}

function parseKey(raw: unknown, at: string): GatewayKey {
  const k = object(raw, at);
  onlyKeys(k, ["name", "sha256", "dailyUsd", "monthlyUsd", "maxCallsPerMinute", "runMaxCalls", "runMaxUsd", "repeatMax", "repeatWindowSeconds"], at);
  if ((k.repeatMax === undefined) !== (k.repeatWindowSeconds === undefined)) fail(`${at}: repeatMax and repeatWindowSeconds go together; set both or neither`);
  const name = text(k.name, `${at}.name`);
  if (!NAME.test(name)) fail(`${at}.name must be 1 to 64 letters, digits, ".", "_" or "-", starting with a letter or digit`);
  const sha256 = text(k.sha256, `${at}.sha256`);
  if (!SHA256_HEX.test(sha256)) fail(`${at}.sha256 must be 64 lowercase hex characters (the SHA-256 of the key, not the key)`);
  return {
    name,
    sha256,
    dailyUsd: positiveNumber(k.dailyUsd, `${at}.dailyUsd`),
    monthlyUsd: positiveNumber(k.monthlyUsd, `${at}.monthlyUsd`),
    ...(k.maxCallsPerMinute === undefined ? {} : { maxCallsPerMinute: integerIn(k.maxCallsPerMinute, `${at}.maxCallsPerMinute`, 1, 100_000) }),
    ...(k.runMaxCalls === undefined ? {} : { runMaxCalls: integerIn(k.runMaxCalls, `${at}.runMaxCalls`, 1, 1_000_000) }),
    ...(k.runMaxUsd === undefined ? {} : { runMaxUsd: positiveNumber(k.runMaxUsd, `${at}.runMaxUsd`) }),
    ...(k.repeatMax === undefined
      ? {}
      : { repeatMax: integerIn(k.repeatMax, `${at}.repeatMax`, 1, 10_000), repeatWindowMs: integerIn(k.repeatWindowSeconds, `${at}.repeatWindowSeconds`, 1, 86_400) * 1000 }),
  };
}

function optionalInteger(value: unknown, at: string, min: number, max: number, fallback: number): number {
  return value === undefined ? fallback : integerIn(value, at, min, max);
}
