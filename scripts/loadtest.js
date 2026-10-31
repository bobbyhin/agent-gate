#!/usr/bin/env node
"use strict";
// npm run loadtest [-- --requests 1000 --concurrency 100] [--json]
// npm run loadtest -- --url <gateway> --key-env <VAR> [--header-env <Header>=<VAR>]... [--model small]
//                     [--requests 20 --concurrency 5]
//
// The LLM gateway under concurrent load. Without --url it starts a fake upstream and a gateway in this
// process (after `npm run build`; nothing leaves the machine and nothing costs money). The gateway has
// one key whose daily cap fits only part of the load, and it checks:
//   1. never overspent: the key's settled dollars for the day are at most its cap; they equal the sum
//      of the x-agent-gate-cost-usd headers of the answers that were let through; `usage --verify`
//      finds the usage log in agreement with the ledger; and no reservation is left in flight;
//   2. no 5xx: every answer is a 200, or a 429 with a named stop rule (budget_exceeded, rate_limited,
//      run_limit_reached, loop_suspected); and the cap did refuse part of the load;
//   3. it reports latency (p50, p95, p99, max) and throughput through the gateway, and for the same
//      requests sent straight to the fake upstream: the difference is what the gateway adds.
// It exits 1 when a check in 1 or 2 fails. Every request reserves more than it settles (the fake
// reports fewer tokens than the gateway estimates), as with a real provider, whose answer cannot be
// longer than max_tokens; the cap holds because of that (docs/adr/0002-reserve-then-settle-budgets.md).
//
// With --url it loads a gateway that is already running, for example right after a deploy. First, one
// request without the gateway key must get the gateway's own 401 (invalid_api_key): that proves the
// request went through whatever stands in front of the gateway (a load balancer, Cloud Run's IAM
// check) and reached it. Headers that platform needs come from environment variables
// (--header-env X-Serverless-Authorization=ID_TOKEN, where ID_TOKEN holds "Bearer <token>"), so no token
// is typed on the command line. Then the load. Each 200 is a real call to whatever upstream that
// gateway routes to, and costs what that call costs: use a key made for the test, with a small cap.
// Check 1 needs the ledger, which lives where the gateway runs: run `agent-gate usage --verify` there.
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { performance } = require("node:perf_hooks");
const { parseArgs } = require("node:util");

const ROOT = path.join(__dirname, "..");
const dist = (file) => require(path.join(ROOT, "dist", file));

/** A 429 that is a stop rule doing its job. Any other refusal fails the run. */
const NAMED_REFUSALS = new Set(["budget_exceeded", "rate_limited", "run_limit_reached", "loop_suspected"]);

// In-process: 400 characters of prompt (the gateway estimates 100 input tokens) and max_tokens 50, so a
// call reserves 150 tokens; the fake upstream reports 100 + 25. At $1 per million tokens either way, a
// call reserves $0.00015 and settles $0.000125.
const PROMPT_CHARS = 400;
const MAX_TOKENS = 50;
const USAGE = { prompt_tokens: 100, completion_tokens: 25 };
const PRICE = { input: 1, output: 1 };

/** Nearest-rank percentile of a sorted list, or null for an empty one. */
function percentile(sorted, p) {
  if (sorted.length === 0) return null;
  return sorted[Math.max(0, Math.ceil((p / 100) * sorted.length) - 1)];
}

function stats(ms) {
  const sorted = [...ms].sort((a, b) => a - b);
  return { count: sorted.length, p50: percentile(sorted, 50), p95: percentile(sorted, 95), p99: percentile(sorted, 99), max: sorted.length ? sorted[sorted.length - 1] : null };
}

/** Sends `n` requests, at most `concurrency` at a time; `send(i)` makes request i. */
async function fire(n, concurrency, send) {
  const results = new Array(n);
  let next = 0;
  const started = performance.now();
  const worker = async () => {
    for (let i = next++; i < n; i = next++) {
      const t0 = performance.now();
      try {
        results[i] = { ...(await send(i)), ms: performance.now() - t0 };
      } catch (err) {
        // A connection the gateway dropped or refused counts like a 5xx: the service failed.
        results[i] = { status: 0, code: `transport: ${err && err.cause ? err.cause.code || err.cause.message : err.message}`, ms: performance.now() - t0 };
      }
      results[i].at = performance.now() - started;
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, n) }, worker));
  return { results, seconds: (performance.now() - started) / 1000 };
}

/** Answers per second over the first and the last tenth of the answers: does the rate hold as the run goes on? */
function tenths(results) {
  const at = results.map((r) => r.at).sort((a, b) => a - b);
  const tenth = Math.max(1, Math.floor(at.length / 10));
  const rate = (from, to) => (to > from ? (tenth * 1000) / (to - from) : null);
  return { first: rate(0, at[tenth - 1]), last: rate(at[at.length - tenth - 1] ?? 0, at[at.length - 1]) };
}

/** One chat completion; the gateway's error code and cost header, if any. */
async function chat(url, headers, body) {
  const res = await fetch(`${url}/v1/chat/completions`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
  const text = await res.text();
  let code;
  try {
    code = JSON.parse(text)?.error?.code;
  } catch {
    // not JSON: leave the code out
  }
  const cost = res.headers.get("x-agent-gate-cost-usd");
  return { status: res.status, ...(code === undefined ? {} : { code }), ...(cost === null ? {} : { cost: Number(cost) }) };
}

/** Request i: the same length every time, different text, so no repeat rule sees the same request twice. */
function body(i, model, maxTokens, chars) {
  return { model, messages: [{ role: "user", content: `load test request ${String(i).padStart(7, "0")} `.padEnd(chars, ".") }], max_tokens: maxTokens };
}

/** What the answers were: status and code counts, and the checks that every run makes on them. */
function tally(results) {
  const counts = new Map();
  for (const r of results) {
    const label = r.status === 200 ? "200" : `${r.status} ${r.code ?? ""}`.trim();
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  const failed = results.filter((r) => r.status === 0 || r.status >= 500);
  const unnamed = results.filter((r) => r.status !== 200 && !(r.status === 429 && NAMED_REFUSALS.has(r.code)));
  return {
    counts: Object.fromEntries([...counts].sort(([a], [b]) => a.localeCompare(b))),
    ok: results.filter((r) => r.status === 200).length,
    refused: results.filter((r) => r.status === 429).length,
    checks: [
      { ok: failed.length === 0, what: failed.length === 0 ? "no 5xx and no dropped connection" : `${failed.length} answers were 5xx or a dropped connection` },
      { ok: unnamed.length === 0, what: unnamed.length === 0 ? "every refusal is a 429 with a named stop rule" : `${unnamed.length} answers were neither 200 nor a 429 with a named stop rule` },
    ],
  };
}

/** The whole in-process run. Returns the numbers and the checks; prints nothing. */
async function runInProcess({ requests = 1000, concurrency = 100, direct = true, capUsd: givenCap } = {}) {
  const { hashKey, loadLeakPolicy, parseLlmConfig } = dist("src/llm/config.js");
  const { roundUsd } = dist("src/llm/budget.js");
  const { openLedger, startLlmGateway } = dist("src/llm/server.js");
  const { readUsageLog, verifyUsage } = dist("src/llm/usage-report.js");
  const { startFakeUpstream } = dist("test/llm/fake-upstream.js");

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-loadtest-"));
  // Keys made for this run only.
  const gatewayKey = `lt-${crypto.randomBytes(16).toString("hex")}`;
  const warmupKey = `lt-${crypto.randomBytes(16).toString("hex")}`;
  const upstreamKey = `lt-up-${crypto.randomBytes(16).toString("hex")}`;
  const reserveUsd = roundUsd(((PROMPT_CHARS / 4) * PRICE.input + MAX_TOKENS * PRICE.output) / 1e6);
  const settleUsd = roundUsd((USAGE.prompt_tokens * PRICE.input + USAGE.completion_tokens * PRICE.output) / 1e6);
  // About half of the load fits, unless the caller sets the cap (--cap-usd, to measure the rate the gateway keeps up).
  const capUsd = givenCap ?? roundUsd(Math.max(1, Math.floor(requests / 2)) * settleUsd);
  const fake = await startFakeUpstream({ mode: "ok", usage: USAGE });
  let gateway;
  try {
    const config = parseLlmConfig(
      {
        listen: { port: 0 },
        stateDir: "state",
        policy: path.join(ROOT, "llm-policy.example.json"),
        upstreams: [{ name: "up", baseUrl: `${fake.url}/v1`, apiKeyEnv: "LOADTEST_UPSTREAM_KEY", models: { small: "fake-small-1" }, pricePerMTok: PRICE }],
        routes: [{ id: "all", use: { upstream: "up" } }],
        keys: [
          { name: "loadtest", sha256: hashKey(gatewayKey), dailyUsd: capUsd, monthlyUsd: roundUsd(capUsd * 10) },
          { name: "warmup", sha256: hashKey(warmupKey), dailyUsd: 100, monthlyUsd: 1000 },
        ],
      },
      tmp,
    );
    gateway = await startLlmGateway(config, loadLeakPolicy(config.policyFile), { env: { LOADTEST_UPSTREAM_KEY: upstreamKey }, log: () => undefined });
    const toGateway = (key) => (i) => chat(gateway.url, { authorization: `Bearer ${key}` }, body(i, "small", MAX_TOKENS, PROMPT_CHARS));
    const toUpstream = (i) => chat(fake.url, { authorization: `Bearer ${upstreamKey}` }, { ...body(i, "fake-small-1", MAX_TOKENS, PROMPT_CHARS) });

    const preflight = await chat(gateway.url, {}, body(0, "small", MAX_TOKENS, PROMPT_CHARS));
    // Warm both paths up (on a key with room), so neither pays for the first connections and the JIT.
    const warm = Math.min(50, requests);
    await fire(warm, Math.min(concurrency, 10), toGateway(warmupKey));
    if (direct) await fire(warm, Math.min(concurrency, 10), toUpstream);

    // While the load runs, GET /healthz every 100 ms: what a liveness or readiness probe would see.
    const health = [];
    let polling = true;
    const poller = (async () => {
      while (polling) {
        const t0 = performance.now();
        try {
          await (await fetch(`${gateway.url}/healthz`)).text();
        } catch {
          // counted by its time, like a probe that gave up
        }
        health.push(performance.now() - t0);
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    })();
    const load = await fire(requests, concurrency, toGateway(gatewayKey));
    polling = false;
    await poller;
    const straight = direct ? await fire(requests, concurrency, toUpstream) : undefined;

    const ledger = openLedger(config).usage(config.keys);
    const ledgerBytes = fs.statSync(path.join(config.stateDir, "ledger.json")).size;
    const row = ledger.find((r) => r.key === "loadtest");
    const usage = readUsageLog(path.join(config.stateDir, "usage.jsonl"));
    const verify = verifyUsage(usage.lines, ledger);
    const headerUsd = roundUsd(load.results.reduce((sum, r) => sum + (r.status === 200 && typeof r.cost === "number" ? r.cost : 0), 0));
    const t = tally(load.results);
    const checks = [
      { ok: preflight.status === 401 && preflight.code === "invalid_api_key", what: `without the key: ${preflight.status} ${preflight.code ?? ""}`.trim() + " (the gateway's own 401 expected)" },
      { ok: row.dayUsd <= capUsd + 1e-12, what: `spend within the cap: $${row.dayUsd} of $${capUsd}` },
      { ok: Math.abs(row.dayUsd - headerUsd) < 1e-9, what: `spend equals the cost headers of the ${t.ok} answers let through ($${headerUsd})` },
      { ok: usage.unreadable.length === 0 && verify.every((v) => v.ok), what: "usage --verify: the usage log agrees with the ledger, for both keys" },
      { ok: row.inFlight === 0, what: `reservations left in flight: ${row.inFlight}` },
      ...t.checks,
      givenCap === undefined
        ? { ok: t.ok > 0 && (t.counts["429 budget_exceeded"] ?? 0) > 0, what: "the cap let part of the load through and refused the rest" }
        : { ok: t.ok > 0, what: `${t.ok} answers let through under the cap that was given` },
    ];
    const gatewayOk = stats(load.results.filter((r) => r.status === 200).map((r) => r.ms));
    const upstream = straight ? stats(straight.results.map((r) => r.ms)) : undefined;
    return {
      mode: "in-process",
      requests,
      concurrency,
      capUsd,
      reserveUsd,
      settleUsd,
      spentUsd: row.dayUsd,
      counts: t.counts,
      ok: t.ok,
      refused: t.refused,
      latencyMs: {
        gatewayAll: stats(load.results.map((r) => r.ms)),
        gatewayOk,
        ...(upstream ? { upstreamDirect: upstream, overheadP50: gatewayOk.p50 - upstream.p50, overheadP95: gatewayOk.p95 - upstream.p95 } : {}),
        healthzDuringLoad: stats(health),
      },
      throughputPerSecond: { gateway: requests / load.seconds, gatewayTenths: tenths(load.results), ...(straight ? { upstreamDirect: requests / straight.seconds } : {}) },
      ledgerBytes,
      seconds: load.seconds,
      checks,
      passed: checks.every((c) => c.ok),
    };
  } finally {
    await gateway?.close();
    await fake.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * A gateway that is already running. Only the checks that need no ledger. The key-less request goes
 * first, and when it does not get agent-gate's own 401, no request with the key is sent: the load would
 * go somewhere else, or through something that is not checked, and a provider may bill every answer.
 */
async function runRemote({ url, key, headers, model, maxTokens, requests, concurrency }) {
  const base = url.replace(/\/+$/, "");
  const preflight = await chat(base, headers, body(0, model, maxTokens, 40));
  const reached = preflight.status === 401 && preflight.code === "invalid_api_key";
  const preflightCheck = {
    ok: reached,
    what: reached
      ? "without the gateway key: the gateway's own 401 (the request got through whatever is in front of it)"
      : `without the gateway key: ${preflight.status} ${preflight.code ?? ""}`.trim() + ": the request did not reach the gateway, or the gateway is not agent-gate; check --header-env. No request was sent with the key.",
  };
  if (!reached) {
    return {
      mode: "remote",
      url: base,
      requests: 0,
      concurrency,
      counts: {},
      ok: 0,
      refused: 0,
      costHeadersUsd: 0,
      latencyMs: { gatewayAll: stats([]), gatewayOk: stats([]) },
      throughputPerSecond: { gateway: 0 },
      checks: [preflightCheck],
      passed: false,
    };
  }
  const load = await fire(requests, concurrency, (i) => chat(base, { ...headers, authorization: `Bearer ${key}` }, body(i, model, maxTokens, 40)));
  const t = tally(load.results);
  const checks = [
    preflightCheck,
    ...t.checks,
    { ok: t.ok > 0, what: t.ok > 0 ? `${t.ok} answers let through with the key` : "no answer was let through with the key" },
  ];
  return {
    mode: "remote",
    url: base,
    requests,
    concurrency,
    counts: t.counts,
    ok: t.ok,
    refused: t.refused,
    costHeadersUsd: Math.round(load.results.reduce((sum, r) => sum + (typeof r.cost === "number" ? r.cost : 0), 0) * 1e9) / 1e9,
    latencyMs: { gatewayAll: stats(load.results.map((r) => r.ms)), gatewayOk: stats(load.results.filter((r) => r.status === 200).map((r) => r.ms)) },
    throughputPerSecond: { gateway: requests / load.seconds },
    checks,
    passed: checks.every((c) => c.ok),
  };
}

function report(r) {
  const ms = (v) => (v === null || v === undefined ? "-" : `${v.toFixed(1)} ms`);
  const out = [];
  if (r.mode === "in-process") {
    out.push(`agent-gate loadtest: ${r.requests} requests, ${r.concurrency} at a time, through a gateway in this process to a fake upstream`);
    out.push(`key "loadtest": daily cap $${r.capUsd}; each call reserves $${r.reserveUsd} and settles $${r.settleUsd}; spent $${r.spentUsd}`);
  } else {
    out.push(`agent-gate loadtest: ${r.requests} requests, ${r.concurrency} at a time, against ${r.url}`);
    out.push(`cost headers of the answers let through: $${r.costHeadersUsd}`);
  }
  out.push("");
  out.push(...Object.entries(r.counts).map(([label, n]) => `  ${label.padEnd(26)} ${n}`));
  out.push("");
  const rows = [["", "p50", "p95", "p99", "max", "requests/s"]];
  const l = r.latencyMs;
  rows.push(["gateway, every answer", ms(l.gatewayAll.p50), ms(l.gatewayAll.p95), ms(l.gatewayAll.p99), ms(l.gatewayAll.max), r.throughputPerSecond.gateway.toFixed(0)]);
  rows.push(["gateway, 200 answers", ms(l.gatewayOk.p50), ms(l.gatewayOk.p95), ms(l.gatewayOk.p99), ms(l.gatewayOk.max), ""]);
  if (l.upstreamDirect) rows.push(["fake upstream, direct", ms(l.upstreamDirect.p50), ms(l.upstreamDirect.p95), ms(l.upstreamDirect.p99), ms(l.upstreamDirect.max), r.throughputPerSecond.upstreamDirect.toFixed(0)]);
  const widths = rows[0].map((_, i) => Math.max(...rows.map((row) => row[i].length)));
  for (const row of rows) out.push(`  ${row.map((cell, i) => (i === 0 ? cell.padEnd(widths[i]) : cell.padStart(widths[i]))).join("  ")}`);
  if (l.upstreamDirect) out.push(`  added by the gateway: ${ms(l.overheadP50)} at p50, ${ms(l.overheadP95)} at p95`);
  const tn = r.throughputPerSecond.gatewayTenths;
  if (tn) out.push(`  answers per second through the gateway: ${tn.first.toFixed(0)} over the first tenth of the run, ${tn.last.toFixed(0)} over the last (${r.seconds.toFixed(1)} s in all; ledger.json ${Math.round(r.ledgerBytes / 1024)} KiB at the end)`);
  if (l.healthzDuringLoad) out.push(`  GET /healthz during the load (${l.healthzDuringLoad.count} probes): ${ms(l.healthzDuringLoad.p50)} at p50, ${ms(l.healthzDuringLoad.p95)} at p95, ${ms(l.healthzDuringLoad.max)} at most`);
  out.push("");
  for (const c of r.checks) out.push(`  ${c.ok ? "PASS" : "FAIL"}  ${c.what}`);
  if (r.mode === "remote") out.push("  (not checked here: the ledger. Run `agent-gate usage --verify` where the gateway keeps its state.)");
  out.push("", r.passed ? "PASS" : "FAIL");
  return `${out.join("\n")}\n`;
}

const USAGE_TEXT = `Usage:
  npm run loadtest [-- --requests <n> --concurrency <n>] [--cap-usd <dollars>] [--json] [--no-direct]
  npm run loadtest -- --url <gateway> --key-env <VAR> [--header-env <Header>=<VAR>]... [--model <alias>]
                      [--max-tokens <n>] [--requests <n>] [--concurrency <n>] [--json]
`;

async function main(argv) {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        requests: { type: "string" },
        concurrency: { type: "string" },
        url: { type: "string" },
        "key-env": { type: "string" },
        "header-env": { type: "string", multiple: true },
        model: { type: "string" },
        "max-tokens": { type: "string" },
        json: { type: "boolean", default: false },
        "no-direct": { type: "boolean", default: false },
        "cap-usd": { type: "string" },
        help: { type: "boolean", short: "h", default: false },
      },
    }));
  } catch (err) {
    process.stderr.write(`loadtest: ${err.message}\n\n${USAGE_TEXT}`);
    return 2;
  }
  if (values.help) {
    process.stdout.write(USAGE_TEXT);
    return 0;
  }
  const remote = values.url !== undefined;
  const whole = (name, fallback, max) => {
    if (values[name] === undefined) return fallback;
    const n = Number(values[name]);
    if (!Number.isInteger(n) || n < 1 || n > max) throw new RangeError(`--${name} must be a whole number from 1 to ${max}`);
    return n;
  };
  let requests;
  let concurrency;
  let maxTokens;
  try {
    requests = whole("requests", remote ? 20 : 1000, 100_000);
    concurrency = whole("concurrency", remote ? 5 : 100, 1000);
    maxTokens = whole("max-tokens", 16, 100_000);
  } catch (err) {
    process.stderr.write(`loadtest: ${err.message}\n`);
    return 2;
  }
  let result;
  if (remote) {
    const keyEnv = values["key-env"];
    if (!keyEnv || !process.env[keyEnv]) {
      process.stderr.write(`loadtest: --url needs --key-env <VAR>, an environment variable that holds the gateway key${keyEnv ? ` (${keyEnv} is not set)` : ""}\n`);
      return 2;
    }
    const headers = {};
    for (const spec of values["header-env"] ?? []) {
      const at = spec.indexOf("=");
      const header = spec.slice(0, at);
      const variable = spec.slice(at + 1);
      if (at <= 0 || !process.env[variable]) {
        process.stderr.write(`loadtest: --header-env takes <Header>=<VAR>, with VAR set in the environment (got ${JSON.stringify(spec)})\n`);
        return 2;
      }
      headers[header] = process.env[variable];
    }
    result = await runRemote({ url: values.url, key: process.env[keyEnv], headers, model: values.model ?? "small", maxTokens, requests, concurrency });
  } else {
    let capUsd;
    if (values["cap-usd"] !== undefined) {
      capUsd = Number(values["cap-usd"]);
      if (!(capUsd > 0)) {
        process.stderr.write("loadtest: --cap-usd must be a positive number of dollars\n");
        return 2;
      }
    }
    result = await runInProcess({ requests, concurrency, direct: !values["no-direct"], ...(capUsd === undefined ? {} : { capUsd }) });
  }
  process.stdout.write(values.json ? `${JSON.stringify(result, null, 2)}\n` : report(result));
  return result.passed ? 0 : 1;
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      process.stderr.write(`loadtest: ${err.stack ?? err}\n`);
      process.exit(1);
    },
  );
}

module.exports = { runInProcess, runRemote, percentile, stats, report };
