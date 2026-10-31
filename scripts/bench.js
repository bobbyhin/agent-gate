#!/usr/bin/env node
"use strict";
// npm run bench [-- --calls 300] [--json]
//
// What the gateways add to one call, measured against the fake downstream server and the fake upstream
// (after `npm run build`; nothing leaves the machine and nothing costs money). Calls go one at a time,
// so this is the gateway's own work per call, not time spent waiting behind other calls (npm run
// loadtest measures that). Each path is timed next to the same call made without the gateway:
//
//   MCP allow         demo__echo through `agent-gate serve` (stdio) with policy.example.json, against
//                     echo sent straight to the fake server; and again with the example's loop limit
//                     taken out, because that limit costs a locked, fsync'd write of repeats.json per call
//   MCP ask, approve, delete_file through the gateway: the call that queues a request; the approval, as
//   retry             `approvals approve --yes` does it (the approval store and its audit line), without
//                     starting a new process; the same call again, now forwarded. And the CLI itself,
//                     started as a new process, as a human would run it
//   LLM call          a chat completion through the LLM gateway (leak guard, reserve, settle, a usage
//                     line), against the same request straight to the fake upstream
//   ledger write      one reserve() and one settle() at several ledger sizes. Each is a locked,
//                     fsync'd rewrite of ledger.json, and settled reservation ids stay in the file for a
//                     reservation's lifetime (302.5 s with the defaults), so a busy gateway's ledger is
//                     larger. Next to it, one fsync of a small file on the same disk: the floor.
//
// The numbers are for one machine, with fake servers on the loopback interface: no network, no model.
// They show the cost of the gateway's own steps and where it goes, not how a deployment performs.
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { performance } = require("node:perf_hooks");
const { parseArgs } = require("node:util");
const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { StdioClientTransport } = require("@modelcontextprotocol/sdk/client/stdio.js");
const { CallToolResultSchema } = require("@modelcontextprotocol/sdk/types.js");
const { percentile } = require("./loadtest.js");

const ROOT = path.join(__dirname, "..");
const BIN = path.join(ROOT, "bin", "agent-gate.js");
const FAKE_SERVER = path.join(ROOT, "dist", "test", "gateway", "fake-downstream.js");
const dist = (file) => require(path.join(ROOT, "dist", file));

function summary(ms) {
  const sorted = [...ms].sort((a, b) => a - b);
  return { count: sorted.length, p50: percentile(sorted, 50), p95: percentile(sorted, 95) };
}

async function timed(fn) {
  const t0 = performance.now();
  const value = await fn();
  return { ms: performance.now() - t0, value };
}

/** An MCP client over stdio: the gateway (`agent-gate serve --config <file>`) or the fake server itself. */
async function connect(args) {
  const client = new Client({ name: "agent-gate-bench", version: "1.0.0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args, stderr: "ignore" }));
  return client;
}

/** A tools/call without the client's own output-schema check, so both sides do the same client work. */
const callTool = (client, name, args) => client.request({ method: "tools/call", params: { name, arguments: args } }, CallToolResultSchema);

async function mcp(tmp, calls) {
  const { ApprovalStore } = dist("src/gateway/approvals.js");
  const { AuditLog } = dist("src/gateway/audit.js");
  const policy = JSON.parse(fs.readFileSync(path.join(ROOT, "policy.example.json"), "utf8"));
  const withoutLimit = path.join(tmp, "policy-no-loop-limit.json");
  fs.writeFileSync(withoutLimit, JSON.stringify({ ...policy, repeat: [] }));
  const config = (name, policyFile) => {
    const file = path.join(tmp, `${name}.config.json`);
    fs.writeFileSync(file, JSON.stringify({ servers: [{ name: "demo", command: process.execPath, args: [FAKE_SERVER] }], policy: policyFile, stateDir: path.join(tmp, name) }));
    return file;
  };
  const exampleConfig = config("example", path.join(ROOT, "policy.example.json"));
  const noLimitConfig = config("no-limit", withoutLimit);

  const direct = await connect([FAKE_SERVER]);
  const gateway = await connect([BIN, "serve", "--config", exampleConfig]);
  const noLimit = await connect([BIN, "serve", "--config", noLimitConfig]);
  try {
    // Warm up every path: the first listing pins the tools, and the JIT has to see some calls.
    await gateway.listTools();
    await noLimit.listTools();
    for (let i = 0; i < 30; i++) {
      await callTool(direct, "echo", { text: `warm ${i}` });
      await callTool(gateway, "demo__echo", { text: `warm ${i}` });
      await callTool(noLimit, "demo__echo", { text: `warm ${i}` });
    }
    // Different text each time: the same call 20 times a minute would trip the example's loop limit.
    const run = async (client, name) => {
      const ms = [];
      for (let i = 0; i < calls; i++) ms.push((await timed(() => callTool(client, name, { text: `bench ${i}` }))).ms);
      return summary(ms);
    };
    const allowDirect = await run(direct, "echo");
    const allowGateway = await run(gateway, "demo__echo");
    const allowNoLimit = await run(noLimit, "demo__echo");

    // Ask, approve, retry, one delete at a time, as the CLI's approve --yes would answer it.
    const stateDir = path.join(tmp, "example");
    const store = new ApprovalStore(stateDir, 24 * 60 * 60 * 1000);
    const audit = new AuditLog(path.join(stateDir, "audit.jsonl"));
    const asks = [];
    const approves = [];
    const retries = [];
    const deletesDirect = [];
    const rounds = Math.max(10, Math.floor(calls / 3));
    for (let i = 0; i < rounds; i++) {
      const args = { path: `notes/bench-${i}.md` };
      deletesDirect.push((await timed(() => callTool(direct, "delete_file", args))).ms);
      const ask = await timed(() => callTool(gateway, "demo__delete_file", args));
      const id = /Approval id: (ap-[0-9a-f]+)/.exec(ask.value.content[0].text)?.[1];
      if (!id) throw new Error(`delete_file did not ask: ${ask.value.content[0].text}`);
      asks.push(ask.ms);
      approves.push(
        (
          await timed(() => {
            const a = store.approve(id, { by: "bench", confirmation: "--yes" });
            audit.writeEvent({ approvalId: a.id, server: a.server, tool: a.tool, rule: a.rule, argsHash: a.argsHash, decision: "approved", waitMs: 0, decidedBy: "bench", confirmation: "--yes" });
          })
        ).ms,
      );
      const retry = await timed(() => callTool(gateway, "demo__delete_file", args));
      if (retry.value.isError) throw new Error(`the approved delete did not run: ${retry.value.content[0].text}`);
      retries.push(retry.ms);
    }
    // The CLI as a human runs it: a new Node process each time.
    const cli = [];
    for (let i = 0; i < 5; i++) {
      const ask = await callTool(gateway, "demo__delete_file", { path: `notes/cli-${i}.md` });
      const id = /Approval id: (ap-[0-9a-f]+)/.exec(ask.content[0].text)?.[1];
      const t0 = performance.now();
      const out = spawnSync(process.execPath, [BIN, "approvals", "approve", id, "--yes", "--config", exampleConfig], { encoding: "utf8" });
      cli.push(performance.now() - t0);
      if (out.status !== 0) throw new Error(`approvals approve failed: ${out.stderr}`);
    }
    return {
      allow: { direct: allowDirect, gateway: allowGateway, gatewayNoLoopLimit: allowNoLimit },
      askApproveRetry: { rounds, deleteDirect: summary(deletesDirect), ask: summary(asks), approve: summary(approves), retry: summary(retries), cliProcess: summary(cli) },
    };
  } finally {
    await Promise.allSettled([direct.close(), gateway.close(), noLimit.close()]);
  }
}

async function llm(tmp, calls) {
  const { hashKey, loadLeakPolicy, parseLlmConfig } = dist("src/llm/config.js");
  const { startLlmGateway } = dist("src/llm/server.js");
  const { startFakeUpstream } = dist("test/llm/fake-upstream.js");
  const fake = await startFakeUpstream({ mode: "ok", usage: { prompt_tokens: 30, completion_tokens: 10 } });
  const key = `bench-${crypto.randomBytes(16).toString("hex")}`;
  const upstreamKey = `bench-up-${crypto.randomBytes(16).toString("hex")}`;
  let gateway;
  try {
    const config = parseLlmConfig(
      {
        listen: { port: 0 },
        stateDir: path.join(tmp, "llm"),
        policy: path.join(ROOT, "llm-policy.example.json"),
        upstreams: [{ name: "up", baseUrl: `${fake.url}/v1`, apiKeyEnv: "BENCH_UPSTREAM_KEY", models: { small: "fake-small-1" }, pricePerMTok: { input: 1, output: 1 } }],
        routes: [{ id: "all", use: { upstream: "up" } }],
        keys: [{ name: "bench", sha256: hashKey(key), dailyUsd: 100, monthlyUsd: 1000 }],
      },
      tmp,
    );
    gateway = await startLlmGateway(config, loadLeakPolicy(config.policyFile), { env: { BENCH_UPSTREAM_KEY: upstreamKey }, log: () => undefined });
    const post = async (url, auth, model, i) => {
      const res = await fetch(`${url}/v1/chat/completions`, {
        method: "POST",
        headers: { authorization: `Bearer ${auth}`, "content-type": "application/json" },
        body: JSON.stringify({ model, messages: [{ role: "user", content: `Summarise ticket ${i}: the printer on floor 3 is out of paper again.` }], max_tokens: 20 }),
      });
      await res.text();
      if (res.status !== 200) throw new Error(`HTTP ${res.status} from ${url}`);
    };
    for (let i = 0; i < 30; i++) {
      await post(fake.url, upstreamKey, "fake-small-1", i);
      await post(gateway.url, key, "small", i);
    }
    const direct = [];
    const through = [];
    for (let i = 0; i < calls; i++) {
      direct.push((await timed(() => post(fake.url, upstreamKey, "fake-small-1", i))).ms);
      through.push((await timed(() => post(gateway.url, key, "small", i))).ms);
    }
    return { direct: summary(direct), gateway: summary(through) };
  } finally {
    await gateway?.close();
    await fake.close();
  }
}

function ledgerWrites(tmp, sizes, ops) {
  const { Ledger, utcDay, utcMonth } = dist("src/llm/budget.js");
  const key = { name: "bench", sha256: "0".repeat(64), dailyUsd: 1e6, monthlyUsd: 1e7 };
  const rows = [];
  for (const size of sizes) {
    const dir = path.join(tmp, `ledger-${size}`);
    fs.mkdirSync(dir, { recursive: true });
    const now = Date.now();
    const until = new Date(now + 60 * 60 * 1000).toISOString();
    const settled = {};
    for (let i = 0; i < size; i++) settled[`rs-${i.toString(16).padStart(8, "0")}`] = until;
    const entry = { day: utcDay(now), dayUsd: 0, month: utcMonth(now), monthUsd: 0, reservations: {}, ...(size > 0 ? { settled } : {}) };
    fs.writeFileSync(path.join(dir, "ledger.json"), `${JSON.stringify({ version: 1, keys: { bench: entry } }, null, 2)}\n`);
    const bytes = fs.statSync(path.join(dir, "ledger.json")).size;
    const ledger = new Ledger(dir, 302_500);
    const reserves = [];
    const settles = [];
    for (let i = 0; i < ops; i++) {
      let t0 = performance.now();
      const r = ledger.reserve(key, 0.0001);
      reserves.push(performance.now() - t0);
      t0 = performance.now();
      ledger.settle("bench", r.id, 0.0001);
      settles.push(performance.now() - t0);
    }
    rows.push({ settledIds: size, bytes, reserve: summary(reserves), settle: summary(settles) });
  }
  // One fsync of a small file on the same disk: no ledger write can be faster than this.
  const probe = path.join(tmp, "fsync-probe");
  const syncs = [];
  for (let i = 0; i < ops; i++) {
    const t0 = performance.now();
    const fd = fs.openSync(probe, "w");
    fs.writeFileSync(fd, "x".repeat(100));
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    syncs.push(performance.now() - t0);
  }
  return { sizes: rows, fsyncSmallFile: summary(syncs) };
}

function machine() {
  const cpus = os.cpus();
  return {
    cpu: cpus[0]?.model?.trim() ?? "unknown",
    cores: cpus.length,
    platform: `${os.platform()} ${os.arch()}`,
    node: process.version,
    loadAverage1m: Math.round(os.loadavg()[0] * 10) / 10,
  };
}

function report(r) {
  const ms = (v) => (v === null || v === undefined ? "-" : `${v.toFixed(2)} ms`);
  const rows = [["path", "p50", "p95", "added at p50"]];
  const pair = (label, s, base) => rows.push([label, ms(s.p50), ms(s.p95), base ? ms(s.p50 - base.p50) : ""]);
  const m = r.mcp;
  pair("MCP echo, straight to the server", m.allow.direct);
  pair("MCP echo through the gateway, example policy", m.allow.gateway, m.allow.direct);
  pair("  the same, without the loop limit", m.allow.gatewayNoLoopLimit, m.allow.direct);
  pair("MCP delete_file, straight to the server", m.askApproveRetry.deleteDirect);
  pair("MCP delete_file: the ask (request queued)", m.askApproveRetry.ask);
  pair("  the approval (store + audit line)", m.askApproveRetry.approve);
  pair("  the retry, forwarded", m.askApproveRetry.retry, m.askApproveRetry.deleteDirect);
  pair("  approvals approve --yes, a new process", m.askApproveRetry.cliProcess);
  pair("LLM call, straight to the upstream", r.llm.direct);
  pair("LLM call through the gateway", r.llm.gateway, r.llm.direct);
  for (const s of r.ledger.sizes) {
    pair(`ledger reserve(), ${s.settledIds} settled ids (${Math.round(s.bytes / 1024)} KiB)`, s.reserve);
    pair(`ledger settle(), ${s.settledIds} settled ids`, s.settle);
  }
  pair("fsync of a 100-byte file, same disk", r.ledger.fsyncSmallFile);
  const widths = rows[0].map((_, i) => Math.max(...rows.map((row) => row[i].length)));
  const lines = rows.map((row) => `| ${row.map((cell, i) => cell.padEnd(widths[i])).join(" | ")} |`);
  lines.splice(1, 0, `| ${widths.map((w) => "-".repeat(w)).join(" | ")} |`);
  const mc = r.machine;
  return [
    `agent-gate bench: ${r.calls} calls per path, one at a time; ${mc.cpu}, ${mc.cores} cores, ${mc.platform}, Node ${mc.node}, load average ${mc.loadAverage1m}`,
    "",
    ...lines,
    "",
  ].join("\n");
}

async function main(argv) {
  let values;
  try {
    ({ values } = parseArgs({ args: argv, options: { calls: { type: "string" }, json: { type: "boolean", default: false }, help: { type: "boolean", short: "h", default: false } } }));
  } catch (err) {
    process.stderr.write(`bench: ${err.message}\nUsage: npm run bench [-- --calls <n>] [--json]\n`);
    return 2;
  }
  if (values.help) {
    process.stdout.write("Usage: npm run bench [-- --calls <n>] [--json]\n");
    return 0;
  }
  const calls = values.calls === undefined ? 300 : Number(values.calls);
  if (!Number.isInteger(calls) || calls < 10 || calls > 100_000) {
    process.stderr.write("bench: --calls must be a whole number from 10 to 100000\n");
    return 2;
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-bench-"));
  try {
    const result = { calls, machine: machine(), mcp: await mcp(tmp, calls), llm: await llm(tmp, calls), ledger: ledgerWrites(tmp, [0, 1000, 10_000, 30_000], 30) };
    process.stdout.write(values.json ? `${JSON.stringify(result, null, 2)}\n` : report(result));
    return 0;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      process.stderr.write(`bench: ${err.stack ?? err}\n`);
      process.exit(1);
    },
  );
}

module.exports = { ledgerWrites, summary };
