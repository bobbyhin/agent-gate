// Downstream servers that fail: one that exits in the middle of a call is started again with backoff,
// while the other servers' calls go on; an optional one may be missing at startup and is started when
// it is needed; one that keeps failing is given up after maxRestarts tries; a required one that cannot
// start still stops the gateway. "agent-gate status" shows each server's state from status.json.
// The gateways run in this process with short backoffs, against the fake downstream server.
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { readAudit } from "../../src/gateway/audit-tools.js";
import { main, type Io } from "../../src/gateway/cli.js";
import { loadConfig, loadPolicy, parseConfig } from "../../src/gateway/config.js";
import { createGateway, type Gateway } from "../../src/gateway/server.js";
import { readStatus, StatusFile } from "../../src/gateway/status.js";

const FAKE = path.join(__dirname, "fake-downstream.js");
const ALLOW_ALL = { default: "allow", rules: [] };

interface Running {
  dir: string;
  configFile: string;
  gateway: Gateway;
  client: Client;
  logs: string[];
  state: (server: string) => string | undefined;
  status: () => Record<string, { state: string; restarts: number; tries: number; maxTries: number; lastError?: string }>;
  call: (name: string, args: Record<string, unknown>) => Promise<CallToolResult>;
  names: () => Promise<string[]>;
}

const running: Running[] = [];
after(async () => {
  for (const r of running) {
    await r.client.close().catch(() => undefined);
    await r.gateway.close().catch(() => undefined);
    fs.rmSync(r.dir, { recursive: true, force: true });
  }
});

async function start(servers: Array<Record<string, unknown>>, backoffMs: number): Promise<Running> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-restarts-"));
  const configFile = path.join(dir, "gateway.config.json");
  fs.writeFileSync(path.join(dir, "policy.json"), JSON.stringify(ALLOW_ALL));
  fs.writeFileSync(configFile, JSON.stringify({ servers, policy: "policy.json", stateDir: "state" }));
  const logs: string[] = [];
  const config = loadConfig(configFile);
  const gateway = await createGateway(config, loadPolicy(config.policyFile), (m) => logs.push(m), { restartBackoffMs: backoffMs });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await gateway.server.connect(serverSide);
  const client = new Client({ name: "restarts-test", version: "1.0.0" });
  await client.connect(clientSide);
  const status = () => readStatus(path.join(dir, "state", "status.json")).find((p) => p.pid === process.pid)?.servers ?? {};
  const r: Running = {
    dir,
    configFile,
    gateway,
    client,
    logs,
    status,
    state: (server) => status()[server]?.state,
    call: async (name, args) => (await client.callTool({ name, arguments: args })) as CallToolResult,
    names: async () => (await client.listTools()).tools.map((t) => t.name).sort(),
  };
  running.push(r);
  return r;
}

/** Waits for a condition, generously: a busy machine starts processes slowly. */
async function until(check: () => boolean | Promise<boolean>, what: string, ms = 15_000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

const text = (r: CallToolResult) => (r.content[0] as { text: string }).text;
const quietIo = (): Io & { output: () => string } => {
  let out = "";
  return { out: (t) => (out += t), err: (t) => (out += t), output: () => out };
};

describe("downstream servers that go away, and come back", () => {
  it("a server that exits mid-call is restarted; meanwhile its calls are refused with the reason, and the others go on", async () => {
    const r = await start(
      [
        { name: "demo", command: process.execPath, args: [FAKE, "--exit-on-text", "crash"] },
        { name: "other", command: process.execPath, args: [FAKE] },
      ],
      // Long enough that the call below lands while the server is down, even on a busy machine.
      2500,
    );
    assert.equal(r.state("demo"), "up");
    await assert.rejects(r.call("demo__echo", { text: "crash" }), "the call that crashed the server fails");
    await until(() => r.state("demo") === "restarting", "demo to be restarting");

    const refused = await r.call("demo__echo", { text: "hello" });
    assert.equal(refused.isError, true);
    assert.match(text(refused), /^agent-gate could not run this call: server "demo" went away and is being restarted: try 1 of 3 in [1-3] s; last error: the server's process exited\. \(rule server-down\) Try again later\.$/);
    assert.deepEqual((await r.names()).filter((n) => n.startsWith("demo__")), [], "a server that is not up lists nothing");
    assert.equal(text(await r.call("other__echo", { text: "still here" })), "still here");

    await until(() => r.state("demo") === "up", "demo to be up again");
    assert.equal(text(await r.call("demo__echo", { text: "back" })), "back");
    assert.ok((await r.names()).includes("demo__echo"));
    assert.deepEqual([r.status().demo?.restarts, r.status().demo?.tries], [1, 0]);

    const lines = readAudit(path.join(r.dir, "state", "audit.jsonl")).lines.map((l) => l.value).filter((l) => l.event === undefined && l.server === "demo");
    assert.deepEqual(
      lines.map((l) => [l.decision, l.rule, l.forwarded]),
      [
        ["allow", "default", true],
        ["block", "server-down", false],
        ["allow", "default", true],
      ],
    );
    assert.ok(r.logs.some((l) => l === 'downstream server "demo" is up again'));
  });

  it("agent-gate status shows each server of each running gateway", async () => {
    const r = await start([{ name: "demo", command: process.execPath, args: [FAKE] }], 50);
    const io = quietIo();
    assert.equal(await main(["status", "--config", r.configFile], io), 0);
    assert.match(io.output(), new RegExp(`^gateway pid ${process.pid} \\(stdio\\), started \\S+, updated \\S+\\n  server  state  restarts  failed tries  since +next try  last error\\n  demo    up     0         0 of 3 `));
    const json = quietIo();
    await main(["status", "--json", "--config", r.configFile], json);
    assert.equal(JSON.parse(json.output())[0].servers.demo.state, "up");
  });

  it("an optional server that cannot start is left out, and starts when it is needed once it can", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-optional-"));
    const marker = path.join(dir, "do-not-start");
    fs.writeFileSync(marker, "");
    try {
      const r = await start(
        [
          { name: "flaky", command: process.execPath, args: [FAKE, "--fail-start-if", marker], optional: true },
          { name: "demo", command: process.execPath, args: [FAKE] },
        ],
        200,
      );
      assert.equal(r.state("flaky"), "down");
      assert.match(text(await r.call("flaky__echo", { text: "x" })), /optional server "flaky" is not running: it is tried again when needed, (in 1 s|now) \(try 1 of 3\); last error: /);
      assert.ok(r.logs.some((l) => l.startsWith('optional server "flaky" did not start (')));
      assert.deepEqual((await r.names()).filter((n) => n.startsWith("flaky__")), []);

      fs.rmSync(marker);
      await new Promise((resolve) => setTimeout(resolve, 250));
      await until(async () => (await r.names()).includes("flaky__echo"), "flaky to start on demand");
      assert.equal(r.state("flaky"), "up");
      assert.equal(text(await r.call("flaky__echo", { text: "now" })), "now");
      assert.equal(r.status().flaky?.restarts, 0, "a first start is not a restart");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("an optional server that never starts is given up after maxRestarts tries", async () => {
    const r = await start(
      [
        { name: "gone", command: process.execPath, args: ["-e", "process.exit(3)"], optional: true, maxRestarts: 2 },
        { name: "demo", command: process.execPath, args: [FAKE] },
      ],
      20,
    );
    await until(async () => {
      await r.names();
      return r.state("gone") === "failed";
    }, "gone to be failed");
    assert.deepEqual([r.status().gone?.tries, r.status().gone?.maxTries], [2, 2]);
    assert.match(text(await r.call("gone__echo", { text: "x" })), /server "gone" is down: 2 tries in a row to start it failed; last error: .+; restart the gateway to try again/);
  });

  it("a server that keeps dying right after a restart ends up failed (a crash loop)", async () => {
    const r = await start([{ name: "loop", command: process.execPath, args: [FAKE, "--exit-after-ms", "300"] }], 20);
    await until(() => r.state("loop") === "failed", "the crash loop to be given up");
    assert.deepEqual([r.status().loop?.restarts, r.status().loop?.tries], [3, 3]);
  });

  it("a required server that cannot start still stops the gateway", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-required-"));
    try {
      const file = path.join(dir, "gateway.config.json");
      fs.writeFileSync(path.join(dir, "policy.json"), JSON.stringify(ALLOW_ALL));
      fs.writeFileSync(file, JSON.stringify({ servers: [{ name: "broken", command: process.execPath, args: ["-e", "process.exit(3)"] }], policy: "policy.json", stateDir: "state" }));
      const run = spawnSync(process.execPath, [path.join(__dirname, "..", "..", "..", "bin", "agent-gate.js"), "serve", "--config", file], { encoding: "utf8", input: "" });
      assert.equal(run.status, 1);
      assert.match(run.stderr, /could not start downstream server "broken"/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("status.json", () => {
  it("keeps one entry per process, drops the entries of processes that are gone, and refuses a damaged file", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-status-"));
    try {
      const gone = spawnSync(process.execPath, ["-e", "0"]).pid as number;
      new StatusFile(dir, { mode: "stdio", startedAt: "2026-10-31T00:00:00.000Z", pid: gone }).write({});
      const mine = new StatusFile(dir, { mode: "http", startedAt: "2026-10-31T00:00:01.000Z" });
      mine.write({ demo: { state: "up", restarts: 0, tries: 0, maxTries: 3, since: "2026-10-31T00:00:01.000Z" } });
      assert.deepEqual(readStatus(path.join(dir, "status.json")).map((p) => [p.pid, p.mode]), [[process.pid, "http"]]);
      mine.remove();
      assert.deepEqual(readStatus(path.join(dir, "status.json")), []);
      fs.writeFileSync(path.join(dir, "status.json"), "{");
      assert.throws(() => readStatus(path.join(dir, "status.json")), /status\.json is not valid JSON/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("config: optional must be true or false, maxRestarts 0 to 10", () => {
    const base = { policy: "p.json", stateDir: "s" };
    assert.throws(() => parseConfig({ ...base, servers: [{ name: "a", command: "node", optional: "yes" }] }, "/srv"), /config\.servers\[0\]\.optional must be true or false/);
    assert.throws(() => parseConfig({ ...base, servers: [{ name: "a", command: "node", maxRestarts: 11 }] }, "/srv"), /config\.servers\[0\]\.maxRestarts must be a whole number from 0 to 10/);
    const config = parseConfig({ ...base, servers: [{ name: "a", command: "node", optional: true, maxRestarts: 0 }] }, "/srv");
    assert.deepEqual([config.servers[0]?.optional, config.servers[0]?.maxRestarts], [true, 0]);
  });
});
