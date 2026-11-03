// Crash tests. A pending approval is a record in a file, not a request waiting in memory
// (docs/adr/0001-non-blocking-approvals.md), so a gateway killed with kill -9 must lose nothing:
// after a restart the queue is still there, an approved call runs once, and the next one asks again.
// A write cut short by a kill must never leave a damaged or empty file, nor a lock or a temporary
// file that gets in the way of the next run.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { ApprovalStore, hashArguments, type Approval, type AskRequest } from "../../src/gateway/approvals.js";
import { isRunning } from "../../src/gateway/state-file.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const BIN = path.join(ROOT, "bin", "agent-gate.js");
const FAKE = path.join(__dirname, "fake-downstream.js");
const APPROVALS_JS = path.join(__dirname, "..", "..", "src", "gateway", "approvals.js");
const TTL = 24 * 60 * 60 * 1000;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const request = (args: Record<string, unknown>): AskRequest => ({ server: "demo", tool: "delete_file", args, argsHash: hashArguments(args), rule: "red-line-4-delete", why: "Red line 4" });

/** A process id that is not running: one of a process that has already exited. */
function deadPid(): number {
  const pid = spawnSync(process.execPath, ["-e", ""]).pid;
  assert.ok(pid && !isRunning(pid));
  return pid;
}

async function waitUntilGone(pid: number): Promise<void> {
  for (let i = 0; i < 200 && isRunning(pid); i++) await sleep(20);
  assert.equal(isRunning(pid), false, `process ${pid} is still running`);
}

describe("crash: what a killed process leaves behind", () => {
  let dir: string;
  before(() => (dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-crash-"))));
  after(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("a lock whose holder is gone is broken at once, and that holder's temporary file is removed", () => {
    const state = path.join(dir, "leftovers");
    fs.mkdirSync(path.join(state, "approvals.lock"), { recursive: true });
    const dead = deadPid();
    fs.writeFileSync(path.join(state, "approvals.lock", "owner"), String(dead));
    const half = path.join(state, `approvals.json.${dead}.0badf00d.tmp`);
    fs.writeFileSync(half, '{"version":1,"approvals":[{"id":"ap-');
    const t0 = Date.now();
    new ApprovalStore(state, TTL).resolveAsk(request({ path: "a.txt" }));
    // Without the check of the owner's id, this write would wait for the 5-second deadline and fail.
    assert.ok(Date.now() - t0 < 4000, "the lock of a dead process must not make the next writer wait for the deadline");
    assert.equal(fs.existsSync(half), false, "the half-written temporary file is gone");
    assert.equal(fs.existsSync(path.join(state, "approvals.lock")), false);
    assert.equal(new ApprovalStore(state, TTL).list().length, 1);
  });

  it("a lock with no owner (a crash between creating it and writing the owner) is broken after a second", () => {
    const state = path.join(dir, "ownerless");
    fs.mkdirSync(path.join(state, "approvals.lock"), { recursive: true });
    const t0 = Date.now();
    new ApprovalStore(state, TTL).resolveAsk(request({ path: "a.txt" }));
    const waited = Date.now() - t0;
    assert.ok(waited >= 900 && waited < 4500, `waited ${waited} ms`);
  });

  it("kill -9 in the middle of a run of writes never leaves approvals.json damaged, and the next write recovers at once", async (t) => {
    const state = path.join(dir, "writes");
    const file = path.join(state, "approvals.json");
    // A child that keeps adding big requests, so that each write takes a while and a kill lands in one.
    const writer = `
      const { ApprovalStore, hashArguments } = require(${JSON.stringify(APPROVALS_JS)});
      const store = new ApprovalStore(process.argv[1], ${TTL});
      for (let i = 0; ; i++) {
        const args = { path: "f" + i + "-" + process.pid, pad: "x".repeat(20000) };
        store.resolveAsk({ server: "demo", tool: "delete_file", args, argsHash: hashArguments(args), rule: "r", why: "w" });
      }`;
    let leftovers = 0;
    fs.mkdirSync(state, { recursive: true }); // a kill can come before the writer has made the folder
    for (const delay of [80, 120, 160, 200, 260, 320, 400, 500]) {
      const child = spawn(process.execPath, ["-e", writer, state], { stdio: "ignore" });
      await sleep(delay);
      child.kill("SIGKILL");
      await once(child, "exit");
      if (fs.existsSync(path.join(state, "approvals.lock")) || fs.readdirSync(state).some((n) => n.endsWith(".tmp"))) leftovers++;
      if (fs.existsSync(file)) {
        const data = JSON.parse(fs.readFileSync(file, "utf8")) as { version: number; approvals: Approval[] };
        assert.equal(data.version, 1, `after a kill at ${delay} ms`);
        assert.ok(Array.isArray(data.approvals));
      }
      const t0 = Date.now();
      new ApprovalStore(state, TTL).resolveAsk(request({ path: `after-${delay}.txt` }));
      assert.ok(Date.now() - t0 < 4000, `the write after a kill at ${delay} ms waited ${Date.now() - t0} ms (the lock deadline is 5 s)`);
      assert.deepEqual(fs.readdirSync(state).filter((n) => n.endsWith(".tmp")), [], "no temporary file is left");
    }
    t.diagnostic(`${leftovers} of 8 kills left a lock or a temporary file behind; the next write cleared each one`);
    assert.ok(new ApprovalStore(state, TTL).list().length >= 8);
  });
});

describe("crash: the gateway is killed with one request pending and one approved but not used", () => {
  let tmp: string;
  let configFile: string;
  let receivedLog: string;
  const clients: Client[] = [];

  before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-night-"));
    receivedLog = path.join(tmp, "received.jsonl");
    configFile = path.join(tmp, "gateway.config.json");
    fs.writeFileSync(
      configFile,
      JSON.stringify({
        servers: [{ name: "demo", command: process.execPath, args: [FAKE, "--log", receivedLog] }],
        policy: path.join(ROOT, "policy.example.json"),
        stateDir: "state",
      }),
    );
  });
  after(async () => {
    await Promise.allSettled(clients.map((c) => c.close()));
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  async function startGateway(): Promise<{ client: Client; pid: number }> {
    const transport = new StdioClientTransport({ command: process.execPath, args: [BIN, "serve", "--config", configFile], stderr: "pipe" });
    const client = new Client({ name: "crash-agent", version: "1.0.0" });
    await client.connect(transport);
    clients.push(client);
    assert.ok(transport.pid, "the gateway runs as a process of its own");
    return { client, pid: transport.pid };
  }
  const call = async (client: Client, args: Record<string, unknown>) => (await client.callTool({ name: "demo__delete_file", arguments: args })) as CallToolResult;
  const text = (r: CallToolResult) => (r.content[0]?.type === "text" ? r.content[0].text : "");
  const idIn = (r: CallToolResult) => /Approval id: (ap-[0-9a-f]{8})/.exec(text(r))?.[1] ?? assert.fail(`no approval id in: ${text(r)}`);
  const received = () => (fs.existsSync(receivedLog) ? fs.readFileSync(receivedLog, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
  const cli = (...args: string[]) => spawnSync(process.execPath, [BIN, ...args, "--config", configFile], { encoding: "utf8" });
  const queue = (): Approval[] => JSON.parse(cli("approvals", "list", "--all", "--json").stdout);

  it("after kill -9 and a restart: the queue is intact, the approved call runs once, the next one asks again", async () => {
    const first = await startGateway();
    const approvedId = idIn(await call(first.client, { path: "notes/a.md" }));
    const pendingId = idIn(await call(first.client, { path: "notes/b.md" }));
    // A delete is irreversible (ADR 0013): the human approves it with the action token that "approvals show" prints.
    const token = (JSON.parse(cli("approvals", "show", approvedId).stdout) as { actionToken: string }).actionToken;
    assert.equal(cli("approvals", "approve", approvedId, "--token", token).status, 0);

    process.kill(first.pid, "SIGKILL"); // the night: no shutdown, no flush
    await waitUntilGone(first.pid);

    const stateDir = path.join(tmp, "state");
    assert.deepEqual(fs.readdirSync(stateDir).filter((n) => n.endsWith(".tmp")), []);
    const onDisk = new Map(queue().map((a) => [a.id, a.status]));
    assert.deepEqual([onDisk.get(approvedId), onDisk.get(pendingId)], ["approved", "pending"], "(a) the queue survived the kill");

    const second = await startGateway();
    assert.notEqual(second.pid, first.pid);
    assert.equal(text(await call(second.client, { path: "notes/a.md" })), "pretended to delete notes/a.md", "(b) the approved call runs");
    assert.deepEqual(received().map((r) => r.args.path), ["notes/a.md"], "it reached the server once");
    const again = idIn(await call(second.client, { path: "notes/a.md" }));
    assert.notEqual(again, approvedId, "(c) a second identical call asks again: the approval was used up");
    assert.equal(idIn(await call(second.client, { path: "notes/b.md" })), pendingId, "the pending request is the same one");
    assert.equal(received().length, 1);
  });
});
