"use strict";
// The status-mcp example (examples/status-mcp/): a real MCP server behind the gateway with its own
// policy. Reads are allowed, a write waits for a human, a bulk write is blocked, and the audit log
// shows each. Runs after the build (npm test), on a copy of the sample folder.
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { StdioClientTransport } = require("@modelcontextprotocol/sdk/client/stdio.js");

const ROOT = path.join(__dirname, "..");
const EXAMPLE = path.join(ROOT, "examples", "status-mcp");
const BIN = path.join(ROOT, "bin", "agent-gate.js");

describe("examples/status-mcp behind the gateway", () => {
  let tmp;
  let config;
  let gateway;

  before(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-status-"));
    fs.cpSync(path.join(EXAMPLE, "sample-status"), path.join(tmp, "status"), { recursive: true });
    config = path.join(tmp, "gateway.config.json");
    const shipped = JSON.parse(fs.readFileSync(path.join(EXAMPLE, "gateway.config.json"), "utf8"));
    fs.writeFileSync(
      config,
      JSON.stringify({
        ...shipped,
        servers: [{ name: "status", command: process.execPath, args: [path.join(EXAMPLE, "server.js"), "--dir", path.join(tmp, "status"), "--writable", "--now", "2026-10-31T00:00:00Z"] }],
        policy: path.join(EXAMPLE, "policy.json"),
        stateDir: "state",
      }),
    );
    gateway = new Client({ name: "status-test", version: "1.0.0" });
    await gateway.connect(new StdioClientTransport({ command: process.execPath, args: [BIN, "serve", "--config", config], stderr: "ignore" }));
  });
  after(async () => {
    await gateway?.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const call = (name, args = {}) => gateway.callTool({ name, arguments: args });
  const cli = (...args) => spawnSync(process.execPath, [BIN, ...args, "--config", config], { encoding: "utf8" });

  it("lists the four tools", async () => {
    const tools = await gateway.listTools();
    assert.deepEqual(tools.tools.map((t) => t.name).sort(), ["status__bot_status", "status__inbox_unread_count", "status__mark_inbox_read", "status__slo_now"]);
  });

  it("allows the reads, which answer with structured JSON", async () => {
    assert.deepEqual((await call("status__slo_now")).structuredContent.objectives.map((o) => [o.name, o.met]), [
      ["jobs finish on time", true],
      ["jobs succeed", false],
    ]);
    assert.deepEqual((await call("status__bot_status")).structuredContent.bots.map((b) => [b.name, b.hoursSinceLastRun, b.overdue]), [
      ["nightly-backup", 22, false],
      ["price-watch", 62.8, true],
      ["report-mailer", 17.5, false],
    ]);
    assert.deepEqual((await call("status__inbox_unread_count")).structuredContent, { unread: 2, oldest: { id: "n-101", subject: "A watched item dropped below its target price" } });
  });

  it("holds a write for a human, then runs it once", async () => {
    const held = await call("status__mark_inbox_read", { id: "n-101" });
    assert.equal(held.isError, true);
    const id = /Approval id: (ap-[0-9a-f]{8})/.exec(held.content[0].text)[1];
    assert.match(held.content[0].text, /This changes the inbox, so a human says yes first\. \(rule inbox-writes\)/);
    assert.equal(cli("approvals", "approve", id, "--yes").status, 0);
    assert.deepEqual((await call("status__mark_inbox_read", { id: "n-101" })).structuredContent, { marked: 1, ids: ["n-101"] });
    assert.equal((await call("status__inbox_unread_count")).structuredContent.unread, 1);
  });

  it("blocks marking the whole inbox read, and the server is never called", async () => {
    const blocked = await call("status__mark_inbox_read", { all: true });
    assert.match(blocked.content[0].text, /^agent-gate blocked this call, so it was not run: Marking the whole inbox read hides what nobody looked at/);
    assert.equal((await call("status__inbox_unread_count")).structuredContent.unread, 1);
  });

  it("leaves an audit log that verifies, with one line per decision", () => {
    const lines = fs.readFileSync(path.join(tmp, "state", "audit.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(
      lines.filter((l) => l.event === undefined).map((l) => [l.tool, l.decision, l.forwarded]),
      [
        ["slo_now", "allow", true],
        ["bot_status", "allow", true],
        ["inbox_unread_count", "allow", true],
        ["mark_inbox_read", "ask", false],
        ["mark_inbox_read", "ask", true],
        ["inbox_unread_count", "allow", true],
        ["mark_inbox_read", "block", false],
        ["inbox_unread_count", "allow", true],
      ],
    );
    const verified = cli("audit", "verify");
    assert.equal(verified.status, 0, verified.stdout);
  });

  it("starts read-only unless told otherwise: a write says what it would have done", () => {
    const run = spawnSync(process.execPath, [path.join(EXAMPLE, "server.js"), "--dir", path.join(tmp, "status")], {
      input: [
        JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } }),
        JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
        JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "mark_inbox_read", arguments: { id: "n-102" } } }),
      ].join("\n") + "\n",
      encoding: "utf8",
      timeout: 20_000,
    });
    const answer = run.stdout.trim().split("\n").map((l) => JSON.parse(l)).find((m) => m.id === 2);
    assert.deepEqual(answer.result.structuredContent, { marked: 0, wouldMark: ["n-102"], note: "this server was started without --writable, so it changed nothing" });
    assert.match(fs.readFileSync(path.join(tmp, "status", "inbox.jsonl"), "utf8"), /"id":"n-102"[^\n]*"read":false/);
  });
});
