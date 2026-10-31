// Rewrite rules and alsoMatched through a running gateway: the downstream server gets the edited
// arguments, an approval is bound to the edited call, and the human sees every rule that matched.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { hashArguments } from "../../src/gateway/approvals.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const BIN = path.join(ROOT, "bin", "agent-gate.js");
const FAKE = path.join(__dirname, "fake-downstream.js");

const POLICY = {
  default: "allow",
  rules: [
    { id: "no-debug", tool: "search_notes", decision: "rewrite", rewrite: { drop: ["debug"] }, why: "Debug output can carry internals." },
    { id: "cap-limit", tool: "search_notes", decision: "rewrite", rewrite: { clamp: { limit: { min: 1, max: 100 } } }, why: "At most 100 rows per search." },
    { id: "ask-exports", tool: "search_notes", args: { query: "export*" }, decision: "ask", why: "An export needs a human." },
    { id: "red-line-4-delete", toolWords: ["delete"], decision: "ask", why: "Red line 4: deletes." },
    { id: "file-tools-logged", tool: "*file*", decision: "warn", why: "File tools are logged." },
  ],
};

describe("rewrite rules and alsoMatched through the gateway", () => {
  let tmp: string;
  let configFile: string;
  let receivedLog: string;
  let gateway: Client;

  before(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-rewrite-"));
    receivedLog = path.join(tmp, "received.jsonl");
    fs.writeFileSync(path.join(tmp, "policy.json"), JSON.stringify(POLICY));
    configFile = path.join(tmp, "gateway.config.json");
    fs.writeFileSync(configFile, JSON.stringify({ servers: [{ name: "demo", command: process.execPath, args: [FAKE, "--log", receivedLog] }], policy: "policy.json", stateDir: "state" }));
    gateway = new Client({ name: "rewrite-test", version: "1.0.0" });
    await gateway.connect(new StdioClientTransport({ command: process.execPath, args: [BIN, "serve", "--config", configFile], stderr: "ignore" }));
  });
  after(async () => {
    await gateway?.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const call = async (name: string, args: Record<string, unknown>) => (await gateway.callTool({ name, arguments: args })) as CallToolResult;
  const received = () => (fs.existsSync(receivedLog) ? fs.readFileSync(receivedLog, "utf8").trim().split("\n").map((l) => JSON.parse(l)) : []);
  const auditLines = () => fs.readFileSync(path.join(tmp, "state", "audit.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const cli = (...args: string[]) => spawnSync(process.execPath, [BIN, ...args, "--config", configFile], { encoding: "utf8" });
  const text = (r: CallToolResult) => (r.content[0] as { text: string }).text;

  it("forwards the edited arguments, says so in the result's _meta, and keeps both hashes in the audit line", async () => {
    const original = { query: "notes", limit: 5000, debug: true };
    const r = await call("demo__search_notes", original);
    assert.equal(r.isError, undefined);
    assert.deepEqual(received().at(-1), { tool: "search_notes", args: { query: "notes", limit: 100 } });
    assert.deepEqual(r._meta?.["agent-gate/rewritten-by"], ["no-debug", "cap-limit"]);
    const line = auditLines().filter((l) => l.event === undefined).at(-1);
    assert.deepEqual(
      [line.decision, line.argsHash, line.originalArgsHash, line.rewrittenBy, line.forwarded],
      ["allow", hashArguments({ query: "notes", limit: 100 }), hashArguments(original), ["no-debug", "cap-limit"], true],
    );
  });

  it("binds an approval to the edited call: the human approves what will run, and the agent's own call then runs once", async () => {
    const original = { query: "export everything", limit: 10_000 };
    const id = /Approval id: (ap-[0-9a-f]{8})/.exec(text(await call("demo__search_notes", original)))?.[1];
    assert.ok(id);
    const shown = JSON.parse(cli("approvals", "show", id).stdout);
    assert.deepEqual([shown.args, shown.argsHash, shown.rewrittenBy], [{ query: "export everything", limit: 100 }, hashArguments({ query: "export everything", limit: 100 }), ["cap-limit"]]);
    assert.match(cli("approvals", "list").stdout, /\n {2}edited: {2}by cap-limit; the args below are what will run\n {2}args: {4}\{"limit":100,"query":"export everything"\}/);
    assert.equal(cli("approvals", "approve", id, "--yes").status, 0);
    const before = received().length;
    assert.match(text(await call("demo__search_notes", original)), /^searched with /);
    assert.deepEqual(received().slice(before), [{ tool: "search_notes", args: { query: "export everything", limit: 100 } }]);
    assert.match(text(await call("demo__search_notes", original)), /needs a human decision/, "used once");
  });

  it("asks when an edit cannot make the call safe, and forwards nothing", async () => {
    const before = received().length;
    const r = await call("demo__search_notes", { query: "notes", limit: "lots" });
    assert.equal(r.isError, true);
    assert.match(text(r), /keeps "limit" within bounds, and this value is not a number, so it cannot be made safe \(rule cap-limit\)/);
    assert.equal(received().length, before);
  });

  it("shows every rule that matched on the approval card and in the audit line, while the first one decides", async () => {
    const r = await call("demo__delete_file", { path: "notes/old.md" });
    const id = /Approval id: (ap-[0-9a-f]{8})/.exec(text(r))?.[1];
    assert.ok(id);
    assert.match(cli("approvals", "list").stdout, new RegExp(`${id} {2}pending {2}demo__delete_file\\n {2}why: {5}Red line 4: deletes\\. \\(rule red-line-4-delete\\)\\n {2}also: {4}file-tools-logged \\(warn: File tools are logged\\.\\)\\n`));
    const read = spawnSync(process.execPath, [BIN, "approvals", "approve", id, "--config", configFile], { encoding: "utf8", input: "no\n" });
    assert.match(read.stdout, /\n {2}also: {5}file-tools-logged \(warn: File tools are logged\.\)\n/);
    const line = auditLines().filter((l) => l.event === undefined).at(-1);
    assert.deepEqual([line.rule, line.alsoMatched], ["red-line-4-delete", ["file-tools-logged"]]);
  });
});
