// What the MCP gateway does when one of its own parts fails: it does not run the call. The rows of
// the README's "Failure behavior" table that are not covered by another suite are proven here.
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { loadPolicy } from "../../src/gateway/config.js";
import { evaluate } from "../../src/gateway/policy.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const BIN = path.join(ROOT, "bin", "agent-gate.js");
const FAKE = path.join(__dirname, "fake-downstream.js");

const open: Array<{ client: Client; dir: string }> = [];
after(async () => {
  for (const g of open) {
    await g.client.close();
    fs.rmSync(g.dir, { recursive: true, force: true });
  }
});

/** A gateway on the example policy whose state directory `prepare` has damaged first. */
async function gatewayWith(prepare: (stateDir: string) => void) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-failure-"));
  const stateDir = path.join(dir, "state");
  fs.mkdirSync(stateDir, { mode: 0o700 });
  prepare(stateDir);
  const received = path.join(dir, "received.jsonl");
  const config = path.join(dir, "gateway.config.json");
  fs.writeFileSync(config, JSON.stringify({ servers: [{ name: "demo", command: process.execPath, args: [FAKE, "--log", received] }], policy: path.join(ROOT, "policy.example.json"), stateDir: "state" }));
  const client = new Client({ name: "failure-test", version: "1.0.0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [BIN, "serve", "--config", config], stderr: "ignore" }));
  open.push({ client, dir });
  return {
    call: async (name: string, args: Record<string, unknown>) => (await client.callTool({ name, arguments: args })) as CallToolResult,
    received: () => (fs.existsSync(received) ? fs.readFileSync(received, "utf8").trim().split("\n").length : 0),
  };
}

const text = (r: CallToolResult) => (r.content[0] as { text: string }).text;

describe("failure behavior: the MCP gateway does not run a call it could not check or record", () => {
  it("if the shell analyzer throws, the older rules decide, and what they do not block asks", () => {
    // The policy calls the analyzer through the module's exports, so it can be made to fail here.
    const guard = require("#command-guard") as { analyze: (command: string) => unknown };
    const analyze = guard.analyze;
    guard.analyze = () => {
      throw new Error("analyzer broken");
    };
    try {
      const policy = loadPolicy(path.join(ROOT, "policy.example.json"));
      const run = (command: string) => evaluate(policy, { server: "demo", tool: "run_command", args: { command } });
      assert.deepEqual([run("git push --force origin main").decision, run("git push --force origin main").why], ["block", "shell guard: force push (legacy rule)"]);
      const ls = run("ls -la");
      assert.equal(ls.decision, "ask");
      assert.match(ls.why, /^shell guard failed \(Error: analyzer broken\), so a human should look at the command$/);
    } finally {
      guard.analyze = analyze;
    }
  });

  it("if the audit log cannot be written, no call is run", async () => {
    const g = await gatewayWith((stateDir) => fs.mkdirSync(path.join(stateDir, "audit.jsonl"))); // a folder where the file should be
    const r = await g.call("demo__echo", { text: "hello" });
    assert.equal(r.isError, true);
    assert.match(text(r), /^agent-gate could not check or record this call, so it was not run: /);
    assert.equal(g.received(), 0);
  });

  it("if approvals.json is damaged, a call that needs a human is not run and nothing is queued; an allowed call still runs", async () => {
    let approvals = "";
    const g = await gatewayWith((stateDir) => {
      approvals = path.join(stateDir, "approvals.json");
      fs.writeFileSync(approvals, "{ cut short");
    });
    const held = await g.call("demo__delete_file", { path: "notes/old.md" });
    assert.match(text(held), /could not check or record this call, so it was not run: .*approvals\.json is not valid JSON/);
    assert.equal(fs.readFileSync(approvals, "utf8"), "{ cut short", "left as it was, for a human to look at");
    assert.equal(text(await g.call("demo__echo", { text: "still allowed" })), "still allowed");
    assert.equal(g.received(), 1);
  });
});
