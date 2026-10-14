// End to end: a real MCP client talks to the gateway process ("agent-gate serve"), which proxies
// the fake downstream server. Approvals are answered with the real CLI, as a human would.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ErrorCode, McpError, type CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { ApprovalStore, hashArguments, type Approval } from "../../src/gateway/approvals.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const BIN = path.join(ROOT, "bin", "agent-gate.js");
const FAKE = path.join(__dirname, "fake-downstream.js");

describe("gateway end to end", () => {
  let tmp: string;
  let configFile: string;
  let stateDir: string;
  let receivedLog: string;
  let gateway: Client;
  let direct: Client;
  let gatewayStderr = "";
  let toolCalls = 0;

  before(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-e2e-"));
    stateDir = path.join(tmp, "state");
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
    const transport = new StdioClientTransport({ command: process.execPath, args: [BIN, "serve", "--config", configFile], stderr: "pipe" });
    transport.stderr?.on("data", (chunk) => (gatewayStderr += String(chunk)));
    gateway = new Client({ name: "e2e-agent", version: "1.0.0" });
    await gateway.connect(transport);

    // The same fake server without the gateway, to compare against.
    direct = new Client({ name: "e2e-direct", version: "1.0.0" });
    await direct.connect(new StdioClientTransport({ command: process.execPath, args: [FAKE], stderr: "pipe" }));
  });

  after(async () => {
    await gateway?.close();
    await direct?.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  /** What actually reached the downstream server. */
  function received(): Array<{ tool: string; args: Record<string, unknown> }> {
    if (!fs.existsSync(receivedLog)) return [];
    return fs.readFileSync(receivedLog, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  }

  async function call(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
    toolCalls++;
    return (await gateway.callTool({ name, arguments: args })) as CallToolResult;
  }

  function text(result: CallToolResult): string {
    const first = result.content[0];
    assert.ok(first && first.type === "text", "expected a text result");
    return first.text;
  }

  function approvalIdIn(result: CallToolResult): string {
    assert.equal(result.isError, true);
    const id = /Approval id: (ap-[0-9a-f]{8})/.exec(text(result))?.[1];
    assert.ok(id, `no approval id in: ${text(result)}`);
    return id;
  }

  /** stderr and stdout are separate pipes, so a log line may arrive just after the result. */
  async function waitFor(condition: () => boolean, what: string): Promise<void> {
    for (let i = 0; i < 100 && !condition(); i++) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.ok(condition(), `timed out waiting for ${what}`);
  }

  function cli(...args: string[]): { code: number | null; out: string; err: string } {
    const run = spawnSync(process.execPath, [BIN, ...args, "--config", configFile], { encoding: "utf8" });
    return { code: run.status, out: run.stdout, err: run.stderr };
  }

  function queue(): Approval[] {
    return JSON.parse(cli("approvals", "list", "--all", "--json").out);
  }

  it("lists every downstream tool as <server>__<tool>, otherwise unchanged", async () => {
    const viaGateway = await gateway.listTools();
    const unproxied = await direct.listTools();
    assert.deepEqual(
      viaGateway.tools,
      unproxied.tools.map((tool) => ({ ...tool, name: `demo__${tool.name}` })),
    );
    assert.deepEqual(viaGateway.tools.map((t) => t.name).sort(), ["demo__delete_file", "demo__echo", "demo__run_command"]);
  });

  it("forwards an allowed call and returns the downstream result unchanged", async () => {
    const result = await call("demo__echo", { text: "hello gateway" });
    assert.deepEqual(result, await direct.callTool({ name: "echo", arguments: { text: "hello gateway" } }));
    assert.deepEqual(result.structuredContent, { echoed: "hello gateway", length: 13 });
    assert.deepEqual(received(), [{ tool: "echo", args: { text: "hello gateway" } }]);
  });

  let firstId = "";
  it("holds a delete call for a human and does not forward it", async () => {
    const result = await call("demo__delete_file", { path: "notes/old.md" });
    firstId = approvalIdIn(result);
    assert.match(text(result), /^agent-gate: this call needs a human decision, so it was not run\./);
    assert.match(text(result), /Red line 4: this tool looks like it deletes or overwrites data\. \(rule red-line-4-delete\)/);
    assert.match(text(result), new RegExp(`agent-gate approvals approve ${firstId}`));
    assert.equal(received().length, 1, "the delete call must not reach the server");

    const listed = cli("approvals", "list");
    assert.equal(listed.code, 0);
    assert.match(listed.out, new RegExp(`^${firstId}  pending  demo__delete_file\\n  why:     Red line 4`));
    assert.match(listed.out, /args: {2,}\{"path":"notes\/old\.md"\}/);
    const shown = JSON.parse(cli("approvals", "show", firstId).out);
    assert.deepEqual([shown.status, shown.args, shown.argsHash], ["pending", { path: "notes/old.md" }, hashArguments({ path: "notes/old.md" })]);
  });

  it("repeating the call before a decision reuses the same request", async () => {
    const result = await call("demo__delete_file", { path: "notes/old.md" });
    assert.equal(approvalIdIn(result), firstId);
    assert.match(text(result), /still waiting for a human decision/);
    assert.equal(received().length, 1);
    assert.equal(queue().length, 1);
  });

  let secondId = "";
  it("after approval the identical call runs exactly once, then needs a new approval", async () => {
    const approved = cli("approvals", "approve", firstId);
    assert.equal(approved.code, 0, approved.err);
    assert.match(approved.out, new RegExp(`^approved ${firstId}: demo__delete_file \\{"path":"notes/old.md"\\}`));

    const result = await call("demo__delete_file", { path: "notes/old.md" });
    assert.equal(result.isError, undefined);
    assert.equal(text(result), "pretended to delete notes/old.md");
    assert.deepEqual(received().at(-1), { tool: "delete_file", args: { path: "notes/old.md" } });
    assert.equal(received().length, 2);

    const second = await call("demo__delete_file", { path: "notes/old.md" });
    secondId = approvalIdIn(second);
    assert.notEqual(secondId, firstId);
    assert.equal(received().length, 2, "a used approval does not allow a second run");
  });

  it("an approval does not cover different arguments", async () => {
    assert.equal(cli("approvals", "approve", secondId).code, 0);
    const other = await call("demo__delete_file", { path: "notes/other.md" });
    const otherId = approvalIdIn(other);
    assert.notEqual(otherId, secondId);
    assert.equal(received().length, 2, "notes/other.md was not approved");

    const original = await call("demo__delete_file", { path: "notes/old.md" });
    assert.equal(text(original), "pretended to delete notes/old.md");
    assert.equal(received().length, 3);
  });

  it("a denied call is never forwarded and is not queued again", async () => {
    const id = approvalIdIn(await call("demo__delete_file", { path: "secrets.txt" }));
    const denied = cli("approvals", "deny", id);
    assert.equal(denied.code, 0, denied.err);

    for (let i = 0; i < 2; i++) {
      const retry = await call("demo__delete_file", { path: "secrets.txt" });
      assert.equal(retry.isError, true);
      assert.match(text(retry), new RegExp(`^agent-gate: a human denied this exact call \\(approval ${id},`));
    }
    assert.equal(received().length, 3);
    assert.equal(queue().filter((a) => a.args.path === "secrets.txt").length, 1);

    const reapprove = cli("approvals", "approve", id);
    assert.equal(reapprove.code, 1);
    assert.match(reapprove.err, new RegExp(`${id} is denied; only a pending request can be approved`));
  });

  it("an expired approval never allows the call", async () => {
    // Create and approve a request as if it happened 25 hours ago, through the real store.
    const ttl = 24 * 60 * 60 * 1000;
    const past = new ApprovalStore(stateDir, ttl, () => Date.now() - 25 * 60 * 60 * 1000);
    const args = { path: "old-approval.txt" };
    const old = past.resolveAsk({ server: "demo", tool: "delete_file", args, argsHash: hashArguments(args), rule: "red-line-4-delete", why: "test" });
    past.approve(old.approval.id);
    const expiredPending = past.resolveAsk({ server: "demo", tool: "delete_file", args: { path: "x" }, argsHash: hashArguments({ path: "x" }), rule: "r", why: "test" });

    const result = await call("demo__delete_file", args);
    const id = approvalIdIn(result);
    assert.notEqual(id, old.approval.id);
    assert.equal(received().length, 3, "the expired approval did not let the call through");

    const late = cli("approvals", "approve", expiredPending.approval.id);
    assert.equal(late.code, 1);
    assert.match(late.err, /expired at/);
  });

  it("a blocked call is refused and never queued", async () => {
    const before = queue().length;
    const result = await call("demo__run_command", { command: "git push --force origin main" });
    assert.equal(result.isError, true);
    assert.equal(text(result).split("\n")[0], "agent-gate blocked this call, so it was not run: shell guard: force push (rule shell-guard)");
    assert.doesNotMatch(text(result), /Approval id/);
    assert.equal(queue().length, before);
    assert.equal(received().length, 3);
  });

  it("decides shell commands with the slice-1 analyzer: allow, warn, ask", async () => {
    assert.equal(text(await call("demo__run_command", { command: "ls -la" })), "pretended to run: ls -la");
    assert.equal(text(await call("demo__run_command", { command: "kill -9 4242" })), "pretended to run: kill -9 4242");
    await waitFor(() => /WARN demo__run_command: shell guard: kill -9 \(SIGKILL\) \(rule shell-guard\)/.test(gatewayStderr), "the WARN line");
    approvalIdIn(await call("demo__run_command", { command: "git push origin main" }));
    assert.deepEqual(
      received().slice(3).map((r) => r.args.command),
      ["ls -la", "kill -9 4242"],
    );
  });

  it("rejects tools that are not <known server>__<tool>", async () => {
    for (const name of ["nope__echo", "echo", "demo__"]) {
      await assert.rejects(gateway.callTool({ name, arguments: {} }), (err: unknown) => err instanceof McpError && err.code === ErrorCode.InvalidParams);
    }
  });

  it("writes one audit line per decision, without argument values", () => {
    const file = path.join(stateDir, "audit.jsonl");
    const content = fs.readFileSync(file, "utf8");
    const lines = content.trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(lines.length, toolCalls);
    for (const line of lines) {
      assert.deepEqual(Object.keys(line).filter((k) => !["ts", "server", "tool", "decision", "rule", "why", "argsHash", "forwarded", "approvalId"].includes(k)), []);
      assert.match(line.argsHash, /^sha256:[0-9a-f]{64}$/);
      assert.equal(typeof line.forwarded, "boolean");
    }
    // Whole argument values. (The why may name a rule, such as "kill -9 (SIGKILL)", but never quotes the call.)
    for (const value of ["hello gateway", "notes/old.md", "notes/other.md", "secrets.txt", "old-approval.txt", "kill -9 4242", "git push --force origin main", "git push origin main", "ls -la"]) {
      assert.equal(content.includes(value), false, `the audit log contains the argument value ${value}`);
    }
    assert.deepEqual(
      lines.map((l) => [l.tool, l.decision, l.forwarded]).slice(0, 4),
      [
        ["echo", "allow", true],
        ["delete_file", "ask", false],
        ["delete_file", "ask", false],
        ["delete_file", "ask", true],
      ],
    );
    assert.equal(lines[3].approvalId, firstId);
    assert.equal(lines.filter((l) => l.decision === "block").length, 1);
    assert.equal(lines.filter((l) => l.decision === "warn" && l.forwarded).length, 1);
    if (process.platform !== "win32") {
      assert.equal(fs.statSync(file).mode & 0o777, 0o600);
      assert.equal(fs.statSync(stateDir).mode & 0o777, 0o700);
    }
  });
});
