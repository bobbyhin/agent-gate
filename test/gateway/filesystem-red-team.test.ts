// Red team: path tricks against the real filesystem MCP server (@modelcontextprotocol/server-filesystem,
// a devDependency) behind the gateway. Each attempt runs three times, each with a fresh folder:
//   alone   a policy with no rules and default allow, so every call reaches the server: what the
//           server's own allowed-folder check does by itself;
//   text    the rules a policy could write before path matchers: globs on the path's text;
//   paths   the same rules with path matchers: under (the workspace) and touches (the gateway state).
// The gateway's state folder is put inside the server's folder on purpose, to show what the server's
// own check cannot know about. The README's table under "Paths" is this test's expectations.
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const BIN = path.join(ROOT, "bin", "agent-gate.js");
const FILESYSTEM_SERVER = path.join(ROOT, "node_modules", "@modelcontextprotocol", "server-filesystem", "dist", "index.js");
const FILE_TOOLS = ["read_text_file", "write_file"];

/** What happened to a call: the gateway held it (ask), blocked it, or forwarded it and the server refused it, failed or ran it. */
type Outcome = "ran" | "server refused" | "server error" | "ask" | "block";

interface Fixture {
  dir: string;
  work: string;
  outside: string;
  state: string;
}

/** A fresh folder: the server's workspace (with the gateway's state inside it), a folder outside, symlinks. */
function fixture(): Fixture {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-fs-red-team-"));
  const work = path.join(dir, "work");
  const outside = path.join(dir, "outside");
  const state = path.join(work, ".agent-gate");
  fs.mkdirSync(path.join(work, "notes"), { recursive: true });
  fs.mkdirSync(state, { mode: 0o700 });
  fs.mkdirSync(outside);
  fs.mkdirSync(path.join(dir, "home"));
  fs.writeFileSync(path.join(work, "notes", "old.md"), "old notes\n");
  fs.writeFileSync(path.join(outside, "secret.txt"), "not for agents\n");
  fs.symlinkSync(path.join("..", "outside"), path.join(work, "link-out"));
  fs.symlinkSync(".agent-gate", path.join(work, "state-link"));
  return { dir, work, outside, state };
}

/** The attempts, in order; the writes into the gateway state come last, because one of them works. */
function attempts(f: Fixture): Array<{ id: string; tool: string; args: Record<string, unknown> }> {
  const read = (p: string) => ({ path: p });
  const write = (p: string) => ({ path: p, content: "overwritten by the agent\n" });
  return [
    { id: "inside the workspace", tool: "read_text_file", args: read(path.join(f.work, "notes", "old.md")) },
    { id: '".." out of the workspace', tool: "read_text_file", args: read(`${f.work}/../outside/secret.txt`) },
    { id: "an absolute path outside", tool: "read_text_file", args: read(path.join(f.outside, "secret.txt")) },
    { id: "a symlink inside that points out", tool: "read_text_file", args: read(path.join(f.work, "link-out", "secret.txt")) },
    { id: 'a percent-encoded ".."', tool: "read_text_file", args: read(`${f.work}/%2e%2e/outside/secret.txt`) },
    { id: '"~/" (the server\'s home)', tool: "read_text_file", args: read("~/notes/old.md") },
    { id: "a relative path", tool: "read_text_file", args: read("notes/old.md") },
    { id: "the gateway's state, by its name", tool: "write_file", args: write(path.join(f.state, "approvals.json")) },
    // The server resolves a relative path against its own folder, where the state is.
    { id: "the gateway's state, by a relative path", tool: "write_file", args: write(".agent-gate/approvals.json") },
    { id: "the gateway's state, through a symlink", tool: "write_file", args: write(path.join(f.work, "state-link", "approvals.json")) },
  ];
}

function policy(kind: "alone" | "text" | "paths", f: Fixture): unknown {
  if (kind === "alone") return { default: "allow", rules: [] };
  const why = { state: "The gateway's state is off limits to agents.", work: "File tools may use the workspace." };
  return {
    default: "ask",
    rules:
      kind === "text"
        ? [
            { id: "protect-gateway-state", args: { path: ["*.agent-gate", "*.agent-gate/*"] }, decision: "block", why: why.state },
            { id: "workspace", tool: FILE_TOOLS, args: { path: `${f.work}/*` }, decision: "allow", why: why.work },
          ]
        : [
            { id: "protect-gateway-state", args: { path: { touches: [f.state] } }, decision: "block", why: why.state },
            { id: "workspace", tool: FILE_TOOLS, args: { path: { under: [f.work] } }, decision: "allow", why: why.work },
          ],
  };
}

const opened: Array<{ client: Client; dir: string }> = [];
after(async () => {
  for (const g of opened) {
    await g.client.close();
    fs.rmSync(g.dir, { recursive: true, force: true });
  }
});

/** Runs every attempt through a gateway with this policy, in front of the real server; returns what happened to each. */
async function run(kind: "alone" | "text" | "paths"): Promise<{ outcomes: Record<string, Outcome>; f: Fixture; tools: string[] }> {
  const f = fixture();
  const policyFile = path.join(f.dir, "policy.json");
  fs.writeFileSync(policyFile, JSON.stringify(policy(kind, f)));
  const config = path.join(f.dir, "gateway.config.json");
  fs.writeFileSync(
    config,
    JSON.stringify({
      // The server's HOME is a folder of the fixture, so "~/" can never reach the real one.
      servers: [{ name: "files", command: process.execPath, args: [FILESYSTEM_SERVER, f.work], env: { HOME: path.join(f.dir, "home") } }],
      policy: policyFile,
      stateDir: f.state,
    }),
  );
  const client = new Client({ name: "fs-red-team", version: "1.0.0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [BIN, "serve", "--config", config], stderr: "ignore" }));
  opened.push({ client, dir: f.dir });
  const tools = (await client.listTools()).tools.map((tool) => tool.name);
  const outcomes: Record<string, Outcome> = {};
  for (const attempt of attempts(f)) {
    const result = (await client.callTool({ name: `files__${attempt.tool}`, arguments: attempt.args })) as CallToolResult;
    const text = (result.content[0] as { text?: string } | undefined)?.text ?? "";
    outcomes[attempt.id] = text.startsWith("agent-gate blocked")
      ? "block"
      : text.startsWith("agent-gate: this call needs a human")
        ? "ask"
        : result.isError
          ? text.includes("Access denied")
            ? "server refused"
            : "server error"
          : "ran";
  }
  return { outcomes, f, tools };
}

describe("red team: path tricks against the real filesystem server, behind the gateway", () => {
  it("each attempt: what the server does alone, with text rules, and with path matchers", async () => {
    assert.ok(fs.existsSync(FILESYSTEM_SERVER), "npm install puts @modelcontextprotocol/server-filesystem in node_modules");
    const alone = await run("alone");
    // The real server's 14 tools, listed through the gateway.
    assert.equal(alone.tools.length, 14);
    for (const tool of ["read_text_file", "write_file", "edit_file", "move_file", "list_allowed_directories"]) assert.ok(alone.tools.includes(`files__${tool}`), tool);
    const text = await run("text");
    const paths = await run("paths");
    const expected: Array<[string, Outcome, Outcome, Outcome]> = [
      // attempt                                   the server alone   text rules        path matchers
      ["inside the workspace", "ran", "ran", "ran"],
      ['".." out of the workspace', "server refused", "server refused", "ask"],
      ["an absolute path outside", "server refused", "ask", "ask"],
      ["a symlink inside that points out", "server refused", "server refused", "ask"],
      ['a percent-encoded ".."', "server error", "server error", "ask"],
      // A path the gateway cannot place (the server's home, its working folder) counts as touching the
      // state: the server may read it there. So the state rule blocks it, before the workspace rule asks.
      ['"~/" (the server\'s home)', "server refused", "ask", "block"],
      ["a relative path", "ran", "ask", "block"],
      ["the gateway's state, by its name", "ran", "block", "block"],
      ["the gateway's state, by a relative path", "ran", "block", "block"],
      ["the gateway's state, through a symlink", "ran", "ran", "block"],
    ];
    assert.deepEqual(
      Object.keys(alone.outcomes).map((id) => [id, alone.outcomes[id], text.outcomes[id], paths.outcomes[id]]),
      expected,
    );
    // With text rules, the symlink write really replaced the gateway's approval queue; with path matchers, nothing did.
    assert.equal(fs.readFileSync(path.join(text.f.state, "approvals.json"), "utf8"), "overwritten by the agent\n");
    assert.notEqual(fs.readFileSync(path.join(paths.f.state, "approvals.json"), "utf8"), "overwritten by the agent\n");
  });
});
