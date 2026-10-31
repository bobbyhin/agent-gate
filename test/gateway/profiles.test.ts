// Profiles: named sets of tools in the gateway config. A connection that runs with one (serve --profile)
// sees only the tools its globs match, and a call to any other tool is blocked (rule not-in-profile),
// audited and never forwarded, on top of a server's own "expose".
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { parseConfig } from "../../src/gateway/config.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const BIN = path.join(ROOT, "bin", "agent-gate.js");
const FAKE = path.join(__dirname, "fake-downstream.js");

const PROFILES = { "read-only": { demo: ["echo", "search_*"] }, full: { demo: ["*"] } };
const ALL_TOOLS = ["demo__delete_file", "demo__deploy", "demo__echo", "demo__execute_sql", "demo__fail", "demo__run_command", "demo__search_notes", "demo__set_echo_description"];

interface Running {
  client: Client;
  dir: string;
  received: () => Array<{ tool: string }>;
  audit: () => Array<Record<string, any>>;
  call: (name: string, args: Record<string, unknown>) => Promise<CallToolResult>;
  names: () => Promise<string[]>;
}

const dirs: string[] = [];
const clients: Client[] = [];
after(async () => {
  for (const c of clients) await c.close();
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function writeConfig(extra: Record<string, unknown> = {}, server: Record<string, unknown> = {}): { dir: string; configFile: string; log: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-profiles-"));
  dirs.push(dir);
  const log = path.join(dir, "received.jsonl");
  fs.writeFileSync(path.join(dir, "policy.json"), JSON.stringify({ default: "allow", rules: [] }));
  const configFile = path.join(dir, "gateway.config.json");
  fs.writeFileSync(
    configFile,
    JSON.stringify({ servers: [{ name: "demo", command: process.execPath, args: [FAKE, "--log", log], ...server }], policy: "policy.json", stateDir: "state", profiles: PROFILES, ...extra }),
  );
  return { dir, configFile, log };
}

async function start(profile: string | undefined, server: Record<string, unknown> = {}): Promise<Running> {
  const { dir, configFile, log } = writeConfig({}, server);
  const client = new Client({ name: "profiles-test", version: "1.0.0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [BIN, "serve", "--config", configFile, ...(profile ? ["--profile", profile] : [])], stderr: "ignore" }));
  clients.push(client);
  return {
    client,
    dir,
    received: () => (fs.existsSync(log) ? fs.readFileSync(log, "utf8").trim().split("\n").map((l) => JSON.parse(l)) : []),
    audit: () => fs.readFileSync(path.join(dir, "state", "audit.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l)),
    call: async (name, args) => (await client.callTool({ name, arguments: args })) as CallToolResult,
    names: async () => (await client.listTools()).tools.map((t) => t.name).sort(),
  };
}

const text = (r: CallToolResult) => (r.content[0] as { text: string }).text;

describe("profiles: what a connection may see and call", () => {
  it("a read-only profile lists only the tools its globs match", async () => {
    const r = await start("read-only");
    assert.deepEqual(await r.names(), ["demo__echo", "demo__search_notes"]);
    const ok = await r.call("demo__echo", { text: "hi" });
    assert.equal(ok.isError, undefined);
    const line = r.audit().find((l) => l.tool === "echo" && l.event === undefined);
    assert.deepEqual([line?.decision, line?.forwarded, line?.profile], ["allow", true, "read-only"]);
  });

  it("a call to a tool the profile leaves out is blocked, audited with the profile, and never reaches the server", async () => {
    const r = await start("read-only");
    const refused = await r.call("demo__delete_file", { path: "notes/old.md" });
    assert.equal(refused.isError, true);
    assert.match(text(refused), /^agent-gate blocked this call, so it was not run: profile "read-only" leaves this tool out, so this connection may not call it \(rule not-in-profile\)/);
    const line = r.audit().find((l) => l.tool === "delete_file");
    assert.deepEqual([line?.decision, line?.rule, line?.forwarded, line?.profile], ["block", "not-in-profile", false, "read-only"]);
    assert.deepEqual(r.received().map((c) => c.tool), [], "nothing reached the server");
  });

  it("a full profile sees every tool, and no profile at all changes nothing", async () => {
    const full = await start("full");
    assert.deepEqual(await full.names(), ALL_TOOLS);
    const none = await start(undefined);
    assert.deepEqual(await none.names(), ALL_TOOLS);
    await none.call("demo__echo", { text: "x" });
    assert.equal("profile" in (none.audit().find((l) => l.tool === "echo" && l.event === undefined) ?? {}), false);
  });

  it("a tool must pass both the server's expose and the profile", async () => {
    const r = await start("read-only", { expose: ["echo", "delete_file"] });
    assert.deepEqual(await r.names(), ["demo__echo"]);
    const hidden = await r.call("demo__search_notes", { query: "x" });
    assert.match(text(hidden), /\(rule not-exposed\)/);
  });

  it("an unknown profile stops the gateway at startup, naming the profiles it has", () => {
    const { configFile } = writeConfig();
    const run = spawnSync(process.execPath, [BIN, "serve", "--config", configFile, "--profile", "admin"], { encoding: "utf8", input: "" });
    assert.equal(run.status, 1);
    assert.match(run.stderr, /the config has no profile "admin" \(it has read-only, full\)/);
  });
});

describe("config: profiles", () => {
  const base = { servers: [{ name: "demo", command: "node" }], policy: "p.json", stateDir: "s" };
  it("reads each profile's globs per server", () => {
    const config = parseConfig({ ...base, profiles: PROFILES }, "/srv");
    assert.deepEqual(config.profiles?.get("read-only")?.get("demo"), ["echo", "search_*"]);
  });
  const refused: Array<[string, unknown, RegExp]> = [
    ["an unknown server", { p: { other: ["*"] } }, /config\.profiles\.p names "other", which is not one of the servers/],
    ["an empty glob list", { p: { demo: [] } }, /config\.profiles\.p\.demo must list at least one glob/],
    ["a profile that names no server", { p: {} }, /config\.profiles\.p must name at least one server/],
    ["no profile", {}, /config\.profiles must define at least one profile/],
    ["a name with a space", { "read only": { demo: ["*"] } }, /config\.profiles has a profile name that is not valid/],
    ["a glob that is not a string", { p: { demo: [3] } }, /config\.profiles\.p\.demo\[0\] must be a/],
  ];
  for (const [what, profiles, message] of refused) {
    it(`refuses ${what}`, () => assert.throws(() => parseConfig({ ...base, profiles }, "/srv"), message));
  }
});
