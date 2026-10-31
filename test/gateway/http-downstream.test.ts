// A remote downstream server over Streamable HTTP, next to a local one over stdio: its header comes
// from the environment, a slow call times out, a 401 stops the gateway at startup without repeating a
// header value, and a server that goes away fails its own calls only. Everything runs on 127.0.0.1.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ErrorCode, McpError, type CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { parseConfig } from "../../src/gateway/config.js";
import { startFakeHttpDownstream, type FakeHttpDownstream } from "./fake-http-downstream.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const BIN = path.join(ROOT, "bin", "agent-gate.js");
const FAKE = path.join(__dirname, "fake-downstream.js");
const TOKEN = "fake-remote-mcp-token-0001";

describe("a remote downstream server over Streamable HTTP", () => {
  let remote: FakeHttpDownstream;
  let tmp: string;
  let gateway: Client;

  const writeConfig = (file: string, url: string, extra: Record<string, unknown> = {}) =>
    fs.writeFileSync(
      file,
      JSON.stringify({
        servers: [
          { name: "remote", url, headersFromEnv: { Authorization: "REMOTE_MCP_AUTH" }, timeoutSeconds: 1, ...extra },
          { name: "demo", command: process.execPath, args: [FAKE] },
        ],
        policy: path.join(ROOT, "policy.example.json"),
        stateDir: "state",
      }),
    );

  before(async () => {
    remote = await startFakeHttpDownstream({ token: TOKEN });
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-http-"));
    writeConfig(path.join(tmp, "gateway.config.json"), remote.url);
    gateway = new Client({ name: "http-test", version: "1.0.0" });
    await gateway.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [BIN, "serve", "--config", path.join(tmp, "gateway.config.json")],
        env: { ...(process.env as Record<string, string>), REMOTE_MCP_AUTH: `Bearer ${TOKEN}` },
        stderr: "ignore",
      }),
    );
  });
  after(async () => {
    await gateway?.close();
    await remote?.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const lines = () => fs.readFileSync(path.join(tmp, "state", "audit.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const text = (r: CallToolResult) => (r.content[0] as { text: string }).text;

  it("lists and calls the remote server's tools next to the local ones, with the header from the environment", async () => {
    const names = (await gateway.listTools()).tools.map((t) => t.name);
    assert.ok(names.includes("remote__echo") && names.includes("remote__slow") && names.includes("demo__echo"), names.join(","));
    assert.equal(text((await gateway.callTool({ name: "remote__echo", arguments: { text: "over http" } })) as CallToolResult), "over http");
    assert.ok(remote.authorizations.length > 0);
    assert.deepEqual(new Set(remote.authorizations), new Set([`Bearer ${TOKEN}`]), "every request carried the header");
    const calls = lines().filter((l) => l.event === undefined);
    assert.equal(calls.find((l) => l.server === "remote")?.transport, "http");
    await gateway.callTool({ name: "demo__echo", arguments: { text: "over stdio" } });
    assert.equal("transport" in lines().filter((l) => l.event === undefined && l.server === "demo")[0], false, "absent for stdio");
  });

  it("a call slower than timeoutSeconds fails with the request-timeout code, and the call-result line keeps it", async () => {
    await assert.rejects(gateway.callTool({ name: "remote__slow", arguments: { ms: 3000 } }), (err: unknown) => err instanceof McpError && err.code === ErrorCode.RequestTimeout);
    const result = lines().filter((l) => l.event === "call-result" && l.tool === "slow")[0];
    assert.deepEqual([result?.isError, result?.errorCode, result?.resultHash], [true, ErrorCode.RequestTimeout, undefined]);
  });

  it("does not start without the header's variable, naming the variable and no value", () => {
    const env = { ...process.env };
    delete env.REMOTE_MCP_AUTH;
    const run = spawnSync(process.execPath, [BIN, "serve", "--config", path.join(tmp, "gateway.config.json")], { env, input: "", encoding: "utf8", timeout: 20_000 });
    assert.equal(run.status, 1);
    assert.equal(run.stderr, "agent-gate: set the environment variables named by headersFromEnv: REMOTE_MCP_AUTH\n");
  });

  it("does not start when the server refuses the header, and does not repeat the value the server quoted back", async () => {
    const wrong = ["Bearer", "fake-wrong-token-0002"].join(" "); // assembled, so no scanner reads it as a header
    // spawn, not spawnSync: the fake server runs in this process and has to answer meanwhile.
    const child = spawn(process.execPath, [BIN, "serve", "--config", path.join(tmp, "gateway.config.json")], { env: { ...process.env, REMOTE_MCP_AUTH: wrong }, stdio: ["pipe", "ignore", "pipe"] });
    let stderr = "";
    child.stderr?.on("data", (chunk) => (stderr += String(chunk)));
    child.stdin?.end();
    const status = await new Promise<number | null>((resolve) => child.once("exit", resolve));
    assert.equal(status, 1);
    assert.match(stderr, /could not start downstream server "remote"/);
    assert.equal(stderr.includes("fake-wrong-token-0002"), false, stderr);
    assert.ok(remote.authorizations.includes(wrong), "the server did get, and quote, the wrong value");
  });

  it("when the remote server goes away, its calls fail and are recorded; the local server's calls still run", async () => {
    await remote.close();
    await assert.rejects(gateway.callTool({ name: "remote__echo", arguments: { text: "anyone there?" } }), (err: unknown) => err instanceof McpError);
    const result = lines().filter((l) => l.event === "call-result" && l.server === "remote").at(-1);
    assert.deepEqual([result?.tool, result?.isError, typeof result?.errorCode], ["echo", true, "number"]);
    assert.equal(text((await gateway.callTool({ name: "demo__echo", arguments: { text: "still here" } })) as CallToolResult), "still here");
  });
});

describe("config: remote servers", () => {
  const config = (server: Record<string, unknown>) => ({ servers: [{ name: "remote", ...server }], policy: "p.json", stateDir: "s" });
  it("takes a url, the header variables and a timeout", () => {
    const parsed = parseConfig(config({ url: "https://mcp.example.com/mcp", headersFromEnv: { Authorization: "DOCS_MCP_AUTH" }, timeoutSeconds: 30 }), "/srv");
    assert.deepEqual(parsed.servers, [{ name: "remote", url: "https://mcp.example.com/mcp", headersFromEnv: { Authorization: "DOCS_MCP_AUTH" }, timeoutMs: 30_000 }]);
    for (const url of ["http://127.0.0.1:8080/mcp", "http://localhost:8080/mcp", "http://[::1]:8080/mcp"]) assert.equal(parseConfig(config({ url }), "/srv").servers[0]?.url, url);
  });
  const bad: Array<[string, Record<string, unknown>, RegExp]> = [
    ["plain http to another machine", { url: "http://mcp.example.com/mcp" }, /must use https:\/\/ \(plain http:\/\/ only for a server on this machine\)/],
    ["credentials in the url", { url: `https://${["user", "pass"].join(":")}@mcp.example.com/mcp` }, /must not contain credentials/],
    ["a url and a command", { url: "https://mcp.example.com/mcp", command: "node" }, /has both "url" and a command/],
    ["neither", {}, /needs "command" \(a local server, over stdio\) or "url"/],
    ["a header value instead of a variable", { url: "https://mcp.example.com/mcp", headersFromEnv: { Authorization: "Bearer abc" } }, /must name an environment variable/],
    ["a header name with a space", { url: "https://mcp.example.com/mcp", headersFromEnv: { "X Token": "T" } }, /header name that is not valid/],
    ["a timeout of 0", { url: "https://mcp.example.com/mcp", timeoutSeconds: 0 }, /timeoutSeconds must be a whole number from 1 to 3600/],
  ];
  for (const [name, server, error] of bad) it(`refuses ${name}`, () => assert.throws(() => parseConfig(config(server), "/srv"), error));
});
