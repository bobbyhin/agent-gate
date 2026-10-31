// serve --http: the gateway as a Streamable HTTP endpoint for several agents, each known by the SHA-256
// of its key, with a policy and a profile of its own. Everything runs on 127.0.0.1 with keys made at
// run time: no key or a wrong one gets 401, another Host or Origin 403, another agent's session 404,
// and one agent's approval never lets another agent's identical call run.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { ApprovalStore, hashArguments } from "../../src/gateway/approvals.js";
import { readAudit, verifyAudit } from "../../src/gateway/audit-tools.js";
import { main, type Io } from "../../src/gateway/cli.js";
import { loadConfig, parseConfig } from "../../src/gateway/config.js";
import { startHttpGateway, type HttpGateway } from "../../src/gateway/http-server.js";
import { hashKey } from "../../src/llm/config.js";

const FAKE = path.join(__dirname, "fake-downstream.js");
const ALL_TOOLS = ["demo__delete_file", "demo__deploy", "demo__echo", "demo__execute_sql", "demo__fail", "demo__run_command", "demo__search_notes", "demo__set_echo_description"];
// Keys are made here, at run time; the config only ever holds their hashes.
const key = (name: string) => `agk_${name}_${randomBytes(12).toString("hex")}`;
const KEYS = { alpha: key("alpha"), beta: key("beta"), reader: key("reader") };
const DELETE_ASKS = { id: "deletes-ask", toolWords: ["delete"], decision: "ask", why: "Deleting needs a human." };

const text = (r: CallToolResult) => (r.content[0] as { text: string }).text;
const quietIo = (): Io & { output: () => string } => {
  let out = "";
  return { out: (t) => (out += t), err: (t) => (out += t), output: () => out };
};

describe("serve --http: agents over Streamable HTTP", () => {
  let dir: string;
  let configFile: string;
  let gw: HttpGateway;
  const clients: Client[] = [];
  const logs: string[] = [];

  before(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-http-agents-"));
    fs.writeFileSync(path.join(dir, "policy-alpha.json"), JSON.stringify({ default: "allow", rules: [DELETE_ASKS] }));
    fs.writeFileSync(path.join(dir, "policy-beta.json"), JSON.stringify({ default: "allow", rules: [DELETE_ASKS, { id: "no-deploy", tool: "deploy", decision: "block", why: "This agent does not deploy." }] }));
    configFile = path.join(dir, "gateway.config.json");
    fs.writeFileSync(
      configFile,
      JSON.stringify({
        servers: [{ name: "demo", command: process.execPath, args: [FAKE, "--log", path.join(dir, "received.jsonl")] }],
        policy: "policy-alpha.json",
        stateDir: "state",
        profiles: { "read-only": { demo: ["echo", "search_*"] } },
        http: {
          listen: { host: "127.0.0.1", port: 0 },
          agents: [
            { name: "alpha", sha256: hashKey(KEYS.alpha) },
            { name: "beta", sha256: hashKey(KEYS.beta), policy: "policy-beta.json" },
            { name: "reader", sha256: hashKey(KEYS.reader), profile: "read-only" },
          ],
        },
      }),
    );
    gw = await startHttpGateway(loadConfig(configFile), (m) => logs.push(m));
  });
  after(async () => {
    for (const c of clients) await c.close().catch(() => undefined);
    await gw?.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  async function connect(agentKey: string): Promise<{ client: Client; transport: StreamableHTTPClientTransport }> {
    const transport = new StreamableHTTPClientTransport(new URL(`${gw.url}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${agentKey}` } } });
    const client = new Client({ name: "http-agent-test", version: "1.0.0" });
    await client.connect(transport);
    clients.push(client);
    return { client, transport };
  }
  const call = async (client: Client, name: string, args: Record<string, unknown>) => (await client.callTool({ name, arguments: args })) as CallToolResult;
  const names = async (client: Client) => (await client.listTools()).tools.map((t) => t.name).sort();
  const audit = () => readAudit(path.join(dir, "state", "audit.jsonl")).lines.map((l) => l.value);
  const received = () => fs.readFileSync(path.join(dir, "received.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as { tool: string });
  const post = (headers: Record<string, string>, body: unknown) =>
    fetch(`${gw.url}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers }, body: JSON.stringify(body) });
  const INITIALIZE = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "raw", version: "1" } } };

  it("each agent sees the tools of its own profile", async () => {
    assert.deepEqual(await names((await connect(KEYS.alpha)).client), ALL_TOOLS);
    assert.deepEqual(await names((await connect(KEYS.reader)).client), ["demo__echo", "demo__search_notes"]);
  });

  it("a missing or unknown key gets 401 and opens nothing", async () => {
    const none = await post({}, INITIALIZE);
    assert.equal(none.status, 401);
    assert.match(none.headers.get("www-authenticate") ?? "", /^Bearer realm="agent-gate-mcp"$/);
    assert.match(((await none.json()) as { error: { message: string } }).error.message, /missing or unknown agent key/);
    const wrong = await post({ authorization: `Bearer ${key("nobody")}` }, INITIALIZE);
    assert.equal(wrong.status, 401);
    assert.equal(wrong.headers.get("mcp-session-id"), null);
  });

  it("a Host or an Origin that is not the gateway's own is refused (DNS rebinding)", async () => {
    const port = new URL(gw.url).port;
    const status = await new Promise<number>((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port, path: "/mcp", method: "POST", headers: { host: `evil.example:${port}`, authorization: `Bearer ${KEYS.alpha}`, "content-type": "application/json" } }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      req.on("error", reject);
      req.end(JSON.stringify(INITIALIZE));
    });
    assert.equal(status, 403);
    const fromPage = await post({ authorization: `Bearer ${KEYS.alpha}`, origin: "http://evil.example" }, INITIALIZE);
    assert.equal(fromPage.status, 403);
    const local = await post({ authorization: `Bearer ${KEYS.alpha}`, origin: `http://localhost:${port}` }, INITIALIZE);
    assert.equal(local.status, 200, "the gateway's own origin is fine");
  });

  it("each agent's calls are decided by its own policy, and the call line names the agent", async () => {
    const alpha = (await connect(KEYS.alpha)).client;
    const beta = (await connect(KEYS.beta)).client;
    assert.equal((await call(alpha, "demo__deploy", { service: "web" })).isError, undefined);
    const refused = await call(beta, "demo__deploy", { service: "web" });
    assert.match(text(refused), /This agent does not deploy\. \(rule no-deploy\)/);
    const lines = audit().filter((l) => l.tool === "deploy" && l.event === undefined);
    assert.deepEqual(
      lines.map((l) => [l.agent, l.decision, l.forwarded]),
      [
        ["alpha", "allow", true],
        ["beta", "block", false],
      ],
    );
    assert.notEqual(lines[0]?.connId, lines[1]?.connId, "each session has a connection id of its own");
  });

  it("a reader's call outside its profile is blocked, with the agent and the profile in the line", async () => {
    const reader = (await connect(KEYS.reader)).client;
    assert.match(text(await call(reader, "demo__delete_file", { path: "notes/x.md" })), /\(rule not-in-profile\)/);
    const line = audit().find((l) => l.tool === "delete_file" && l.agent === "reader");
    assert.deepEqual([line?.rule, line?.profile, line?.forwarded], ["not-in-profile", "read-only", false]);
  });

  it("a session belongs to the agent that opened it: another key gets 404 for its id", async () => {
    const { transport } = await connect(KEYS.alpha);
    const id = transport.sessionId as string;
    assert.match(id, /^[0-9a-f-]{36}$/);
    const list = { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} };
    const hijack = await post({ authorization: `Bearer ${KEYS.beta}`, "mcp-session-id": id, "mcp-protocol-version": "2025-06-18" }, list);
    assert.equal(hijack.status, 404);
    assert.deepEqual(await hijack.json(), { jsonrpc: "2.0", error: { code: -32001, message: "Session not found" }, id: null });
    const own = await post({ authorization: `Bearer ${KEYS.alpha}`, "mcp-session-id": id, "mcp-protocol-version": "2025-06-18" }, list);
    assert.equal(own.status, 200);
  });

  it("an approval is bound to the agent whose call asked: another agent's identical call is asked about anew", async () => {
    const alpha = (await connect(KEYS.alpha)).client;
    const beta = (await connect(KEYS.beta)).client;
    const args = { path: "notes/shared.md" };
    const first = text(await call(alpha, "demo__delete_file", args));
    const alphaId = /Approval id: (ap-[0-9a-f]{8})/.exec(first)?.[1] as string;
    assert.ok(alphaId, first);
    const io = quietIo();
    assert.equal(await main(["approvals", "approve", alphaId, "--yes", "--config", configFile], io), 0, io.output());

    // beta makes exactly the same call: it is not alpha's to use.
    const betaText = text(await call(beta, "demo__delete_file", args));
    const betaId = /Approval id: (ap-[0-9a-f]{8})/.exec(betaText)?.[1];
    assert.ok(betaId && betaId !== alphaId, betaText);
    // alpha's own repeat runs, once.
    assert.equal((await call(alpha, "demo__delete_file", args)).isError, undefined);
    assert.equal(received().filter((c) => c.tool === "delete_file").length, 1);

    const store = new ApprovalStore(path.join(dir, "state"), 3_600_000);
    assert.deepEqual(
      [store.get(alphaId).agent, store.get(alphaId).status, store.get(betaId as string).agent, store.get(betaId as string).status],
      ["alpha", "used", "beta", "pending"],
    );
    const list = quietIo();
    await main(["approvals", "list", "--config", configFile], list);
    assert.match(list.output(), new RegExp(`${betaId}  pending  demo__delete_file\\n[\\s\\S]*?  agent:   beta \\(its key; only its own call can use this approval\\)`));
    const decided = audit().find((l) => l.event === "approval-decided" && l.approvalId === alphaId);
    assert.equal(decided?.agent, "alpha");
  });

  it("the whole log passes audit verify", () => {
    assert.deepEqual(verifyAudit(readAudit(path.join(dir, "state", "audit.jsonl")), new ApprovalStore(path.join(dir, "state"), 3_600_000).list()), []);
    assert.ok(logs.some((l) => /^session cn-[0-9a-f]{8} opened for agent "alpha"$/.test(l)));
  });
});

describe("approvals and standing grants are bound to an agent", () => {
  let dir: string;
  before(() => (dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-agent-bound-"))));
  after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const ask = (agent?: string) => ({
    server: "demo",
    tool: "execute_sql",
    args: { sql: "INSERT INTO t VALUES (1)" },
    argsHash: hashArguments({ sql: "INSERT INTO t VALUES (1)" }),
    rule: "sql-write",
    why: "writes",
    standing: true,
    ...(agent !== undefined ? { agent } : {}),
  });

  it("a grant for one agent covers that agent's calls, not another's and not stdio's", () => {
    const store = new ApprovalStore(path.join(dir, "a"), 3_600_000);
    const grant = store.grant({ server: "demo", tool: "execute_sql", args: {}, agent: "beta", maxUses: 5, ttlMs: 3_600_000 });
    assert.equal(store.resolveCall(ask("beta")).kind, "standing");
    assert.equal(store.resolveCall(ask("alpha")).kind, "pending");
    assert.equal(store.resolveCall(ask()).kind, "pending");
    assert.equal(store.getStanding(grant.id).used, 1);
  });

  it("a grant with no agent covers stdio calls only", () => {
    const store = new ApprovalStore(path.join(dir, "b"), 3_600_000);
    store.grant({ server: "demo", tool: "execute_sql", args: {}, maxUses: 5, ttlMs: 3_600_000 });
    assert.equal(store.resolveCall(ask()).kind, "standing");
    assert.equal(store.resolveCall(ask("beta")).kind, "pending");
  });

  it("audit verify fails a call that ran under another agent's approval or grant", () => {
    const line = (n: number, value: Record<string, unknown>) => ({ line: n, value });
    const hash = "sha256:aa";
    const lines = [
      line(1, { connId: "cn-1", seq: 1, server: "demo", tool: "delete_file", decision: "ask", argsHash: hash, forwarded: false, approvalId: "ap-1", agent: "alpha" }),
      line(2, { event: "approval-decided", approvalId: "ap-1", server: "demo", tool: "delete_file", argsHash: hash, decision: "approved", agent: "alpha", ts: "2026-10-31T00:00:01.000Z" }),
      line(3, { connId: "cn-2", seq: 1, server: "demo", tool: "delete_file", decision: "ask", argsHash: hash, forwarded: true, approvalId: "ap-1", agent: "beta", ts: "2026-10-31T00:00:02.000Z" }),
      line(4, { event: "standing-approval", id: "sa-1", decision: "granted", server: "demo", tool: "execute_sql", args: {}, maxUses: 3, used: 0, expiresAt: "2026-11-01T00:00:00.000Z", agent: "beta" }),
      line(5, { connId: "cn-3", seq: 1, server: "demo", tool: "execute_sql", decision: "ask", argsHash: hash, forwarded: true, approvalId: "sa-1", ts: "2026-10-31T00:00:03.000Z" }),
    ];
    assert.deepEqual(
      verifyAudit({ lines, unreadable: [] }).map((p) => [p.line, p.why]),
      [
        [3, 'forwarded under ap-1, which was approved for agent "alpha", but this call came from agent "beta" (line 2)'],
        [5, 'sa-1 was granted for agent "beta", but this call came with no agent'],
      ],
    );
  });
});

describe("serve --http on the command line, and the http config", () => {
  it("needs an http section, and --profile is for stdio only", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-http-cli-"));
    try {
      const file = path.join(dir, "gateway.config.json");
      fs.writeFileSync(file, JSON.stringify({ servers: [{ name: "demo", command: process.execPath, args: [FAKE] }], policy: "p.json", stateDir: "state" }));
      fs.writeFileSync(path.join(dir, "p.json"), JSON.stringify({ default: "allow", rules: [] }));
      const io = quietIo();
      assert.equal(await main(["serve", "--http", "--config", file], io), 1);
      assert.match(io.output(), /this config has no "http" section/);
      const both = quietIo();
      assert.equal(await main(["serve", "--http", "--profile", "x", "--config", file], both), 2);
      assert.match(both.output(), /--profile is for one stdio client/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("the example config loads, on 127.0.0.1, with the hashes of the demo keys the README uses", () => {
    const config = loadConfig(path.join(__dirname, "..", "..", "..", "gateway.config.http.example.json"));
    assert.deepEqual(
      config.http?.agents.map((a) => [a.name, a.sha256 === hashKey(`demo-${a.name}-key-not-a-secret`), a.profile]),
      [
        ["builder", true, undefined],
        ["reader", true, "read-only"],
      ],
    );
    assert.deepEqual([config.http?.host, config.http?.port], ["127.0.0.1", 8788]);
  });

  const base = { servers: [{ name: "demo", command: "node" }], policy: "p.json", stateDir: "s", profiles: { ro: { demo: ["get_*"] } } };
  const agent = (name: string, extra: Record<string, unknown> = {}) => ({ name, sha256: hashKey(name), ...extra });
  it("reads the listen address, the agents, their policies and profiles", () => {
    const config = parseConfig({ ...base, http: { agents: [agent("a"), agent("b", { policy: "b.json", profile: "ro" })] } }, "/srv");
    assert.deepEqual(
      [config.http?.host, config.http?.port, config.http?.agents.map((a) => [a.name, a.policyFile, a.profile]), config.http?.sessionIdleMs],
      ["127.0.0.1", 8788, [["a", undefined, undefined], ["b", "/srv/b.json", "ro"]], 3_600_000],
    );
  });
  const refused: Array<[string, unknown, RegExp]> = [
    ["no agents", { agents: [] }, /config\.http\.agents must list at least one agent/],
    ["a name used twice", { agents: [agent("a"), { ...agent("b"), name: "a" }] }, /config\.http\.agents: the name "a" is used twice/],
    ["a key instead of its hash", { agents: [{ name: "a", sha256: "agk_not_a_hash" }] }, /config\.http\.agents\[0\]\.sha256 must be 64 lowercase hex characters/],
    ["the same hash twice", { agents: [agent("a"), { ...agent("a"), name: "b" }] }, /config\.http\.agents\[1\]\.sha256 is the same as an earlier agent's/],
    ["an unknown profile", { agents: [agent("a", { profile: "admin" })] }, /config\.http\.agents\[0\]\.profile "admin" is not one of config\.profiles/],
    ["another address without allowedHosts", { listen: { host: "0.0.0.0" }, agents: [agent("a")] }, /config\.http\.allowedHosts must list the host names clients use/],
    ["an unknown field", { agents: [agent("a")], tls: true }, /config\.http has an unknown field "tls"/],
  ];
  for (const [what, httpSpec, message] of refused) {
    it(`refuses ${what}`, () => assert.throws(() => parseConfig({ ...base, http: httpSpec }, "/srv"), message));
  }
});
