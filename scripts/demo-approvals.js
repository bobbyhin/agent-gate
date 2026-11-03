#!/usr/bin/env node
"use strict";
// Writes docs/demo/approvals.html: the approvals page (src/gateway/approvals-page.ts) in its read-only
// demo mode, with a real local run recorded in it. The run: the MCP gateway with the example policy and
// the fake test server; an agent makes three calls that need a human (an irreversible delete, an SQL
// insert, an irreversible deploy); "agent-gate approvals ui" is started as a human starts it; the page's
// requests are made over HTTP as the page makes them, and each answer is recorded with the audit lines
// it wrote; the agent makes its calls again; and "audit verify" checks the whole log.
//
// Usage, after `npm run build`: node scripts/demo-approvals.js   (or: npm run demo:approvals)
// It rewrites docs/demo/approvals.html. test/demo-approvals.test.js fails while the page's code in the
// file is not the page's code now: run this again after changing src/gateway/approvals-page.ts.
// The OS user name becomes "alice" and the temporary folder /tmp/demo; the link's key and the session
// and CSRF tokens become placeholders. The action token is the run's own, made with a key in the
// temporary folder, which is deleted at the end.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const PAGE = path.join(ROOT, "docs", "demo", "approvals.html");
const BIN = path.join(ROOT, "bin", "agent-gate.js");
const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { StdioClientTransport } = require("@modelcontextprotocol/sdk/client/stdio.js");
const { approvalsPage } = require(path.join(ROOT, "dist", "src", "gateway", "approvals-page.js"));

const LINK = /^ {2}(http:\/\/127\.0\.0\.1:(\d+))\/#key=([A-Za-z0-9_-]{43})$/m;

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-demo-approvals-"));
  const config = path.join(tmp, "gateway.config.json");
  const stateDir = path.join(tmp, "state");
  fs.writeFileSync(
    config,
    JSON.stringify({ servers: [{ name: "demo", command: process.execPath, args: [path.join(ROOT, "dist", "test", "gateway", "fake-downstream.js")] }], policy: path.join(ROOT, "policy.example.json"), stateDir }),
  );
  const user = os.userInfo().username;
  const secrets = new Map();
  /** The user, the folder and every secret of the run out of a text: what the page may show of it. */
  const clean = (text) => {
    let out = text.split(tmp).join("/tmp/demo");
    for (const [value, placeholder] of secrets) out = out.split(value).join(placeholder);
    return out.split(user).join("alice");
  };
  const cleanJson = (value) => JSON.parse(clean(JSON.stringify(value)));
  const auditFile = path.join(stateDir, "audit.jsonl");
  let seen = 0;
  /** Audit lines written since the last step; the tool-pinned lines of the first listing are left out. */
  const newAudit = () => {
    const all = fs.existsSync(auditFile) ? fs.readFileSync(auditFile, "utf8").trim().split("\n").filter(Boolean) : [];
    const fresh = all.slice(seen);
    seen = all.length;
    return fresh.map((l) => JSON.parse(clean(l))).filter((l) => l.event !== "tool-pinned");
  };
  const steps = [];
  let client;
  let ui;
  try {
    await record();
  } finally {
    // Also after a failure: no page left listening, no gateway left running, no key left on disk.
    if (ui && ui.exitCode === null && ui.signalCode === null) ui.kill("SIGKILL");
    await client?.close().catch(() => undefined);
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  async function record() {
    // The agent, through the gateway over stdio.
    client = new Client({ name: "demo-agent", version: "1.0.0" });
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [BIN, "serve", "--config", config], stderr: "ignore" }));
    await client.listTools();
    newAudit();
    const agent = async (tool, args, step) => {
      const result = await client.callTool({ name: tool, arguments: args });
      steps.push({ ...step, call: { tool, args }, answer: clean(result.content[0].text), isError: result.isError === true, audit: newAudit() });
      return result.content[0].text;
    };

    const held = await agent("demo__delete_file", { path: "notes/old.md" }, {
      title: "An agent's delete is held for a human",
      note: "Red line 4 asks about deletes, and its rule is irreversible: the request gets a nonce, and the human's yes will need the action token made from it. The agent is told that, and never shown the token.",
    });
    await agent("demo__execute_sql", { sql: "INSERT INTO events (name) VALUES ('signup')" }, {
      title: "An SQL insert is held too",
      note: "The sql-write rule asks about a write. It is not irreversible, so a yes is confirmed by typing the end of the request's id, as at the CLI.",
    });
    await agent("demo__deploy", { service: "web" }, {
      title: "And a deploy",
      note: "Red line 3, shipping: irreversible, and its request lives 30 minutes.",
    });
    const deleteId = /Approval id: (ap-[0-9a-f]{8})/.exec(held)[1];

    // The human starts the page in their own terminal; its link is the only way in.
    ui = spawn(process.execPath, [BIN, "approvals", "ui", "--config", config], { stdio: ["ignore", "pipe", "pipe"] });
    let terminal = "";
    ui.stdout.on("data", (chunk) => (terminal += chunk.toString("utf8")));
    ui.stderr.on("data", (chunk) => (terminal += chunk.toString("utf8")));
    for (let i = 0; i < 500 && !LINK.test(terminal); i++) await new Promise((resolve) => setTimeout(resolve, 10));
    const link = LINK.exec(terminal);
    if (!link) throw new Error(`agent-gate approvals ui printed no link: ${terminal}`);
    const [, origin, , key] = link;
    secrets.set(key, "<the link's key: printed once, to this terminal>");
    steps.push({
      title: "The human starts the page",
      note: "In their own terminal, like the CLI. It listens on 127.0.0.1 only. The link carries a key in its fragment, which a browser never sends to a server; the page trades it once for a session.",
      command: "$ agent-gate approvals ui",
      output: clean(terminal.trimEnd()),
      audit: [],
    });

    let session;
    let csrf;
    /** One request as the page sends it (or as another site would), recorded with the answer and the audit lines it wrote. */
    const page = async (method, route, { body, auth = true, withCsrf = true, from = origin } = {}, step = {}) => {
      const headers = { accept: "application/json" };
      if (auth && session) headers.authorization = `Bearer ${session}`;
      if (method === "POST") {
        headers["content-type"] = "application/json";
        headers.origin = from;
        if (withCsrf && csrf) headers["x-agent-gate-csrf"] = csrf;
      }
      const res = await fetch(`${origin}${route}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
      const answer = await res.json();
      if (step.title) {
        const shown = Object.entries(headers).filter(([name]) => name !== "accept").map(([name, value]) => `${name}: ${value}`);
        steps.push({ ...step, request: cleanJson({ method, path: route, headers: shown, ...(body !== undefined ? { body } : {}) }), response: { status: res.status, body: cleanJson(answer) }, audit: newAudit() });
      }
      return { status: res.status, body: answer };
    };

    await page("GET", "/api/approvals", { auth: false }, {
      title: "Without the link, nothing opens",
      note: "Every API call needs the session. A process on this machine that never saw the link, an agent's included, gets 401.",
    });
    await page("POST", "/api/session", { body: { key: "a page on another site cannot know it" }, from: "http://evil.example" }, {
      title: "A page on another site cannot use it",
      note: "A web page the human has open elsewhere can make the browser send requests to 127.0.0.1. Requests that change anything must carry this page's own Origin, so this one is refused before anything else is looked at.",
    });
    const opened = await page("POST", "/api/session", { body: { key } });
    session = opened.body.session;
    csrf = opened.body.csrf;
    secrets.set(session, "<session token>");
    secrets.set(csrf, "<CSRF token>");
    steps.push({
      title: "The link opens one session",
      note: "The page trades the key for a session token and a CSRF token, and keeps them in the tab's sessionStorage, scoped to this host and port. They go out as headers, never as cookies: a cookie for 127.0.0.1 would also be sent to any other port on it, a server an agent started included.",
      request: cleanJson({ method: "POST", path: "/api/session", headers: ["content-type: application/json", `origin: ${origin}`], body: { key } }),
      response: { status: opened.status, body: cleanJson(opened.body) },
      audit: newAudit(),
    });
    await page("POST", "/api/session", { body: { key } }, {
      title: "The link works once",
      note: "The same link again opens nothing: a copy of it found later, in the browser's history or a terminal's scrollback, is spent.",
    });
    const queue = await page("GET", "/api/approvals", {}, {
      title: "The queue",
      note: "The requests waiting for a decision, and the standing approvals in force. The list never carries an action token.",
    });
    const readBacks = {};
    for (const a of queue.body.pending) {
      const read = await page("GET", `/api/approvals/${a.id}`, {}, a.id === deleteId ? { title: "The delete, read back", note: "The read-back is the CLI's, word for word. For an irreversible request it comes with the action token, for the human to type: only in this answer, to this session, never in the list, the audit log or the terminal." } : {});
      readBacks[a.id] = cleanJson(read.body);
    }
    const del = readBacks[deleteId].approval;
    const token = readBacks[deleteId].actionToken;
    const sql = queue.body.pending.find((a) => a.tool === "execute_sql");
    const deploy = queue.body.pending.find((a) => a.tool === "deploy");

    await page("POST", `/api/approvals/${deleteId}/approve`, { body: { argsHash: del.argsHash, token }, withCsrf: false }, {
      title: "A decision without the CSRF token changes nothing",
      note: "The session alone is not enough to change anything: every decision also carries the session's CSRF token. Nothing is decided, and nothing is written.",
    });
    await page("POST", `/api/approvals/${deleteId}/approve`, { body: { argsHash: del.argsHash, token: "", note: "" } }, {
      title: "A yes without the action token is refused",
      note: "Clicking Approve with the token field empty is a yes without the token, like --yes at the CLI. It is refused and logged, by the same code as the CLI's refusal.",
    });
    await page("POST", `/api/approvals/${deleteId}/approve`, { body: { argsHash: del.argsHash, token: "at-0000-0000", note: "" } }, {
      title: "A wrong token is refused",
      note: "The server checks what was typed against the request's own token: this call, these arguments, until it expires. The page never checks it, and never fills it in.",
    });
    await page("POST", `/api/approvals/${deleteId}/approve`, { body: { argsHash: del.argsHash, token, note: "old notes, fine" } }, {
      title: "The token from the read-back approves this one call",
      note: "Typed back, it checks out: the approval is written with its proof and \"confirmation\": \"token\", and the audit line is the CLI's.",
    });
    await page("POST", `/api/approvals/${sql.id}/approve`, { body: { argsHash: sql.argsHash, confirm: sql.id.slice(-4), note: "" } }, {
      title: "The insert: the last 4 characters of its id",
      note: "Not irreversible, so the read-back asks for the end of the id, as the CLI's does. The record says \"confirmation\": \"typed\".",
    });
    await page("POST", `/api/approvals/${deploy.id}/deny`, { body: { argsHash: deploy.argsHash, reason: "Not on a Friday; ship it on Monday." } }, {
      title: "The deploy is denied, with a reason",
      note: "The reason is stored as one line of text and shown to the agent, quoted, the next time it makes the call.",
    });

    const banner = terminal.indexOf("Stop with Ctrl-C.");
    steps.push({
      title: "The terminal saw every refusal and decision",
      note: "What agent-gate approvals ui printed after its link: each request it refused and why, and each decision, in the CLI's words. Never a token, a session or the key.",
      command: "(the terminal where agent-gate approvals ui runs)",
      output: clean(terminal.slice(terminal.indexOf("\n", banner) + 1).trimEnd()),
      audit: [],
    });

    await agent("demo__delete_file", { path: "notes/old.md" }, {
      title: "The agent makes the delete again: it runs once",
      note: "The gateway checks the approval's proof with its key, marks it used and spends its token before the call goes on. The call line names the nonce, never the token.",
    });
    await agent("demo__execute_sql", { sql: "INSERT INTO events (name) VALUES ('signup')" }, {
      title: "The insert runs",
      note: "Its approval is used up; the same insert again would ask again.",
    });
    await agent("demo__deploy", { service: "web" }, {
      title: "The deploy: the agent is told no, and why",
      note: "A denial sticks: the agent gets the human's reason, labelled as information, and nothing is queued.",
    });

    const verify = spawnSync(process.execPath, [BIN, "audit", "verify", "--config", config], { encoding: "utf8" });
    steps.push({
      title: "The log checks out",
      note: "audit verify reads the whole log, the page's decisions with the gateway's calls: every call that ran after an ask was approved first, for the same arguments, and used its approval once.",
      command: "$ agent-gate audit verify",
      output: clean(verify.stdout.trimEnd()),
      audit: [],
    });

    await new Promise((resolve) => {
      ui.once("exit", resolve);
      ui.kill("SIGTERM");
    });

    const snapshot = {
      about: "A real run of agent-gate approvals ui, with policy.example.json and the fake test server, written by scripts/demo-approvals.js. Times, ids and the action token are from that run (its key was deleted afterwards); the user name is replaced, and the link's key and the session and CSRF tokens are left out.",
      queue: cleanJson(queue.body),
      readBacks,
      steps,
    };
    fs.writeFileSync(PAGE, approvalsPage({ mode: "demo", snapshot }));
    process.stdout.write(`wrote ${steps.length} steps and ${Object.keys(readBacks).length} read-backs into ${path.relative(ROOT, PAGE)}\n`);
  }
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`demo-approvals: ${err.stack ?? err}\n`);
    process.exit(1);
  });
}
