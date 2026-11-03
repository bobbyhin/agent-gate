"use strict";
// docs/demo/approvals.html: the approvals page in its read-only demo mode, with a recorded run. The page
// must be the page's real code (exactly what approvalsPage() writes now, so its script is the one the
// live page runs), its audit lines must pass audit verify, it must load nothing, connect nowhere and
// carry no secret of the run, and its script, run against a small stand-in for the page with no network
// at all, must show the queue and the read-backs and send nothing. Runs after the build.
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..");
const PAGE = fs.readFileSync(path.join(ROOT, "docs", "demo", "approvals.html"), "utf8");
const { approvalsPage, pageCsp, PAGE_SCRIPT, PAGE_STYLE } = require("../dist/src/gateway/approvals-page.js");
const { verifyAudit } = require("../dist/src/gateway/audit-tools.js");

const block = /<script type="application\/json" id="snapshot">\n([\s\S]*?)\n<\/script>/.exec(PAGE);
const data = JSON.parse(block[1]);

describe("docs/demo/approvals.html: the approvals page, replaying a recorded run", () => {
  it("is exactly the page the code writes now (npm run demo:approvals refreshes it)", () => {
    assert.equal(PAGE, approvalsPage({ mode: "demo", snapshot: data }), "out of date: run npm run demo:approvals");
    assert.ok(PAGE.includes(`<script>${PAGE_SCRIPT}</script>`) && PAGE.includes(`<style>${PAGE_STYLE}</style>`));
    assert.match(PAGE, /<html lang="en" data-mode="demo">/);
  });

  it("holds the recorded run: three requests, the page's guards, the decisions, the calls and a log that verifies", () => {
    assert.deepEqual(
      data.steps.map((s) => s.title),
      [
        "An agent's delete is held for a human",
        "An SQL insert is held too",
        "And a deploy",
        "The human starts the page",
        "Without the link, nothing opens",
        "A page on another site cannot use it",
        "The link opens one session",
        "The link works once",
        "The queue",
        "The delete, read back",
        "A decision without the CSRF token changes nothing",
        "A yes without the action token is refused",
        "A wrong token is refused",
        "The token from the read-back approves this one call",
        "The insert: the last 4 characters of its id",
        "The deploy is denied, with a reason",
        "The terminal saw every refusal and decision",
        "The agent makes the delete again: it runs once",
        "The insert runs",
        "The deploy: the agent is told no, and why",
        "The log checks out",
      ],
    );
    assert.deepEqual(
      data.steps.filter((s) => s.response).map((s) => s.response.status),
      [401, 403, 200, 403, 200, 200, 403, 409, 409, 200, 200, 200],
    );
    const refusals = data.steps.flatMap((s) => s.audit).filter((l) => l.event === "action-token-refused");
    assert.deepEqual(refusals.map((l) => l.reason), ["no-token", "mismatch"]);
    const decided = data.steps.flatMap((s) => s.audit).filter((l) => l.event === "approval-decided");
    assert.deepEqual(decided.map((l) => [l.tool, l.decision, l.confirmation]), [
      ["delete_file", "approved", "token"],
      ["execute_sql", "approved", "typed"],
      ["deploy", "denied", undefined],
    ]);
    const calls = data.steps.flatMap((s) => s.audit).filter((l) => l.event === undefined);
    assert.deepEqual(calls.map((l) => [l.tool, l.forwarded]), [
      ["delete_file", false],
      ["execute_sql", false],
      ["deploy", false],
      ["delete_file", true],
      ["execute_sql", true],
      ["deploy", false],
    ]);
    assert.match(calls[3].nonce, /^nc-[0-9a-f]{24}$/, "the delete ran on its token's nonce");
    assert.match(data.steps.at(-1).output, /^PASS: \d+ lines checked, no problems$/);
  });

  it("replays audit lines that pass audit verify", () => {
    const lines = data.steps.flatMap((s) => s.audit).map((value, i) => ({ line: i + 1, value }));
    assert.deepEqual(verifyAudit({ lines, unreadable: [] }), []);
  });

  it("loads nothing, connects nowhere, and carries no local path, user name or secret of the run", () => {
    assert.equal(/<script[^>]+src=|<link[^>]+href=|@import|url\(/i.test(PAGE), false, "self-contained");
    assert.ok(PAGE.includes(`<meta http-equiv="Content-Security-Policy" content="${pageCsp("demo")}">`));
    assert.match(pageCsp("demo"), /connect-src 'none'/);
    for (const bad of [...["Users", "home", "private", "var/folders"].map((dir) => `/${dir}/`), "\\Users\\"]) assert.equal(PAGE.includes(bad), false, bad);
    for (const step of data.steps) for (const l of step.audit) if (l.decidedBy !== undefined) assert.equal(l.decidedBy, "alice");
    const opened = data.steps.find((s) => s.title === "The link opens one session");
    assert.deepEqual([opened.response.body.session, opened.response.body.csrf], ["<session token>", "<CSRF token>"]);
    assert.equal(/#key=[A-Za-z0-9_-]{43}/.test(PAGE), false, "the link's key is left out");
    const sent = data.steps.filter((s) => s.request).flatMap((s) => s.request.headers);
    assert.ok(sent.some((h) => h.startsWith("x-agent-gate-csrf:")) && sent.some((h) => h.startsWith("authorization:")));
    for (const h of sent) {
      if (h.startsWith("authorization:")) assert.equal(h, "authorization: Bearer <session token>");
      if (h.startsWith("x-agent-gate-csrf:")) assert.equal(h, "x-agent-gate-csrf: <CSRF token>");
    }
    const started = data.steps.find((s) => s.title === "The human starts the page");
    assert.equal(started.command, "$ agent-gate approvals ui");
    assert.match(started.output, /#key=<the link's key: printed once, to this terminal>/);
    assert.equal(/Note: --port/.test(started.output), false, "a new port, no note");
    assert.equal(/Bearer [A-Za-z0-9_-]{43}/.test(PAGE), false, "and every session token");
  });

  it("runs its own script with no network: shows the queue and the read-backs, and sends nothing", () => {
    const nodes = new Map();
    const make = (tag) => ({
      tag,
      children: [],
      attributes: {},
      listeners: {},
      disabled: false,
      hidden: false,
      set textContent(value) {
        this.children = [];
        this.text = value;
      },
      get textContent() {
        return (this.text ?? "") + this.children.map((c) => c.textContent).join("");
      },
      appendChild(child) {
        this.children.push(child);
        return child;
      },
      setAttribute(name, value) {
        this.attributes[name] = value;
      },
      getAttribute(name) {
        return this.attributes[name] ?? null;
      },
      addEventListener(type, fn) {
        this.listeners[type] = fn;
      },
    });
    const all = (node, test, found = []) => {
      if (test(node)) found.push(node);
      for (const child of node.children ?? []) all(child, test, found);
      return found;
    };
    const document = {
      documentElement: { getAttribute: (name) => (name === "data-mode" ? "demo" : null) },
      createElement: make,
      createTextNode: (text) => Object.assign(make("#text"), { text }),
      getElementById(id) {
        if (id === "snapshot") return { textContent: block[1] };
        if (!nodes.has(id)) nodes.set(id, make("div"));
        return nodes.get(id);
      },
    };
    const sent = [];
    const trap = () => {
      sent.push("a request");
      throw new Error("the demo must send nothing");
    };
    // No fetch, no XMLHttpRequest, no storage: the demo has to work without any of them.
    vm.runInNewContext(PAGE_SCRIPT, { document, fetch: trap, XMLHttpRequest: trap, setInterval: trap, sessionStorage: undefined, location: undefined });
    const node = (id) => document.getElementById(id);
    assert.equal(node("banner").hidden, false);
    assert.match(node("banner").textContent, /read-only/);
    assert.equal(node("refresh").disabled, true);
    assert.equal(node("queue").children.length, 3);
    assert.equal(node("run").children.length, data.steps.length);
    for (const item of node("queue").children) {
      item.listeners.click();
      const detail = node("detail");
      assert.match(detail.textContent, /^Approve this call\? ap-[0-9a-f]{8}/);
      const controls = all(detail, (n) => n.tag === "button" || n.tag === "input");
      assert.equal(controls.length, 5);
      assert.ok(controls.every((c) => c.disabled), "every control is disabled");
      for (const c of controls) assert.equal(c.listeners.click, undefined, "and none is wired to send anything");
    }
    assert.deepEqual(sent, []);
  });
});
