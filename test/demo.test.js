"use strict";
// docs/demo/index.html: a replay of a real gateway run. The page must stay true to the code: every
// excerpt it quotes is still at that line of that file, the audit lines it replays pass audit verify,
// it loads nothing from elsewhere, and its script steps through every step. Runs after the build.
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..");
const PAGE = fs.readFileSync(path.join(ROOT, "docs", "demo", "index.html"), "utf8");
const { EXCERPTS, excerpt } = require("../scripts/demo-transcript.js");
const { verifyAudit } = require("../dist/src/gateway/audit-tools.js");

const block = /<script type="application\/json" id="transcript">\n([\s\S]*?)\n<\/script>/.exec(PAGE);
const data = JSON.parse(block[1]);

describe("docs/demo: the step-through page", () => {
  it("holds the recorded run: ten steps, from an allowed call to a log that verifies", () => {
    assert.deepEqual(
      data.steps.map((s) => s.title),
      [
        "An ordinary call goes straight through",
        "A delete is held for a human",
        "The human sees the request",
        "The human approves this one call",
        "The same call now runs, once",
        "A third time needs a new yes",
        "A force push is blocked outright",
        "A tool result carries an instruction",
        "The agent obeys, and the upload is blocked",
        "The log checks out",
      ],
    );
    const calls = data.steps.flatMap((s) => s.audit.filter((l) => l.event === undefined));
    assert.deepEqual(
      calls.map((l) => [l.tool, l.decision, l.forwarded]),
      [
        ["echo", "allow", true],
        ["delete_file", "ask", false],
        ["delete_file", "ask", true],
        ["delete_file", "ask", false],
        ["run_command", "block", false],
        ["echo", "allow", true],
        ["run_command", "block", false],
      ],
    );
    assert.equal(calls[2].approvalId, calls[1].approvalId, "the call that ran used the approval the human gave");
    assert.match(data.steps[9].answer, /^PASS: \d+ lines checked, no problems$/);
  });

  it("quotes code that is still where the page says, word for word (npm run demo refreshes it)", () => {
    assert.deepEqual(Object.keys(data.excerpts).sort(), Object.keys(EXCERPTS).sort());
    for (const id of Object.keys(EXCERPTS)) assert.deepEqual(data.excerpts[id], excerpt(id), `${id} is out of date: run npm run demo`);
    for (const step of data.steps) for (const id of step.code) assert.ok(data.excerpts[id], `${step.title}: no excerpt ${id}`);
  });

  it("replays audit lines that pass audit verify", () => {
    const lines = data.steps.flatMap((s) => s.audit).map((value, i) => ({ line: i + 1, value }));
    assert.deepEqual(verifyAudit({ lines, unreadable: [] }), []);
  });

  it("loads nothing from elsewhere, and carries no local path or user name", () => {
    assert.equal(/<script[^>]+src=|<link[^>]+href=|@import|url\(/i.test(PAGE), false, "self-contained");
    // Home and temp folders of macOS, Linux and Windows, built here so this file names none of them.
    for (const bad of [...["Users", "home", "private", "var/folders"].map((dir) => `/${dir}/`), "\\Users\\"]) assert.equal(PAGE.includes(bad), false, bad);
    for (const step of data.steps) for (const l of step.audit) if (l.decidedBy !== undefined) assert.equal(l.decidedBy, "alice");
  });

  it("steps through every step in its own script, against a small stand-in for the page", () => {
    const nodes = new Map();
    const make = (tag) => {
      const node = {
        tag,
        children: [],
        attributes: {},
        listeners: {},
        disabled: false,
        set textContent(value) {
          this.children = [];
          this.text = value;
        },
        get textContent() {
          return this.text ?? "";
        },
        appendChild(child) {
          this.children.push(child);
          return child;
        },
        setAttribute(name, value) {
          this.attributes[name] = value;
        },
        addEventListener(type, fn) {
          this.listeners[type] = fn;
        },
        querySelector() {
          return null;
        },
      };
      return node;
    };
    const document = {
      createElement: make,
      createTextNode: (text) => ({ text }),
      getElementById(id) {
        if (id === "transcript") return { textContent: block[1] };
        if (!nodes.has(id)) nodes.set(id, make("div"));
        return nodes.get(id);
      },
      addEventListener(type, fn) {
        this.listeners = { ...this.listeners, [type]: fn };
      },
    };
    const script = /<script>\n([\s\S]*?)<\/script>/.exec(PAGE)[1];
    vm.runInNewContext(script, { document, window: { innerWidth: 1200 }, JSON });
    assert.equal(nodes.get("count").text, "step 1 of 10");
    for (let i = 0; i < 12; i++) nodes.get("next").listeners.click();
    assert.equal(nodes.get("count").text, "step 10 of 10");
    assert.equal(nodes.get("story").children.length, 10);
    assert.equal(nodes.get("next").disabled, true);
    document.listeners.keydown({ key: "ArrowLeft" });
    assert.equal(nodes.get("count").text, "step 9 of 10");
  });
});
