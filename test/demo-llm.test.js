"use strict";
// docs/demo/llm.html: a replay of a real run of the LLM gateway. The page must stay true to the code:
// every excerpt it quotes is still at that line of that file, its numbers add up (what the usage lines
// booked is what the ledger holds), no upstream key or gateway key is on it, it loads nothing from
// elsewhere, and its script steps through every step. Runs after the build.
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..");
const PAGE = fs.readFileSync(path.join(ROOT, "docs", "demo", "llm.html"), "utf8");
const { EXCERPTS, excerpt, GATEWAY_KEY, UPSTREAM_ENV } = require("../scripts/demo-llm-transcript.js");
const { roundUsd } = require("../dist/src/llm/budget.js");

const block = /<script type="application\/json" id="transcript">\n([\s\S]*?)\n<\/script>/.exec(PAGE);
const data = JSON.parse(block[1]);

describe("docs/demo/llm.html: the LLM gateway's step-through page", () => {
  it("holds the recorded run: an allowed call, a secret blocked, a budget refusal, a held stream, the books checked", () => {
    assert.deepEqual(
      data.steps.map((s) => s.title),
      [
        "A classification goes to the cheap model",
        "A secret in the prompt never leaves",
        "A call that could pass the budget is refused before it is sent",
        "A streamed answer is held until it has been read",
        "The books balance",
      ],
    );
    const calls = data.steps.filter((s) => s.actor === "agent");
    assert.deepEqual(
      calls.map((s) => [s.response.status, s.upstreamCalls, s.usage.map((u) => u.error ?? "ok")]),
      [
        [200, 1, ["ok"]],
        [400, 0, ["secret_detected"]],
        [429, 0, ["budget_exceeded"]],
        [200, 1, ["ok"]],
      ],
    );
    assert.equal(calls[0].response.headers["x-agent-gate-route"], "classify-is-cheap");
    assert.equal(JSON.parse(calls[1].response.body).error.rule, "private-key");
    assert.match(calls[2].response.headers["retry-after"], /^\d+$/);
    assert.match(calls[3].response.headers["content-type"], /^text\/event-stream/);
    assert.match(calls[3].response.body, /data: \[DONE\]\s*$/);
    assert.deepEqual([calls[3].usage[0].stream, calls[3].usage[0].streamEnd], [true, "done"]);
    const verify = data.steps[4];
    assert.equal(verify.exitCode, 0);
    assert.match(verify.answer, /demo-agent .* ok$/);
  });

  it("adds up: the dollars in the usage lines are what the ledger holds, and refused calls cost nothing", () => {
    const lines = data.steps.flatMap((s) => s.usage);
    for (const l of lines) if (l.error) assert.equal(l.costUsd, 0, `${l.error} cost nothing`);
    const booked = roundUsd(lines.reduce((sum, l) => sum + l.costUsd, 0));
    assert.equal(data.steps[data.steps.length - 1].ledger[0].dayUsd, booked);
    assert.ok(booked > 0);
  });

  it("quotes code that is still where the page says, word for word (npm run demo:llm refreshes it)", () => {
    assert.deepEqual(Object.keys(data.excerpts).sort(), Object.keys(EXCERPTS).sort());
    for (const id of Object.keys(EXCERPTS)) assert.deepEqual(data.excerpts[id], excerpt(id), `${id} is out of date: run npm run demo:llm`);
    for (const step of data.steps) for (const id of step.code) assert.ok(data.excerpts[id], `${step.title}: no excerpt ${id}`);
  });

  it("carries no key, no prompt text in the usage lines, no local path, and loads nothing from elsewhere", () => {
    assert.equal(/<script[^>]+src=|<link[^>]+href=|@import|url\(/i.test(PAGE), false, "self-contained");
    for (const secret of [GATEWAY_KEY, ...Object.values(UPSTREAM_ENV)]) assert.equal(PAGE.includes(secret), false, "a key is on the page");
    for (const step of data.steps) for (const l of step.usage) assert.equal(JSON.stringify(l).includes("ssh reject"), false, "prompt text in a usage line");
    // Home and temp folders of macOS, Linux and Windows, built here so this file names none of them.
    for (const bad of [...["Users", "home", "private", "var/folders"].map((dir) => `/${dir}/`), "\\Users\\"]) assert.equal(PAGE.includes(bad), false, bad);
  });

  it("steps through every step in its own script, against a small stand-in for the page", () => {
    const nodes = new Map();
    const make = (tag) => ({
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
    });
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
    vm.runInNewContext(script, { document, window: { innerWidth: 1200 }, JSON, String, Object });
    assert.equal(nodes.get("count").text, "step 1 of 5");
    for (let i = 0; i < 7; i++) nodes.get("next").listeners.click();
    assert.equal(nodes.get("count").text, "step 5 of 5");
    assert.equal(nodes.get("story").children.length, 5);
    assert.equal(nodes.get("next").disabled, true);
    document.listeners.keydown({ key: "ArrowLeft" });
    assert.equal(nodes.get("count").text, "step 4 of 5");
  });
});
