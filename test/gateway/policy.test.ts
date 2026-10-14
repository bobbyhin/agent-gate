// Table tests for the policy engine and the shipped policy.example.json.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { loadPolicy } from "../../src/gateway/config.js";
import { evaluate, parsePolicy, SHELL_TO_DECISION, splitWords, type Decision, type Policy, type Verdict } from "../../src/gateway/policy.js";
import { ConfigError } from "../../src/gateway/validate.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const example = loadPolicy(path.join(ROOT, "policy.example.json"));

interface Case {
  id: string;
  category: string;
  expect: "pass" | "warn" | "ask" | "block" | "ask_or_block";
  cmd: string;
}
const cases: Case[] = JSON.parse(fs.readFileSync(path.join(ROOT, "test", "cases.json"), "utf8"));

function check(policy: Policy, tool: string, args: Record<string, unknown> = {}, server = "demo"): Verdict {
  return evaluate(policy, { server, tool, args });
}

function expectVerdict(tool: string, decision: Decision, rule: string, args: Record<string, unknown> = {}): void {
  const verdict = check(example, tool, args);
  assert.equal(verdict.decision, decision, `${tool}: ${JSON.stringify(verdict)}`);
  assert.equal(verdict.rule, rule, `${tool}: ${JSON.stringify(verdict)}`);
  assert.ok(verdict.why.length > 0, `${tool}: every verdict needs a why`);
}

describe("policy.example.json: the red lines", () => {
  const table: Array<[rule: string, why: RegExp, tools: string[]]> = [
    ["red-line-1-money", /^Red line 1/, ["pay_invoice", "createCharge", "purchase-item", "transfer_funds", "checkout", "issueRefund", "create_payment_intent", "place_order", "BuyCredits"]],
    ["red-line-2-public", /^Red line 2/, ["post_message", "publishPost", "send_email", "tweet", "add_comment", "email_report", "reply_to_thread", "share_file"]],
    ["red-line-3-ship", /^Red line 3/, ["push_files", "merge_pull_request", "create_pull_request", "deploy_site", "createRelease", "create_pr"]],
    ["red-line-4-delete", /^Red line 4/, ["delete_file", "removeItem", "drop_table", "destroy-instance", "overwrite_file", "PurgeCache", "truncate_table", "files.delete"]],
  ];
  for (const [rule, why, tools] of table) {
    for (const tool of tools) {
      it(`${tool} -> ask (${rule})`, () => {
        expectVerdict(tool, "ask", rule);
        assert.match(check(example, tool).why, why);
      });
    }
  }

  // Whole words, not substrings: these share letters with a red-line word but are not one.
  for (const tool of ["read_file", "postgres_query", "list_comments", "get_posts", "display_text", "list_payments", "get_pull_request", "deleted_items_report", "dropdown_options", "search_issues"]) {
    it(`${tool} -> allow (default)`, () => expectVerdict(tool, "allow", "default"));
  }
});

describe("policy.example.json: the shell rule runs the slice-1 analyzer", () => {
  const byId = (id: string): Case => {
    const found = cases.find((c) => c.id === id);
    assert.ok(found, `test/cases.json has no case ${id}`);
    return found;
  };
  const table: Array<[id: string, decision: Decision]> = [
    ["A-c1", "ask"], // git push origin main
    ["D-ctl04", "block"], // git push --force origin main
    ["B-aug03", "block"], // rm -rf ~
    ["A-c6", "allow"], // ls -la
    ["B-aug26", "warn"], // kill -9 78811
  ];
  for (const [id, decision] of table) {
    const c = byId(id);
    it(`${id} ${JSON.stringify(c.cmd)} -> ${decision}`, () => expectVerdict("run_command", decision, "shell-guard", { command: c.cmd }));
  }

  it("the why carries the analyzer's label and reason", () => {
    const verdict = check(example, "run_command", { command: "git push origin main" });
    assert.equal(verdict.why, "shell guard: git push (any form): Red line 3 — a push needs a human decision");
  });

  it("every case in test/cases.json gets the mapped decision", () => {
    for (const c of cases) {
      const got = check(example, "run_command", { command: c.cmd });
      const allowed = c.expect === "ask_or_block" ? ["ask", "block"] : [SHELL_TO_DECISION[c.expect]];
      assert.ok(allowed.includes(got.decision), `${c.id}: expected ${allowed.join(" or ")}, got ${got.decision} for ${JSON.stringify(c.cmd)}`);
      assert.equal(got.rule, "shell-guard", c.id);
    }
  });

  it("covers the other common shell tool names", () => {
    for (const tool of ["exec", "bash", "execute_command", "shell_exec"]) {
      expectVerdict(tool, "block", "shell-guard", { command: "git push --force origin main" });
    }
  });

  it("asks when the command argument is missing or not a string", () => {
    expectVerdict("run_command", "ask", "shell-guard", {});
    expectVerdict("run_command", "ask", "shell-guard", { command: ["git", "push"] });
    expectVerdict("run_command", "ask", "shell-guard", { cmd: "ls" });
  });

  it("blocks an agent that tries to answer its own approval request or touch the state", () => {
    expectVerdict("run_command", "block", "no-self-approval", { command: "node bin/agent-gate.js approvals approve ap-1234abcd" });
    expectVerdict("bash", "block", "no-self-approval", { command: "agent-gate approvals deny ap-1234abcd" });
    expectVerdict("run_command", "block", "no-self-approval", { command: "cat .agent-gate/approvals.json" });
    expectVerdict("write_file", "block", "protect-gateway-state", { path: "/srv/work/.agent-gate/approvals.json" });
    expectVerdict("delete_file", "block", "protect-gateway-state", { path: ".agent-gate" });
  });
});

describe("rule matching", () => {
  const policy = parsePolicy({
    default: "warn",
    rules: [
      { id: "exact", tool: "Read_File", decision: "allow", why: "glob without wildcards = whole name, any case" },
      { id: "glob", tool: ["list_*", "get_?"], decision: "allow", why: "globs" },
      { id: "regex", tool: { regex: "^admin", flags: "i" }, decision: "block", why: "regex" },
      { id: "regex-anywhere", tool: { regex: "secret" }, decision: "block", why: "regex without anchors" },
      { id: "server", server: "prod-*", toolWords: ["update"], decision: "ask", why: "server and words" },
      { id: "args", tool: "write_file", args: { path: "*.env", mode: "overwrite" }, decision: "block", why: "every listed argument must match" },
      { id: "json-arg", tool: "configure", args: { options: { regex: "\"force\":true" } }, decision: "ask", why: "non-strings match as JSON" },
      { id: "inherited", tool: "probe", args: { constructor: "*" }, decision: "block", why: "own properties only" },
      { id: "first", tool: "twice", decision: "ask", why: "first match wins" },
      { id: "second", tool: "twice", decision: "block", why: "never reached" },
    ],
  });

  it("matches globs on the whole name, case-insensitively", () => {
    assert.equal(check(policy, "read_file").rule, "exact");
    assert.equal(check(policy, "READ_FILE").rule, "exact");
    assert.equal(check(policy, "read_file_now").rule, "default");
    assert.equal(check(policy, "list_things").rule, "glob");
    assert.equal(check(policy, "get_x").rule, "glob");
    assert.equal(check(policy, "get_xy").rule, "default");
  });

  it("matches regexes as written (unanchored unless they say so)", () => {
    assert.equal(check(policy, "Admin_reset").rule, "regex");
    assert.equal(check(policy, "user_admin").rule, "default");
    assert.equal(check(policy, "get_secret_value").rule, "regex-anywhere");
    assert.equal(check(policy, "get_SECRET_value").rule, "default", "no i flag: case matters");
  });

  it("combines server, tool words and arguments with AND", () => {
    assert.equal(check(policy, "update_row", {}, "prod-db").rule, "server");
    assert.equal(check(policy, "update_row", {}, "staging").rule, "default");
    assert.equal(check(policy, "write_file", { path: "app/.env", mode: "overwrite" }).rule, "args");
    assert.equal(check(policy, "write_file", { path: "app/.env", mode: "append" }).rule, "default");
    assert.equal(check(policy, "write_file", { path: "app/.env" }).rule, "default", "a missing argument does not match");
  });

  it("matches non-string arguments as JSON text, and only own properties", () => {
    assert.equal(check(policy, "configure", { options: { force: true } }).rule, "json-arg");
    assert.equal(check(policy, "configure", { options: { force: false } }).rule, "default");
    assert.equal(check(policy, "probe", {}).rule, "default");
  });

  it("lets the first matching rule decide, and falls back to the default", () => {
    assert.deepEqual(check(policy, "twice"), { decision: "ask", rule: "first", why: "first match wins" });
    assert.deepEqual(check(policy, "anything_else"), { decision: "warn", rule: "default", why: "no rule matched; the policy default is warn" });
  });

  it("splits tool names into words across naming styles", () => {
    assert.deepEqual(splitWords("delete_file"), ["delete", "file"]);
    assert.deepEqual(splitWords("deleteFile"), ["delete", "file"]);
    assert.deepEqual(splitWords("DeleteFile"), ["delete", "file"]);
    assert.deepEqual(splitWords("delete-file.v2"), ["delete", "file", "v2"]);
    assert.deepEqual(splitWords("HTTPRequest"), ["http", "request"]);
    assert.deepEqual(splitWords("createPullRequest"), ["create", "pull", "request"]);
  });

  it("is pure: the same call always gets the same verdict", () => {
    const call = { server: "demo", tool: "run_command", args: { command: "git push origin main" } };
    assert.deepEqual(evaluate(example, call), evaluate(example, call));
    assert.deepEqual(check(policy, "Admin_x"), check(policy, "Admin_x"));
  });
});

describe("parsePolicy rejects mistakes with the field named", () => {
  const rule = { id: "r", tool: "x", decision: "ask", why: "because" };
  const table: Array<[name: string, json: unknown, message: RegExp]> = [
    ["not an object", [], /^policy must be an object$/],
    ["missing default", { rules: [] }, /policy\.default must be one of allow, warn, ask, block/],
    ["unknown decision", { default: "allow", rules: [{ ...rule, decision: "maybe" }] }, /policy\.rules\[0\]\.decision must be one of/],
    ["typo in a field name", { default: "allow", rules: [{ ...rule, decison: "ask" }] }, /policy\.rules\[0\] has an unknown field "decison"/],
    ["missing why", { default: "allow", rules: [{ id: "r", tool: "x", decision: "ask" }] }, /policy\.rules\[0\]\.why must be a non-empty string/],
    ["duplicate id", { default: "allow", rules: [rule, rule] }, /policy\.rules\[1\]\.id "r" is already used/],
    ["reserved id", { default: "allow", rules: [{ ...rule, id: "default" }] }, /reserved/],
    ["stateful regex flag", { default: "allow", rules: [{ ...rule, tool: { regex: "x", flags: "g" } }] }, /flags may only contain i, m, s and u/],
    ["broken regex", { default: "allow", rules: [{ ...rule, tool: { regex: "(" } }] }, /tool\.regex is not a valid regular expression/],
    ["empty matcher list", { default: "allow", rules: [{ ...rule, tool: [] }] }, /must not be an empty list/],
    ["shell rule with a decision", { default: "allow", rules: [{ id: "s", type: "shell", tool: "bash", decision: "allow" }] }, /unknown field "decision"/],
    ["shell rule for every tool", { default: "allow", rules: [{ id: "s", type: "shell" }] }, /needs "tool" or "toolWords"/],
    ["unknown rule type", { default: "allow", rules: [{ ...rule, type: "match" }] }, /type must be "shell" or left out/],
    ["empty tool word", { default: "allow", rules: [{ ...rule, tool: undefined, toolWords: ["--"] }] }, /toolWords\[0\] has no letters or digits/],
  ];
  for (const [name, json, message] of table) {
    it(name, () => assert.throws(() => parsePolicy(json), (err: unknown) => err instanceof ConfigError && message.test(err.message)));
  }
});
