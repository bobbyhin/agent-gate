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
    // cloud resources that start a bill
    ["red-line-1-money", /^Red line 1/, ["create_rag_corpus", "enable_api", "enableService", "provision_cluster", "create_instance", "createBucket", "create_cluster", "scale_up_nodes", "create_key"]],
    ["red-line-2-public", /^Red line 2/, ["post_message", "publishPost", "send_email", "tweet", "add_comment", "email_report", "reply_to_thread", "share_file"]],
    ["red-line-3-ship", /^Red line 3/, ["push_files", "merge_pull_request", "create_pull_request", "deploy_site", "createRelease", "create_pr"]],
    ["red-line-4-delete", /^Red line 4/, ["delete_file", "removeItem", "drop_table", "destroy-instance", "overwrite_file", "PurgeCache", "truncate_table", "files.delete"]],
    ["red-line-5-memory", /^Red line 5/, ["remember_fact", "create_entities", "add_observations", "create_relations", "archival_memory_insert", "core_memory_append", "save_memory", "set_preference", "updateProfile"]],
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
  // Reading cloud resources and memory, and saving an ordinary file, stay allowed.
  for (const tool of ["list_corpora", "get_corpus", "describe_instance", "list_buckets", "read_graph", "search_nodes", "open_nodes", "get_preferences", "save_file", "type_definition"]) {
    it(`${tool} -> allow (default)`, () => expectVerdict(tool, "allow", "default"));
  }
});

describe("policy.example.json: SQL in an sql argument", () => {
  const table: Array<[sql: string, decision: Decision]> = [
    ["SELECT * FROM users WHERE id = 1", "allow"],
    ["select count(*) from orders;", "allow"],
    ["WITH recent AS (SELECT * FROM orders WHERE created_at > now() - interval '1 day') SELECT count(*) FROM recent", "allow"],
    ["EXPLAIN SELECT updated_at, is_deleted, created_by FROM accounts", "allow"],
    ["SHOW TABLES", "allow"],
    ["DROP TABLE users", "ask"],
    ["delete from sessions", "ask"],
    ["  UPDATE users SET admin = true WHERE id = 7", "ask"],
    ["INSERT INTO audit VALUES (1, 'x')", "ask"],
    ["WITH gone AS (DELETE FROM carts RETURNING *) SELECT count(*) FROM gone", "ask"],
    ["/* weekly report */ DROP TABLE reports", "ask"],
    ["-- read only\nTRUNCATE logs", "ask"],
    ["SELECT 1; DROP TABLE users", "ask"],
    ["SELECT * INTO users_backup FROM users", "ask"],
    ["GRANT ALL ON DATABASE app TO PUBLIC", "ask"],
    ["ALTER TABLE t ADD COLUMN c int", "ask"],
    ["CALL purge_old_rows()", "ask"],
  ];
  for (const [sql, decision] of table) {
    it(`${JSON.stringify(sql.slice(0, 60))} -> ${decision}`, () => expectVerdict("execute_sql", decision, decision === "ask" ? "sql-write" : "default", { sql }));
  }

  it("a regex is not a SQL parser: a write word inside a string literal asks too", () => {
    expectVerdict("execute_sql", "ask", "sql-write", { sql: "SELECT * FROM events WHERE action = 'delete'" });
  });

  it("only an argument named sql is read; a tool that names it differently needs its own rule", () => {
    expectVerdict("run_query", "allow", "default", { query: "DROP TABLE users" });
  });
});

describe("policy.example.json: browser tools", () => {
  const table: Array<[tool: string, decision: Decision, rule: string]> = [
    ["browser_click", "ask", "browser-input"],
    ["browser_type", "ask", "browser-input"],
    ["browser_press_key", "ask", "browser-input"],
    ["browser_fill_form", "ask", "browser-input"],
    ["browser_select_option", "ask", "browser-input"],
    ["browser_file_upload", "ask", "browser-input"],
    ["browser_evaluate", "ask", "browser-input"],
    ["browser_handle_dialog", "ask", "browser-input"],
    ["puppeteer_fill", "ask", "browser-input"],
    ["playwright_click", "ask", "browser-input"],
    ["browser_take_screenshot", "allow", "browser-read"],
    ["browser_snapshot", "allow", "browser-read"],
    ["browser_navigate", "allow", "browser-read"],
    ["puppeteer_screenshot", "allow", "browser-read"],
    ["browser_tabs", "allow", "browser-read"],
    // not a browser tool: the browser words alone do not apply
    ["select_rows", "allow", "default"],
  ];
  for (const [tool, decision, rule] of table) {
    it(`${tool} -> ${decision} (${rule})`, () => expectVerdict(tool, decision, rule, { element: "Submit button", ref: "e12" }));
  }

  it("the tool name decides, not the target: a click on anything asks, whatever the arguments say", () => {
    expectVerdict("browser_click", "ask", "browser-input", { element: "harmless link", ref: "e1" });
    expectVerdict("browser_click", "ask", "browser-input", {});
  });
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

  it("every case in test/cases-exfil.json (uploads) gets the mapped decision", () => {
    const exfil: Case[] = JSON.parse(fs.readFileSync(path.join(ROOT, "test", "cases-exfil.json"), "utf8"));
    for (const c of exfil) {
      const got = check(example, "run_command", { command: c.cmd });
      assert.equal(got.decision, SHELL_TO_DECISION[c.expect as "pass" | "warn" | "ask" | "block"], `${c.id}: got ${got.decision} for ${JSON.stringify(c.cmd)}`);
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
    expectVerdict("bash", "block", "no-self-approval", { command: "agent-gate approvals grant demo__execute_sql --uses 100 --hours 168" });
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
      { id: "second", tool: "twice", decision: "block", why: "matches too, decides nothing" },
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

  it("lets the first matching rule decide, lists the later ones that match too, and falls back to the default", () => {
    assert.deepEqual(check(policy, "twice"), {
      decision: "ask",
      rule: "first",
      why: "first match wins",
      alsoMatched: [{ rule: "second", decision: "block", why: "matches too, decides nothing" }],
    });
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
    ["ttlMinutes that is not positive", { default: "allow", rules: [{ ...rule, ttlMinutes: 0 }] }, /ttlMinutes must be a positive number of minutes/],
    ["ttlMinutes as text", { default: "allow", rules: [{ ...rule, ttlMinutes: "30" }] }, /ttlMinutes must be a positive number of minutes/],
    ["ttlMinutes on a rule that never asks", { default: "allow", rules: [{ ...rule, decision: "block", ttlMinutes: 30 }] }, /ttlMinutes only applies to a rule whose decision is ask/],
    ["standing on a rule that never asks", { default: "allow", rules: [{ ...rule, decision: "allow", standing: true }] }, /standing only applies to a rule whose decision is ask/],
    ["standing that is not true or false", { default: "allow", rules: [{ ...rule, standing: "yes" }] }, /standing must be true or false/],
    ["standing on a shell rule", { default: "allow", rules: [{ id: "s", type: "shell", tool: "bash", standing: true }] }, /unknown field "standing"/],
  ];
  for (const [name, json, message] of table) {
    it(name, () => assert.throws(() => parsePolicy(json), (err: unknown) => err instanceof ConfigError && message.test(err.message)));
  }
});

describe("ttlMinutes: a rule can give its approval requests a shorter life", () => {
  it("the example gives money 15 minutes and shipping 30; the other asks use approvalTtlHours", () => {
    assert.equal(check(example, "create_payment").ttlMs, 15 * 60 * 1000);
    assert.equal(check(example, "merge_pull_request").ttlMs, 30 * 60 * 1000);
    for (const tool of ["delete_file", "send_email", "add_memory"]) assert.equal(check(example, tool).ttlMs, undefined, tool);
  });

  it("is attached to an ask only, also from a shell rule", () => {
    const policy = parsePolicy({
      default: "allow",
      rules: [{ id: "sh", type: "shell", tool: "bash", ttlMinutes: 5 }],
    });
    assert.deepEqual([check(policy, "bash", { command: "git push" }).decision, check(policy, "bash", { command: "git push" }).ttlMs], ["ask", 5 * 60 * 1000]);
    assert.equal(check(policy, "bash", { command: "ls" }).ttlMs, undefined); // allow: nothing to expire
    assert.equal(check(policy, "bash", { command: "git push --force" }).ttlMs, undefined); // block: never queued
  });
});

describe("standing: which rules a standing approval may answer", () => {
  it("in the example, only sql-write and browser-input; never money, shipping, memory or the shell rule", () => {
    assert.equal(check(example, "execute_sql", { sql: "INSERT INTO t VALUES (1)" }).standing, true);
    assert.equal(check(example, "browser_click").standing, true);
    for (const tool of ["create_payment", "merge_pull_request", "delete_file", "send_email", "add_memory"]) assert.equal(check(example, tool).standing, undefined, tool);
    assert.equal(check(example, "run_command", { command: "git push" }).standing, undefined);
  });
});

/** The engine before alsoMatched and rewrite: the first matching rule decides, and nothing more. */
function firstMatch(policy: Policy, call: { server: string; tool: string; args: Record<string, unknown> }): Verdict {
  for (const rule of policy.rules) {
    if (!rule.verdict) continue;
    const matched = evaluate({ default: "allow", rules: [rule], repeat: [] }, call);
    if (matched.rule === rule.id) return rule.verdict(call);
  }
  return { decision: policy.default, rule: "default", why: `no rule matched; the policy default is ${policy.default}` };
}

describe("alsoMatched: every rule that matched, while the first one still decides", () => {
  it("decides exactly as first match did, for the red-line tools, the SQL samples and every shell case", () => {
    const calls: Array<{ server: string; tool: string; args: Record<string, unknown> }> = [];
    for (const tool of ["pay_invoice", "create_rag_corpus", "post_message", "push_files", "delete_file", "remember_fact", "read_file", "browser_click", "browser_navigate", "deploy_and_delete", "send_and_pay"]) calls.push({ server: "demo", tool, args: {} });
    for (const sql of ["SELECT 1", "DELETE FROM t", "SELECT 1; DROP TABLE t"]) calls.push({ server: "demo", tool: "execute_sql", args: { sql } });
    for (const c of cases) calls.push({ server: "demo", tool: "run_command", args: { command: c.cmd } });
    calls.push({ server: "demo", tool: "bash", args: { command: "node bin/agent-gate.js approvals approve ap-12345678" } });
    calls.push({ server: "demo", tool: "write_note", args: { path: "/srv/.agent-gate/approvals.json" } });
    for (const call of calls) {
      const { alsoMatched: _also, ...decided } = evaluate(example, call);
      assert.deepEqual(decided, firstMatch(example, call), JSON.stringify(call).slice(0, 120));
    }
    assert.ok(calls.length > 250);
  });

  it("lists each later matching rule in policy order, with its own decision and why", () => {
    const verdict = check(example, "delete_and_publish_post");
    assert.deepEqual([verdict.decision, verdict.rule], ["ask", "red-line-2-public"]);
    assert.deepEqual(verdict.alsoMatched, [{ rule: "red-line-4-delete", decision: "ask", why: "Red line 4: this tool looks like it deletes or overwrites data." }]);
    const shell = check(example, "bash", { command: "git push --force origin main", path: "/srv/.agent-gate/x" });
    assert.deepEqual([shell.decision, shell.rule], ["block", "protect-gateway-state"]);
    assert.deepEqual(shell.alsoMatched?.map((m) => [m.rule, m.decision, m.why]), [["shell-guard", "block", "shell guard: force push"]]);
    assert.equal(check(example, "read_file").alsoMatched, undefined, "nothing else matched: no field");
  });

  it("reordering the rules changes which one decides, not which ones matched", () => {
    const rules = [
      { id: "a", toolWords: ["delete"], decision: "ask", why: "a" },
      { id: "b", toolWords: ["publish"], decision: "block", why: "b" },
      { id: "c", tool: "*", decision: "warn", why: "c" },
    ];
    const forward = evaluate(parsePolicy({ default: "allow", rules }), { server: "s", tool: "delete_publish", args: {} });
    const backward = evaluate(parsePolicy({ default: "allow", rules: [...rules].reverse() }), { server: "s", tool: "delete_publish", args: {} });
    assert.deepEqual([forward.rule, backward.rule], ["a", "c"]);
    const all = (v: Verdict) => [v.rule, ...(v.alsoMatched ?? []).map((m) => m.rule)].sort();
    assert.deepEqual(all(forward), all(backward));
  });
});

describe("rewrite rules: edit the arguments, then the next rules decide on the edited call", () => {
  const policy = parsePolicy({
    default: "allow",
    rules: [
      { id: "no-debug", tool: "search_*", decision: "rewrite", rewrite: { drop: ["debug"] }, why: "debug output can carry internals" },
      { id: "cap-limit", tool: "search_*", decision: "rewrite", rewrite: { clamp: { limit: { min: 1, max: 100 } } }, why: "at most 100 rows" },
      { id: "dry-run-deploys", toolWords: ["deploy"], decision: "rewrite", rewrite: { set: { dryRun: true } }, why: "deploys run as a dry run first" },
      { id: "hide-tokens", decision: "rewrite", rewrite: { redact: [{ regex: "tok_[a-z0-9]{8,}" }] }, why: "tokens never leave" },
      { id: "ask-deploys", toolWords: ["deploy"], decision: "ask", why: "a human looks at every deploy" },
    ],
  });
  const call = (tool: string, args: Record<string, unknown>) => evaluate(policy, { server: "demo", tool, args });

  it("drops, clamps, sets and redacts, in rule order, and names the rules that changed something", () => {
    const v = call("search_notes", { query: "q tok_abcdef123456", limit: 5000, debug: true, nested: { list: ["tok_00000000aa", 3] } });
    assert.deepEqual([v.decision, v.rule], ["allow", "default"]);
    assert.deepEqual(v.args, { query: "q [REDACTED:hide-tokens]", limit: 100, nested: { list: ["[REDACTED:hide-tokens]", 3] } });
    assert.deepEqual(v.rewrittenBy, ["no-debug", "cap-limit", "hide-tokens"]);
  });

  it("leaves the call alone, and says nothing, when no edit changes anything", () => {
    const v = call("search_notes", { query: "q", limit: 50 });
    assert.deepEqual([v.args, v.rewrittenBy], [undefined, undefined]);
    assert.equal(call("search_notes", { query: "q" }).args, undefined, "an absent limit is not invented");
  });

  it("a later ask decides on the edited call, so an approval binds to what will run", () => {
    const v = call("deploy_site", { site: "web", dryRun: false });
    assert.deepEqual([v.decision, v.rule, v.args, v.rewrittenBy], ["ask", "ask-deploys", { site: "web", dryRun: true }, ["dry-run-deploys"]]);
  });

  it("asks when a value cannot be made safe: a clamp on something that is not a number", () => {
    const v = call("search_notes", { query: "q", limit: "5000" });
    assert.deepEqual([v.decision, v.rule], ["ask", "cap-limit"]);
    assert.match(v.why, /keeps "limit" within bounds, and this value is not a number/);
  });

  it("a rewrite after the deciding rule is listed, not applied", () => {
    const late = parsePolicy({
      default: "allow",
      rules: [
        { id: "ask-first", tool: "search_notes", decision: "ask", why: "decides first" },
        { id: "cap-late", tool: "search_notes", decision: "rewrite", rewrite: { clamp: { limit: { max: 10 } } }, why: "too late" },
      ],
    });
    const v = evaluate(late, { server: "demo", tool: "search_notes", args: { limit: 99 } });
    assert.deepEqual([v.decision, v.args, v.alsoMatched], ["ask", undefined, [{ rule: "cap-late", decision: "rewrite", why: "too late" }]]);
  });

  const bad: Array<[string, unknown, RegExp]> = [
    ["a rewrite rule without edits", { id: "r", decision: "rewrite", why: "w" }, /policy\.rules\[0\] is a rewrite rule, so it needs "rewrite"/],
    ["an empty rewrite", { id: "r", decision: "rewrite", rewrite: {}, why: "w" }, /needs at least one of set, clamp, drop and redact/],
    ["edits on a rule that decides", { id: "r", decision: "allow", rewrite: { drop: ["x"] }, why: "w" }, /rewrite only applies to a rule whose decision is rewrite/],
    ["set and drop of one argument", { id: "r", decision: "rewrite", rewrite: { set: { x: 1 }, drop: ["x"] }, why: "w" }, /both sets and drops "x"/],
    ["a clamp with min above max", { id: "r", decision: "rewrite", rewrite: { clamp: { n: { min: 5, max: 1 } } }, why: "w" }, /min is more than its max/],
    ["a clamp without bounds", { id: "r", decision: "rewrite", rewrite: { clamp: { n: {} } }, why: "w" }, /needs "min", "max" or both/],
    ["a redact regex that matches nothing at all", { id: "r", decision: "rewrite", rewrite: { redact: [{ regex: "x*" }] }, why: "w" }, /matches empty text/],
    ["a redact with the g flag", { id: "r", decision: "rewrite", rewrite: { redact: [{ regex: "x", flags: "g" }] }, why: "w" }, /flags may only contain i, m, s and u/],
    ["ttlMinutes on a rewrite rule", { id: "r", decision: "rewrite", rewrite: { drop: ["x"] }, why: "w", ttlMinutes: 5 }, /ttlMinutes does not apply to a rewrite rule/],
    ["a shell rule with edits", { id: "r", type: "shell", tool: "bash", rewrite: { drop: ["x"] } }, /unknown field "rewrite"/],
  ];
  for (const [name, rule, message] of bad) {
    it(`refuses ${name}`, () => assert.throws(() => parsePolicy({ default: "allow", rules: [rule] }), (err: unknown) => err instanceof ConfigError && message.test(err.message)));
  }
});
