// agent-gate policy suggest: each tool's decision from its name, the tools that no rule names, and a
// draft policy (default ask, reads allowed by name or by HTTP method).
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { main } from "../../src/gateway/cli.js";
import { loadPolicy } from "../../src/gateway/config.js";
import { evaluate, parsePolicy } from "../../src/gateway/policy.js";
import { openApiCandidates, readsByName, shownName, suggest, type SuggestReport } from "../../src/gateway/suggest.js";
import { ConfigError } from "../../src/gateway/validate.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const EXAMPLE = path.join(ROOT, "policy.example.json");
const SAMPLE = path.join(ROOT, "test", "gateway", "openapi-sample.json");
const FAKE = path.join(__dirname, "fake-downstream.js");
const policy = loadPolicy(EXAMPLE);
const raw = JSON.parse(fs.readFileSync(EXAMPLE, "utf8")) as unknown;

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-suggest-"));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

async function run(...argv: string[]): Promise<{ code: number; out: string; err: string }> {
  let out = "";
  let err = "";
  const code = await main(argv, { out: (t) => (out += t), err: (t) => (err += t) });
  return { code, out, err };
}

function config(servers: unknown[]): string {
  const file = path.join(tmp, `config-${fs.readdirSync(tmp).length}.json`);
  fs.writeFileSync(file, JSON.stringify({ servers, policy: EXAMPLE, stateDir: path.join(tmp, "state") }));
  return file;
}

describe("policy suggest", () => {
  it("reads a name as a read only when it starts with a read verb and has no word that changes something", () => {
    const table: Array<[string, boolean]> = [
      ["get_file_info", true],
      ["list_directory", true],
      ["read_text_file", true],
      ["search_files", true],
      ["getUser", true],
      ["count_rows", true],
      ["get_or_create_user", false],
      ["list_and_delete_old", false],
      ["fetch", false],
      ["directory_tree", false],
      ["write_file", false],
      ["get_download_url", false],
    ];
    for (const [name, reads] of table) assert.equal(readsByName(name), reads, name);
  });

  it("decides each tool from its name, names the rules that arguments can change, and drafts a stricter policy", () => {
    const tools = ["echo", "delete_file", "run_command", "search_notes", "create_note"].map((tool) => ({ server: "demo", tool }));
    const report = suggest(policy, raw, tools);
    const by = new Map(report.suggestions.map((s) => [s.tool, s]));
    assert.deepEqual(
      report.suggestions.map((s) => [s.tool, s.decision, s.rule, s.draft]),
      [
        ["echo", "allow", "default", "ask"],
        ["delete_file", "ask", "red-line-4-delete", "ask"],
        ["run_command", "ask", "shell-guard", "ask"],
        ["search_notes", "allow", "default", "allow"],
        ["create_note", "allow", "default", "ask"],
      ],
    );
    assert.deepEqual(by.get("run_command")?.dependsOn, ["no-self-approval", "shell-guard"]);
    assert.deepEqual(by.get("echo")?.dependsOn, []);
    assert.deepEqual(report.argumentRules, ["protect-gateway-state", "sql-write"]);
    assert.deepEqual(report.unmatched, ["demo__echo", "demo__search_notes", "demo__create_note"]);
    // The draft keeps every rule, adds one allow rule for the reads, and asks by default.
    const draft = parsePolicy(report.draft);
    assert.equal(draft.default, "ask");
    assert.deepEqual(draft.rules.map((r) => r.id), [...policy.rules.map((r) => r.id), "suggested-reads-demo"]);
    assert.deepEqual(report.draft.rules.at(-1), {
      id: "suggested-reads-demo",
      server: "demo",
      tool: ["search_notes"],
      decision: "allow",
      why: "Suggested by agent-gate policy suggest: these names read. Check each one before you keep it.",
    });
    // A rule that the arguments decide still decides in the draft: the shell guard blocks a force push.
    assert.equal(evaluate(draft, { server: "demo", tool: "run_command", args: { command: "git push --force origin main" } }).decision, "block");
  });

  it("never turns a server's tool name into a pattern: a name that is not plain stays out of the draft, and nothing hangs", () => {
    // A hostile server picks its own names. As globs, "get*" would allow every get... tool of the
    // server, and a run of "*" takes exponential time to match against the other names.
    const stars = `get${"*".repeat(14)}x`;
    const names = ["get*", "get_notes", "getAndExecuteShell", stars, "get_\u001b[2Jx", "list?"];
    const started = Date.now();
    const report = suggest(policy, raw, names.map((tool) => ({ server: "evil", tool })));
    assert.ok(Date.now() - started < 2000, "suggest() answers at once, whatever the names");
    assert.deepEqual(report.draft.rules.at(-1), {
      id: "suggested-reads-evil",
      server: "evil",
      tool: ["get_notes"],
      decision: "allow",
      why: "Suggested by agent-gate policy suggest: these names read. Check each one before you keep it.",
    });
    assert.deepEqual(report.notDrafted, ["evil__get*", `evil__${stars}`, "evil__get_\u001b[2Jx", "evil__list?"]);
    const draft = parsePolicy(report.draft);
    for (const tool of ["getAndExecuteShell", "get_and_run_script", "get_anything", "get*", stars]) {
      assert.equal(evaluate(draft, { server: "evil", tool, args: {} }).decision, "ask", tool);
    }
    assert.equal(evaluate(draft, { server: "evil", tool: "get_notes", args: {} }).decision, "allow");
    // The output prints such a name quoted, so a control character shows as an escape, not as an action.
    assert.equal(shownName("evil", "get_\u001b[2Jx"), 'evil__"get_\\u001b[2Jx"');
    assert.equal(shownName("evil", "get_notes"), "evil__get_notes");
  });

  it("a tool left out by the config's expose globs is blocked, as in the gateway", () => {
    const report = suggest(policy, raw, [{ server: "demo", tool: "search_notes" }, { server: "demo", tool: "echo" }], new Map([["demo", ["search_*"]]]));
    assert.deepEqual(report.suggestions.map((s) => [s.tool, s.decision, s.rule]), [["search_notes", "allow", "default"], ["echo", "block", "not-exposed"]]);
  });

  it("reads an OpenAPI document: operations named by operationId; GET and HEAD are reads unless the name changes something", () => {
    const spec = JSON.parse(fs.readFileSync(SAMPLE, "utf8")) as unknown;
    const candidates = openApiCandidates(spec, "notes");
    assert.deepEqual(
      candidates.map((c) => `${c.http?.method.toUpperCase()} ${c.http?.path} ${c.tool}`),
      [
        "GET /notes listNotes",
        "POST /notes createNote",
        "GET /notes/{id} getNote",
        "PUT /notes/{id} updateNote",
        "DELETE /notes/{id} deleteNote",
        "PATCH /notes/{id} patch_notes_id",
        "POST /notes/{id}/share shareNote",
        "GET /notes/{id}/export exportNote",
        "POST /search searchNotes",
        "HEAD /health checkHealth",
      ],
    );
    const report = suggest(policy, raw, candidates);
    assert.deepEqual(report.draft.rules.at(-1), {
      id: "suggested-reads-notes",
      server: "notes",
      tool: ["listNotes", "getNote", "checkHealth"],
      decision: "allow",
      why: "Suggested by agent-gate policy suggest: these names read. Check each one before you keep it.",
    });
    // The example lets createNote and updateNote run unattended; the draft asks.
    const decided = new Map(report.suggestions.map((s) => [s.tool, [s.decision, s.draft]]));
    assert.deepEqual([decided.get("createNote"), decided.get("updateNote"), decided.get("searchNotes")], [["allow", "ask"], ["allow", "ask"], ["allow", "ask"]]);
    for (const bad of [{ paths: {} }, { openapi: "3.0.0" }, []]) assert.throws(() => openApiCandidates(bad, "notes"), ConfigError);
  });

  it("the CLI lists the downstream servers' tools, and the draft it prints is a policy", async () => {
    const file = config([{ name: "demo", command: process.execPath, args: [FAKE] }]);
    const text = await run("policy", "suggest", "--config", file);
    assert.equal(text.code, 0, text.err);
    assert.match(text.out, /^8 tools, decided from their names by policy\.example\.json/);
    assert.match(text.out, /\ndemo__delete_file +ask +red-line-4-delete +ask\n/);
    assert.match(text.out, /No rule names 5 of them, so the policy's default \(allow\) decides: demo__echo,/);
    const draft = parsePolicy(JSON.parse(text.out.slice(text.out.indexOf("\n{\n") + 1)));
    assert.equal(draft.default, "ask");

    const json = await run("policy", "suggest", "--json", "--config", file);
    const report = JSON.parse(json.out) as SuggestReport & { failures: string[] };
    assert.deepEqual([json.code, report.suggestions.length, report.failures], [0, 8, []]);

    // With one server in the config, an OpenAPI document describes that server, and the draft's rule names it.
    const api = await run("policy", "suggest", "--openapi", SAMPLE, "--json", "--config", file);
    const apiReport = JSON.parse(api.out) as SuggestReport;
    assert.deepEqual([api.code, apiReport.suggestions.map((s) => s.tool).slice(0, 2)], [0, ["listNotes", "createNote"]]);
    assert.deepEqual((apiReport.draft.rules.at(-1) as { server: string }).server, "demo");
  });

  it("--server starts only that server; with --openapi it names the server the document describes", async () => {
    const file = config([
      { name: "demo", command: process.execPath, args: [FAKE] },
      { name: "broken", command: process.execPath, args: [path.join(tmp, "no-such-server.js")] },
    ]);
    // Only demo is started, so the broken server is never tried and nothing fails.
    const one = await run("policy", "suggest", "--server", "demo", "--json", "--config", file);
    const report = JSON.parse(one.out) as SuggestReport & { failures: string[] };
    assert.deepEqual([one.code, report.suggestions.length, report.failures, one.err], [0, 8, [], ""]);
    assert.ok(report.suggestions.every((s) => s.server === "demo"));

    const unknown = await run("policy", "suggest", "--server", "nope", "--config", file);
    assert.equal(unknown.code, 1);
    assert.match(unknown.err, /--server "nope" is not a server in .*; it has demo, broken/);

    // Two servers: which one the document describes has to be said.
    const unnamed = await run("policy", "suggest", "--openapi", SAMPLE, "--config", file);
    assert.equal(unnamed.code, 1);
    assert.match(unnamed.err, /with --openapi, name the server that the document describes with --server <name>/);
    const named = await run("policy", "suggest", "--openapi", SAMPLE, "--server", "broken", "--json", "--config", file);
    const namedReport = JSON.parse(named.out) as SuggestReport;
    assert.equal(named.code, 0, "an OpenAPI document starts no server, so the broken one does not matter");
    assert.deepEqual(namedReport.draft.rules.at(-1), {
      id: "suggested-reads-broken",
      server: "broken",
      tool: ["listNotes", "getNote", "checkHealth"],
      decision: "allow",
      why: "Suggested by agent-gate policy suggest: these names read. Check each one before you keep it.",
    });
  });

  it("names a server it could not start, still lists the others, and exits 1; bad input is refused", async () => {
    const file = config([
      { name: "demo", command: process.execPath, args: [FAKE] },
      { name: "broken", command: process.execPath, args: [path.join(tmp, "no-such-server.js")] },
    ]);
    const r = await run("policy", "suggest", "--json", "--config", file);
    assert.equal(r.code, 1);
    assert.match(r.err, /"broken": could not start or reach it/);
    assert.equal((JSON.parse(r.out) as SuggestReport).suggestions.length, 8);

    const yaml = path.join(tmp, "spec.yaml");
    fs.writeFileSync(yaml, "openapi: 3.0.3\npaths: {}\n");
    const notJson = await run("policy", "suggest", "--openapi", yaml, "--server", "demo", "--config", file);
    assert.equal(notJson.code, 1);
    assert.match(notJson.err, /a YAML document has to be converted to JSON first/);
    assert.equal((await run("policy", "suggest", "--all", "--config", file)).code, 2);
  });
});
