// Action tokens for irreversible calls (ADR 0013): the confirmation carries a token the gateway bound
// to one call; --yes, another request's token, a decided or expired request and a CLI without the key
// are refused; the gateway uses an approval only with a valid proof and a token never spent before, so
// reuse, expiry, other arguments, a forged record and a replayed one are refused; standing approvals
// never answer; and every refusal is in the audit log, which never holds a token.
import { after, afterEach, before, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { ActionTokens, spentNonces, type TokenBinding } from "../../src/gateway/action-tokens.js";
import { ApprovalError, ApprovalStore, hashArguments, type Approval, type AskRequest, type TokenCheck } from "../../src/gateway/approvals.js";
import { readAudit, verifyAudit } from "../../src/gateway/audit-tools.js";
import { main } from "../../src/gateway/cli.js";
import { loadConfig, loadPolicy } from "../../src/gateway/config.js";
import { evaluate, irreversibleRuleFor, parsePolicy } from "../../src/gateway/policy.js";
import { createGateway, type Gateway } from "../../src/gateway/server.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const FAKE = path.join(__dirname, "fake-downstream.js");
const TOKEN = /at-[0-9a-z]{4}-[0-9a-z]{4}/i;

const binding = (over: Partial<TokenBinding> = {}): TokenBinding => ({
  id: "ap-0000abcd",
  server: "demo",
  tool: "delete_file",
  argsHash: hashArguments({ path: "notes/old.md" }),
  expiresAt: "2026-11-04T09:00:00.000Z",
  nonce: "nc-000000000000000000000001",
  ...over,
});

describe("action tokens: the key, the code and the proof", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-tokens-"));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("creates a private key once, and every reader of the file gets the same one", () => {
    const file = path.join(dir, "keys", "action-token.key");
    assert.equal(new ActionTokens(file).key(false), undefined, "no key, none made without asking");
    const key = new ActionTokens(file).key(true);
    assert.equal(key?.length, 32);
    assert.match(fs.readFileSync(file, "utf8"), /^[0-9a-f]{64}\n$/);
    if (process.platform !== "win32") assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.deepEqual(new ActionTokens(file).key(true), key);
  });

  it("refuses a key other users can read, one that is not a key, and one that cannot be read", () => {
    const file = path.join(dir, "action-token.key");
    fs.writeFileSync(file, `${"ab".repeat(32)}\n`, { mode: 0o644 });
    if (process.platform !== "win32") assert.throws(() => new ActionTokens(file).key(), /can be read by other users; make it readable by its owner only/);
    fs.chmodSync(file, 0o600);
    fs.writeFileSync(file, "not a key\n");
    assert.throws(() => new ActionTokens(file).key(), /is not an action-token key/);
    fs.rmSync(file);
    fs.mkdirSync(file);
    assert.throws(() => new ActionTokens(file).key(true), /cannot read the action-token key/);
  });

  it("gives a short code bound to every field of the request; case, dashes and the prefix do not matter", () => {
    const tokens = new ActionTokens(path.join(dir, "k"));
    const code = tokens.code(binding());
    assert.match(code, /^at-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
    assert.equal(tokens.code(binding()), code, "the same request, the same code");
    for (const typed of [code, code.toLowerCase(), code.slice(3), code.replace(/-/g, ""), ` ${code} `]) assert.ok(tokens.matches(binding(), typed), typed);
    const others: Array<Partial<TokenBinding>> = [
      { id: "ap-0000abce" },
      { server: "other" },
      { tool: "delete_folder" },
      { argsHash: hashArguments({ path: "notes/new.md" }) },
      { agent: "beta" },
      { expiresAt: "2026-11-05T09:00:00.000Z" },
      { nonce: "nc-000000000000000000000002" },
    ];
    for (const over of others) assert.equal(tokens.matches(binding(over), code), false, JSON.stringify(over));
    assert.equal(tokens.matches(binding(), "at-0000-0000"), false);
    assert.equal(tokens.matches(binding(), ""), false);
  });

  it("verifies a proof only for its binding and only under its key", () => {
    const tokens = new ActionTokens(path.join(dir, "k"));
    const proof = tokens.proof(binding());
    assert.match(proof, /^[0-9a-f]{64}$/);
    assert.equal(tokens.verify(binding(), proof), true);
    assert.equal(tokens.verify(binding({ argsHash: hashArguments({ path: "notes/new.md" }) }), proof), false);
    assert.equal(tokens.verify(binding({ expiresAt: "2026-12-04T09:00:00.000Z" }), proof), false, "a record given a longer life");
    assert.equal(tokens.verify(binding(), undefined), false);
    assert.equal(tokens.verify(binding(), "ff".repeat(32)), false);
    assert.equal(new ActionTokens(path.join(dir, "another-key")).verify(binding(), proof), false, "another key");
    assert.equal(new ActionTokens(path.join(dir, "no-key-yet")).verify(binding(), proof), false, "no key: nothing verifies");
  });

  it("reads the spent nonces from the audit log: forwarded call lines only", () => {
    const file = path.join(dir, "audit.jsonl");
    assert.deepEqual([...spentNonces(file)], [], "no log yet");
    fs.writeFileSync(file, [JSON.stringify({ forwarded: true, nonce: "nc-a" }), JSON.stringify({ forwarded: false, nonce: "nc-b" }), "not json", JSON.stringify({ forwarded: true, nonce: "nc-c" })].join("\n"));
    assert.deepEqual([...spentNonces(file)].sort(), ["nc-a", "nc-c"]);
  });
});

describe("policy: irreversible rules", () => {
  const rules = (list: unknown[]) => parsePolicy({ default: "allow", rules: list });

  it("marks the asks of an irreversible rule, and of a shell rule that says so", () => {
    const policy = rules([
      { id: "shell", type: "shell", tool: "run_command", irreversible: true },
      { id: "delete", toolWords: ["delete"], decision: "ask", why: "deletes", irreversible: true },
    ]);
    assert.equal(evaluate(policy, { server: "s", tool: "delete_file", args: {} }).irreversible, true);
    assert.equal(evaluate(policy, { server: "s", tool: "run_command", args: { command: "git push origin main" } }).irreversible, true);
    assert.equal(evaluate(policy, { server: "s", tool: "run_command", args: { command: "ls" } }).irreversible, undefined, "a pass is not asked about");
  });

  it("refuses irreversible on a rule that does not ask, with standing, on a rewrite, or as anything but true or false", () => {
    assert.throws(() => rules([{ id: "r", decision: "block", why: "w", irreversible: true }]), /irreversible only applies to a rule whose decision is ask/);
    assert.throws(() => rules([{ id: "r", decision: "ask", why: "w", irreversible: true, standing: true }]), /cannot be both irreversible and standing/);
    assert.throws(() => rules([{ id: "r", decision: "rewrite", why: "w", rewrite: { drop: ["x"] }, irreversible: true }]), /irreversible does not apply to a rewrite rule/);
    assert.throws(() => rules([{ id: "r", decision: "ask", why: "w", irreversible: "yes" }]), /irreversible must be true or false/);
  });

  it("sticks: a later irreversible rule makes an ask irreversible and takes its standing approvals away", () => {
    const policy = rules([
      { id: "sql-write", args: { sql: { regex: "drop", flags: "i" } }, decision: "ask", why: "sql", standing: true },
      { id: "drop", toolWords: ["execute sql"], decision: "ask", why: "can drop a table", irreversible: true },
    ]);
    const verdict = evaluate(policy, { server: "db", tool: "execute_sql", args: { sql: "DROP TABLE events" } });
    assert.deepEqual([verdict.rule, verdict.irreversible, verdict.standing], ["sql-write", true, undefined]);
  });

  it("finds the irreversible rule that decides every call to a tool in the example policy", () => {
    const example = loadPolicy(path.join(ROOT, "policy.example.json"));
    assert.equal(irreversibleRuleFor(example, "demo", "delete_file"), "red-line-4-delete");
    assert.equal(irreversibleRuleFor(example, "demo", "deploy"), "red-line-3-ship");
    assert.equal(irreversibleRuleFor(example, "demo", "execute_sql"), undefined, "sql-write decides by its arguments");
    assert.equal(irreversibleRuleFor(example, "demo", "echo"), undefined);
  });
});

describe("the approval store: an irreversible call's approval", () => {
  const TTL = 60 * 60 * 1000;
  let dir: string;
  let now: number;
  let store: ApprovalStore;
  let tokens: ActionTokens;
  let spent: Set<string>;
  let check: TokenCheck;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-irreversible-"));
    now = Date.parse("2026-11-03T09:00:00.000Z");
    store = new ApprovalStore(dir, TTL, () => now);
    tokens = new ActionTokens(path.join(dir, "action-token.key"));
    spent = new Set();
    check = { verify: (a) => tokens.verify(a as TokenBinding, a.tokenProof), spent: (id) => spent.has(id) };
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  const ask = (args: Record<string, unknown>, extra: Partial<AskRequest> = {}): AskRequest => ({
    server: "demo",
    tool: "delete_file",
    args,
    argsHash: hashArguments(args),
    rule: "red-line-4-delete",
    why: "Red line 4",
    irreversible: check,
    ...extra,
  });
  const prove = (a: Approval) => tokens.proof(a as TokenBinding);
  /** Asks, approves with the token's proof, and returns the request. */
  const approved = (args: Record<string, unknown>): Approval => {
    const first = store.resolveCall(ask(args));
    assert.equal(first.kind, "pending");
    const a = (first as { approval: Approval }).approval;
    store.approve(a.id, { confirmation: "token", prove });
    return a;
  };

  it("queues a request with a nonce, and approves it only with the proof", () => {
    const first = store.resolveCall(ask({ path: "a.md" }));
    assert.equal(first.kind, "pending");
    const a = (first as { approval: Approval }).approval;
    assert.deepEqual([a.irreversible, /^nc-[0-9a-f]{24}$/.test(a.nonce ?? "")], [true, true]);
    assert.throws(() => store.approve(a.id, { confirmation: "--yes" }), (err: unknown) => err instanceof ApprovalError && /needs its action token, not only a yes/.test(err.message));
    assert.equal(store.get(a.id).status, "pending");
    const yes = store.approve(a.id, { confirmation: "token", prove });
    assert.equal(tokens.verify(yes as TokenBinding, yes.tokenProof), true);
  });

  it("lets the approved call through once, with its nonce", () => {
    const a = approved({ path: "a.md" });
    const used = store.resolveCall(ask({ path: "a.md" }));
    assert.deepEqual([used.kind, used.kind === "approved" && used.approval.nonce], ["approved", a.nonce]);
  });

  it("reuse: the same call after its approval was used is refused as used, and waits for a new yes", () => {
    const a = approved({ path: "a.md" });
    store.resolveCall(ask({ path: "a.md" }));
    const again = store.resolveCall(ask({ path: "a.md" }));
    assert.equal(again.kind, "pending");
    assert.deepEqual(again.kind === "pending" && [again.refused?.reason, again.refused?.approval.id, again.created], ["used", a.id, true]);
  });

  it("expiry: an approval past its life is refused as expired", () => {
    const a = approved({ path: "a.md" });
    now += TTL + 1;
    const late = store.resolveCall(ask({ path: "a.md" }));
    assert.deepEqual(late.kind === "pending" && [late.refused?.reason, late.refused?.approval.id], ["expired", a.id]);
  });

  it("wrong arguments: an approval of other arguments covers nothing else, and still covers its own call", () => {
    const a = approved({ path: "a.md" });
    const other = store.resolveCall(ask({ path: "everything/" }));
    assert.deepEqual(other.kind === "pending" && [other.refused?.reason, other.refused?.approval.id], ["wrong-arguments", a.id]);
    assert.equal(store.resolveCall(ask({ path: "a.md" })).kind, "approved");
  });

  it("forged: an approval without a valid proof is refused as invalid and goes stale", () => {
    const first = store.resolveCall(ask({ path: "a.md" }));
    const a = (first as { approval: Approval }).approval;
    // What an agent that can write approvals.json, but not read the key, could do.
    const file = JSON.parse(fs.readFileSync(store.file, "utf8"));
    Object.assign(file.approvals[0], { status: "approved", confirmation: "--yes", tokenProof: "ab".repeat(32) });
    fs.writeFileSync(store.file, JSON.stringify(file));
    const forged = store.resolveCall(ask({ path: "a.md" }));
    assert.deepEqual(forged.kind === "pending" && [forged.refused?.reason, forged.refused?.approval.id], ["invalid", a.id]);
    assert.equal(store.get(a.id).status, "stale");
  });

  it("replay: an approval whose token was spent is refused as replayed, even with a valid proof", () => {
    const a = approved({ path: "a.md" });
    const snapshot = fs.readFileSync(store.file, "utf8");
    assert.equal(store.resolveCall(ask({ path: "a.md" })).kind, "approved");
    spent.add(a.nonce as string); // the gateway's memory of spent tokens
    fs.writeFileSync(store.file, snapshot); // the old file, put back
    const replayed = store.resolveCall(ask({ path: "a.md" }));
    assert.deepEqual(replayed.kind === "pending" && [replayed.refused?.reason, replayed.refused?.approval.id], ["replayed", a.id]);
  });

  it("a nonce the gateway did not make is never verified or spent: the approval is refused as invalid", () => {
    // Written into a pending record before the human's yes, so that the proof is made over it: a nonce
    // that cannot be remembered as spent ("", 0, false, an object) would let one yes through again and again.
    for (const nonce of ["", 0, false, {}, "tk-000000000000000000000001"]) {
      const args = { path: `odd-${JSON.stringify(nonce)}.md` };
      const a = approved(args);
      const file = JSON.parse(fs.readFileSync(store.file, "utf8"));
      const record = file.approvals.find((r: Approval) => r.id === a.id);
      record.nonce = nonce;
      record.tokenProof = tokens.proof(record as TokenBinding);
      fs.writeFileSync(store.file, JSON.stringify(file));
      const out = store.resolveCall(ask(args));
      assert.deepEqual(out.kind === "pending" && out.refused?.reason, "invalid", JSON.stringify(nonce));
    }
  });

  it("bound files are part of the token: a file hash written into the record after the yes does not match", () => {
    const files = (sha256: string) => [{ argument: "path", path: "/work/report.txt", sha256 }];
    const first = store.resolveCall(ask({ path: "/work/report.txt" }, { files: files("sha256:aaa") }));
    store.approve((first as { approval: Approval }).approval.id, { confirmation: "token", prove });
    // The file changes after the yes, and something edits the record's hash to match the new content.
    const file = JSON.parse(fs.readFileSync(store.file, "utf8"));
    file.approvals[0].files = files("sha256:bbb");
    fs.writeFileSync(store.file, JSON.stringify(file));
    const out = store.resolveCall(ask({ path: "/work/report.txt" }, { files: files("sha256:bbb") }));
    assert.deepEqual(out.kind === "pending" && out.refused?.reason, "invalid");
  });

  it("a token spent through one gateway process is spent for every process on the state directory", () => {
    const a = approved({ path: "a.md" });
    const snapshot = fs.readFileSync(store.file, "utf8");
    assert.equal(store.resolveCall(ask({ path: "a.md" })).kind, "approved");
    assert.ok(JSON.parse(fs.readFileSync(store.spentFile, "utf8")).spent[a.nonce as string], "spent where every process looks");
    fs.writeFileSync(store.file, snapshot);
    // Another process: a store of its own, and nothing spent in its memory.
    const other = new ApprovalStore(dir, TTL, () => now);
    const replayed = other.resolveCall({ ...ask({ path: "a.md" }), irreversible: { verify: check.verify, spent: () => false } });
    assert.deepEqual(replayed.kind === "pending" && [replayed.refused?.reason, replayed.refused?.approval.id], ["replayed", a.id]);
  });

  it("a damaged spent-tokens file is an error, never an empty list", () => {
    const a = approved({ path: "a.md" });
    fs.writeFileSync(store.spentFile, "{ cut short");
    assert.throws(() => store.resolveCall(ask({ path: "a.md" })), /spent-tokens\.json is not valid JSON/);
    assert.equal(store.get(a.id).status, "approved", "nothing was changed or let through");
  });

  it("no standing approval answers an irreversible call, even under a rule that would allow one", () => {
    store.grant({ server: "demo", tool: "delete_file", args: {}, maxUses: 5, ttlMs: TTL });
    assert.equal(store.resolveCall(ask({ path: "a.md" }, { standing: true })).kind, "pending");
    const { irreversible: _drop, ...plain } = ask({ path: "b.md" }, { standing: true });
    assert.equal(store.resolveCall(plain).kind, "standing", "the same grant still answers a call that is not irreversible");
  });
});

describe("the CLI: confirming an irreversible request", () => {
  const TTL = 60 * 60 * 1000;
  let tmp: string;
  let config: string;
  let stateDir: string;

  before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-token-cli-"));
    stateDir = path.join(tmp, "state");
    config = path.join(tmp, "gateway.config.json");
    fs.writeFileSync(config, JSON.stringify({ servers: [{ name: "demo", command: "node" }], policy: path.join(ROOT, "policy.example.json"), stateDir: "state" }));
  });
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));

  const run = async (typed: string | undefined, ...argv: string[]) => {
    let out = "";
    let err = "";
    const code = await main([...argv, "--config", config], { out: (t) => (out += t), err: (t) => (err += t), readLine: async () => typed });
    return { code, out, err };
  };
  /** A request queued the way the gateway queues one for an irreversible rule, `when` ms from now. */
  const queued = (args: Record<string, unknown>, when = 0): Approval => {
    const tokens = new ActionTokens(path.join(stateDir, "action-token.key"));
    const check: TokenCheck = { verify: (a) => tokens.verify(a as TokenBinding, a.tokenProof), spent: () => false };
    const outcome = new ApprovalStore(stateDir, TTL, () => Date.now() + when).resolveCall({ server: "demo", tool: "delete_file", args, argsHash: hashArguments(args), rule: "red-line-4-delete", why: "Red line 4", irreversible: check });
    return (outcome as { approval: Approval }).approval;
  };
  const record = (id: string): Approval => new ApprovalStore(stateDir, TTL).get(id);
  const audit = (): Array<Record<string, any>> => (fs.existsSync(path.join(stateDir, "audit.jsonl")) ? readAudit(path.join(stateDir, "audit.jsonl")).lines.map((l) => l.value as Record<string, any>) : []);
  const tokenOf = async (id: string): Promise<string> => (JSON.parse((await run(undefined, "approvals", "show", id)).out) as { actionToken: string }).actionToken;

  it("--yes alone is refused and audited; the request stays pending", async () => {
    const a = queued({ path: "yes.md" });
    const r = await run(undefined, "approvals", "approve", a.id, "--yes");
    assert.equal(r.code, 1);
    assert.match(r.err, /is for an irreversible action \(rule red-line-4-delete\), so --yes is not enough/);
    assert.equal(record(a.id).status, "pending");
    assert.deepEqual(audit().at(-1), { ...audit().at(-1), event: "action-token-refused", approvalId: a.id, reason: "no-token", rule: "red-line-4-delete", argsHash: a.argsHash });
  });

  it("show prints the token for whoever can read the key; list says the request needs one", async () => {
    const a = queued({ path: "show.md" });
    assert.match(await tokenOf(a.id), /^at-[0-9A-Z]{4}-[0-9A-Z]{4}$/);
    assert.match((await run(undefined, "approvals", "list")).out, new RegExp(`${a.id}  pending  demo__delete_file\\n(?:.*\\n)*?  token:   irreversible: approve it with its action token`));
  });

  it("another request's token is refused as a mismatch, and audited", async () => {
    const a = queued({ path: "mine.md" });
    const b = queued({ path: "theirs.md" });
    const r = await run(undefined, "approvals", "approve", a.id, "--token", await tokenOf(b.id));
    assert.equal(r.code, 1);
    assert.match(r.err, /that is not the action token of ap-[0-9a-f]{8}, so it was not approved/);
    assert.deepEqual([audit().at(-1)?.event, audit().at(-1)?.reason, record(a.id).status], ["action-token-refused", "mismatch", "pending"]);
  });

  it("the read-back shows the token; the end of the id is no longer enough; the token approves", async () => {
    const a = queued({ path: "typed.md" });
    const token = await tokenOf(a.id);
    const idEnd = await run(a.id.slice(-4), "approvals", "approve", a.id);
    assert.equal(idEnd.code, 1);
    assert.match(idEnd.out, new RegExp(`^Approve this call\\? ${a.id}\\n(?:.*\\n)*  token:    ${token}\\nThis cannot be undone\\. Type the action token \\(${token}\\) to approve it`));
    const ok = await run(token, "approvals", "approve", a.id, "--note", "checked the path");
    assert.equal(ok.code, 0, ok.err);
    assert.deepEqual([record(a.id).status, record(a.id).confirmation, record(a.id).decisionNote], ["approved", "token", "checked the path"]);
    const decided = audit().filter((l) => l.event === "approval-decided" && l.approvalId === a.id);
    assert.deepEqual(decided.map((l) => [l.decision, l.confirmation]), [["approved", "token"]]);
  });

  it("a call changed between the read-back and the approval is not approved", async () => {
    const a = queued({ path: "read-back.md" });
    const token = await tokenOf(a.id);
    let out = "";
    let err = "";
    // While the human reads the call back, another writer of approvals.json swaps the call for another.
    const swap = async (): Promise<string> => {
      const file = path.join(stateDir, "approvals.json");
      const data = JSON.parse(fs.readFileSync(file, "utf8"));
      const record = data.approvals.find((r: Approval) => r.id === a.id);
      Object.assign(record, { args: { path: "everything/" }, argsHash: hashArguments({ path: "everything/" }) });
      fs.writeFileSync(file, JSON.stringify(data));
      return token;
    };
    const code = await main(["approvals", "approve", a.id, "--config", config], { out: (t) => (out += t), err: (t) => (err += t), readLine: swap });
    assert.equal(code, 1);
    assert.match(out, /"path": "read-back\.md"/, "the human read back the call as it was");
    assert.match(err, /changed after it was read back, so it was not approved/);
    assert.deepEqual([audit().at(-1)?.event, audit().at(-1)?.reason], ["action-token-refused", "changed"]);
    assert.equal(record(a.id).status, "pending");
    assert.equal(record(a.id).tokenProof, undefined);
  });

  /** Changes one request in approvals.json, as an agent that can write the file could. */
  const edit = (id: string, change: (r: Record<string, unknown>) => void): void => {
    const file = path.join(stateDir, "approvals.json");
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    change(data.approvals.find((r: Approval) => r.id === id));
    fs.writeFileSync(file, JSON.stringify(data));
  };

  it("a record whose nonce the gateway did not make shows no token and is not approved", async () => {
    const a = queued({ path: "odd-nonce.md" });
    edit(a.id, (r) => {
      r.nonce = "";
    });
    const shown = JSON.parse((await run(undefined, "approvals", "show", a.id)).out);
    assert.deepEqual([shown.actionToken, /nonce is not one the gateway makes/.test(shown.actionTokenError)], [null, true]);
    const r = await run(undefined, "approvals", "approve", a.id, "--token", "at-0000-0000");
    assert.equal(r.code, 1);
    assert.match(r.err, /nonce is not one the gateway makes/);
    assert.deepEqual([audit().at(-1)?.event, audit().at(-1)?.reason, record(a.id).status], ["action-token-refused", "changed", "pending"]);
  });

  it("a record that shows other arguments than its argsHash stands for shows no token and is not approved", async () => {
    // The agent asked to delete everything/, then made the record show a harmless path.
    const a = queued({ path: "everything/" });
    const token = await tokenOf(a.id);
    edit(a.id, (r) => {
      r.args = { path: "notes/old.md" };
    });
    const shown = JSON.parse((await run(undefined, "approvals", "show", a.id)).out);
    assert.equal(shown.actionToken, null);
    assert.match(shown.actionTokenError, /its arguments do not hash to its argsHash/);
    const r = await run(undefined, "approvals", "approve", a.id, "--token", token);
    assert.equal(r.code, 1);
    assert.match(r.err, /its arguments do not hash to its argsHash/);
    assert.deepEqual([audit().at(-1)?.event, audit().at(-1)?.reason, record(a.id).status], ["action-token-refused", "changed", "pending"]);
  });

  it("reuse: confirming the same request again with its right token is refused as used, and audited", async () => {
    const a = queued({ path: "twice.md" });
    const token = await tokenOf(a.id);
    assert.equal((await run(undefined, "approvals", "approve", a.id, "--token", token)).code, 0);
    const again = await run(undefined, "approvals", "approve", a.id, "--token", token);
    assert.equal(again.code, 1);
    assert.match(again.err, /is approved: its action token confirmed it once already/);
    assert.deepEqual([audit().at(-1)?.event, audit().at(-1)?.reason], ["action-token-refused", "used"]);
    assert.equal((await run(undefined, "approvals", "show", a.id)).out.includes("actionToken"), false, "no token is shown for a decided request");
  });

  it("expiry: an expired request is refused, and audited both ways", async () => {
    const a = queued({ path: "late.md" }, -2 * TTL);
    const r = await run(undefined, "approvals", "approve", a.id, "--token", "at-0000-0000");
    assert.equal(r.code, 1);
    assert.match(r.err, /expired at/);
    assert.deepEqual(
      audit()
        .slice(-2)
        .map((l) => [l.event, l.decision ?? l.reason]),
      [
        ["approval-decided", "expired"],
        ["action-token-refused", "expired"],
      ],
    );
  });

  it("a CLI that cannot read the key cannot approve, as an agent's sandboxed shell cannot", async () => {
    const elsewhere = path.join(tmp, "unreadable.config.json");
    const keyDir = path.join(tmp, "not-a-key-file");
    fs.mkdirSync(keyDir);
    fs.writeFileSync(elsewhere, JSON.stringify({ servers: [{ name: "demo", command: "node" }], policy: path.join(ROOT, "policy.example.json"), stateDir: "state", actionTokenKeyFile: keyDir }));
    const a = queued({ path: "sandboxed.md" });
    let err = "";
    const code = await main(["approvals", "approve", a.id, "--token", "at-0000-0000", "--config", elsewhere], { out: () => undefined, err: (t) => (err += t) });
    assert.equal(code, 1);
    assert.match(err, /needs the gateway's key, which cannot be used here/);
    assert.deepEqual([audit().at(-1)?.event, audit().at(-1)?.reason, record(a.id).status], ["action-token-refused", "no-key", "pending"]);
  });

  it("--token on a request that has none is a usage error", async () => {
    const plain = new ApprovalStore(stateDir, TTL).resolveAsk({ server: "demo", tool: "echo", args: { text: "x" }, argsHash: hashArguments({ text: "x" }), rule: "r", why: "w" }).approval;
    assert.equal((await run(undefined, "approvals", "approve", plain.id, "--token", "at-0000-0000")).code, 2);
  });

  it("refuses a standing approval for a tool that is irreversible on every call; allows one where arguments decide", async () => {
    const del = await run(undefined, "approvals", "grant", "demo__delete_file", "--uses", "5", "--hours", "1");
    assert.equal(del.code, 1);
    assert.match(del.err, /every call to demo__delete_file is decided by rule red-line-4-delete, which is irreversible/);
    assert.equal((await run(undefined, "approvals", "grant", "demo__execute_sql", "--arg", "sql=INSERT INTO events*", "--uses", "5", "--hours", "1")).code, 0);
  });

  it("never writes a token to the audit log", () => {
    assert.equal(TOKEN.test(fs.readFileSync(path.join(stateDir, "audit.jsonl"), "utf8")), false);
  });
});

describe("a running gateway: irreversible calls end to end", () => {
  let tmp: string;
  let configFile: string;
  let stateDir: string;
  /** A gateway process, as an agent's MCP client starts one. Two can share a state directory. */
  interface Running {
    gateway: Gateway;
    client: Client;
  }
  let main1: Running;
  let second: Running;

  const start = async (): Promise<Running> => {
    const config = loadConfig(configFile);
    const gateway = await createGateway(config, loadPolicy(config.policyFile), () => undefined);
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await gateway.server.connect(serverSide);
    const client = new Client({ name: "token-e2e", version: "1.0.0" });
    await client.connect(clientSide);
    return { gateway, client };
  };
  const stop = async (r: Running | undefined): Promise<void> => {
    await r?.client.close();
    await r?.gateway.close();
  };

  before(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-token-e2e-"));
    stateDir = path.join(tmp, "state");
    configFile = path.join(tmp, "gateway.config.json");
    fs.writeFileSync(configFile, JSON.stringify({ servers: [{ name: "demo", command: process.execPath, args: [FAKE] }], policy: path.join(ROOT, "policy.example.json"), stateDir: "state" }));
    main1 = await start();
    second = await start(); // started before any token is spent: it can learn of one only from the shared file
  });
  after(async () => {
    await stop(main1);
    await stop(second);
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const quiet = { out: () => undefined, err: () => undefined };
  const idIn = (text: string): string => /Approval id: (ap-[0-9a-f]{8})/.exec(text)?.[1] ?? assert.fail(text);
  /** Every token the human was shown, to look for afterwards in everything the agent read. */
  const shownTokens: string[] = [];
  const approve = async (id: string): Promise<void> => {
    let shown = "";
    await main(["approvals", "show", id, "--config", configFile], { out: (t) => (shown += t), err: () => undefined });
    const token = (JSON.parse(shown) as { actionToken: string }).actionToken;
    shownTokens.push(token);
    assert.equal(await main(["approvals", "approve", id, "--token", token, "--config", configFile], quiet), 0);
  };
  const lines = () => readAudit(path.join(stateDir, "audit.jsonl")).lines.map((l) => l.value as Record<string, any>).filter((l) => l.event === undefined);
  const approvalsFile = () => path.join(stateDir, "approvals.json");
  const texts: string[] = [];
  const said = async (args: Record<string, unknown>, through: Running = main1): Promise<string> => {
    const result = (await through.client.callTool({ name: "demo__delete_file", arguments: args })) as CallToolResult;
    const text = (result.content[0] as { text: string }).text;
    texts.push(text);
    return text;
  };

  let firstId = "";
  let snapshot = "";
  it("asks, tells the agent a token is needed without giving one, and runs once after the token", async () => {
    // A policy with irreversible rules: the key exists from the gateway's first start, private.
    const keyFile = path.join(stateDir, "action-token.key");
    assert.ok(fs.existsSync(keyFile), "the key is made when the gateway starts");
    if (process.platform !== "win32") assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600);
    const held = await said({ path: "notes/a.md" });
    firstId = idIn(held);
    assert.match(held, /This action cannot be undone: the human confirms it at the CLI with an action token that is never shown to you\./);
    await approve(firstId);
    snapshot = fs.readFileSync(approvalsFile(), "utf8"); // approved, not used yet
    assert.equal(await said({ path: "notes/a.md" }), "pretended to delete notes/a.md");
    const ran = lines().at(-1);
    assert.deepEqual([ran?.forwarded, ran?.approvalId, /^nc-[0-9a-f]{24}$/.test(ran?.nonce ?? "")], [true, firstId, true]);
  });

  it("reuse and other arguments are refused and audited", async () => {
    const reused = await said({ path: "notes/a.md" });
    assert.match(reused, new RegExp(`^agent-gate: the approval of this exact call \\(${firstId}\\) was used already`));
    assert.deepEqual([lines().at(-1)?.tokenRefused, lines().at(-1)?.refusedApprovalId], ["used", firstId]);
    const pendingId = idIn(reused);
    await approve(pendingId);
    const stretched = await said({ path: "notes/" });
    assert.match(stretched, new RegExp(`^agent-gate: ${pendingId} approved this tool with other arguments`));
    assert.deepEqual([lines().at(-1)?.tokenRefused, lines().at(-1)?.refusedApprovalId, lines().at(-1)?.forwarded], ["wrong-arguments", pendingId, false]);
  });

  it("a forged approval is refused as invalid", async () => {
    const id = idIn(await said({ path: "notes/forged.md" }));
    const file = JSON.parse(fs.readFileSync(approvalsFile(), "utf8"));
    const forged = file.approvals.find((a: Approval) => a.id === id);
    Object.assign(forged, { status: "approved", confirmation: "typed" });
    fs.writeFileSync(approvalsFile(), JSON.stringify(file));
    assert.match(await said({ path: "notes/forged.md" }), new RegExp(`^agent-gate: the approval of this call \\(${id}\\) carries no valid action token`));
    assert.deepEqual([lines().at(-1)?.tokenRefused, lines().at(-1)?.forwarded], ["invalid", false]);
  });

  it("a replayed approval is refused: by the process that spent it, by another process, and after a restart", async () => {
    const replayedText = new RegExp(`^agent-gate: the action token of ${firstId} let a call through already`);
    fs.writeFileSync(approvalsFile(), snapshot); // approvals.json as it was before the first call ran
    assert.match(await said({ path: "notes/a.md" }), replayedText);
    assert.deepEqual([lines().at(-1)?.tokenRefused, lines().at(-1)?.forwarded], ["replayed", false]);
    // A second gateway process on the same state directory, started before the token was spent.
    fs.writeFileSync(approvalsFile(), snapshot);
    assert.match(await said({ path: "notes/a.md" }, second), replayedText);
    // After a restart, even with the shared spent-tokens file gone, the audit log read at startup knows it.
    await stop(main1);
    fs.rmSync(path.join(stateDir, "spent-tokens.json"));
    main1 = await start();
    fs.writeFileSync(approvalsFile(), snapshot);
    assert.match(await said({ path: "notes/a.md" }), /let a call through already; an old confirmation cannot be used again/);
    assert.equal(lines().filter((l) => l.forwarded && l.tool === "delete_file").length, 1, "notes/a.md ran once in all");
  });

  it("a standing approval written straight into the store does not let an irreversible call through", async () => {
    new ApprovalStore(stateDir, 60 * 60 * 1000).grant({ server: "demo", tool: "delete_file", args: {}, maxUses: 10, ttlMs: 60 * 60 * 1000 });
    assert.match(await said({ path: "notes/granted.md" }), /^agent-gate: this call needs a human decision/);
  });

  it("the agent never saw a token, the log holds none, and audit verify passes", () => {
    const squash = (text: string) => text.toUpperCase().replace(/[^0-9A-Z]/g, "");
    const log = fs.readFileSync(path.join(stateDir, "audit.jsonl"), "utf8");
    assert.ok(shownTokens.length >= 2);
    for (const text of [...texts, log]) {
      assert.equal(TOKEN.test(text), false, text);
      for (const token of shownTokens) assert.equal(squash(text).includes(squash(token).slice(2)), false, `${token} in: ${text.slice(0, 200)}`);
    }
    assert.deepEqual(verifyAudit(readAudit(path.join(stateDir, "audit.jsonl")), new ApprovalStore(stateDir, 1).list()), []);
  });
});

describe("a running gateway: a standing rule and an irreversible rule on the same call", () => {
  let tmp: string;
  let configFile: string;
  let gateway: Gateway;
  let client: Client;

  before(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-token-standing-"));
    configFile = path.join(tmp, "gateway.config.json");
    // sql-write decides first and accepts standing approvals; a DROP also matches the irreversible rule after it.
    fs.writeFileSync(
      path.join(tmp, "policy.json"),
      JSON.stringify({
        default: "allow",
        rules: [
          { id: "sql-write", args: { sql: { regex: "\\b(?:insert|drop)\\b", flags: "i" } }, decision: "ask", why: "This SQL changes data.", standing: true },
          { id: "sql-drop", args: { sql: { regex: "\\bdrop\\b", flags: "i" } }, decision: "ask", why: "Dropping a table cannot be undone.", irreversible: true },
        ],
      }),
    );
    fs.writeFileSync(configFile, JSON.stringify({ servers: [{ name: "demo", command: process.execPath, args: [FAKE] }], policy: "policy.json", stateDir: "state" }));
    const config = loadConfig(configFile);
    gateway = await createGateway(config, loadPolicy(config.policyFile), () => undefined);
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await gateway.server.connect(serverSide);
    client = new Client({ name: "token-standing", version: "1.0.0" });
    await client.connect(clientSide);
  });
  after(async () => {
    await client?.close();
    await gateway?.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("the grant covers the writes it was made for, and never a call an irreversible rule also asks about", async () => {
    const quiet = { out: () => undefined, err: () => undefined };
    assert.equal(await main(["approvals", "grant", "demo__execute_sql", "--arg", "sql=*", "--uses", "5", "--hours", "1", "--config", configFile], quiet), 0);
    const call = async (statement: string): Promise<string> => {
      const result = (await client.callTool({ name: "demo__execute_sql", arguments: { sql: statement } })) as CallToolResult;
      return (result.content[0] as { text: string }).text;
    };
    assert.equal(await call("INSERT INTO events VALUES (1)"), "pretended to run: INSERT INTO events VALUES (1)", "the standing approval answers");
    const drop = await call("DROP TABLE events");
    assert.match(drop, /^agent-gate: this call needs a human decision, so it was not run\.\nReason: This SQL changes data\. \(rule sql-write\)/);
    assert.match(drop, /This action cannot be undone/);
  });
});
