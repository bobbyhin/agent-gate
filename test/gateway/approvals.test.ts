// Tests for the approval store, with a clock the test controls.
import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { ApprovalError, ApprovalStore, canonicalJson, hashArguments, type AskRequest } from "../../src/gateway/approvals.js";

const HOUR = 60 * 60 * 1000;
const TTL = 24 * HOUR;

function request(args: Record<string, unknown>, tool = "delete_file"): AskRequest {
  return { server: "demo", tool, args, argsHash: hashArguments(args), rule: "red-line-4-delete", why: "Red line 4" };
}

describe("canonical arguments", () => {
  it("ignores key order at every level but keeps array order", () => {
    assert.equal(canonicalJson({ b: 1, a: { d: [2, 1], c: null } }), '{"a":{"c":null,"d":[2,1]},"b":1}');
    assert.equal(hashArguments({ a: 1, b: { c: 2, d: 3 } }), hashArguments({ b: { d: 3, c: 2 }, a: 1 }));
    assert.notEqual(hashArguments({ list: [1, 2] }), hashArguments({ list: [2, 1] }));
  });

  it("changes when any value changes", () => {
    assert.match(hashArguments({ path: "a.txt" }), /^sha256:[0-9a-f]{64}$/);
    assert.notEqual(hashArguments({ path: "a.txt" }), hashArguments({ path: "b.txt" }));
    assert.notEqual(hashArguments({ n: 1 }), hashArguments({ n: "1" }));
  });
});

describe("ApprovalStore", () => {
  let dir: string;
  let now: number;
  let store: ApprovalStore;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-approvals-"));
    now = Date.parse("2026-10-14T06:00:00.000Z");
    store = new ApprovalStore(dir, TTL, () => now);
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("queues a call once, approves it, lets it through exactly once, then asks again", () => {
    const first = store.resolveAsk(request({ path: "a.txt" }));
    assert.equal(first.kind, "pending");
    assert.equal(first.kind === "pending" && first.created, true);
    assert.match(first.approval.id, /^ap-[0-9a-f]{8}$/);
    assert.equal(first.approval.expiresAt, new Date(now + TTL).toISOString());

    const again = store.resolveAsk(request({ path: "a.txt" }));
    assert.deepEqual([again.kind, again.kind === "pending" && again.created, again.approval.id], ["pending", false, first.approval.id]);

    store.approve(first.approval.id);
    const used = store.resolveAsk(request({ path: "a.txt" }));
    assert.deepEqual([used.kind, used.approval.id, used.approval.status], ["approved", first.approval.id, "used"]);

    const next = store.resolveAsk(request({ path: "a.txt" }));
    assert.equal(next.kind, "pending");
    assert.notEqual(next.approval.id, first.approval.id);
  });

  it("binds an approval to the exact server, tool and arguments", () => {
    const pending = store.resolveAsk(request({ path: "a.txt" }));
    store.approve(pending.approval.id);
    assert.equal(store.resolveAsk(request({ path: "b.txt" })).kind, "pending");
    assert.equal(store.resolveAsk(request({ path: "a.txt" }, "remove_file")).kind, "pending");
    assert.equal(store.resolveAsk({ ...request({ path: "a.txt" }), server: "other" }).kind, "pending");
    assert.equal(store.resolveAsk(request({ path: "a.txt" })).kind, "approved");
  });

  it("never lets a denied call through, and does not re-queue it until the denial expires", () => {
    const pending = store.resolveAsk(request({ path: "a.txt" }));
    store.deny(pending.approval.id);
    for (let i = 0; i < 3; i++) {
      const outcome = store.resolveAsk(request({ path: "a.txt" }));
      assert.deepEqual([outcome.kind, outcome.approval.id], ["denied", pending.approval.id]);
    }
    assert.equal(store.list().length, 1);
    assert.throws(() => store.approve(pending.approval.id), ApprovalError);

    now += TTL;
    const fresh = store.resolveAsk(request({ path: "a.txt" }));
    assert.equal(fresh.kind, "pending");
    assert.notEqual(fresh.approval.id, pending.approval.id);
  });

  it("can take back an approval before it is used", () => {
    const pending = store.resolveAsk(request({ path: "a.txt" }));
    store.approve(pending.approval.id);
    store.deny(pending.approval.id);
    assert.equal(store.resolveAsk(request({ path: "a.txt" })).kind, "denied");
  });

  it("expires requests after the TTL: they cannot be approved and never allow a call", () => {
    const stale = store.resolveAsk(request({ path: "old.txt" }));
    now += TTL;
    assert.throws(() => store.approve(stale.approval.id), /expired at/);

    const approved = store.resolveAsk(request({ path: "a.txt" }));
    store.approve(approved.approval.id);
    now += TTL;
    const after = store.resolveAsk(request({ path: "a.txt" }));
    assert.equal(after.kind, "pending");
    assert.notEqual(after.approval.id, approved.approval.id);
    assert.equal(store.get(approved.approval.id).status, "approved", "the expired approval was not used");
  });

  it("refuses ids that do not exist or are already used", () => {
    assert.throws(() => store.approve("ap-00000000"), /no approval with id ap-00000000/);
    assert.throws(() => store.deny("ap-00000000"), ApprovalError);
    const pending = store.resolveAsk(request({ path: "a.txt" }));
    store.approve(pending.approval.id);
    store.resolveAsk(request({ path: "a.txt" }));
    assert.throws(() => store.approve(pending.approval.id), /is used/);
    assert.throws(() => store.deny(pending.approval.id), /is used/);
  });

  it("writes a private, versioned file atomically and leaves no temporary files", () => {
    store.resolveAsk(request({ path: "a.txt" }));
    assert.deepEqual(fs.readdirSync(dir), ["approvals.json"]);
    const file = JSON.parse(fs.readFileSync(store.file, "utf8"));
    assert.equal(file.version, 1);
    assert.equal(file.approvals.length, 1);
    assert.deepEqual(file.approvals[0].args, { path: "a.txt" });
    if (process.platform !== "win32") assert.equal(fs.statSync(store.file).mode & 0o777, 0o600);
  });

  it("fails closed on a damaged file instead of starting from an empty queue", () => {
    fs.writeFileSync(store.file, "{ not json");
    assert.throws(() => store.resolveAsk(request({ path: "a.txt" })), /not valid JSON/);
    assert.equal(fs.readFileSync(store.file, "utf8"), "{ not json");
    fs.writeFileSync(store.file, JSON.stringify({ version: 99, approvals: [] }));
    assert.throws(() => store.list(), /not a version 1 approvals file/);
  });

  it("drops records a week after they expire", () => {
    const old = store.resolveAsk(request({ path: "old.txt" }));
    now += TTL + 7 * 24 * HOUR;
    store.resolveAsk(request({ path: "new.txt" }));
    assert.deepEqual(
      store.list().map((a) => a.args.path),
      ["new.txt"],
    );
    assert.throws(() => store.get(old.approval.id), /no approval/);
  });

  it("breaks a lock left behind by a crashed process", () => {
    const lock = path.join(dir, "approvals.lock");
    fs.mkdirSync(lock);
    const minuteAgo = new Date(Date.now() - 60_000);
    fs.utimesSync(lock, minuteAgo, minuteAgo);
    assert.equal(store.resolveAsk(request({ path: "a.txt" })).kind, "pending");
    assert.equal(fs.existsSync(lock), false);
  });
});
