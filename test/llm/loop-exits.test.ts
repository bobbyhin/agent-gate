// A loop's three exits and its hard cap: SHIP when a round's score reaches runShipScore, STOP on
// budget (scored rounds, seconds, tokens, calls, dollars), STOP on a flat line (runFlatRounds rounds
// without a gain); a client may lower its run's limits with x-run-budget, never raise them; a run that
// stopped stays stopped; and every stop is a usage line with its exit, rule and reason.
import { after, before, beforeEach, afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Ledger, overCaps, parseRunBudget, runLimits, RUN_MEMORY_MS, type ReserveOutcome, type ScoreOutcome } from "../../src/llm/budget.js";
import { hashKey, parseLlmConfig, type GatewayKey } from "../../src/llm/config.js";
import { parseLeakPolicy } from "../../src/llm/leak-guard.js";
import { startLlmGateway, type LlmGateway } from "../../src/llm/server.js";
import { groupUsage, readUsageLog } from "../../src/llm/usage-report.js";
import { FAKE_GATEWAY_KEYS } from "./fake-secrets.js";
import { startFakeUpstream, type FakeUpstream } from "./fake-upstream.js";

const refused = (outcome: ReserveOutcome): Extract<ReserveOutcome, { ok: false }> => {
  assert.equal(outcome.ok, false, JSON.stringify(outcome));
  return outcome as Extract<ReserveOutcome, { ok: false }>;
};
const admitted = (outcome: ReserveOutcome): string => {
  assert.equal(outcome.ok, true, JSON.stringify(outcome));
  return (outcome as Extract<ReserveOutcome, { ok: true }>).id;
};

describe("x-run-budget: what a run may declare for itself", () => {
  it("reads any of calls, rounds, seconds, tokens and usd, each once", () => {
    assert.deepEqual(parseRunBudget("calls=12, rounds=4, seconds=600, tokens=50000, usd=0.25"), { calls: 12, rounds: 4, seconds: 600, tokens: 50000, usd: 0.25 });
    assert.deepEqual(parseRunBudget("rounds = 3"), { rounds: 3 });
  });

  it("refuses anything else, so a budget that cannot be read is never silently dropped", () => {
    for (const bad of ["", "calls", "calls=0", "calls=1.5", "usd=0", "price=1", "calls=1, calls=2", "calls=-1", "calls=1,", "calls=99999999999", "calls=1;rounds=2"]) {
      assert.ok("error" in parseRunBudget(bad), `accepted ${JSON.stringify(bad)}`);
    }
  });
});

describe("loop exits in the config", () => {
  const config = (extra: Record<string, unknown>) => ({
    stateDir: "s",
    policy: "p",
    upstreams: [{ name: "u", baseUrl: "http://127.0.0.1:9/v1", apiKeyEnv: "K", models: { m: "m" }, pricePerMTok: { input: 1, output: 1 } }],
    routes: [{ id: "r", use: { upstream: "u" } }],
    keys: [{ name: "k", sha256: "a".repeat(64), dailyUsd: 1, monthlyUsd: 1, ...extra }],
  });

  it("takes the new limits and exits on a key", () => {
    const key = parseLlmConfig(config({ runMaxSeconds: 600, runMaxTokens: 50_000, runMaxRounds: 4, runShipScore: 0.9, runFlatRounds: 2, runMinGain: 0.01 }), "/").keys[0];
    assert.deepEqual(
      [key?.runMaxSeconds, key?.runMaxTokens, key?.runMaxRounds, key?.runShipScore, key?.runFlatRounds, key?.runMinGain],
      [600, 50_000, 4, 0.9, 2, 0.01],
    );
  });

  it("refuses limits out of range, a score that is not a number, and a gain without a flat line", () => {
    assert.throws(() => parseLlmConfig(config({ runMaxSeconds: 0 }), "/"), /runMaxSeconds must be a whole number from 1 to 86400/);
    assert.throws(() => parseLlmConfig(config({ runMaxSeconds: 86_401 }), "/"), /runMaxSeconds must be a whole number from 1 to 86400/);
    assert.throws(() => parseLlmConfig(config({ runMaxTokens: 0 }), "/"), /runMaxTokens must be a whole number/);
    assert.throws(() => parseLlmConfig(config({ runMaxRounds: 1.5 }), "/"), /runMaxRounds must be a whole number/);
    assert.throws(() => parseLlmConfig(config({ runShipScore: "0.9" }), "/"), /runShipScore must be a number/);
    assert.throws(() => parseLlmConfig(config({ runFlatRounds: 0 }), "/"), /runFlatRounds must be a whole number from 1 to 100/);
    assert.throws(() => parseLlmConfig(config({ runFlatRounds: 2, runMinGain: -0.1 }), "/"), /runMinGain must be a number, 0 or more/);
    assert.throws(() => parseLlmConfig(config({ runMinGain: 0.1 }), "/"), /runMinGain only applies with runFlatRounds/);
  });
});

describe("the ledger: run limits, a run's own budget, and score decisions", () => {
  const BASE: GatewayKey = { name: "team-a", sha256: "a".repeat(64), dailyUsd: 10, monthlyUsd: 100 };
  const TTL = 5 * 60 * 1000;
  let dir: string;
  let now: number;
  let ledger: Ledger;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-loop-ledger-"));
    now = Date.parse("2026-11-03T09:00:00.000Z");
    ledger = new Ledger(dir, TTL, () => now);
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("runMaxSeconds counts from the run's first call; a call at the limit is refused", () => {
    const key: GatewayKey = { ...BASE, runMaxSeconds: 60 };
    admitted(ledger.reserve(key, 0.01, "timed"));
    now += 59_000;
    admitted(ledger.reserve(key, 0.01, "timed"));
    now += 1_000;
    assert.deepEqual(refused(ledger.reserve(key, 0.01, "timed")), { ok: false, cap: "runMaxSeconds", runId: "timed", limit: 60, seconds: 60 });
    admitted(ledger.reserve(key, 0.01, "another-run"));
  });

  it("runMaxTokens holds booked tokens, what calls in flight hold, and this call's estimate", () => {
    const key: GatewayKey = { ...BASE, runMaxTokens: 300 };
    ledger.settle(key.name, admitted(ledger.reserve(key, 0.01, "metered", { tokens: 150 })), 0.01, 110);
    admitted(ledger.reserve(key, 0.01, "metered", { tokens: 100 })); // in flight
    assert.deepEqual(refused(ledger.reserve(key, 0.01, "metered", { tokens: 100 })), {
      ok: false,
      cap: "runMaxTokens",
      runId: "metered",
      limit: 300,
      spentTokens: 110,
      reservedTokens: 100,
      requestedTokens: 100,
    });
    admitted(ledger.reserve(key, 0.01, "metered", { tokens: 90 })); // exactly 300: fits
  });

  it("a run's own budget lowers a cap; a later, higher declaration does not raise it back", () => {
    const key: GatewayKey = { ...BASE, runMaxCalls: 10 };
    admitted(ledger.reserve(key, 0.01, "self-limited", { budget: { calls: 2 } }));
    admitted(ledger.reserve(key, 0.01, "self-limited"));
    assert.deepEqual(refused(ledger.reserve(key, 0.01, "self-limited")), { ok: false, cap: "runMaxCalls", runId: "self-limited", limit: 2, calls: 2, declared: true });
    assert.equal(refused(ledger.reserve(key, 0.01, "self-limited", { budget: { calls: 9 } })).cap, "runMaxCalls", "it declared 2 before: 9 does not raise it");
  });

  it("a declaration above the key's cap changes nothing: the cap holds, and overCaps names the field", () => {
    const key: GatewayKey = { ...BASE, runMaxCalls: 3, runMaxSeconds: 60 };
    for (let i = 0; i < 3; i++) admitted(ledger.reserve(key, 0.01, "greedy", { budget: { calls: 1000, seconds: 30 } }));
    assert.deepEqual(refused(ledger.reserve(key, 0.01, "greedy", { budget: { calls: 1000 } })), { ok: false, cap: "runMaxCalls", runId: "greedy", limit: 3, calls: 3 });
    assert.deepEqual(overCaps(key, { calls: 1000, seconds: 30, tokens: 5 }), ["calls"], "seconds is lower than the cap; tokens has no cap to pass");
    assert.deepEqual(runLimits(key, { calls: 1000, seconds: 30 }), { calls: 3, seconds: 30, minGain: 0 });
  });

  it("a run with a declared budget is counted even on a key without run limits", () => {
    admitted(ledger.reserve(BASE, 0.01, "own-only", { budget: { calls: 1 } }));
    assert.equal(refused(ledger.reserve(BASE, 0.01, "own-only")).cap, "runMaxCalls", "the stored budget holds without the header");
    admitted(ledger.reserve(BASE, 0.01, "not-counted"));
  });

  it("a budget declared on a call that is refused still holds the run's next call", () => {
    const key: GatewayKey = { ...BASE, dailyUsd: 0.05, runMaxCalls: 10 };
    // The daily cap refuses this call, but the run said it wants at most one call.
    assert.equal(refused(ledger.reserve(key, 0.1, "careful", { budget: { calls: 1 } })).cap, "daily");
    admitted(ledger.reserve(key, 0.01, "careful"));
    assert.deepEqual(refused(ledger.reserve(key, 0.01, "careful")), { ok: false, cap: "runMaxCalls", runId: "careful", limit: 1, calls: 1, declared: true });
  });

  const looper: GatewayKey = { ...BASE, runShipScore: 0.9, runMaxRounds: 4, runFlatRounds: 2, runMinGain: 0.01 };
  /** A score for a run the key knows: one that made a call. */
  const scored = (key: GatewayKey, run: string, score: number): ScoreOutcome => {
    const out = ledger.score(key, run, score);
    assert.ok(out, `no run ${run}`);
    return out;
  };
  /** A run's first call, then a score for each of its rounds. */
  const decisions = (run: string, scores: number[]): ScoreOutcome[] => {
    admitted(ledger.reserve(looper, 0.01, run));
    return scores.map((s) => scored(looper, run, s));
  };

  it("SHIP: a round at or above runShipScore ends the run with exit ship", () => {
    const out = decisions("good", [0.5, 0.7, 0.9]);
    assert.deepEqual(out.map((o) => o.decision), ["continue", "continue", "ship"]);
    assert.deepEqual([out[2]?.stop?.exit, out[2]?.stop?.rule, out[2]?.round, out[2]?.best], ["ship", "runShipScore", 3, 0.9]);
    assert.match(out[2]?.stop?.why ?? "", /^round 3 scored 0\.9, at or above the ship score 0\.9$/);
  });

  it("STOP on budget: the run's scored rounds run out (runMaxRounds); ship still wins at the last round", () => {
    const out = decisions("slow", [0.1, 0.2, 0.3, 0.4]);
    assert.deepEqual(out.map((o) => o.decision), ["continue", "continue", "continue", "stop"]);
    assert.deepEqual([out[3]?.stop?.exit, out[3]?.stop?.rule, out[3]?.stop?.why], ["budget", "runMaxRounds", "4 scored rounds, the run's limit"]);
    const last = decisions("late-pass", [0.1, 0.2, 0.3, 0.95]);
    assert.equal(last[3]?.decision, "ship");
  });

  it("STOP on a flat line: runFlatRounds rounds in a row without a gain of more than runMinGain", () => {
    const out = decisions("stuck", [0.6, 0.605, 0.6]);
    assert.deepEqual(out.map((o) => [o.decision, o.flat, o.best]), [["continue", 0, 0.6], ["continue", 1, 0.6], ["stop", 2, 0.6]]);
    assert.deepEqual([out[2]?.stop?.exit, out[2]?.stop?.rule], ["flat_line", "runFlatRounds"]);
    assert.equal(out[2]?.stop?.why, "2 scored rounds in a row without a gain of more than 0.01 over the best score 0.6");
    // A real gain resets the count.
    assert.deepEqual(decisions("recovers", [0.5, 0.5, 0.6]).map((o) => [o.decision, o.flat]), [["continue", 0], ["continue", 1], ["continue", 0]]);
  });

  it("STOP on budget at score time when a limit the gateway counts is used up", () => {
    const key: GatewayKey = { ...BASE, runMaxCalls: 2 };
    admitted(ledger.reserve(key, 0.01, "spent"));
    assert.equal(scored(key, "spent", 0.1).decision, "continue");
    admitted(ledger.reserve(key, 0.01, "spent"));
    const out = scored(key, "spent", 0.2);
    assert.deepEqual([out.decision, out.stop?.exit, out.stop?.rule, out.spent.calls], ["stop", "budget", "runMaxCalls", 2]);
  });

  it("a stopped run stays stopped: later scores are not counted and every call is refused with the stop", () => {
    decisions("done", [0.95]);
    const late = scored(looper, "done", 0.1);
    assert.deepEqual([late.decision, late.already, late.round, late.stop?.rule], ["ship", true, 1, "runShipScore"]);
    const no = refused(ledger.reserve(looper, 0.01, "done"));
    assert.deepEqual([no.cap, no.cap === "runStopped" && no.stop.exit], ["runStopped", "ship"]);
    // A refused call keeps the run in memory: knocking every 23 hours, it never gets a fresh budget.
    now += 23 * 60 * 60 * 1000;
    assert.equal(refused(ledger.reserve(looper, 0.01, "done")).cap, "runStopped");
    now += 23 * 60 * 60 * 1000;
    assert.equal(refused(ledger.reserve(looper, 0.01, "done")).cap, "runStopped");
    now += RUN_MEMORY_MS + 1; // a day of silence: forgotten, as every run is
    admitted(ledger.reserve(looper, 0.01, "done"));
  });

  it("a score needs a run that made a call; a run belongs to its key", () => {
    assert.equal(ledger.score(looper, "never-called", 0.5), undefined, "a report alone does not make a run");
    assert.equal(JSON.parse(fs.readFileSync(ledger.file, "utf8")).keys["team-a"].runs, undefined, "and leaves nothing in the ledger");
    decisions("shared-name", [0.95]);
    assert.equal(ledger.score({ ...looper, name: "team-b" }, "shared-name", 0.1), undefined, "to another key, the run does not exist");
  });
});

describe("loop exits on a running gateway", () => {
  const KEY_LOOP = FAKE_GATEWAY_KEYS.teamA;
  const KEY_CAPPED = FAKE_GATEWAY_KEYS.teamB;
  const KEY_METERED = `${FAKE_GATEWAY_KEYS.teamA}-metered`;
  const KEY_PLAIN = `${FAKE_GATEWAY_KEYS.teamB}-plain`;
  let fake: FakeUpstream;
  let tmp: string;
  let gateway: LlmGateway;
  let clock = Date.parse("2026-11-03T10:00:00.000Z");

  before(async () => {
    // Each call: 100 + 10 tokens, $0.00011.
    fake = await startFakeUpstream({ mode: "ok", usage: { prompt_tokens: 100, completion_tokens: 10 } });
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-loop-exits-"));
    const config = parseLlmConfig(
      {
        listen: { port: 0 },
        stateDir: "state",
        policy: "p.json",
        upstreams: [{ name: "up", baseUrl: `${fake.url}/v1`, apiKeyEnv: "UP_KEY", models: { small: "s" }, pricePerMTok: { input: 1, output: 1 } }],
        routes: [{ id: "all", use: { upstream: "up" } }],
        keys: [
          { name: "looper", sha256: hashKey(KEY_LOOP), dailyUsd: 1, monthlyUsd: 10, runShipScore: 0.9, runMaxRounds: 4, runFlatRounds: 2, runMinGain: 0.01 },
          { name: "capped", sha256: hashKey(KEY_CAPPED), dailyUsd: 1, monthlyUsd: 10, runMaxCalls: 3 },
          { name: "metered", sha256: hashKey(KEY_METERED), dailyUsd: 1, monthlyUsd: 10, runMaxTokens: 300, runMaxSeconds: 60 },
          { name: "plain", sha256: hashKey(KEY_PLAIN), dailyUsd: 1, monthlyUsd: 10 },
        ],
      },
      tmp,
    );
    gateway = await startLlmGateway(config, parseLeakPolicy({ leakGuard: [] }), { env: { UP_KEY: "fake-upstream-key-loop-exits" }, log: () => undefined, now: () => clock });
  });
  after(async () => {
    await gateway?.close();
    await fake?.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  type Answer = { status: number; json: Record<string, any> };
  const chat = async (key: string, runId?: string, headers: Record<string, string> = {}): Promise<Answer> => {
    const res = await fetch(`${gateway.url}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json", ...(runId ? { "x-run-id": runId } : {}), ...headers },
      body: JSON.stringify({ model: "small", messages: [{ role: "user", content: "again" }], max_tokens: 10 }),
    });
    return { status: res.status, json: (await res.json()) as Record<string, any> };
  };
  const score = async (key: string, runId: string | undefined, body: unknown, headers: Record<string, string> = {}): Promise<Answer> => {
    const res = await fetch(`${gateway.url}/v1/runs/score`, {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json", ...(runId ? { "x-run-id": runId } : {}), ...headers },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
    return { status: res.status, json: (await res.json()) as Record<string, any> };
  };
  const usage = () => readUsageLog(path.join(tmp, "state", "usage.jsonl")).lines as Array<Record<string, any>>;

  it("SHIP: the gateway answers continue, continue, ship; the run then takes no more calls", async () => {
    const decided: string[] = [];
    for (const s of [0.5, 0.7, 0.92]) {
      assert.equal((await chat(KEY_LOOP, "ship-run")).status, 200);
      const r = await score(KEY_LOOP, "ship-run", { score: s });
      assert.equal(r.status, 200);
      decided.push(r.json.decision);
    }
    assert.deepEqual(decided, ["continue", "continue", "ship"]);
    const after = await chat(KEY_LOOP, "ship-run");
    assert.deepEqual([after.status, after.json.error?.code, after.json.error?.exit, after.json.error?.cap], [429, "run_stopped", "ship", "runShipScore"]);
    assert.match(after.json.error?.message, /^agent-gate: run "ship-run" of key "looper" has shipped at \S+: round 3 scored 0\.92, at or above the ship score 0\.9 \(runShipScore\)\. Use its last result; the run takes no more calls\.$/);
    const late = await score(KEY_LOOP, "ship-run", { score: 0.99 });
    assert.deepEqual([late.json.decision, late.json.already, late.json.round], ["ship", true, 3], "a later score does not reopen it");
  });

  it("STOP on budget: four scored rounds, the key's runMaxRounds", async () => {
    const r = [];
    assert.equal((await chat(KEY_LOOP, "budget-run")).status, 200, "a run starts with its first call");
    for (const s of [0.1, 0.2, 0.3, 0.4]) r.push((await score(KEY_LOOP, "budget-run", { score: s })).json);
    assert.deepEqual(r.map((x) => x.decision), ["continue", "continue", "continue", "stop"]);
    assert.deepEqual([r[3]?.exit, r[3]?.rule, r[3]?.why], ["budget", "runMaxRounds", "4 scored rounds, the run's limit"]);
    assert.deepEqual(r[3]?.limits, { rounds: 4, shipScore: 0.9, flatRounds: 2, minGain: 0.01 });
  });

  it("STOP on a flat line: two rounds in a row without a gain over 0.6", async () => {
    const r = [];
    assert.equal((await chat(KEY_LOOP, "flat-run")).status, 200);
    for (const s of [0.6, 0.6, 0.55]) r.push((await score(KEY_LOOP, "flat-run", { score: s })).json);
    assert.deepEqual(r.map((x) => [x.decision, x.flat]), [["continue", 0], ["continue", 1], ["stop", 2]]);
    assert.deepEqual([r[2]?.exit, r[2]?.rule], ["flat_line", "runFlatRounds"]);
    const after = await chat(KEY_LOOP, "flat-run");
    assert.deepEqual([after.status, after.json.error?.code, after.json.error?.exit], [429, "run_stopped", "flat_line"]);
  });

  it("STOP on budget, counted by the gateway: tokens, then time", async () => {
    // Each call is estimated at 2 + 10 tokens and books 110: 110, 220, 330 would pass 300 at the fourth.
    const statuses = [];
    for (let i = 0; i < 4; i++) statuses.push((await chat(KEY_METERED, "token-run")).status);
    assert.deepEqual(statuses, [200, 200, 200, 429]);
    const cut = await chat(KEY_METERED, "token-run");
    assert.deepEqual([cut.status, cut.json.error?.code, cut.json.error?.cap], [429, "run_limit_reached", "runMaxTokens"]);
    assert.match(cut.json.error?.message, /could use up to 12 tokens, and run "token-run" of key "metered" has 0 left of its limit \(runMaxTokens\) of 300 \(330 booked, 0 held/);

    assert.equal((await chat(KEY_METERED, "timed-run")).status, 200);
    clock += 61_000;
    const late = await chat(KEY_METERED, "timed-run");
    assert.deepEqual([late.status, late.json.error?.code, late.json.error?.cap], [429, "run_limit_reached", "runMaxSeconds"]);
    assert.match(late.json.error?.message, /run "timed-run" of key "metered" has run for 61 s; its limit \(runMaxSeconds\) is 60 s\. Retrying will not help/);
  });

  it("the hard cap: x-run-budget can lower a run's limit, and asking for more than the key's cap changes nothing", async () => {
    const greedy = [];
    for (let i = 0; i < 4; i++) greedy.push((await chat(KEY_CAPPED, "greedy-run", { "x-run-budget": "calls=1000" })).status);
    assert.deepEqual(greedy, [200, 200, 200, 429], "the key's runMaxCalls of 3 held");
    const modest = [];
    for (let i = 0; i < 3; i++) modest.push(await chat(KEY_CAPPED, "modest-run", { "x-run-budget": "calls=2" }));
    assert.deepEqual(modest.map((r) => r.status), [200, 200, 429]);
    assert.match(modest[2]?.json.error?.message, /has made 2 calls, its own budget \(x-run-budget, under the key's runMaxCalls\)/);
    const raise = await chat(KEY_CAPPED, "modest-run", { "x-run-budget": "calls=3" });
    assert.equal(raise.status, 429, "the run cannot raise its own earlier budget either");
    // A key without run limits still holds a run to the budget it declared.
    assert.equal((await chat(KEY_PLAIN, "self-run", { "x-run-budget": "calls=1" })).status, 200);
    assert.equal((await chat(KEY_PLAIN, "self-run")).status, 429);
  });

  it("refuses a budget that cannot be read, or one without a run, before anything is sent", async () => {
    const calls = fake.requests.length;
    const bad = await chat(KEY_CAPPED, "bad-budget", { "x-run-budget": "calls=lots" });
    assert.deepEqual([bad.status, bad.json.error?.code, bad.json.error?.param], [400, "invalid_run_budget", "x-run-budget"]);
    const orphan = await chat(KEY_CAPPED, undefined, { "x-run-budget": "calls=2" });
    assert.deepEqual([orphan.status, orphan.json.error?.code], [400, "invalid_run_budget"]);
    assert.match(orphan.json.error?.message, /needs an x-run-id header too/);
    assert.equal(fake.requests.length, calls);
  });

  it("the score endpoint: needs a key, a run id, a number and a run that made a call; a run belongs to its key", async () => {
    const anonymous = await fetch(`${gateway.url}/v1/runs/score`, { method: "POST", body: "{}" });
    assert.equal(anonymous.status, 401);
    const wrongMethod = await fetch(`${gateway.url}/v1/runs/score`, { headers: { authorization: `Bearer ${KEY_LOOP}` } });
    assert.deepEqual([wrongMethod.status, wrongMethod.headers.get("allow")], [405, "POST"]);
    assert.deepEqual([(await score(KEY_LOOP, undefined, { score: 1 })).status, (await score(KEY_LOOP, undefined, { score: 1 })).json.error?.param], [400, "x-run-id"]);
    for (const body of ["not json", { score: "0.9" }, { score: null }, {}, { score: 0.5, round: 2 }, [0.5]]) {
      const r = await score(KEY_LOOP, "bad-body", body);
      assert.deepEqual([r.status, r.json.error?.code, r.json.error?.param], [400, "invalid_request", "score"], JSON.stringify(body));
    }
    // A report alone does not make a run (it costs nothing, so it must not fill the ledger), and a run belongs to its key.
    const unknown = await score(KEY_LOOP, "never-called", { score: 0.5 });
    assert.deepEqual([unknown.status, unknown.json.error?.code, unknown.json.error?.param], [404, "run_not_found", "x-run-id"]);
    const theirs = await score(KEY_PLAIN, "ship-run", { score: 0.1 });
    assert.deepEqual([theirs.status, theirs.json.error?.code], [404, "run_not_found"], "another key's run of the same name is not this key's");
  });

  it("writes every stop to the usage log with its exit, rule and reason; the reports leave score lines out", () => {
    const lines = usage();
    const stops = lines.filter((l) => l.event === "run-score" && l.decision !== undefined && l.decision !== "continue" && !l.already);
    assert.deepEqual(
      stops.map((l) => [l.key, l.runId, l.decision, l.exit, l.rule]),
      [
        ["looper", "ship-run", "ship", "ship", "runShipScore"],
        ["looper", "budget-run", "stop", "budget", "runMaxRounds"],
        ["looper", "flat-run", "stop", "flat_line", "runFlatRounds"],
      ],
    );
    for (const l of stops) {
      assert.equal(typeof l.why, "string");
      assert.deepEqual([l.status, l.costUsd, l.inputTokens, l.outputTokens], [200, 0, 0, 0]);
    }
    const refusedCalls = lines.filter((l) => l.event === undefined && (l.error === "run_stopped" || l.error === "run_limit_reached"));
    assert.deepEqual(
      refusedCalls.map((l) => [l.key, l.runId, l.error, l.exit, l.rule]),
      [
        ["looper", "ship-run", "run_stopped", "ship", "runShipScore"],
        ["looper", "flat-run", "run_stopped", "flat_line", "runFlatRounds"],
        ["metered", "token-run", "run_limit_reached", "budget", "runMaxTokens"],
        ["metered", "token-run", "run_limit_reached", "budget", "runMaxTokens"],
        ["metered", "timed-run", "run_limit_reached", "budget", "runMaxSeconds"],
        ["capped", "greedy-run", "run_limit_reached", "budget", "runMaxCalls"],
        ["capped", "modest-run", "run_limit_reached", "budget", "runMaxCalls"],
        ["capped", "modest-run", "run_limit_reached", "budget", "runMaxCalls"],
        ["plain", "self-run", "run_limit_reached", "budget", "runMaxCalls"],
      ],
    );
    for (const l of refusedCalls) assert.ok(typeof l.why === "string" && l.why.length > 0, JSON.stringify(l));
    // The run that asked for more than the key allows is on record, on every one of its lines.
    const greedy = lines.filter((l) => l.runId === "greedy-run");
    assert.equal(greedy.length, 4);
    assert.ok(greedy.every((l) => JSON.stringify(l.budgetClamped) === '["calls"]'));
    assert.equal(lines.filter((l) => l.runId === "modest-run").some((l) => l.budgetClamped !== undefined), false, "a lower budget is not clamped");
    // usage --by runId counts calls only: ship-run made 4 calls (3 answered, 1 refused) and 4 score reports.
    const byRun = groupUsage(lines, "runId").find((g) => g.group === "ship-run");
    assert.deepEqual([byRun?.requests, byRun?.ok], [4, 3]);
  });
});
