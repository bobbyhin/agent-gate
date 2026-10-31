// Trajectory fixtures: test/gateway/trajectories.jsonl holds one trajectory per line, a sequence of
// tool calls with the outcome each must get, and the human's answers in between. Each line is replayed
// through a real gateway (createGateway, the fake downstream server, an MCP client over an in-memory
// transport), the human steps go through the real CLI, and every step's outcome is read back from the
// audit log. Then the log must pass audit verify, and the calls that ran must score exact against the
// calls the trajectory expected to run. A new case is a new line; no code changes.
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { hashArguments } from "../../src/gateway/approvals.js";
import { isCallLine, readAudit, scoreTrajectory, trajectoryOf, verifyAudit } from "../../src/gateway/audit-tools.js";
import { main } from "../../src/gateway/cli.js";
import { loadConfig, loadPolicy } from "../../src/gateway/config.js";
import { createGateway } from "../../src/gateway/server.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const FAKE = path.join(__dirname, "fake-downstream.js");
const FILE = path.join(ROOT, "test", "gateway", "trajectories.jsonl");

const OUTCOMES = ["allow", "warn", "ask", "ask-forwarded", "block", "denied"] as const;
type Outcome = (typeof OUTCOMES)[number];
type Step =
  | { call: string; args: Record<string, unknown>; expect: Outcome; rule?: string; times?: number }
  | { human: "approve" | "deny"; reason?: string };
interface Trajectory {
  id: string;
  about: string;
  steps: Step[];
}

/** The fixture, checked line by line: a typo in a field must fail, not pass silently. */
function load(): Trajectory[] {
  return fs
    .readFileSync(FILE, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line, i) => {
      const t = JSON.parse(line) as Trajectory;
      const where = `trajectories.jsonl line ${i + 1}`;
      assert.deepEqual(Object.keys(t).sort(), ["about", "id", "steps"], where);
      assert.ok(t.steps.length > 0, where);
      for (const step of t.steps) {
        if ("human" in step) assert.ok(["approve", "deny"].includes(step.human) && Object.keys(step).every((k) => ["human", "reason"].includes(k)), `${where}: ${JSON.stringify(step)}`);
        else {
          assert.ok(Object.keys(step).every((k) => ["call", "args", "expect", "rule", "times"].includes(k)), `${where}: ${JSON.stringify(step)}`);
          assert.ok(step.call.includes("__") && OUTCOMES.includes(step.expect), `${where}: ${JSON.stringify(step)}`);
        }
      }
      return t;
    });
}

const trajectories = load();
const dirs: string[] = [];
after(() => {
  for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
});

const quiet = { out: () => undefined, err: () => undefined };

/** Replays one trajectory; returns each call's outcome and rule, and the audit file it left. */
async function replay(t: Trajectory): Promise<{ got: Array<[Outcome, string]>; auditFile: string; ran: Array<{ tool: string; argsHash: string }> }> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-trajectory-"));
  dirs.push(dir);
  const configFile = path.join(dir, "gateway.config.json");
  fs.writeFileSync(configFile, JSON.stringify({ servers: [{ name: "demo", command: process.execPath, args: [FAKE] }], policy: path.join(ROOT, "policy.example.json"), stateDir: "state" }));
  const config = loadConfig(configFile);
  const gateway = await createGateway(config, loadPolicy(config.policyFile), () => undefined);
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await gateway.server.connect(serverSide);
  const client = new Client({ name: "trajectory-replay", version: "1.0.0" });
  await client.connect(clientSide);
  const auditFile = path.join(config.stateDir, "audit.jsonl");
  const callLines = () => (fs.existsSync(auditFile) ? readAudit(auditFile).lines.filter((l) => isCallLine(l.value)) : []);
  const got: Array<[Outcome, string]> = [];
  const ran: Array<{ tool: string; argsHash: string }> = [];
  let lastHeld: string | undefined;
  try {
    for (const step of t.steps) {
      if ("human" in step) {
        assert.ok(lastHeld, `${t.id}: a human step needs a call held before it`);
        const argv = step.human === "approve" ? ["approvals", "approve", lastHeld, "--yes"] : ["approvals", "deny", lastHeld, ...(step.reason ? ["--reason", step.reason] : [])];
        assert.equal(await main([...argv, "--config", configFile], quiet), 0, `${t.id}: ${step.human} ${lastHeld}`);
        continue;
      }
      for (let n = 0; n < (step.times ?? 1); n++) {
        const seen = callLines().length;
        const result = (await client.callTool({ name: step.call, arguments: step.args })) as CallToolResult;
        const line = callLines()[seen]?.value;
        assert.ok(line, `${t.id}: ${step.call} left a call line`);
        const text = (result.content[0] as { text?: string } | undefined)?.text ?? "";
        const outcome: Outcome =
          line.decision === "ask"
            ? line.forwarded === true
              ? "ask-forwarded"
              : text.startsWith("agent-gate: a human denied")
                ? "denied"
                : "ask"
            : (line.decision as Outcome);
        if (outcome === "ask") lastHeld = String(line.approvalId);
        got.push([outcome, String(line.rule)]);
        if (step.expect === "allow" || step.expect === "warn" || step.expect === "ask-forwarded") ran.push({ tool: step.call, argsHash: hashArguments(step.args) });
      }
    }
  } finally {
    await client.close();
    await gateway.close();
  }
  return { got, auditFile, ran };
}

describe("trajectory fixtures, replayed through a real gateway", () => {
  it("each line is a trajectory with a unique id", () => {
    assert.ok(trajectories.length >= 10);
    assert.equal(new Set(trajectories.map((t) => t.id)).size, trajectories.length);
  });

  for (const t of trajectories) {
    it(`${t.id}: ${t.about}`, async () => {
      const { got, auditFile, ran } = await replay(t);
      const wanted = t.steps.flatMap((s) => ("call" in s ? Array.from({ length: s.times ?? 1 }, () => s) : []));
      assert.equal(got.length, wanted.length);
      wanted.forEach((step, i) => {
        assert.equal(got[i]?.[0], step.expect, `${t.id}, call ${i + 1} (${step.call}): outcome`);
        if (step.rule) assert.equal(got[i]?.[1], step.rule, `${t.id}, call ${i + 1} (${step.call}): rule`);
      });
      // The log the replay wrote checks out, and the calls that ran are exactly the ones expected to run.
      const log = readAudit(auditFile);
      assert.deepEqual(verifyAudit(log), []);
      const score = scoreTrajectory(trajectoryOf(log.lines), ran);
      assert.deepEqual([score.exact, score.precision, score.recall], [true, 1, 1], `${t.id}: trajectory score`);
    });
  }
});
