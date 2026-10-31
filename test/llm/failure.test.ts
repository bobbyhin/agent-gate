// What the LLM gateway does when one of its own files fails: a damaged ledger refuses calls rather
// than start from zero; a usage log that cannot be written does not stop a call that was answered.
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { hashKey, parseLlmConfig } from "../../src/llm/config.js";
import { parseLeakPolicy } from "../../src/llm/leak-guard.js";
import { startLlmGateway, type LlmGateway } from "../../src/llm/server.js";
import { FAKE_GATEWAY_KEYS } from "./fake-secrets.js";
import { startFakeUpstream, type FakeUpstream } from "./fake-upstream.js";

describe("failure behavior: the LLM gateway's state files", () => {
  const cleanup: Array<() => Promise<void>> = [];
  after(async () => {
    for (const step of cleanup) await step();
  });

  async function gatewayWith(prepare: (stateDir: string) => void, extra: Record<string, unknown> = {}): Promise<{ gateway: LlmGateway; fake: FakeUpstream; log: string[] }> {
    const fake = await startFakeUpstream({ mode: "ok" });
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-llm-failure-"));
    fs.mkdirSync(path.join(tmp, "state"), { mode: 0o700 });
    prepare(path.join(tmp, "state"));
    const config = parseLlmConfig(
      {
        listen: { port: 0 },
        stateDir: "state",
        policy: "p.json",
        upstreams: [{ name: "up", baseUrl: `${fake.url}/v1`, apiKeyEnv: "UP_KEY", models: { m: "fake" }, pricePerMTok: { input: 1, output: 1 } }],
        routes: [{ id: "all", use: { upstream: "up" } }],
        keys: [{ name: "team-a", sha256: hashKey(FAKE_GATEWAY_KEYS.teamA), dailyUsd: 1, monthlyUsd: 10 }],
        ...extra,
      },
      tmp,
    );
    const log: string[] = [];
    const gateway = await startLlmGateway(config, parseLeakPolicy({ leakGuard: [] }), { env: { UP_KEY: "fake-upstream-key-failure" }, log: (m) => log.push(m) });
    cleanup.push(async () => {
      await gateway.close();
      await fake.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    });
    return { gateway, fake, log };
  }

  const post = (url: string) =>
    fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${FAKE_GATEWAY_KEYS.teamA}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }], max_tokens: 5 }),
    });

  it("a damaged ledger refuses the call before anything is sent upstream", async () => {
    const { gateway, fake, log } = await gatewayWith((stateDir) => fs.writeFileSync(path.join(stateDir, "ledger.json"), "{ cut short"));
    const res = await post(gateway.url);
    assert.equal(res.status, 500);
    assert.equal(((await res.json()) as { error: { code: string } }).error.code, "gateway_error");
    assert.equal(fake.requests.length, 0);
    assert.ok(log.some((line) => /ledger\.json is not valid JSON/.test(line)), log.join("\n"));
  });

  it("a usage log that cannot be written does not stop an answered call; the gateway says so on stderr", async () => {
    const { gateway, fake, log } = await gatewayWith((stateDir) => fs.mkdirSync(path.join(stateDir, "usage.jsonl"))); // a folder where the file should be
    const res = await post(gateway.url);
    assert.equal(res.status, 200);
    assert.equal(fake.requests.length, 1);
    assert.ok(log.some((line) => line.startsWith("could not write the usage log")), log.join("\n"));
  });

  it("sendTraceparent: false keeps the trace to the usage log and sends the upstream no traceparent", async () => {
    const { gateway, fake } = await gatewayWith(() => undefined, { sendTraceparent: false });
    const res = await post(gateway.url);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("x-agent-gate-trace-id") ?? "", /^[0-9a-f]{32}$/);
    assert.equal(fake.requests[0]?.traceparent, undefined);
  });
});
