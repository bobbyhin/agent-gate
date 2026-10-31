// Divert: a call whose messages match a divert rule goes, unredacted, to a local upstream and nowhere
// else. Two fakes stand in for a cloud provider and a model on this machine.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { hashKey, isLocalHost, loadLeakPolicy, loadLlmConfig, parseLlmConfig, type LlmConfig } from "../../src/llm/config.js";
import { startLlmGateway, type LlmGateway } from "../../src/llm/server.js";
import { readUsageLog } from "../../src/llm/usage-report.js";
import { ConfigError } from "../../src/gateway/validate.js";
import { PII } from "./fake-pii.js";
import { FAKE, FAKE_GATEWAY_KEYS } from "./fake-secrets.js";
import { startFakeUpstream, type FakeUpstream } from "./fake-upstream.js";

// This file runs from dist/test/llm/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const KEY = FAKE_GATEWAY_KEYS.teamA;
const policy = loadLeakPolicy(path.join(ROOT, "llm-policy.example.json"));

describe("divert: personal data goes to the local model only", () => {
  let cloud: FakeUpstream;
  let local: FakeUpstream;
  let tmp: string;
  let gateway: LlmGateway;
  let config: LlmConfig;

  const raw = (localUrl: string, divert: Record<string, unknown>) => ({
    listen: { port: 0 },
    stateDir: "state",
    policy: path.join(ROOT, "llm-policy.example.json"),
    upstreams: [
      { name: "cloud", baseUrl: `${cloud.url}/v1`, apiKeyEnv: "CLOUD_KEY", models: { small: "cloud-small", large: "cloud-large" }, pricePerMTok: { input: 1, output: 2 } },
      { name: "local", baseUrl: localUrl, apiKeyEnv: "LOCAL_KEY", models: { small: "local-small" }, pricePerMTok: { input: 0, output: 0 } },
    ],
    routes: [{ id: "cloud-models", use: { upstream: "cloud" } }],
    keys: [{ name: "agent", sha256: hashKey(KEY), dailyUsd: 1, monthlyUsd: 10 }],
    divert,
  });
  const env = { CLOUD_KEY: "fake-provider-key-cloud-divert", LOCAL_KEY: "local" };

  before(async () => {
    cloud = await startFakeUpstream({ mode: "ok" });
    local = await startFakeUpstream({ mode: "ok" });
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-divert-"));
    config = parseLlmConfig(raw(`${local.url}/v1`, { rules: ["credit-card", "jp-my-number", "aws-access-key-id"], to: { upstream: "local", model: "small" } }), tmp);
    gateway = await startLlmGateway(config, policy, { env, log: () => undefined });
  });
  after(async () => {
    await gateway?.close();
    await cloud?.close();
    await local?.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const chat = async (content: string, extra: Record<string, unknown> = {}, target = gateway) => {
    const res = await fetch(`${target.url}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "small", messages: [{ role: "user", content }], max_tokens: 20, ...extra }),
    });
    return { status: res.status, headers: res.headers, text: await res.text() };
  };
  const sentTo = (fake: FakeUpstream) => JSON.stringify(fake.requests[fake.requests.length - 1]?.body.messages);
  const lineFor = (id: string | null) => (readUsageLog(path.join(config.stateDir, "usage.jsonl")).lines as Array<Record<string, any>>).find((l) => l.id === id);

  it("sends a call with nothing to divert to the route's upstream, as before", async () => {
    const r = await chat("What is the capital of Japan?");
    assert.equal(r.status, 200);
    assert.deepEqual([r.headers.get("x-agent-gate-upstream"), r.headers.get("x-agent-gate-diverted")], ["cloud", null]);
    assert.equal(lineFor(r.headers.get("x-agent-gate-request-id"))?.diverted, undefined);
  });

  it("sends a call with a card number to the local upstream, unredacted, and nothing to the cloud", async () => {
    const cloudCalls = cloud.requests.length;
    const r = await chat(`Fill in the payment form with ${PII.cardSpaced}, please.`);
    assert.equal(r.status, 200, r.text);
    assert.deepEqual([r.headers.get("x-agent-gate-upstream"), r.headers.get("x-agent-gate-diverted"), r.headers.get("x-agent-gate-redacted")], ["local", "credit-card", null]);
    assert.equal(cloud.requests.length, cloudCalls, "the cloud upstream got nothing");
    assert.ok(sentTo(local).includes(PII.cardSpaced), "the local model got the number as it was written");
    assert.equal(local.requests.at(-1)?.body.model, "local-small");
    const line = lineFor(r.headers.get("x-agent-gate-request-id"))!;
    assert.deepEqual([line.upstream, line.model, line.diverted, line.costUsd], ["local", "local-small", ["credit-card"], 0]);
    assert.equal(JSON.stringify(line).includes(PII.card.slice(0, 8)), false, "no text in the usage line");
  });

  it("diverts as it is: other redact rules do not touch a diverted call either", async () => {
    const r = await chat(`My Number ${PII.myNumberSpaced} and api_key = "${FAKE.apiKeyValue}"`);
    assert.deepEqual([r.status, r.headers.get("x-agent-gate-diverted"), r.headers.get("x-agent-gate-redacted")], [200, "jp-my-number", null]);
    assert.ok(sentTo(local).includes(FAKE.apiKeyValue));
    // Without a divert rule in it, the same key assignment is redacted and goes to the cloud.
    const plain = await chat(`api_key = "${FAKE.apiKeyValue}"`);
    assert.deepEqual([plain.headers.get("x-agent-gate-upstream"), plain.headers.get("x-agent-gate-redacted")], ["cloud", "api-key-assignment"]);
    assert.equal(sentTo(cloud).includes(FAKE.apiKeyValue), false);
  });

  it("a block rule still blocks, unless the divert lists it; then it diverts", async () => {
    const before = cloud.requests.length + local.requests.length;
    const blocked = await chat(`Why does this fail? ${FAKE.privateKey}`);
    assert.deepEqual([blocked.status, JSON.parse(blocked.text).error.rule], [400, "private-key"]);
    // A private key next to a card number: the block wins.
    const both = await chat(`${PII.card} ${FAKE.privateKey}`);
    assert.equal(both.status, 400);
    assert.equal(cloud.requests.length + local.requests.length, before, "nothing was sent anywhere");
    const listed = await chat(`Is this key id still active? ${FAKE.awsAccessKeyId}`);
    assert.deepEqual([listed.status, listed.headers.get("x-agent-gate-diverted")], [200, "aws-access-key-id"]);
  });

  it("streams a diverted call from the local upstream too", async () => {
    const r = await chat(`Card ${PII.card}: is it a test card?`, { stream: true });
    assert.equal(r.status, 200);
    assert.deepEqual([r.headers.get("x-agent-gate-upstream"), r.headers.get("x-agent-gate-diverted")], ["local", "credit-card"]);
    assert.match(r.text, /data: \[DONE\]/);
  });

  it("refuses rather than fall back to the cloud: a missing alias, or a local upstream that is down", async () => {
    const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-divert-down-"));
    try {
      // No fixed alias: the client's alias must exist on the local upstream.
      const noAlias = parseLlmConfig(raw(`${local.url}/v1`, { rules: ["credit-card"], to: { upstream: "local" } }), tmp2);
      const g2 = await startLlmGateway(noAlias, policy, { env, log: () => undefined });
      const cloudCalls = cloud.requests.length;
      try {
        const missing = await chat(`card ${PII.card}`, { model: "large" }, g2);
        assert.deepEqual([missing.status, JSON.parse(missing.text).error.code], [404, "model_not_found"]);
        assert.match(JSON.parse(missing.text).error.message, /may go only to upstream "local", which has no model alias "large"\. It was not sent anywhere\./);
      } finally {
        await g2.close();
      }
      // The local upstream is down (nothing listens there): 502, and still nothing to the cloud.
      const closed = await startFakeUpstream({ mode: "ok" });
      const deadUrl = `${closed.url}/v1`;
      await closed.close();
      const down = parseLlmConfig({ ...raw(deadUrl, { rules: ["credit-card"], to: { upstream: "local", model: "small" } }), stateDir: "state-down", retries: 0 }, tmp2);
      const g3 = await startLlmGateway(down, policy, { env, log: () => undefined });
      try {
        const r = await chat(`card ${PII.card}`, {}, g3);
        assert.deepEqual([r.status, JSON.parse(r.text).error.code], [502, "upstream_error"]);
      } finally {
        await g3.close();
      }
      assert.equal(cloud.requests.length, cloudCalls, "nothing went to the cloud");
    } finally {
      fs.rmSync(tmp2, { recursive: true, force: true });
    }
  });

  it("refuses a divert that could send text off this machine or its network, or names an unknown rule", async () => {
    const remote = { ...raw("https://llm.example.com/v1", { rules: ["credit-card"], to: { upstream: "local" } }) };
    assert.throws(() => parseLlmConfig(remote, tmp), /config\.divert\.to: upstream "local" is at llm\.example\.com, which is not on this machine or a private network/);
    assert.throws(() => parseLlmConfig(raw(`${local.url}/v1`, { rules: [], to: { upstream: "local" } }), tmp), /config\.divert\.rules must name at least one/);
    assert.throws(() => parseLlmConfig(raw(`${local.url}/v1`, { rules: ["credit-card"], to: { upstream: "nowhere" } }), tmp), /config\.divert\.to\.upstream "nowhere" is not one of the upstreams/);
    assert.throws(() => parseLlmConfig(raw(`${local.url}/v1`, { rules: ["credit-card"], to: { upstream: "local", model: "large" } }), tmp), /upstream "local" has no model alias "large"/);
    const unknownRule = parseLlmConfig(raw(`${local.url}/v1`, { rules: ["passport"], to: { upstream: "local" } }), tmp);
    await assert.rejects(startLlmGateway(unknownRule, policy, { env, log: () => undefined }), (err: unknown) => err instanceof ConfigError && /"passport" is not a rule of the leak policy/.test(err.message));
    assert.deepEqual(
      ["127.0.0.1", "localhost", "[::1]", "10.1.2.3", "172.16.0.1", "172.31.9.9", "192.168.1.20", "[fd12:3456::1]", "ollama", "172.32.0.1", "8.8.8.8", "169.254.169.254", "llm.example.com", "[2001:db8::1]"].map(isLocalHost),
      [true, true, true, true, true, true, true, true, true, false, false, false, false, false],
    );
  });

  it("llm-gateway.config.ollama.example.json loads: the cloud for the rest, Ollama on this machine for personal numbers", () => {
    const example = loadLlmConfig(path.join(ROOT, "llm-gateway.config.ollama.example.json"));
    assert.deepEqual(example.divert, { rules: ["credit-card", "jp-my-number", "us-ssn", "us-itin"], to: { upstream: "local", model: "small" } });
    assert.equal(example.upstreams.get("local")?.baseUrl, "http://127.0.0.1:11434/v1");
    for (const id of example.divert?.rules ?? []) assert.ok(policy.rules.some((r) => r.id === id), id);
  });
});
