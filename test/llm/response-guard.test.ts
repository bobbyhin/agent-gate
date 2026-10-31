// The leak guard on the model's answer: the same rules as on the request, so a secret the model writes
// (read off an image, repeated from its context, or made up in a known shape) does not reach the client.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { hashKey, loadLeakPolicy, parseLlmConfig } from "../../src/llm/config.js";
import { guardMessages, guardResponse } from "../../src/llm/leak-guard.js";
import { startLlmGateway, type LlmGateway } from "../../src/llm/server.js";
import { FAKE, FAKE_GATEWAY_KEYS } from "./fake-secrets.js";
import { startFakeUpstream, type FakeUpstream } from "./fake-upstream.js";

// This file runs from dist/test/llm/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const POLICY = loadLeakPolicy(path.join(ROOT, "llm-policy.example.json"));

const answer = (content: unknown, toolArguments?: string) => ({
  id: "chatcmpl-1",
  choices: [{ index: 0, message: { role: "assistant", content, ...(toolArguments ? { tool_calls: [{ id: "c", type: "function", function: { name: "f", arguments: toolArguments } }] } : {}) }, finish_reason: "stop" }],
  usage: { prompt_tokens: 1, completion_tokens: 1 },
});

describe("guardResponse", () => {
  const samples: Array<[rule: string, text: string]> = [
    ["private-key", `the key is\n${FAKE.privateKey}`],
    ["aws-access-key-id", `export AWS_ACCESS_KEY_ID=${FAKE.awsAccessKeyId}`],
    ["github-token", `token: ${FAKE.githubToken}`],
    ["slack-token", FAKE.slackToken],
    ["sk-style-key", `OPENAI_API_KEY=${FAKE.skKey}`],
    ["huggingface-token", FAKE.huggingfaceToken],
    ["google-api-key", `key=${FAKE.googleApiKey}`],
    ["gcp-service-account-key", FAKE.serviceAccountJson],
  ];
  for (const [rule, text] of samples) {
    it(`blocks ${rule} on both sides with the same rule`, () => {
      assert.deepEqual(guardMessages(POLICY, [{ role: "user", content: text }]), { action: "block", rule });
      assert.deepEqual(guardResponse(POLICY, answer(text)), { action: "block", rule });
    });
  }

  it("reads tool-call arguments, text parts and every choice", () => {
    assert.deepEqual(guardResponse(POLICY, answer(null, JSON.stringify({ note: FAKE.githubToken }))), { action: "block", rule: "github-token" });
    assert.deepEqual(guardResponse(POLICY, answer([{ type: "text", text: FAKE.awsAccessKeyId }])), { action: "block", rule: "aws-access-key-id" });
    const two = { choices: [answer("fine").choices[0], { index: 1, message: { role: "assistant", content: FAKE.slackToken } }] };
    assert.deepEqual(guardResponse(POLICY, two), { action: "block", rule: "slack-token" }, "the second choice is read too");
  });

  it("redacts what a redact rule matches and keeps the answer valid JSON; returns a clean answer as it is", () => {
    const leaky = answer(`Use api_key = "${FAKE.apiKeyValue}" in the config.`, JSON.stringify({ password: FAKE.apiKeyValue }));
    const result = guardResponse(POLICY, leaky);
    assert.equal(result.action, "pass");
    if (result.action !== "pass") return;
    assert.deepEqual(result.redactions, [{ rule: "api-key-assignment", count: 2 }]);
    const text = JSON.stringify(result.body);
    assert.equal(text.includes(FAKE.apiKeyValue), false);
    const message = (result.body.choices as Array<{ message: { content: string; tool_calls: Array<{ function: { arguments: string } }> } }>)[0]!.message;
    assert.equal(message.content, 'Use api_key = "[REDACTED:api-key-assignment]" in the config.');
    assert.deepEqual(JSON.parse(message.tool_calls[0]!.function.arguments), { password: "[REDACTED:api-key-assignment]" });
    assert.equal(String(leaky.choices[0]!.message.content).includes(FAKE.apiKeyValue), true, "the input is not changed");
    const clean = answer("No secrets here: const apiKey = process.env.OPENAI_API_KEY;");
    assert.deepEqual(guardResponse(POLICY, clean), { action: "pass", body: clean, redactions: [] });
    assert.deepEqual(guardResponse(POLICY, { object: "list", data: [] }), { action: "pass", body: { object: "list", data: [] }, redactions: [] });
  });
});

describe("answers through a running gateway", () => {
  const fakes: FakeUpstream[] = [];
  let tmp: string;
  let gateway: LlmGateway;
  let unscanned: LlmGateway;

  before(async () => {
    const leaky = await startFakeUpstream({ mode: "ok", content: `Sure, here it is: ${FAKE.githubToken}` });
    const redacting = await startFakeUpstream({ mode: "ok", content: `Set api_key = "${FAKE.apiKeyValue}" and restart.` });
    const tooly = await startFakeUpstream({ mode: "ok", content: "", toolCallArguments: JSON.stringify({ text: FAKE.privateKey }) });
    fakes.push(leaky, redacting, tooly);
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-response-guard-"));
    const upstream = (name: string, fake: FakeUpstream) => ({ name, baseUrl: `${fake.url}/v1`, apiKeyEnv: "UP_KEY", models: { m: "fake" }, pricePerMTok: { input: 1, output: 1 } });
    const config = (stateDir: string, scanResponses?: boolean) =>
      parseLlmConfig(
        {
          listen: { port: 0 },
          stateDir,
          policy: "p.json",
          upstreams: [upstream("leaky", leaky), upstream("redacting", redacting), upstream("tooly", tooly)],
          routes: ["leaky", "redacting", "tooly"].map((name) => ({ id: name, when: { task: name }, use: { upstream: name } })),
          keys: [{ name: "team-a", sha256: hashKey(FAKE_GATEWAY_KEYS.teamA), dailyUsd: 1, monthlyUsd: 10 }],
          ...(scanResponses === undefined ? {} : { scanResponses }),
        },
        tmp,
      );
    const options = { env: { UP_KEY: "fake-upstream-key-response-guard" }, log: () => undefined };
    gateway = await startLlmGateway(config("scanned"), POLICY, options);
    unscanned = await startLlmGateway(config("unscanned", false), POLICY, options);
  });
  after(async () => {
    await gateway?.close();
    await unscanned?.close();
    for (const fake of fakes) await fake.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const post = async (url: string, task: string) => {
    const res = await fetch(`${url}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${FAKE_GATEWAY_KEYS.teamA}`, "content-type": "application/json", "x-agent-task": task },
      body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hello" }], max_tokens: 10 }),
    });
    return { status: res.status, headers: res.headers, text: await res.text() };
  };
  const lastLine = (dir: string) => JSON.parse(fs.readFileSync(path.join(tmp, dir, "usage.jsonl"), "utf8").trim().split("\n").at(-1)!);

  it("refuses an answer with a secret: 502 response_blocked, naming the rule, not the text; the call is booked", async () => {
    const r = await post(gateway.url, "leaky");
    assert.equal(r.status, 502);
    const error = JSON.parse(r.text).error;
    assert.deepEqual([error.code, error.rule], ["response_blocked", "github-token"]);
    assert.equal(r.text.includes(FAKE.githubToken), false);
    const line = lastLine("scanned");
    assert.deepEqual([line.status, line.error, line.rule, line.side], [502, "response_blocked", "github-token", "response"]);
    assert.ok(line.costUsd > 0, "the upstream answered, so the call is paid for");
  });

  it("refuses a secret in an answer's tool-call arguments", async () => {
    const r = await post(gateway.url, "tooly");
    assert.equal(r.status, 502);
    assert.equal(JSON.parse(r.text).error.rule, "private-key");
  });

  it("redacts what a redact rule matches in the answer, and says so in a header and the usage line", async () => {
    const r = await post(gateway.url, "redacting");
    assert.equal(r.status, 200, r.text);
    assert.equal(r.headers.get("x-agent-gate-response-redacted"), "api-key-assignment");
    assert.equal(JSON.parse(r.text).choices[0].message.content, 'Set api_key = "[REDACTED:api-key-assignment]" and restart.');
    assert.deepEqual(lastLine("scanned").responseRedacted, ["api-key-assignment"]);
  });

  it("passes answers on unchanged with scanResponses: false", async () => {
    const r = await post(unscanned.url, "leaky");
    assert.equal(r.status, 200);
    assert.equal(JSON.parse(r.text).choices[0].message.content.includes(FAKE.githubToken), true);
    const valid = {
      stateDir: "s",
      policy: "p",
      upstreams: [{ name: "u", baseUrl: "http://127.0.0.1:9/v1", apiKeyEnv: "K", models: { m: "m" }, pricePerMTok: { input: 1, output: 1 } }],
      routes: [{ id: "r", use: { upstream: "u" } }],
      keys: [{ name: "k", sha256: "a".repeat(64), dailyUsd: 1, monthlyUsd: 1 }],
    };
    assert.equal(parseLlmConfig(valid, "/").scanResponses, true, "on unless turned off");
    assert.throws(() => parseLlmConfig({ ...valid, scanResponses: "no" }, "/"), /config\.scanResponses must be true or false/);
  });
});
