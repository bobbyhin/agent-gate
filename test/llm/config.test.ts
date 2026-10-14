// Tests for the LLM gateway config file.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { DEFAULTS, hashKey, loadLlmConfig, parseLlmConfig } from "../../src/llm/config.js";
import { ConfigError } from "../../src/gateway/validate.js";

// This file runs from dist/test/llm/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");

const upstream = { name: "cheap", baseUrl: "http://cheap.test/v1", apiKeyEnv: "CHEAP_KEY", models: { small: "small-v1" }, pricePerMTok: { input: 0.1, output: 0.4 } };
const valid = {
  stateDir: "state",
  policy: "policy.json",
  upstreams: [upstream],
  routes: [{ id: "all", use: { upstream: "cheap" } }],
  keys: [{ name: "agent", sha256: "a".repeat(64), dailyUsd: 1, monthlyUsd: 10 }],
};

describe("LLM gateway config", () => {
  it("loads llm-gateway.config.example.json and resolves paths against the config's directory", () => {
    const config = loadLlmConfig(path.join(ROOT, "llm-gateway.config.example.json"));
    assert.equal(config.policyFile, path.join(ROOT, "llm-policy.example.json"));
    assert.equal(config.stateDir, path.join(ROOT, ".agent-gate"));
    assert.deepEqual([config.host, config.port], ["127.0.0.1", 8787]);
    assert.deepEqual([...config.upstreams.keys()], ["cheap", "strong", "backup"]);
    assert.deepEqual(
      config.routes.map((r) => r.id),
      ["classify-is-cheap", "code-is-strong", "cheap-models", "strong-models"],
    );
    assert.equal(config.keys[0]?.sha256, hashKey("demo-gateway-key-not-a-secret"));
  });

  it("fills in defaults", () => {
    const config = parseLlmConfig(valid, "/srv/gate");
    assert.equal(config.stateDir, path.resolve("/srv/gate", "state"));
    assert.equal(config.policyFile, path.resolve("/srv/gate", "policy.json"));
    assert.deepEqual(
      [config.host, config.port, config.defaultMaxTokens, config.timeoutMs, config.retries, config.backoffMs, config.maxBodyBytes],
      [DEFAULTS.host, DEFAULTS.port, DEFAULTS.defaultMaxTokens, DEFAULTS.timeoutMs, DEFAULTS.retries, DEFAULTS.backoffMs, DEFAULTS.maxBodyBytes],
    );
  });

  it("strips a trailing slash from baseUrl", () => {
    const config = parseLlmConfig({ ...valid, upstreams: [{ ...upstream, baseUrl: "https://llm.test/v1/" }] }, "/srv");
    assert.equal(config.upstreams.get("cheap")?.baseUrl, "https://llm.test/v1");
  });

  it("hashes gateway keys with SHA-256", () => {
    assert.equal(hashKey("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  const table: Array<[name: string, json: unknown, message: RegExp]> = [
    ["no upstreams", { ...valid, upstreams: [] }, /at least one upstream/],
    ["duplicate upstream names", { ...valid, upstreams: [upstream, upstream] }, /the name "cheap" is used twice/],
    ["baseUrl that is not a URL", { ...valid, upstreams: [{ ...upstream, baseUrl: "cheap.test" }] }, /config\.upstreams\[0\]\.baseUrl is not a valid URL/],
    ["baseUrl that is not http", { ...valid, upstreams: [{ ...upstream, baseUrl: "file:///etc/passwd" }] }, /must start with http:\/\/ or https:\/\//],
    ["credentials in baseUrl", { ...valid, upstreams: [{ ...upstream, baseUrl: "https://user:pw@llm.test/v1" }] }, /must not contain credentials; use apiKeyEnv/],
    ["apiKeyEnv that is not a variable name", { ...valid, upstreams: [{ ...upstream, apiKeyEnv: "sk-not-a-name" }] }, /apiKeyEnv must be the name of an environment variable/],
    ["no models", { ...valid, upstreams: [{ ...upstream, models: {} }] }, /models must map at least one alias/],
    ["negative price", { ...valid, upstreams: [{ ...upstream, pricePerMTok: { input: -1, output: 1 } }] }, /pricePerMTok\.input must be a number, 0 or more/],
    ["no routes", { ...valid, routes: [] }, /at least one route/],
    ["route to an unknown upstream", { ...valid, routes: [{ id: "r", use: { upstream: "nope" } }] }, /config\.routes\[0\]\.use\.upstream "nope" is not one of the upstreams/],
    ["route to an alias the upstream lacks", { ...valid, routes: [{ id: "r", use: { upstream: "cheap", model: "large" } }] }, /config\.routes\[0\]\.use\.model: upstream "cheap" has no model alias "large"/],
    [
      "fallback without the fixed alias",
      { ...valid, upstreams: [upstream, { ...upstream, name: "other", models: { tiny: "t" } }], routes: [{ id: "r", use: { upstream: "cheap", model: "small" }, fallback: { upstream: "other" } }] },
      /config\.routes\[0\]\.fallback: upstream "other" has no model alias "small"/,
    ],
    ["duplicate route ids", { ...valid, routes: [valid.routes[0], valid.routes[0]] }, /config\.routes\[1\]\.id "all" is already used/],
    ["empty task list", { ...valid, routes: [{ id: "r", when: { task: [] }, use: { upstream: "cheap" } }] }, /config\.routes\[0\]\.when\.task must not be an empty list/],
    ["unknown condition", { ...valid, routes: [{ id: "r", when: { team: "a" }, use: { upstream: "cheap" } }] }, /config\.routes\[0\]\.when has an unknown field "team"/],
    ["no keys", { ...valid, keys: [] }, /at least one gateway key/],
    ["a key instead of its hash", { ...valid, keys: [{ ...valid.keys[0], sha256: "demo-gateway-key" }] }, /sha256 must be 64 lowercase hex characters \(the SHA-256 of the key, not the key\)/],
    ["duplicate key hashes", { ...valid, keys: [valid.keys[0], { ...valid.keys[0], name: "other" }] }, /config\.keys\[1\]\.sha256 is the same as an earlier key's/],
    ["zero daily cap", { ...valid, keys: [{ ...valid.keys[0], dailyUsd: 0 }] }, /config\.keys\[0\]\.dailyUsd must be a positive number/],
    ["retries above the limit", { ...valid, retries: 4 }, /config\.retries must be a whole number from 0 to 3/],
    ["port out of range", { ...valid, listen: { port: 70000 } }, /config\.listen\.port must be a whole number from 0 to 65535/],
    ["unknown field", { ...valid, budget: {} }, /config has an unknown field "budget"/],
  ];
  for (const [name, json, message] of table) {
    it(`rejects: ${name}`, () => assert.throws(() => parseLlmConfig(json, "/srv"), (err: unknown) => err instanceof ConfigError && message.test(err.message)));
  }
});
