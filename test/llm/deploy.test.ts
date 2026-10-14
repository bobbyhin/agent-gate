// Tests for the gateway configs under deploy/. They must pass the gateway's own checks, and agree
// with the paths that the Dockerfile, docker-compose.yml, the Kubernetes manifests and the
// Terraform for Cloud Run mount them at.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { hashKey, loadLeakPolicy, loadLlmConfig } from "../../src/llm/config.js";

// This file runs from dist/test/llm/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");

// Paths inside the container image.
const POLICY = "/etc/agent-gate/policy/llm-policy.json";
const STATE = "/var/lib/agent-gate";

interface ConfigJson {
  listen: unknown;
  stateDir: string;
  policy: string;
  upstreams: { baseUrl: string }[];
}

const read = (file: string): string => fs.readFileSync(path.join(ROOT, file), "utf8");

describe("deploy configs", () => {
  for (const file of ["deploy/compose/llm-gateway.config.json", "deploy/k8s/llm-gateway.config.json"]) {
    it(`${file} is a valid config that listens on all interfaces and uses the container's paths`, () => {
      const config = loadLlmConfig(path.join(ROOT, file));
      assert.deepEqual([config.host, config.port], ["0.0.0.0", 8787]);
      assert.equal(config.stateDir, STATE);
      assert.equal(config.policyFile, POLICY);
    });
  }

  it("the compose config is the example config, with container paths and the fake upstream's host", () => {
    const expected = JSON.parse(read("llm-gateway.config.example.json")) as ConfigJson;
    expected.listen = { host: "0.0.0.0", port: 8787 };
    expected.stateDir = STATE;
    expected.policy = POLICY;
    for (const upstream of expected.upstreams) upstream.baseUrl = "http://fake-upstream:9101/v1";
    assert.deepEqual(JSON.parse(read("deploy/compose/llm-gateway.config.json")), expected);
  });

  it("the Kubernetes and Cloud Run config refuses the demo key and calls providers over HTTPS only", () => {
    const config = loadLlmConfig(path.join(ROOT, "deploy/k8s/llm-gateway.config.json"));
    assert.ok(
      config.keys.every((key) => key.sha256 !== hashKey("demo-gateway-key-not-a-secret")),
      "a deployable config must not accept the key printed in the README",
    );
    assert.ok(
      [...config.upstreams.values()].every((upstream) => upstream.baseUrl.startsWith("https://")),
      "the NetworkPolicy lets the gateway out on port 443 only",
    );
  });

  it("deploy/k8s/llm-policy.json is a byte-for-byte copy of llm-policy.example.json", () => {
    assert.equal(read("deploy/k8s/llm-policy.json"), read("llm-policy.example.json"));
    assert.ok(loadLeakPolicy(path.join(ROOT, "deploy/k8s/llm-policy.json")));
  });
});
