// Tests for the gateway config file.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { DEFAULT_APPROVAL_TTL_HOURS, loadConfig, parseConfig } from "../../src/gateway/config.js";
import { VERSION } from "../../src/gateway/server.js";
import { ConfigError } from "../../src/gateway/validate.js";

// This file runs from dist/test/gateway/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");

describe("gateway config", () => {
  it("loads gateway.config.example.json and resolves paths against the config's directory", () => {
    const config = loadConfig(path.join(ROOT, "gateway.config.example.json"));
    assert.equal(config.policyFile, path.join(ROOT, "policy.example.json"));
    assert.equal(config.stateDir, path.join(ROOT, ".agent-gate"));
    assert.equal(config.approvalTtlMs, DEFAULT_APPROVAL_TTL_HOURS * 3600 * 1000);
    assert.equal(config.auditArguments, false);
    assert.deepEqual(config.servers, [{ name: "demo", command: "node", args: ["dist/test/gateway/fake-downstream.js"] }]);
  });

  it("accepts optional fields", () => {
    const config = parseConfig(
      {
        servers: [{ name: "files_v2", command: "npx", env: { TOKEN_FILE: "/run/token" } }],
        policy: "/etc/agent-gate/policy.json",
        stateDir: "state",
        approvalTtlHours: 0.5,
        auditArguments: true,
      },
      "/srv/gate",
    );
    assert.equal(config.policyFile, "/etc/agent-gate/policy.json");
    assert.equal(config.stateDir, path.resolve("/srv/gate", "state"));
    assert.equal(config.approvalTtlMs, 30 * 60 * 1000);
    assert.equal(config.auditArguments, true);
    assert.deepEqual(config.servers, [{ name: "files_v2", command: "npx", args: [], env: { TOKEN_FILE: "/run/token" } }]);
  });

  const valid = { servers: [{ name: "demo", command: "node" }], policy: "p.json", stateDir: "s" };
  const table: Array<[name: string, json: unknown, message: RegExp]> = [
    ["no servers", { ...valid, servers: [] }, /at least one server/],
    ["server name with __", { ...valid, servers: [{ name: "a__b", command: "x" }] }, /config\.servers\[0\]\.name must use/],
    ["server name ending in _", { ...valid, servers: [{ name: "a_", command: "x" }] }, /config\.servers\[0\]\.name must use/],
    ["duplicate server names", { ...valid, servers: [{ name: "a", command: "x" }, { name: "a", command: "y" }] }, /"a" is used twice/],
    ["missing command", { ...valid, servers: [{ name: "a" }] }, /config\.servers\[0\]\.command must be a non-empty string/],
    ["non-string argument", { ...valid, servers: [{ name: "a", command: "x", args: [1] }] }, /config\.servers\[0\]\.args\[0\] must be a string/],
    ["non-string env value", { ...valid, servers: [{ name: "a", command: "x", env: { N: 1 } }] }, /config\.servers\[0\]\.env\.N must be a string/],
    ["zero TTL", { ...valid, approvalTtlHours: 0 }, /approvalTtlHours must be a positive number/],
    ["missing stateDir", { servers: valid.servers, policy: "p.json" }, /config\.stateDir must be a non-empty string/],
    ["unknown field", { ...valid, statedir: "x" }, /config has an unknown field "statedir"/],
  ];
  for (const [name, json, message] of table) {
    it(`rejects: ${name}`, () => assert.throws(() => parseConfig(json, "/srv"), (err: unknown) => err instanceof ConfigError && message.test(err.message)));
  }

  it("reports the server version that package.json declares", () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
    assert.equal(VERSION, pkg.version);
  });
});
