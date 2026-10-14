// The CLI's exit codes: 0 done, 1 failed, 2 bad usage (checked before any file is read).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { main } from "../../src/gateway/cli.js";

async function run(...argv: string[]): Promise<{ code: number; out: string; err: string }> {
  let out = "";
  let err = "";
  const code = await main(argv, { out: (t) => (out += t), err: (t) => (err += t) });
  return { code, out, err };
}

describe("agent-gate CLI", () => {
  it("prints usage for --help", async () => {
    const r = await run("--help");
    assert.equal(r.code, 0);
    assert.match(r.out, /^Usage:\n {2}agent-gate serve/);
  });

  for (const argv of [[], ["approvals"], ["approvals", "frobnicate"], ["approvals", "approve"], ["approvals", "list", "extra"], ["serve", "now"], ["--bogus"]]) {
    it(`exits 2 for: ${argv.join(" ") || "(nothing)"}`, async () => {
      const r = await run(...argv, "--config", "/nonexistent/gateway.config.json");
      assert.equal(r.code, 2);
      assert.match(r.err, /Usage:/);
    });
  }

  it("exits 1 with a clear message when the config cannot be read", async () => {
    const r = await run("approvals", "list", "--config", "/nonexistent/gateway.config.json");
    assert.equal(r.code, 1);
    assert.match(r.err, /^agent-gate: cannot read the config file \/nonexistent\/gateway\.config\.json/);
  });
});
