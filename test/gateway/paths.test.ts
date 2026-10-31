// Path matchers in the policy: { under }, { outside } and { touches }. A path is read every way the
// gateway knows (as written, decoded, lexically, with symlinks resolved like the kernel does), and a
// reading it cannot place (relative, "~", NUL, a bad escape, a loop) counts against "under" and for
// "touches": it could be anywhere, so both fail closed.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { evaluate, parsePolicy, pathReadings } from "../../src/gateway/policy.js";
import { ConfigError } from "../../src/gateway/validate.js";

let base: string; // as os.tmpdir() spells it (on macOS a symlink: /var -> /private/var)
let root: string;
let outside: string;
let state: string;

before(() => {
  base = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-paths-"));
  root = path.join(base, "root");
  outside = path.join(base, "outside");
  state = path.join(root, ".agent-gate");
  fs.mkdirSync(path.join(root, "notes"), { recursive: true });
  fs.mkdirSync(state);
  fs.mkdirSync(outside);
  fs.writeFileSync(path.join(root, "notes", "old.md"), "old notes\n");
  fs.writeFileSync(path.join(outside, "secret.txt"), "not for agents\n");
  fs.symlinkSync(path.join("..", "outside"), path.join(root, "link-out"));
  fs.symlinkSync("notes", path.join(root, "link-in"));
  fs.symlinkSync(".agent-gate", path.join(root, "state-link"));
  fs.symlinkSync("loop-b", path.join(root, "loop-a"));
  fs.symlinkSync("loop-a", path.join(root, "loop-b"));
});

after(() => fs.rmSync(base, { recursive: true, force: true }));

/** One rule whose only condition is the path matcher; true when it matches the value. */
function matches(spec: unknown, value: unknown): boolean {
  const policy = parsePolicy({ default: "allow", rules: [{ id: "m", args: { path: spec }, decision: "block", why: "matched" }] });
  return evaluate(policy, { server: "files", tool: "read_file", args: { path: value } }).rule === "m";
}

describe("path matchers: under, outside and touches", () => {
  it("under: every way of reading the path stays inside the folder", () => {
    const real = fs.realpathSync(root);
    const table: Array<[string, unknown, boolean, boolean]> = [
      // [what, value, under (symlinks resolved), under with "symlinks": "ignore"]
      ["a file inside", path.join(root, "notes", "old.md"), true, true],
      ["a file not created yet", path.join(root, "notes", "new.md"), true, true],
      ["the same file through its real path (lexically, the same only where tmp is not a symlink)", path.join(real, "notes", "old.md"), true, real === root],
      ["a symlink that stays inside", path.join(root, "link-in", "old.md"), true, true],
      ['".." out of the folder', `${root}/../outside/secret.txt`, false, false],
      ["an absolute path outside", path.join(outside, "secret.txt"), false, false],
      ["a symlink inside that points out", path.join(root, "link-out", "secret.txt"), false, true],
      ['".." after a symlink: the kernel goes to the parent of its target', `${root}/link-out/../notes/old.md`, false, true],
      ['".." after a folder that does not exist', `${root}/missing/../notes/old.md`, false, true],
      ["a percent-encoded ..", `${root}/%2e%2e/outside/secret.txt`, false, false],
      ["a double-encoded ..", `${root}/%252e%252e/outside/secret.txt`, false, false],
      ["an escape that does not decode", `${root}/notes/%E0%A4%A`, false, false],
      ["a NUL inside", `${root}/notes/old.md\0.txt`, false, false],
      ['"~": the server\'s home is not known', "~/notes/old.md", false, false],
      ["a relative path: the server's working folder is not known", "notes/old.md", false, false],
      ["a loop of symlinks", path.join(root, "loop-a", "x"), false, true],
      ["not a string", 42, false, false],
      ["a list, every item inside", [path.join(root, "notes", "old.md"), path.join(root, "link-in", "old.md")], true, true],
      ["a list with one item outside", [path.join(root, "notes", "old.md"), path.join(outside, "secret.txt")], false, false],
      ["an empty list", [], false, false],
    ];
    for (const [what, value, resolved, lexical] of table) {
      assert.equal(matches({ under: [root] }, value), resolved, `under: ${what}`);
      assert.equal(matches({ under: [root], symlinks: "ignore" }, value), lexical, `under, symlinks ignored: ${what}`);
      assert.equal(matches({ outside: [root] }, value), !resolved, `outside: ${what}`);
    }
  });

  it("touches: some way of reading the path lands inside, or cannot be placed, which is what protecting a folder needs", () => {
    const table: Array<[string, unknown, boolean]> = [
      ["the state folder's file", path.join(state, "approvals.json"), true],
      ["through a symlink to it", path.join(root, "state-link", "approvals.json"), true],
      ['".." into it', `${root}/notes/../.agent-gate/approvals.json`, true],
      ["a percent-encoded way in that only a decoding server takes", `${root}/notes/%2e%2e/.agent-gate/approvals.json`, true],
      ["a file next to it", path.join(root, "notes", "old.md"), false],
      ["an absolute path elsewhere", path.join(outside, "secret.txt"), false],
      ["a list with no item inside", [path.join(root, "notes", "old.md"), path.join(outside, "secret.txt")], false],
      ["a list with one item inside", [path.join(root, "notes", "old.md"), path.join(state, "approvals.json")], true],
      ["an empty list: no path at all", [], false],
      // Fail closed: a path the gateway cannot place could be inside. The real filesystem server reads a
      // relative path inside its own folder, so ".agent-gate/approvals.json" reaches the state when the
      // state is inside that folder (test/gateway/filesystem-red-team.test.ts does exactly that).
      ["a relative path", ".agent-gate/approvals.json", true],
      ["a relative path that looks harmless", "notes/old.md", true],
      ['"~": the server\'s home is not known', "~/.agent-gate/approvals.json", true],
      ["a file: URL, which some servers accept", `file://${state}/approvals.json`, true],
      ["a NUL inside", `${root}/notes/old.md\0.txt`, true],
      ["not a string", 42, true],
    ];
    for (const [what, value, expected] of table) assert.equal(matches({ touches: [state] }, value), expected, what);
  });

  it('"symlinks": "ignore" compares text after the lexical step: another spelling of the folder is not inside it', () => {
    // On a case-insensitive file system (the default on macOS and Windows) .AGENT-GATE is the same folder
    // as .agent-gate; only resolving symlinks (the default) reads the disk's own spelling. On a
    // case-sensitive one they are two folders, and the text comparison is right.
    const upper = path.join(root, ".AGENT-GATE", "approvals.json");
    assert.equal(matches({ touches: [state], symlinks: "ignore" }, upper), false);
    const foldsCase = fs.existsSync(path.join(root, ".AGENT-GATE"));
    assert.equal(matches({ touches: [state] }, upper), foldsCase, "resolving reads the disk's spelling where the disk folds case");
  });

  it("reads a path as written, decoded, lexically and with symlinks resolved", () => {
    const real = fs.realpathSync(root);
    assert.deepEqual(pathReadings(`${root}/link-out/../notes/old.md`, true), [path.join(real, "notes", "old.md"), path.join(fs.realpathSync(base), "notes", "old.md")]);
    assert.deepEqual(pathReadings(`${root}/%2e%2e/x`, false), [path.join(root, "%2e%2e", "x"), path.join(base, "x")]);
    assert.deepEqual(pathReadings("relative/x", true), [undefined]);
  });

  it("an allow rule for the workspace, before the red lines: writes inside run, writes that leave it ask", () => {
    const policy = parsePolicy({
      default: "allow",
      rules: [
        { id: "workspace-writes", tool: ["write_file", "edit_file"], args: { path: { under: [root] } }, decision: "allow", why: "inside the workspace" },
        { id: "red-line-4-overwrite", toolWords: ["write", "edit"], decision: "ask", why: "overwrites a file" },
      ],
    });
    const decide = (p: string) => evaluate(policy, { server: "files", tool: "write_file", args: { path: p, content: "" } }).rule;
    assert.equal(decide(path.join(root, "notes", "old.md")), "workspace-writes");
    assert.equal(decide(`${root}/../outside/secret.txt`), "red-line-4-overwrite");
    assert.equal(decide(path.join(root, "link-out", "secret.txt")), "red-line-4-overwrite");
  });

  it("refuses path matchers that cannot work, naming the field", () => {
    const bad: Array<[unknown, RegExp]> = [
      [{ under: ["relative/dir"] }, /policy\.rules\[0\]\.args\.path\.under\[0\] must be an absolute path/],
      [{ under: [] }, /under must list at least one folder/],
      [{ under: "/srv" }, /under must be an array/],
      [{ under: ["/srv"], outside: ["/srv"] }, /needs exactly one of "under", "outside" and "touches"/],
      [{ under: ["/srv"], symlinks: "follow" }, /symlinks must be "resolve" or "ignore"/],
      [{ under: ["/srv"], regex: "x" }, /has an unknown field "regex"/],
    ];
    for (const [spec, message] of bad) {
      assert.throws(() => parsePolicy({ default: "allow", rules: [{ id: "r", args: { path: spec }, decision: "block", why: "x" }] }), (err: unknown) => err instanceof ConfigError && message.test(err.message));
    }
    // A path matcher is for argument values, not for server or tool names.
    assert.throws(() => parsePolicy({ default: "allow", rules: [{ id: "r", tool: { under: ["/srv"] }, decision: "block", why: "x" }] }), ConfigError);
    // A list may mix globs and path matchers: any one may match.
    const mixed = parsePolicy({ default: "allow", rules: [{ id: "r", args: { path: ["*.env", { touches: [state] }] }, decision: "block", why: "x" }] });
    assert.equal(evaluate(mixed, { server: "s", tool: "t", args: { path: "/srv/app/.env" } }).rule, "r");
    assert.equal(evaluate(mixed, { server: "s", tool: "t", args: { path: path.join(root, "state-link", "x") } }).rule, "r");
  });
});
