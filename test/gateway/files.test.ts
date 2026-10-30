// Tests for binding approvals to file content (src/gateway/files.ts): which files are bound, and how.
import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { bindFiles, sameFiles, type FileBindingConfig } from "../../src/gateway/files.js";

const sha = (text: string) => `sha256:${createHash("sha256").update(text).digest("hex")}`;

describe("bindFiles", () => {
  let tmp: string;
  let root: string;
  let outside: string;
  let config: FileBindingConfig;

  beforeEach(() => {
    // realpath: on macOS the temp folder itself sits behind a symlink (/var -> /private/var)
    tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-files-")));
    root = path.join(tmp, "work");
    outside = path.join(tmp, "elsewhere");
    fs.mkdirSync(path.join(root, "sub"), { recursive: true });
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(root, "report.txt"), "v1");
    fs.writeFileSync(path.join(outside, "secret.txt"), "not yours");
    config = { roots: [root], arguments: ["path", "source"] };
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it("binds an absolute path inside a root to the hash of its content", () => {
    assert.deepEqual(bindFiles({ path: path.join(root, "report.txt") }, config), [{ argument: "path", path: path.join(root, "report.txt"), sha256: sha("v1") }]);
  });

  it("binds a file that does not exist yet, in a folder inside a root, as null", () => {
    assert.deepEqual(bindFiles({ path: path.join(root, "sub", "new.txt") }, config), [{ argument: "path", path: path.join(root, "sub", "new.txt"), sha256: null }]);
  });

  it("follows symlinks: a link out of the root is not bound, a link into it is bound by its real path", () => {
    fs.symlinkSync(path.join(outside, "secret.txt"), path.join(root, "link-out.txt"));
    fs.symlinkSync(path.join(root, "report.txt"), path.join(outside, "link-in.txt"));
    assert.deepEqual(bindFiles({ path: path.join(root, "link-out.txt") }, config), []);
    assert.deepEqual(bindFiles({ path: path.join(outside, "link-in.txt") }, config), [{ argument: "path", path: path.join(root, "report.txt"), sha256: sha("v1") }]);
  });

  it("does not bind: a relative path, a path outside the roots, '..' out of a root, a folder, a missing folder", () => {
    for (const value of ["report.txt", "./work/report.txt", path.join(outside, "secret.txt"), path.join(root, "..", "elsewhere", "secret.txt"), path.join(root, "sub"), path.join(root, "gone", "x.txt"), `${root}-sibling/x.txt`]) {
      assert.deepEqual(bindFiles({ path: value }, config), [], value);
    }
  });

  it("reads only the listed arguments, only strings, and only own properties", () => {
    const file = path.join(root, "report.txt");
    assert.deepEqual(bindFiles({ target: file, path: 42 }, config), []);
    assert.deepEqual(bindFiles(Object.create({ path: file }) as Record<string, unknown>, config), []);
    assert.deepEqual(bindFiles({ source: file, path: file }, config).map((f) => f.argument), ["path", "source"]);
  });

  it("sameFiles: equal content is the same; a change, a deletion or a new binding is not", () => {
    const before = bindFiles({ path: path.join(root, "report.txt") }, config);
    assert.equal(sameFiles(before, bindFiles({ path: path.join(root, "report.txt") }, config)), true);
    assert.equal(sameFiles(undefined, []), true);
    fs.writeFileSync(path.join(root, "report.txt"), "v2");
    assert.equal(sameFiles(before, bindFiles({ path: path.join(root, "report.txt") }, config)), false);
    fs.rmSync(path.join(root, "report.txt"));
    assert.equal(sameFiles(before, bindFiles({ path: path.join(root, "report.txt") }, config)), false);
    assert.equal(sameFiles(undefined, before), false);
  });
});
