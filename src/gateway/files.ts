// Approvals bound to the content of the files a call names.
//
// An approval is bound to the exact arguments, and an argument that names a file is only text:
// approving "upload /work/report.pdf" said nothing about which report. With "fileBinding" in the
// gateway config, when a call needs a human, the gateway also hashes each file that the listed
// arguments name and keeps the hashes with the request. When the approved call comes back, it hashes
// the files again. If one has changed or gone, the approval no longer fits what the human saw: the
// call is not run, the approval is marked "stale", and a new request is queued.
//
// Which files are bound: the value of a listed argument, if it is an absolute path that leads,
// after every symlink is resolved, to a regular file inside one of the configured roots, or to a
// file that does not exist yet in a folder inside one. Not bound: a relative path (it depends on the
// downstream server's working directory, which the gateway cannot see), a path that leads outside
// the roots (by "..", by a symlink, or written that way), a directory, a file that cannot be read.
// ponytail: this narrows the window between the human's yes and the action to the moment between
// the second hash and the downstream server opening the file. It cannot close it: the downstream
// server reads the file itself.

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

export interface FileBindingConfig {
  /** Real paths (symlinks resolved) of the folders whose files may be bound. */
  roots: string[];
  /** The argument names whose values are file paths. */
  arguments: string[];
}

export interface BoundFile {
  argument: string;
  /** The real path, symlinks resolved. */
  path: string;
  /** "sha256:<hex>" of the content, or null when the file does not exist. */
  sha256: string | null;
}

/** The files that a call's arguments name, with their content hashes, in the order of config.arguments. */
export function bindFiles(args: Record<string, unknown>, config: FileBindingConfig): BoundFile[] {
  const bound: BoundFile[] = [];
  for (const argument of config.arguments) {
    // Own properties only: an argument named "constructor" must not read Object.prototype.
    const value = Object.prototype.hasOwnProperty.call(args, argument) ? args[argument] : undefined;
    if (typeof value !== "string") continue;
    const real = realPathInside(value, config.roots);
    if (real === undefined) continue;
    let sha256: string | null;
    try {
      if (!fs.statSync(real).isFile()) continue;
      sha256 = hashFile(real);
    } catch (err) {
      if (code(err) !== "ENOENT") continue;
      sha256 = null;
    }
    bound.push({ argument, path: real, sha256 });
  }
  return bound;
}

/** True when two bindings name the same files with the same content. No binding equals an empty one. */
export function sameFiles(a: BoundFile[] | undefined, b: BoundFile[] | undefined): boolean {
  const text = (files: BoundFile[] | undefined) => JSON.stringify((files ?? []).map((f) => [f.argument, f.path, f.sha256]));
  return text(a) === text(b);
}

/** The real path of `value` if it is absolute and leads inside a root; a missing file counts by its folder. */
function realPathInside(value: string, roots: string[]): string | undefined {
  if (!path.isAbsolute(value)) return undefined;
  let real: string;
  try {
    real = fs.realpathSync(value);
  } catch (err) {
    if (code(err) !== "ENOENT") return undefined;
    try {
      real = path.join(fs.realpathSync(path.dirname(value)), path.basename(value));
    } catch {
      return undefined;
    }
  }
  return roots.some((root) => real === root || real.startsWith(root.endsWith(path.sep) ? root : root + path.sep)) ? real : undefined;
}

function hashFile(file: string): string {
  const hash = createHash("sha256");
  const fd = fs.openSync(file, "r");
  try {
    const buffer = Buffer.alloc(1 << 20);
    for (let n = fs.readSync(fd, buffer, 0, buffer.length, null); n > 0; n = fs.readSync(fd, buffer, 0, buffer.length, null)) {
      hash.update(buffer.subarray(0, n));
    }
  } finally {
    fs.closeSync(fd);
  }
  return `sha256:${hash.digest("hex")}`;
}

function code(err: unknown): string | undefined {
  return (err as NodeJS.ErrnoException | undefined)?.code;
}
