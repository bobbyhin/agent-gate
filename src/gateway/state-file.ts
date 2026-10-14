// Small JSON state files shared by a long-running gateway and the CLI: the MCP gateway's
// approvals.json and the LLM gateway's ledger.json.
//
// They are separate processes, so every change is a locked read-modify-write, and every write goes
// to a temporary file that is then renamed over the old one: a reader sees the old file or the new
// one, never half of one. Readers that only read do not need the lock.

import { randomBytes } from "node:crypto";
import * as fs from "node:fs";

const LOCK_WAIT_MS = 5000;
const LOCK_STALE_MS = 10_000;

/**
 * Runs `fn` while holding `lockDir` (a directory: mkdir either creates it or fails, atomically).
 * A lock older than 10 seconds is treated as left behind by a crashed process and broken.
 * ponytail: a lock directory with a stale timeout. Enough for one gateway plus a human at the
 * CLI on a local disk; many concurrent writers or a network filesystem would need a database.
 */
export function withLock<T>(dir: string, lockDir: string, fn: () => T): T {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      fs.mkdirSync(lockDir);
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      if (ageMs(lockDir) > LOCK_STALE_MS) {
        fs.rmSync(lockDir, { recursive: true, force: true });
        continue;
      }
      if (Date.now() > deadline) throw new Error(`${lockDir} is held by another process; try again`);
      sleep(20);
    }
  }
  try {
    return fn();
  } finally {
    fs.rmSync(lockDir, { recursive: true, force: true });
  }
}

/** Write to a temporary file, flush it to disk, then rename it over the target. */
export function writeAtomic(file: string, content: string): void {
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  try {
    const fd = fs.openSync(tmp, "wx", 0o600);
    try {
      fs.writeFileSync(fd, content);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
}

/** The file's content, or undefined when it does not exist yet. Any other error is thrown. */
export function readIfExists(file: string): string | undefined {
  try {
    return fs.readFileSync(file, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
}

function ageMs(file: string): number {
  try {
    return Date.now() - fs.statSync(file).mtimeMs;
  } catch {
    return 0; // released in the meantime: just try again
  }
}

const sleeper = new Int32Array(new SharedArrayBuffer(4));
function sleep(ms: number): void {
  Atomics.wait(sleeper, 0, 0, ms);
}
