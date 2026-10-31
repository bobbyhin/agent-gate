// Small JSON state files shared by a long-running gateway and the CLI: the MCP gateway's
// approvals.json and the LLM gateway's ledger.json.
//
// They are separate processes, so every change is a locked read-modify-write, and every write goes
// to a temporary file that is then renamed over the old one: a reader sees the old file or the new
// one, never half of one. Readers that only read do not need the lock.

import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

const LOCK_WAIT_MS = 5000;
const LOCK_STALE_MS = 10_000;
// A lock with no owner file: its holder died between creating the lock and writing its id there,
// a gap of microseconds, so after a second nobody is coming back for it.
const OWNERLESS_STALE_MS = 1000;

/**
 * Runs `fn` while holding `lockDir` (a directory: mkdir either creates it or fails, atomically).
 * The holder writes its process id into the lock. A lock whose holder is no longer running was
 * left behind by a crash (kill -9, power loss) and is broken at once; a lock with no id after a
 * second (a crash between the two steps), or any lock older than 10 seconds, is broken too.
 * ponytail: a lock directory with a stale timeout. Enough for one gateway plus a human at the
 * CLI on a local disk; many concurrent writers or a network filesystem would need a database.
 */
export function withLock<T>(dir: string, lockDir: string, fn: () => T): T {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      fs.mkdirSync(lockDir);
      try {
        fs.writeFileSync(path.join(lockDir, "owner"), String(process.pid));
      } catch {
        // the age check still breaks the lock if this process dies
      }
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      const owner = ownerOf(lockDir);
      const age = ageMs(lockDir);
      const abandoned = owner === undefined ? age > OWNERLESS_STALE_MS : owner !== process.pid && !isRunning(owner);
      if (abandoned || age > LOCK_STALE_MS) {
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

/**
 * Write to a temporary file, flush it to disk, then rename it over the target. Called only while
 * holding the target's lock, so a temporary file of this target whose writer is no longer running
 * was left by a write that a crash cut short, and is removed first.
 */
export function writeAtomic(file: string, content: string): void {
  removeLeftovers(file);
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

/** The process id written into a lock, if it can be read. */
function ownerOf(lockDir: string): number | undefined {
  try {
    const pid = Number(fs.readFileSync(path.join(lockDir, "owner"), "utf8"));
    return Number.isSafeInteger(pid) && pid > 0 ? pid : undefined;
  } catch {
    return undefined;
  }
}

/** True while a process with this id exists (signal 0 checks without sending anything). */
export function isRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM"; // it exists, it is just not ours
  }
}

/** Removes "<file>.<pid>.<hex>.tmp" files whose writer is no longer running. */
function removeLeftovers(file: string): void {
  const dir = path.dirname(file);
  const prefix = `${path.basename(file)}.`;
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return;
  }
  for (const name of names) {
    const m = /^(\d+)\.[0-9a-f]{8}\.tmp$/.exec(name.startsWith(prefix) ? name.slice(prefix.length) : "");
    const pid = m ? Number(m[1]) : NaN;
    if (m && pid !== process.pid && !isRunning(pid)) fs.rmSync(path.join(dir, name), { force: true });
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
