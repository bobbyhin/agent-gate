// The approval queue behind the "ask" decision.
//
// A call that needs a human is not run. The gateway records it here as a pending approval and
// tells the agent the approval id. A human approves or denies it with the CLI. An approval is
// bound to one exact call (server, tool and a hash of the arguments): it lets that call through
// once, and is then marked "used". Denied and expired approvals never let anything through.
//
// Everything lives in one JSON file, <stateDir>/approvals.json. The gateway and the CLI are
// separate processes, so every change is a locked read-modify-write, and every write goes to a
// temporary file that is then renamed over the old one: a reader sees the old file or the new
// one, never half of one.

import { createHash, randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

export type ApprovalStatus = "pending" | "approved" | "denied" | "used";

export interface Approval {
  id: string;
  server: string;
  tool: string;
  /** sha256 of the canonical JSON of the arguments. An approval covers exactly these arguments. */
  argsHash: string;
  /**
   * The arguments themselves, because the human has to see what they are approving. Unlike the
   * audit log, this file is short-lived: records are dropped a week after they expire.
   */
  args: Record<string, unknown>;
  rule: string;
  why: string;
  status: ApprovalStatus;
  createdAt: string;
  /** createdAt + TTL. After this, the record cannot be approved and cannot allow a call. */
  expiresAt: string;
  decidedAt?: string;
  usedAt?: string;
}

export interface AskRequest {
  server: string;
  tool: string;
  args: Record<string, unknown>;
  argsHash: string;
  rule: string;
  why: string;
}

export type AskOutcome =
  /** An approval for this exact call existed and has now been used up: run the call. */
  | { kind: "approved"; approval: Approval }
  /** Waiting for a human. `created` is false when the agent repeated a call that is already queued. */
  | { kind: "pending"; approval: Approval; created: boolean }
  /** A human said no to this exact call. */
  | { kind: "denied"; approval: Approval };

/** A request the CLI cannot carry out, such as approving an expired id. */
export class ApprovalError extends Error {
  override name = "ApprovalError";
}

const FILE_VERSION = 1;
const KEEP_AFTER_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;
const LOCK_WAIT_MS = 5000;
const LOCK_STALE_MS = 10_000;

/** JSON with object keys sorted at every level, so equal arguments always give the same text. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>;
    const fields = Object.keys(record)
      .filter((key) => record[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`);
    return `{${fields.join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

export function hashArguments(args: Record<string, unknown>): string {
  return `sha256:${createHash("sha256").update(canonicalJson(args)).digest("hex")}`;
}

/** True while an approval can still be approved, denied or used. A malformed date counts as expired. */
export function isLive(approval: Approval, now: number): boolean {
  return approval.status !== "used" && now < Date.parse(approval.expiresAt);
}

export class ApprovalStore {
  readonly file: string;
  private readonly lockDir: string;

  /** `now` is injectable so that tests can move the clock past the TTL. */
  constructor(
    readonly dir: string,
    readonly ttlMs: number,
    private readonly now: () => number = Date.now,
  ) {
    this.file = path.join(dir, "approvals.json");
    this.lockDir = path.join(dir, "approvals.lock");
  }

  list(): Approval[] {
    return this.read();
  }

  get(id: string): Approval {
    return find(this.read(), id);
  }

  /** Called by the gateway for every "ask" verdict. */
  resolveAsk(request: AskRequest): AskOutcome {
    return this.update((approvals, now) => {
      const sameCall = approvals.filter(
        (a) => a.server === request.server && a.tool === request.tool && a.argsHash === request.argsHash && isLive(a, now),
      );
      // A denial wins over everything else for the same call.
      const denied = sameCall.find((a) => a.status === "denied");
      if (denied) return { kind: "denied", approval: denied };
      const approved = sameCall.find((a) => a.status === "approved");
      if (approved) {
        approved.status = "used";
        approved.usedAt = new Date(now).toISOString();
        return { kind: "approved", approval: approved };
      }
      const pending = sameCall.find((a) => a.status === "pending");
      if (pending) return { kind: "pending", approval: pending, created: false };
      const created: Approval = {
        id: newId(approvals),
        server: request.server,
        tool: request.tool,
        argsHash: request.argsHash,
        args: request.args,
        rule: request.rule,
        why: request.why,
        status: "pending",
        createdAt: new Date(now).toISOString(),
        expiresAt: new Date(now + this.ttlMs).toISOString(),
      };
      approvals.push(created);
      return { kind: "pending", approval: created, created: true };
    });
  }

  approve(id: string): Approval {
    return this.update((approvals, now) => {
      const approval = find(approvals, id);
      if (approval.status !== "pending") throw new ApprovalError(`${id} is ${approval.status}; only a pending request can be approved`);
      if (!isLive(approval, now)) throw new ApprovalError(`${id} expired at ${approval.expiresAt}; the agent has to make the call again to ask again`);
      approval.status = "approved";
      approval.decidedAt = new Date(now).toISOString();
      return approval;
    });
  }

  /** Denies a pending request, or takes back an approval that has not been used yet. */
  deny(id: string): Approval {
    return this.update((approvals, now) => {
      const approval = find(approvals, id);
      if (approval.status !== "pending" && approval.status !== "approved") {
        throw new ApprovalError(`${id} is ${approval.status}; only a pending or an unused approved request can be denied`);
      }
      if (!isLive(approval, now)) throw new ApprovalError(`${id} expired at ${approval.expiresAt}; it can no longer allow anything`);
      approval.status = "denied";
      approval.decidedAt = new Date(now).toISOString();
      return approval;
    });
  }

  private read(): Approval[] {
    let content: string;
    try {
      content = fs.readFileSync(this.file, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    let data: unknown;
    try {
      data = JSON.parse(content);
    } catch (err) {
      throw new Error(`${this.file} is not valid JSON (${(err as Error).message}); fix or remove it`);
    }
    // Fail closed: a damaged file is an error, never an empty queue, because an empty queue
    // would forget denials.
    const file = data as { version?: unknown; approvals?: unknown } | null;
    if (typeof file !== "object" || file === null || file.version !== FILE_VERSION || !Array.isArray(file.approvals)) {
      throw new Error(`${this.file} is not a version ${FILE_VERSION} approvals file; fix or remove it`);
    }
    return file.approvals as Approval[];
  }

  private update<T>(change: (approvals: Approval[], now: number) => T): T {
    return this.locked(() => {
      const approvals = this.read();
      const before = JSON.stringify(approvals);
      const now = this.now();
      const result = change(approvals, now);
      const kept = approvals.filter((a) => Date.parse(a.expiresAt) + KEEP_AFTER_EXPIRY_MS > now);
      if (JSON.stringify(kept) !== before) {
        writeAtomic(this.file, `${JSON.stringify({ version: FILE_VERSION, approvals: kept }, null, 2)}\n`);
      }
      return result;
    });
  }

  // ponytail: a lock directory with a stale timeout. Enough for one gateway plus a human at the
  // CLI on a local disk; many concurrent writers or a network filesystem would need a database.
  private locked<T>(fn: () => T): T {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const deadline = Date.now() + LOCK_WAIT_MS;
    for (;;) {
      try {
        fs.mkdirSync(this.lockDir);
        break;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
        if (ageMs(this.lockDir) > LOCK_STALE_MS) {
          fs.rmSync(this.lockDir, { recursive: true, force: true });
          continue;
        }
        if (Date.now() > deadline) throw new Error(`${this.lockDir} is held by another process; try again`);
        sleep(20);
      }
    }
    try {
      return fn();
    } finally {
      fs.rmSync(this.lockDir, { recursive: true, force: true });
    }
  }
}

function find(approvals: Approval[], id: string): Approval {
  const approval = approvals.find((a) => a.id === id);
  if (!approval) throw new ApprovalError(`no approval with id ${id}`);
  return approval;
}

function newId(taken: Approval[]): string {
  for (;;) {
    const id = `ap-${randomBytes(4).toString("hex")}`;
    if (!taken.some((a) => a.id === id)) return id;
  }
}

/** Write to a temporary file, flush it to disk, then rename it over the target. */
function writeAtomic(file: string, content: string): void {
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
