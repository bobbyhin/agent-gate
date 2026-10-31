// The approval queue behind the "ask" decision.
//
// A call that needs a human is not run. The gateway records it here as a pending approval and
// tells the agent the approval id. A human approves or denies it with the CLI. An approval is
// bound to one exact call (server, tool and a hash of the arguments): it lets that call through
// once, and is then marked "used". Denied and expired approvals never let anything through.
// With "fileBinding" in the config, it is also bound to the content of the files the call names
// (src/gateway/files.ts): if one changed before the call came back, the approval is marked "stale"
// and a new request is queued.
//
// Everything lives in one JSON file, <stateDir>/approvals.json. The gateway and the CLI are
// separate processes, so every change is a locked read-modify-write, and every write goes to a
// temporary file that is then renamed over the old one: a reader sees the old file or the new
// one, never half of one (src/gateway/state-file.ts).

import { createHash, randomBytes } from "node:crypto";
import * as path from "node:path";
import { sameFiles, type BoundFile } from "./files.js";
import { readIfExists, withLock, writeAtomic } from "./state-file.js";

/** "stale": approved, but a file the call names changed before the call came back. It allows nothing. */
export type ApprovalStatus = "pending" | "approved" | "denied" | "used" | "stale";

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
  /** The files the arguments name and their content hashes when the request was made (fileBinding). */
  files?: BoundFile[];
  rule: string;
  why: string;
  status: ApprovalStatus;
  createdAt: string;
  /** createdAt + TTL. After this, the record cannot be approved and cannot allow a call. */
  expiresAt: string;
  decidedAt?: string;
  /** Who approved or denied it: the OS user that ran the CLI. */
  decidedBy?: string;
  /**
   * What the human wrote with the decision: the reason for a denial (--reason), a note for an
   * approval (--note). One line, cleaned by cleanNote(). A denial's reason is shown to the agent.
   */
  decisionNote?: string;
  /** How the human confirmed an approval: "typed" (the read-back, then the id's last characters) or "--yes". */
  confirmation?: Confirmation;
  usedAt?: string;
}

export type Confirmation = "typed" | "--yes";

/** Who decided and what they wrote: the optional extras of approve() and deny(). */
export interface DecisionInput {
  by?: string;
  note?: string;
  /** Approvals only: how the human confirmed. */
  confirmation?: Confirmation;
}

export interface AskRequest {
  server: string;
  tool: string;
  args: Record<string, unknown>;
  argsHash: string;
  rule: string;
  why: string;
  /** How long a new request lives: the rule's ttlMinutes. Absent: the store's TTL (approvalTtlHours). */
  ttlMs?: number;
  /** The files the arguments name, hashed now (fileBinding). Absent: none are bound. */
  files?: BoundFile[];
}

export type AskOutcome =
  /** An approval for this exact call existed and has now been used up: run the call. */
  | { kind: "approved"; approval: Approval }
  /**
   * Waiting for a human. `created` is false when the agent repeated a call that is already queued.
   * `replaced` is an approval of this call that went stale because a file it names changed.
   */
  | { kind: "pending"; approval: Approval; created: boolean; replaced?: Approval }
  /** A human said no to this exact call. */
  | { kind: "denied"; approval: Approval };

/** A request the CLI cannot carry out, such as approving an expired id. */
export class ApprovalError extends Error {
  override name = "ApprovalError";
  /** Set when the request had expired, so the CLI can record that it was found expired. */
  constructor(
    message: string,
    readonly expired?: Approval,
  ) {
    super(message);
  }
}

const FILE_VERSION = 1;
const KEEP_AFTER_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;
export const NOTE_MAX_CHARS = 500;
const BY_MAX_CHARS = 64;

// C0 and C1 control characters, DEL, the Unicode line and paragraph separators and the bidirectional
// text marks. Built from code points so that none of these characters has to appear in this file.
const range = (from: number, to: number): string => `${String.fromCharCode(from)}-${String.fromCharCode(to)}`;
const UNSAFE_CHARS = new RegExp(`[${range(0x00, 0x1f)}${range(0x7f, 0x9f)}${range(0x200e, 0x200f)}${range(0x2028, 0x202e)}${range(0x2066, 0x2069)}]`, "g");

/**
 * Makes what a human typed safe to store and to show to an agent: control characters, line breaks
 * and bidirectional-text marks become spaces, runs of spaces become one, and the text is cut at
 * `max` characters. Returns undefined when nothing is left. The agent sees the result only as a
 * quoted string, and it never changes a decision.
 */
export function cleanNote(text: string | undefined, max = NOTE_MAX_CHARS): string | undefined {
  if (text === undefined) return undefined;
  const one = text.replace(UNSAFE_CHARS, " ").replace(/\s+/g, " ").trim();
  if (one === "") return undefined;
  const chars = [...one];
  return chars.length <= max ? one : `${chars.slice(0, max - 1).join("")}…`;
}

function applyDecision(approval: Approval, now: number, input: DecisionInput): void {
  approval.decidedAt = new Date(now).toISOString();
  const by = cleanNote(input.by, BY_MAX_CHARS);
  const note = cleanNote(input.note);
  if (by === undefined) delete approval.decidedBy;
  else approval.decidedBy = by;
  if (note === undefined) delete approval.decisionNote;
  else approval.decisionNote = note;
  if (input.confirmation === undefined) delete approval.confirmation;
  else approval.confirmation = input.confirmation;
}

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
      let replaced: Approval | undefined;
      if (approved && sameFiles(approved.files, request.files)) {
        approved.status = "used";
        approved.usedAt = new Date(now).toISOString();
        return { kind: "approved", approval: approved };
      }
      if (approved) {
        // A file changed or went away since the human saw the request: this yes was for other content.
        approved.status = "stale";
        replaced = approved;
      }
      const pending = sameCall.find((a) => a.status === "pending");
      if (pending) return { kind: "pending", approval: pending, created: false, ...(replaced ? { replaced } : {}) };
      const created: Approval = {
        id: newId(approvals),
        server: request.server,
        tool: request.tool,
        argsHash: request.argsHash,
        args: request.args,
        ...(request.files ? { files: request.files } : {}),
        rule: request.rule,
        why: request.why,
        status: "pending",
        createdAt: new Date(now).toISOString(),
        expiresAt: new Date(now + (request.ttlMs ?? this.ttlMs)).toISOString(),
      };
      approvals.push(created);
      return { kind: "pending", approval: created, created: true, ...(replaced ? { replaced } : {}) };
    });
  }

  approve(id: string, input: DecisionInput = {}): Approval {
    return this.update((approvals, now) => {
      const approval = find(approvals, id);
      if (approval.status !== "pending") throw new ApprovalError(`${id} is ${approval.status}; only a pending request can be approved`);
      if (!isLive(approval, now)) throw new ApprovalError(`${id} expired at ${approval.expiresAt}; the agent has to make the call again to ask again`, { ...approval });
      approval.status = "approved";
      applyDecision(approval, now, input);
      return approval;
    });
  }

  /** Denies a pending request, or takes back an approval that has not been used yet. */
  deny(id: string, input: DecisionInput = {}): Approval {
    return this.update((approvals, now) => {
      const approval = find(approvals, id);
      if (approval.status !== "pending" && approval.status !== "approved") {
        throw new ApprovalError(`${id} is ${approval.status}; only a pending or an unused approved request can be denied`);
      }
      if (!isLive(approval, now)) throw new ApprovalError(`${id} expired at ${approval.expiresAt}; it can no longer allow anything`, { ...approval });
      approval.status = "denied";
      applyDecision(approval, now, input);
      return approval;
    });
  }

  private read(): Approval[] {
    const content = readIfExists(this.file);
    if (content === undefined) return [];
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
    return withLock(this.dir, this.lockDir, () => {
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
