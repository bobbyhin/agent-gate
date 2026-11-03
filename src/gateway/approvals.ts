// The approval queue behind the "ask" decision.
//
// A call that needs a human is not run. The gateway records it here as a pending approval and
// tells the agent the approval id. A human approves or denies it with the CLI. An approval is
// bound to one exact call (server, tool and a hash of the arguments): it lets that call through
// once, and is then marked "used". Denied and expired approvals never let anything through.
// With "fileBinding" in the config, it is also bound to the content of the files the call names
// (src/gateway/files.ts): if one changed before the call came back, the approval is marked "stale"
// and a new request is queued. A call from an HTTP agent (serve --http) is bound to that agent too:
// another agent's identical call does not use it, and a standing approval covers only the agent it
// names (or, naming none, only calls that come with no agent: the stdio gateway).
// A call that an "irreversible" rule asks about (ADR 0013) is held to more: its request carries a
// nonce, the human's approval must carry the proof that its action token was given back
// (src/gateway/action-tokens.ts), the gateway checks that proof and that the token was not spent before
// (<stateDir>/spent-tokens.json, shared by every gateway process on the state directory), and no
// standing approval answers it. When such a call cannot use an approval (used, expired, issued
// for other arguments, without a valid proof, or replayed), the outcome says which, for the audit log.
//
// Everything lives in one JSON file, <stateDir>/approvals.json. The gateway and the CLI are
// separate processes, so every change is a locked read-modify-write, and every write goes to a
// temporary file that is then renamed over the old one: a reader sees the old file or the new
// one, never half of one (src/gateway/state-file.ts).

import { createHash, randomBytes } from "node:crypto";
import * as path from "node:path";
import { isNonce, newNonce } from "./action-tokens.js";
import { sameFiles, type BoundFile } from "./files.js";
import { globToRegExp, type AlsoMatched } from "./policy.js";
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
  /**
   * The agents the call passed through, as the client stated it (main>research-sub), from the call
   * that created the request. The gateway checked its format, not its truth.
   */
  agentPath?: string;
  /** Rules after the deciding one that matched too, so the human sees every reason, not only the first. */
  alsoMatched?: AlsoMatched[];
  /** Rewrite rules that edited the arguments; `args` are the edited ones, the call that will run. */
  rewrittenBy?: string[];
  /** The HTTP agent whose call made the request (authenticated by its key); only its own identical call can use it. */
  agent?: string;
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
  /**
   * How the human confirmed an approval: "typed" (the read-back, then the id's last characters),
   * "--yes", or "token" (the request's action token, for an irreversible call).
   */
  confirmation?: Confirmation;
  usedAt?: string;
  /** An "irreversible" rule asked (ADR 0013): the approval needs the request's action token. */
  irreversible?: true;
  /** The random id the action token is bound to, picked when the call asked. Not a secret: the key is. */
  nonce?: string;
  /** Written by the CLI when the action token checked out: an HMAC the gateway checks before the call runs. */
  tokenProof?: string;
}

export type Confirmation = "typed" | "--yes" | "token";

/** Who decided and what they wrote: the optional extras of approve() and deny(). */
export interface DecisionInput {
  by?: string;
  note?: string;
  /** Approvals only: how the human confirmed. */
  confirmation?: Confirmation;
  /** Approvals of an irreversible request: the proof that its action token was given back, made from the record as it is now. */
  prove?: (approval: Approval) => string;
}

/** What the gateway checks before an irreversible call uses an approval: its proof, and whether its token let a call through before. */
export interface TokenCheck {
  verify(approval: Approval): boolean;
  spent(nonce: string): boolean;
}

/**
 * Why an irreversible call did not use an approval: "used" (it let this call through already),
 * "expired", "wrong-arguments" (it was for this tool with other arguments), "invalid" (no valid proof:
 * not confirmed with its token, or the record was changed) or "replayed" (its token let a call through
 * before: an old copy of the record came back).
 */
export type TokenRefusalReason = "used" | "expired" | "wrong-arguments" | "invalid" | "replayed";

export interface TokenRefusal {
  reason: TokenRefusalReason;
  approval: Approval;
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
  /** The rule allows a standing approval to answer this call (policy "standing": true). */
  standing?: boolean;
  /** The client's agent path for this call (see Approval.agentPath). */
  agentPath?: string;
  alsoMatched?: AlsoMatched[];
  rewrittenBy?: string[];
  /** The HTTP agent making the call; absent for the stdio gateway. */
  agent?: string;
  /** An "irreversible" rule asked (ADR 0013): how to check an approval's action token. No standing approval answers. */
  irreversible?: TokenCheck;
}

/**
 * A standing approval (ADR 0006): one yes for a bounded set of calls to one tool, instead of one per
 * call. It covers a call to exactly that server and tool whose listed arguments are present, are
 * strings and match their globs (other arguments are free), at most `maxUses` times, until it expires,
 * and only when the rule that asked allows it. Each use is audited with its id.
 */
export interface StandingApproval {
  /** "sa-" and 8 hex digits. */
  id: string;
  server: string;
  tool: string;
  /** Argument name -> glob (as in policy rules: whole value, case-insensitive, * and ?). */
  args: Record<string, string>;
  /** The HTTP agent it is for; absent: calls that come with no agent (the stdio gateway). */
  agent?: string;
  maxUses: number;
  used: number;
  status: "active" | "revoked";
  createdAt: string;
  expiresAt: string;
  decidedBy?: string;
  decisionNote?: string;
  lastUsedAt?: string;
}

export interface GrantInput extends DecisionInput {
  server: string;
  tool: string;
  args: Record<string, string>;
  agent?: string;
  maxUses: number;
  ttlMs: number;
}

export const GRANT_MAX_USES = 100;
export const GRANT_MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export type AskOutcome =
  /** An approval for this exact call existed and has now been used up: run the call. */
  | { kind: "approved"; approval: Approval }
  /**
   * Waiting for a human. `created` is false when the agent repeated a call that is already queued.
   * `replaced` is an approval of this call that went stale because a file it names changed.
   * `refused`, for an irreversible call, is an approval it could not use, and why.
   */
  | { kind: "pending"; approval: Approval; created: boolean; replaced?: Approval; refused?: TokenRefusal }
  /** A human said no to this exact call. */
  | { kind: "denied"; approval: Approval };

/** What resolveCall() can answer: an AskOutcome, or a standing approval that covered the call. */
export type CallOutcome =
  | AskOutcome
  /** A standing approval covered the call, and one of its uses is now spent: run the call. */
  | { kind: "standing"; grant: StandingApproval };

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
  /**
   * The nonces of the action tokens that let a call through (ADR 0013), with the expiry of their
   * approvals: <stateDir>/spent-tokens.json, changed under the same lock as approvals.json, so every
   * gateway process on the state directory sees a token another one spent. Kept a week past expiry.
   */
  readonly spentFile: string;
  private readonly lockDir: string;

  /** `now` is injectable so that tests can move the clock past the TTL. */
  constructor(
    readonly dir: string,
    readonly ttlMs: number,
    private readonly now: () => number = Date.now,
  ) {
    this.file = path.join(dir, "approvals.json");
    this.spentFile = path.join(dir, "spent-tokens.json");
    this.lockDir = path.join(dir, "approvals.lock");
  }

  list(): Approval[] {
    return this.read().approvals;
  }

  get(id: string): Approval {
    return find(this.read().approvals, id);
  }

  standing(): StandingApproval[] {
    return this.read().standing;
  }

  getStanding(id: string): StandingApproval {
    const grant = this.read().standing.find((g) => g.id === id);
    if (!grant) throw new ApprovalError(`no standing approval with id ${id}`);
    return grant;
  }

  /** A human grants a standing approval. The bounds are required and capped. */
  grant(input: GrantInput): StandingApproval {
    if (!Number.isSafeInteger(input.maxUses) || input.maxUses < 1 || input.maxUses > GRANT_MAX_USES) {
      throw new ApprovalError(`--uses must be a whole number from 1 to ${GRANT_MAX_USES}`);
    }
    if (!Number.isFinite(input.ttlMs) || input.ttlMs <= 0 || input.ttlMs > GRANT_MAX_TTL_MS) {
      throw new ApprovalError(`--hours must be more than 0 and at most ${GRANT_MAX_TTL_MS / 3_600_000}`);
    }
    return this.update((_approvals, now, standing) => {
      const grant: StandingApproval = {
        id: newId("sa", standing),
        server: input.server,
        tool: input.tool,
        args: { ...input.args },
        ...(input.agent !== undefined ? { agent: input.agent } : {}),
        maxUses: input.maxUses,
        used: 0,
        status: "active",
        createdAt: new Date(now).toISOString(),
        expiresAt: new Date(now + input.ttlMs).toISOString(),
      };
      const by = cleanNote(input.by, BY_MAX_CHARS);
      const note = cleanNote(input.note);
      if (by !== undefined) grant.decidedBy = by;
      if (note !== undefined) grant.decisionNote = note;
      standing.push(grant);
      return grant;
    });
  }

  /** Takes a standing approval back; it allows nothing more. */
  revoke(id: string, input: DecisionInput = {}): StandingApproval {
    return this.update((_approvals, _now, standing) => {
      const grant = standing.find((g) => g.id === id);
      if (!grant) throw new ApprovalError(`no standing approval with id ${id}`);
      if (grant.status !== "active") throw new ApprovalError(`${id} is already ${grant.status}`);
      grant.status = "revoked";
      const by = cleanNote(input.by, BY_MAX_CHARS);
      const note = cleanNote(input.note);
      if (by !== undefined) grant.decidedBy = by;
      if (note !== undefined) grant.decisionNote = note;
      return grant;
    });
  }

  /** The exact-call queue alone: resolveCall() with standing approvals left out. */
  resolveAsk(request: AskRequest): AskOutcome {
    return this.resolveCall({ ...request, standing: false }) as AskOutcome;
  }

  /**
   * Called by the gateway for every "ask" verdict. In this order: a denial of this exact call wins;
   * then an approval of this exact call is used (for an irreversible call, only with a valid proof and a
   * token not spent before); then, if the rule allows it and the call is not irreversible, a standing
   * approval that covers the call; then the call waits for a human.
   */
  resolveCall(request: AskRequest): CallOutcome {
    return this.update((approvals, now, standing): CallOutcome => {
      // The same call from the same agent: an approval made for one agent's call is not another's.
      const sameCall = approvals.filter(
        (a) => a.server === request.server && a.tool === request.tool && a.argsHash === request.argsHash && a.agent === request.agent && isLive(a, now),
      );
      // A denial wins over everything else for the same call.
      const denied = sameCall.find((a) => a.status === "denied");
      if (denied) return { kind: "denied", approval: denied };
      const approved = sameCall.find((a) => a.status === "approved");
      const tokens = request.irreversible;
      let replaced: Approval | undefined;
      let refused: TokenRefusal | undefined;
      if (approved && !sameFiles(approved.files, request.files)) {
        // A file changed or went away since the human saw the request: this yes was for other content.
        approved.status = "stale";
        replaced = approved;
      } else if (approved && tokens && (!isNonce(approved.nonce) || !tokens.verify(approved))) {
        // Not confirmed with its action token, or written by something other than the CLI.
        approved.status = "stale";
        refused = { reason: "invalid", approval: approved };
      } else if (approved && tokens && (tokens.spent(approved.nonce as string) || this.spent(now).has(approved.nonce as string))) {
        // Its token let a call through before, in this process or another: an old copy of the record, brought back.
        approved.status = "used";
        refused = { reason: "replayed", approval: approved };
      } else if (approved) {
        approved.status = "used";
        approved.usedAt = new Date(now).toISOString();
        // Spent before the call goes on, where every gateway process on this state directory looks.
        if (tokens) this.spend(approved.nonce as string, approved.expiresAt, now);
        return { kind: "approved", approval: approved };
      }
      // A standing approval answers only when the rule allows it, never an irreversible call, and never over a denial (above).
      const grant = request.standing && !tokens ? standing.find((g) => covers(g, request, now)) : undefined;
      if (grant) {
        grant.used++;
        grant.lastUsedAt = new Date(now).toISOString();
        return { kind: "standing", grant };
      }
      const pending = sameCall.find((a) => a.status === "pending");
      if (pending) return { kind: "pending", approval: pending, created: false, ...(replaced ? { replaced } : {}), ...(refused ? { refused } : {}) };
      // A new request for an irreversible call: say which approval this call tried and could not use, if any.
      if (tokens && !refused) refused = unusable(approvals, request, now);
      const created: Approval = {
        id: newId("ap", approvals),
        server: request.server,
        tool: request.tool,
        argsHash: request.argsHash,
        args: request.args,
        ...(request.files ? { files: request.files } : {}),
        rule: request.rule,
        why: request.why,
        ...(request.agentPath ? { agentPath: request.agentPath } : {}),
        ...(request.alsoMatched ? { alsoMatched: request.alsoMatched } : {}),
        ...(request.rewrittenBy ? { rewrittenBy: request.rewrittenBy } : {}),
        ...(request.agent !== undefined ? { agent: request.agent } : {}),
        status: "pending",
        createdAt: new Date(now).toISOString(),
        expiresAt: new Date(now + (request.ttlMs ?? this.ttlMs)).toISOString(),
        ...(tokens ? { irreversible: true as const, nonce: newNonce() } : {}),
      };
      approvals.push(created);
      return { kind: "pending", approval: created, created: true, ...(replaced ? { replaced } : {}), ...(refused ? { refused } : {}) };
    });
  }

  /** An irreversible request is approved only with `input.prove`: the proof that its action token was given back (ADR 0013). */
  approve(id: string, input: DecisionInput = {}): Approval {
    return this.update((approvals, now) => {
      const approval = find(approvals, id);
      if (approval.status !== "pending") throw new ApprovalError(`${id} is ${approval.status}; only a pending request can be approved`);
      if (!isLive(approval, now)) throw new ApprovalError(`${id} expired at ${approval.expiresAt}; the agent has to make the call again to ask again`, { ...approval });
      if (approval.irreversible && !input.prove) throw new ApprovalError(`${id} is for an irreversible action (rule ${approval.rule}): it needs its action token, not only a yes`);
      approval.status = "approved";
      applyDecision(approval, now, input);
      if (approval.irreversible && input.prove) approval.tokenProof = input.prove(approval);
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

  /**
   * The spent nonces (ADR 0013) and the expiry of their approvals, as of `now`. Called under the lock.
   * Fail closed: a damaged file is an error, never an empty list, because an empty list would let a
   * replayed approval through.
   */
  private spent(now: number): Map<string, string> {
    const spent = new Map<string, string>();
    const content = readIfExists(this.spentFile);
    if (content === undefined) return spent;
    let data: unknown;
    try {
      data = JSON.parse(content);
    } catch (err) {
      throw new Error(`${this.spentFile} is not valid JSON (${(err as Error).message}); fix or remove it`);
    }
    const file = data as { version?: unknown; spent?: unknown } | null;
    if (typeof file !== "object" || file === null || file.version !== FILE_VERSION || typeof file.spent !== "object" || file.spent === null || Array.isArray(file.spent)) {
      throw new Error(`${this.spentFile} is not a version ${FILE_VERSION} spent-tokens file; fix or remove it`);
    }
    // An approval cannot be used past its expiry, so its nonce need not be kept much longer.
    for (const [nonce, until] of Object.entries(file.spent as Record<string, unknown>)) {
      if (typeof until === "string" && Date.parse(until) + KEEP_AFTER_EXPIRY_MS > now) spent.set(nonce, until);
    }
    return spent;
  }

  /** Records a nonce as spent. Called under the lock, before the call is forwarded. */
  private spend(nonce: string, expiresAt: string, now: number): void {
    const spent = this.spent(now);
    spent.set(nonce, expiresAt);
    writeAtomic(this.spentFile, `${JSON.stringify({ version: FILE_VERSION, spent: Object.fromEntries(spent) }, null, 2)}\n`);
  }

  private read(): { approvals: Approval[]; standing: StandingApproval[] } {
    const content = readIfExists(this.file);
    if (content === undefined) return { approvals: [], standing: [] };
    let data: unknown;
    try {
      data = JSON.parse(content);
    } catch (err) {
      throw new Error(`${this.file} is not valid JSON (${(err as Error).message}); fix or remove it`);
    }
    // Fail closed: a damaged file is an error, never an empty queue, because an empty queue
    // would forget denials.
    const file = data as { version?: unknown; approvals?: unknown; standing?: unknown } | null;
    if (typeof file !== "object" || file === null || file.version !== FILE_VERSION || !Array.isArray(file.approvals) || (file.standing !== undefined && !Array.isArray(file.standing))) {
      throw new Error(`${this.file} is not a version ${FILE_VERSION} approvals file; fix or remove it`);
    }
    return { approvals: file.approvals as Approval[], standing: (file.standing ?? []) as StandingApproval[] };
  }

  private update<T>(change: (approvals: Approval[], now: number, standing: StandingApproval[]) => T): T {
    return withLock(this.dir, this.lockDir, () => {
      const { approvals, standing } = this.read();
      const before = JSON.stringify({ approvals, standing });
      const now = this.now();
      const result = change(approvals, now, standing);
      const kept = approvals.filter((a) => Date.parse(a.expiresAt) + KEEP_AFTER_EXPIRY_MS > now);
      const keptStanding = standing.filter((g) => Date.parse(g.expiresAt) + KEEP_AFTER_EXPIRY_MS > now);
      if (JSON.stringify({ approvals: kept, standing: keptStanding }) !== before) {
        const file = { version: FILE_VERSION, approvals: kept, ...(keptStanding.length ? { standing: keptStanding } : {}) };
        writeAtomic(this.file, `${JSON.stringify(file, null, 2)}\n`);
      }
      return result;
    });
  }
}

/**
 * For a new request of an irreversible call: the approval this call came back for and could not use,
 * if there is one. Of this exact call: the latest used one that has not expired yet ("used": a token
 * lets one call through) or the latest approved one that expired ("expired"). Else an approval of this
 * tool, for this agent, with other arguments that is still good ("wrong-arguments": it covers only its
 * own call).
 */
function unusable(approvals: readonly Approval[], request: AskRequest, now: number): TokenRefusal | undefined {
  const mine = approvals.filter((a) => a.server === request.server && a.tool === request.tool && a.agent === request.agent);
  const latest = (list: Approval[]): Approval | undefined => list.reduce<Approval | undefined>((best, a) => (!best || a.createdAt > best.createdAt ? a : best), undefined);
  const same = mine.filter((a) => a.argsHash === request.argsHash);
  const spent = latest(same.filter((a) => (a.status === "used" && now < Date.parse(a.expiresAt)) || (a.status === "approved" && !isLive(a, now))));
  if (spent) return { reason: spent.status === "used" ? "used" : "expired", approval: spent };
  const other = latest(mine.filter((a) => a.argsHash !== request.argsHash && a.status === "approved" && isLive(a, now)));
  return other ? { reason: "wrong-arguments", approval: other } : undefined;
}

/** Does this standing approval cover the call now: same server and tool, live, uses left, every listed argument a matching string? */
function covers(grant: StandingApproval, request: AskRequest, now: number): boolean {
  if (grant.status !== "active" || grant.used >= grant.maxUses || now >= Date.parse(grant.expiresAt)) return false;
  if (grant.server !== request.server || grant.tool !== request.tool || grant.agent !== request.agent) return false;
  return Object.entries(grant.args).every(([name, glob]) => {
    const value = Object.prototype.hasOwnProperty.call(request.args, name) ? request.args[name] : undefined;
    return typeof value === "string" && globToRegExp(glob).test(value);
  });
}

function find(approvals: Approval[], id: string): Approval {
  const approval = approvals.find((a) => a.id === id);
  if (!approval) throw new ApprovalError(`no approval with id ${id}`);
  return approval;
}

function newId(prefix: "ap" | "sa", taken: ReadonlyArray<{ id: string }>): string {
  for (;;) {
    const id = `${prefix}-${randomBytes(4).toString("hex")}`;
    if (!taken.some((a) => a.id === id)) return id;
  }
}
