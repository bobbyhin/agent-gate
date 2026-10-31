// The audit log: one JSON line per decision, appended to <stateDir>/audit.jsonl.
// Several kinds of line share the file. The gateway writes one per tool call before it forwards
// anything (AuditEntry, no "event" field), and one more when a forwarded call comes back
// (CallResultEvent, "event": "call-result": how long it took and a hash of what came back, joined to
// its call by connId and seq). The CLI writes one when a human answers an approval request or finds
// it expired (ApprovalEvent, "event": "approval-decided"); approvals.json forgets a request a week
// after it expires, and these lines are the lasting record of who decided what and how long it waited.
// ponytail: the file is never rotated or shipped anywhere; that is left to the operator.

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import { canonicalJson } from "./approvals.js";
import type { CallContext } from "./context.js";
import type { Decision } from "./policy.js";

export interface ApprovalEvent {
  ts: string;
  event: "approval-decided";
  approvalId: string;
  server: string;
  tool: string;
  rule: string;
  argsHash: string;
  /** "expired": a human came to decide after the request had expired. */
  decision: "approved" | "denied" | "expired";
  /** Milliseconds from the request to the decision; for "expired", to the expiry. */
  waitMs: number;
  decidedBy?: string;
  /** The human's reason or note, as stored in approvals.json (one line, at most 500 characters). */
  note?: string;
  /** For "approved": "typed" after the read-back, or "--yes". */
  confirmation?: "typed" | "--yes";
}

/** A standing approval granted or revoked by a human (ADR 0006). Its globs are the human's patterns, not call values. */
export interface StandingEvent {
  ts: string;
  event: "standing-approval";
  id: string;
  decision: "granted" | "revoked";
  server: string;
  tool: string;
  args: Record<string, string>;
  maxUses: number;
  used: number;
  expiresAt: string;
  decidedBy?: string;
  note?: string;
}

export interface AuditEntry extends CallContext {
  ts: string;
  /** The gateway connection the call came in on: one per "agent-gate serve" process, "cn-" and 8 hex digits. */
  connId: string;
  /** The call's place in its connection, from 1. Its call-result line has the same connId and seq. */
  seq: number;
  server: string;
  tool: string;
  decision: Decision;
  rule: string;
  why: string;
  /** Ties the line to an approval, or to a call someone has in hand, without storing the values. */
  argsHash: string;
  /** True when the call was sent on to the downstream server. */
  forwarded: boolean;
  approvalId?: string;
  /** "http" for a server reached over Streamable HTTP; absent for one started over stdio. */
  transport?: "http";
  /** Set when rewrite rules edited the arguments: argsHash is then the edited call's, this the agent's. */
  originalArgsHash?: string;
  rewrittenBy?: string[];
  /** Rules after the deciding one that matched too (policy.ts); they decided nothing. */
  alsoMatched?: string[];
  /** Only present when "auditArguments" is true in the gateway config. */
  args?: Record<string, unknown>;
}

/** What came back from a forwarded call. The result itself is never stored, only its hash and size. */
export interface CallResultEvent {
  ts: string;
  event: "call-result";
  connId: string;
  seq: number;
  server: string;
  tool: string;
  argsHash: string;
  /** Milliseconds from forwarding the call to the downstream server's answer. Time spent waiting for a human is not in it. */
  durationMs: number;
  /** The result said isError: true, or the call failed and there is no result (errorCode). */
  isError: boolean;
  /** sha256 of the canonical JSON of the result the agent got. Someone holding a result can hash it and compare. */
  resultHash?: string;
  /** The size of that canonical JSON in bytes. */
  resultBytes?: number;
  /** The JSON-RPC error code when the call failed without a result, for example -32001 (timeout). */
  errorCode?: number;
  /** When the gateway changed the result (result guard, rewrite note): the hash of what the downstream server sent. */
  originalResultHash?: string;
  /** The result guard's block rule that withheld the result. */
  withheld?: string;
  /** The result guard's redact rules that changed it. */
  redacted?: string[];
  /** Instruction-like text the result guard found (result-guard.ts). */
  flags?: string[];
}

/** A change to the pinned tool definitions (src/gateway/tool-pins.ts). */
export interface ToolEvent {
  ts: string;
  event: "tool-pinned" | "tool-changed" | "tool-accepted";
  server: string;
  tool: string;
  /** The definition's hash: for tool-changed, the new one, with the pinned one in pinnedSha256. */
  sha256: string;
  pinnedSha256?: string;
  decidedBy?: string;
}

/** sha256 of canonical JSON (object keys sorted), with its size: how the audit log names a value without storing it. */
export function hashJson(value: unknown): { hash: string; bytes: number } {
  const text = canonicalJson(value);
  return { hash: `sha256:${createHash("sha256").update(text).digest("hex")}`, bytes: Buffer.byteLength(text) };
}

export class AuditLog {
  constructor(
    readonly file: string,
    private readonly withArguments = false,
  ) {}

  /**
   * Appends one line, or throws. The gateway does not run a call it could not record.
   *
   * Argument values are left out by default. Tool arguments routinely carry secrets (API tokens,
   * passwords, connection strings) and personal data (names, addresses, message bodies), while an
   * audit log is kept for a long time and read by more people than the call itself. The hash is
   * enough to match a line to an approval or to a call that someone already has in hand.
   */
  write(entry: Omit<AuditEntry, "ts" | "args">, args: Record<string, unknown>, now = new Date()): AuditEntry {
    const line: AuditEntry = { ts: now.toISOString(), ...entry };
    if (this.withArguments) line.args = args;
    fs.appendFileSync(this.file, `${JSON.stringify(line)}\n`, { mode: 0o600 });
    return line;
  }

  /** Appends the line for a call that came back, or throws. Its value stays out; its hash and size go in. */
  writeResult(event: Omit<CallResultEvent, "ts" | "event">, now = new Date()): CallResultEvent {
    const line: CallResultEvent = { ts: now.toISOString(), event: "call-result", ...event };
    fs.appendFileSync(this.file, `${JSON.stringify(line)}\n`, { mode: 0o600 });
    return line;
  }

  /** Appends one tool-definition event, or throws. */
  writeTool(event: Omit<ToolEvent, "ts">, now = new Date()): ToolEvent {
    const line: ToolEvent = { ts: now.toISOString(), ...event };
    fs.appendFileSync(this.file, `${JSON.stringify(line)}\n`, { mode: 0o600 });
    return line;
  }

  /** Appends one standing-approval event, or throws. */
  writeStanding(event: Omit<StandingEvent, "ts" | "event">, now = new Date()): StandingEvent {
    const line: StandingEvent = { ts: now.toISOString(), event: "standing-approval", ...event };
    fs.appendFileSync(this.file, `${JSON.stringify(line)}\n`, { mode: 0o600 });
    return line;
  }

  /** Appends one approval event, or throws. Like a call line, it holds the arguments' hash, never their values. */
  writeEvent(event: Omit<ApprovalEvent, "ts" | "event">, now = new Date()): ApprovalEvent {
    const line: ApprovalEvent = { ts: now.toISOString(), event: "approval-decided", ...event };
    fs.appendFileSync(this.file, `${JSON.stringify(line)}\n`, { mode: 0o600 });
    return line;
  }
}
