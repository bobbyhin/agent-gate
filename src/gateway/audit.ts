// The audit log: one JSON line per decision, appended to <stateDir>/audit.jsonl.
// Two kinds of line share the file. The gateway writes one per tool call (AuditEntry, no "event"
// field). The CLI writes one when a human answers an approval request or finds it expired
// (ApprovalEvent, "event": "approval-decided"); approvals.json forgets a request a week after it
// expires, and these lines are the lasting record of who decided what and how long it waited.
// ponytail: the file is never rotated or shipped anywhere; that is left to the operator.

import * as fs from "node:fs";
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

export interface AuditEntry {
  ts: string;
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
  /** Only present when "auditArguments" is true in the gateway config. */
  args?: Record<string, unknown>;
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
