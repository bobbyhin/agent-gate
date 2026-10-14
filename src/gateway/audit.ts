// The audit log: one JSON line per decision, appended to <stateDir>/audit.jsonl.
// ponytail: the file is never rotated or shipped anywhere; that is left to the operator.

import * as fs from "node:fs";
import type { Decision } from "./policy.js";

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
}
