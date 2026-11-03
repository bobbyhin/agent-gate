// What a human's answer to an approval request does, whichever way it comes in: the CLI
// ("agent-gate approvals approve|deny") or the approvals page ("agent-gate approvals ui",
// src/gateway/approvals-ui.ts). Both call these functions, so a decision leaves the same record in
// approvals.json and the same lines in the audit log, and a request from an irreversible rule
// (ADR 0013) is held to the same checks, in the same order, with the same refusals.

import * as os from "node:os";
import { ActionTokens, isNonce, type TokenBinding } from "./action-tokens.js";
import { ApprovalError, canonicalJson, cleanNote, hashArguments, isLive, type Approval, type ApprovalStore, type Confirmation } from "./approvals.js";
import type { ActionTokenRefusal, ApprovalEvent, AuditLog } from "./audit.js";
import type { GatewayConfig } from "./config.js";
import { bindFiles } from "./files.js";
import { SEPARATOR } from "./server.js";

/** The OS user running the CLI or the approvals page, recorded as who decided. */
export function currentUser(): string | undefined {
  try {
    return cleanNote(os.userInfo().username, 64);
  } catch {
    return undefined;
  }
}

/** Records a human's decision in approvals.json, then as an approval-decided line in the audit log. */
export function decide(store: ApprovalStore, audit: AuditLog, id: string, decision: "approved" | "denied", note: string | undefined, confirmation?: Confirmation, prove?: (a: Approval) => string): Approval {
  const by = currentUser();
  let approval: Approval;
  try {
    approval = decision === "approved" ? store.approve(id, { by, note, ...(confirmation ? { confirmation } : {}), ...(prove ? { prove } : {}) }) : store.deny(id, { by, note });
  } catch (err) {
    // A request found expired is worth a line too: it shows how long requests wait unanswered.
    if (err instanceof ApprovalError && err.expired) {
      try {
        writeEvent(audit, err.expired, "expired", by);
      } catch {
        // the expiry error below is what the human needs to see
      }
    }
    throw err;
  }
  try {
    writeEvent(audit, approval, decision, approval.decidedBy);
  } catch (err) {
    throw new ApprovalError(`${id} is ${decision}, but the audit log could not be written: ${(err as Error).message}`);
  }
  return approval;
}

export function writeEvent(audit: AuditLog, a: Approval, decision: ApprovalEvent["decision"], by: string | undefined): void {
  const end = Date.parse(decision === "expired" ? a.expiresAt : (a.decidedAt ?? ""));
  audit.writeEvent({
    approvalId: a.id,
    server: a.server,
    tool: a.tool,
    rule: a.rule,
    argsHash: a.argsHash,
    decision,
    waitMs: Math.max(0, end - Date.parse(a.createdAt)) || 0,
    ...(by ? { decidedBy: by } : {}),
    ...(decision !== "expired" && a.decisionNote ? { note: a.decisionNote } : {}),
    ...(decision === "approved" && a.confirmation ? { confirmation: a.confirmation } : {}),
    ...(a.agent !== undefined ? { agent: a.agent } : {}),
  });
}

/** A confirmation of an irreversible request that was refused. Its action-token-refused line is written already. */
export class TokenRefused extends Error {
  override name = "TokenRefused";
  constructor(
    readonly reason: ActionTokenRefusal,
    message: string,
  ) {
    super(message);
  }
}

/** Writes the action-token-refused line of a refusal (if the log can be written) and returns the error to throw. */
export function refuseToken(audit: AuditLog, request: Approval, reason: ActionTokenRefusal, message: string, by: string | undefined): TokenRefused {
  try {
    audit.writeTokenRefusal({ approvalId: request.id, server: request.server, tool: request.tool, rule: request.rule, argsHash: request.argsHash, reason, ...(by ? { decidedBy: by } : {}), ...(request.agent !== undefined ? { agent: request.agent } : {}) });
  } catch {
    // the refusal is what the human needs to see
  }
  return new TokenRefused(reason, message);
}

/**
 * The checks an irreversible request (ADR 0013) passes before its action token is asked for, in this
 * order: approved or used already ("used": its token confirmed it once), not pending (an ApprovalError:
 * a denied or stale request is simply not pending), expired ("expired", after an expired line), a record
 * that is not the call it shows ("changed"), and a key this process cannot use ("no-key"). A refusal is
 * written to the audit log and thrown as a TokenRefused. Returns the tokens and the code the human
 * gives back.
 */
export function checkIrreversible(audit: AuditLog, config: Pick<GatewayConfig, "actionTokenKeyFile">, request: Approval, by: string | undefined, now = Date.now()): { tokens: ActionTokens; expected: string } {
  // Confirming a request that was approved already is a token used twice; a denied or stale one is simply not pending.
  if (request.status === "approved" || request.status === "used") throw refuseToken(audit, request, "used", `${request.id} is ${request.status}: its action token confirmed it once already, so it was not approved again`, by);
  if (request.status !== "pending") throw new ApprovalError(`${request.id} is ${request.status}; only a pending request can be approved`);
  if (!isLive(request, now)) {
    try {
      writeEvent(audit, request, "expired", by);
    } catch {
      // the refusal below is what the human needs to see
    }
    throw refuseToken(audit, request, "expired", `${request.id} expired at ${request.expiresAt}; the agent has to make the call again to ask again`, by);
  }
  // A record whose call is not what it shows (its arguments do not hash to argsHash) or whose nonce the
  // gateway did not make was written by something else: the human would confirm one call and run another.
  const problem = recordProblem(request);
  if (problem) throw refuseToken(audit, request, "changed", `${request.id} was not approved: ${problem}`, by);
  const tokens = new ActionTokens(config.actionTokenKeyFile);
  try {
    return { tokens, expected: tokens.code(request as TokenBinding) };
  } catch (err) {
    throw refuseToken(audit, request, "no-key", `${request.id} is for an irreversible action, and its action token needs the gateway's key, which cannot be used here (${(err as Error).message}); only someone who can read the key can approve it`, by);
  }
}

/**
 * Approves an irreversible request with the code the human gave back, after checkIrreversible(): a code
 * that is not this request's is refused ("mismatch"). The proof is made from the record as it is when it
 * is approved, under the queue's lock: if the call changed since `request` was read back (another writer
 * of approvals.json), the human did not confirm this one ("changed").
 */
export function confirmIrreversible(store: ApprovalStore, audit: AuditLog, request: Approval, tokens: ActionTokens, presented: string, note: string | undefined, by: string | undefined): Approval {
  if (!tokens.matches(request as TokenBinding, presented)) {
    throw refuseToken(audit, request, "mismatch", `that is not the action token of ${request.id}, so it was not approved; a token belongs to one request: this call, with these arguments, until it expires`, by);
  }
  try {
    return decide(store, audit, request.id, "approved", note, "token", (a) => {
      if (!sameBinding(a, request) || recordProblem(a) !== undefined) throw new BindingChanged();
      return tokens.proof(a as TokenBinding);
    });
  } catch (err) {
    if (err instanceof BindingChanged) throw refuseToken(audit, request, "changed", `${request.id} changed after it was read back, so it was not approved; read it back again`, by);
    throw err;
  }
}

/** Thrown from inside the approval's lock when the call is not the one that was read back. */
class BindingChanged extends Error {}

/** The fields an action token is bound to are the same in both records. */
export function sameBinding(a: Approval, b: Approval): boolean {
  return (
    a.id === b.id &&
    a.server === b.server &&
    a.tool === b.tool &&
    a.argsHash === b.argsHash &&
    a.agent === b.agent &&
    a.expiresAt === b.expiresAt &&
    a.nonce === b.nonce &&
    canonicalJson(a.files ?? null) === canonicalJson(b.files ?? null)
  );
}

/** Why an irreversible request cannot be the call it shows, or undefined when it can be. */
export function recordProblem(a: Approval): string | undefined {
  if (!isNonce(a.nonce)) return "its nonce is not one the gateway makes, so approvals.json was edited";
  if (typeof a.args !== "object" || a.args === null || hashArguments(a.args) !== a.argsHash) return "its arguments do not hash to its argsHash, so approvals.json was edited: what it shows is not the call that would run";
  return undefined;
}

/** A pending irreversible request as "approvals show" prints it: with its action token, for the human who can read the key. */
export function withToken(a: Approval, config: Pick<GatewayConfig, "actionTokenKeyFile">): Approval & { actionToken?: string | null; actionTokenError?: string } {
  if (!a.irreversible || a.status !== "pending") return a;
  const problem = recordProblem(a);
  if (problem) return { ...a, actionToken: null, actionTokenError: problem };
  try {
    return { ...a, actionToken: new ActionTokens(config.actionTokenKeyFile).code(a as TokenBinding) };
  } catch (err) {
    return { ...a, actionToken: null, actionTokenError: (err as Error).message };
  }
}

/**
 * What the human is approving, in full: the call, every argument, the rule and its reason, the files
 * the request is bound to (hashed again now, to show whether they still match), and the time left.
 */
export function readBack(a: Approval, config: Pick<GatewayConfig, "fileBinding">, now = Date.now()): string {
  const args = JSON.stringify(JSON.parse(canonicalJson(a.args)), null, 2).split("\n");
  const current = a.files && config.fileBinding ? bindFiles(a.args, config.fileBinding) : [];
  const files = (a.files ?? []).map((f) => {
    const again = current.find((c) => c.argument === f.argument);
    const state = again && again.path === f.path && again.sha256 === f.sha256 ? "unchanged since the request" : "CHANGED since the request: the agent will be asked again";
    return `  file:     ${f.path} ${f.sha256 ?? "(did not exist)"}, ${state}`;
  });
  return [
    `Approve this call? ${a.id}`,
    `  call:     ${a.server}${SEPARATOR}${a.tool}`,
    ...(a.agent !== undefined ? [`  agent:    ${a.agent} (known by its key; only its own call can use this approval)`] : []),
    ...(a.agentPath ? [`  agents:   ${a.agentPath} (as the client states it)`] : []),
    `  args:     ${args[0]}`,
    ...args.slice(1).map((line) => `            ${line}`),
    `  rule:     ${a.rule}: ${a.why}`,
    ...(a.alsoMatched ?? []).map((m) => `  also:     ${m.rule} (${m.decision}: ${m.why})`),
    ...(a.rewrittenBy ? [`  edited:   by ${a.rewrittenBy.join(", ")}; these args are what will run, not what the agent sent`] : []),
    ...files,
    `  expires:  ${a.expiresAt} (in ${duration(Math.max(0, Date.parse(a.expiresAt) - now))})`,
    "",
  ].join("\n");
}

/** 4m 12s · 1h 05m · 2d 03h */
export function duration(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${String(Math.floor((s % 3600) / 60)).padStart(2, "0")}m`;
  return `${Math.floor(s / 86400)}d ${String(Math.floor((s % 86400) / 3600)).padStart(2, "0")}h`;
}

/** The call in one line: id, tool and its arguments, cut at 300 characters. */
export function describeCall(a: Approval): string {
  return `${a.id}: ${a.server}${SEPARATOR}${a.tool} ${preview(canonicalJson(a.args))}`;
}

const PREVIEW_CHARS = 300;
export function preview(json: string): string {
  return json.length <= PREVIEW_CHARS ? json : `${json.slice(0, PREVIEW_CHARS)}... (${json.length} characters; "approvals show <id>" prints all of it)`;
}
