// A second reviewer for MCP tool calls that can only make a decision stricter (ADR 0008).
//
// Not wired into the gateway yet. This module holds the rule the whole design depends on, so that
// it is written once and tested on every combination: the policy decides, and the second reviewer
// (a local model, say) can only add a question. Its "allow" never lowers an ask or a block, and a
// reviewer that fails, times out or answers something unreadable changes nothing.

import { cleanNote } from "./approvals.js";
import type { Decision, Verdict } from "./policy.js";

export type AdvisorVote = "allow" | "ask";

/** What the second reviewer answered, or why it gave no answer (timeout, crash, unreadable output). */
export type AdvisorResult = { vote: AdvisorVote; why: string } | { error: string };

export interface Combined {
  /** What the gateway does: the policy's verdict, or an ask when the reviewer asked for a human. */
  verdict: Verdict;
  advisor: AdvisorVote | "error";
  /** Did both want a human, or both not? null when the reviewer gave no vote. The research number. */
  agreed: boolean | null;
  /** The reviewer's reason, cleaned to one line, for the human's approval card only, never for the agent. */
  advisorWhy?: string;
}

const STRICTNESS: Readonly<Record<Decision, number>> = { allow: 0, warn: 1, ask: 2, block: 3 };

export function escalateOnly(policy: Verdict, result: AdvisorResult): Combined {
  if ("error" in result) return { verdict: policy, advisor: "error", agreed: null };
  const advisorWantsHuman = result.vote === "ask";
  const policyWantsHuman = STRICTNESS[policy.decision] >= STRICTNESS.ask;
  const why = cleanNote(result.why);
  const combined: Combined = { verdict: policy, advisor: result.vote, agreed: advisorWantsHuman === policyWantsHuman, ...(why ? { advisorWhy: why } : {}) };
  if (advisorWantsHuman && !policyWantsHuman) {
    // The reviewer's own words stay off the agent's screen: the text it read may have steered it.
    combined.verdict = { decision: "ask", rule: `${policy.rule}+advisor`, why: `${policy.why} A second reviewer asked for a human to look at this call.` };
  }
  return combined;
}

/** Reads the reviewer's answer: exactly one JSON object { "vote": "allow" | "ask", "why": "..." }. */
export function parseOpinion(text: string): AdvisorResult {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return { error: "the answer is not JSON" };
  }
  const answer = data as { vote?: unknown; why?: unknown } | null;
  if (typeof answer !== "object" || answer === null || Array.isArray(answer)) return { error: "the answer is not a JSON object" };
  if (answer.vote !== "allow" && answer.vote !== "ask") return { error: 'the answer has no vote of "allow" or "ask"' };
  return { vote: answer.vote, why: typeof answer.why === "string" ? answer.why : "" };
}
