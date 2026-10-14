// Types for the slice-1 analyzer in command-guard.js, which stays plain CommonJS with no build
// step. The TypeScript gateway imports it as "#command-guard" (see "imports" in package.json), so
// the same import works from src/ when type-checking and from dist/ at run time.

export type GuardAction = "pass" | "warn" | "ask" | "block";

export interface GuardDecision {
  action: GuardAction;
  /** Present unless the action is "pass". */
  label?: string;
  /** Present for "ask". */
  why?: string;
}

/** Classifies one shell command. Pure: no I/O. */
export function analyze(command: string): GuardDecision;

/** The rule set from before the v5 rewrite; the fallback when analyze() itself fails. */
export function legacyDecide(text: string): GuardDecision;

/** Appends a decision to the file named by AGENT_GATE_LOG, if set. Best effort. */
export function logDecision(command: string, decision: GuardDecision): void;
