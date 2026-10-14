// The usage log: one JSON line per authenticated call, appended to <stateDir>/usage.jsonl.
// ponytail: the file is never rotated or shipped anywhere; that is left to the operator.

import * as fs from "node:fs";

export interface UsageEntry {
  ts: string;
  /** The gateway's id for the request, also sent to the client as x-agent-gate-request-id. */
  id: string;
  /** The gateway key's name from the config, never the key. */
  key: string;
  /** The route rule that decided; absent when no route matched. */
  route?: string;
  upstream?: string;
  /** The model name sent to the upstream. */
  model?: string;
  /** The HTTP status the client got. */
  status: number;
  /** Why the call failed or was refused, for example "budget_exceeded" or "secret_detected". */
  error?: string;
  /** The leak-guard rule that blocked the call, or the budget cap that refused it. */
  rule?: string;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  /** Where the tokens came from: the upstream's usage, or the gateway's estimate when it had none. */
  usage?: "upstream" | "estimate";
  attempts?: number;
  fallback?: boolean;
  /** Leak-guard rules that redacted text in this call. */
  redacted?: string[];
  latencyMs: number;
}

export class UsageLog {
  constructor(readonly file: string) {}

  /**
   * Appends one line, or throws.
   *
   * There is no prompt or completion text in it, on purpose. Prompts carry whatever the agent read
   * or was told, which includes secrets, customer data and personal data, and completions repeat
   * it. This log is for cost and availability: it is kept for a long time and read by people
   * (finance, on-call) who need the tokens and the dollars, not the conversation. The id ties a
   * line to the client's own logs when someone does need to look at one call.
   */
  write(entry: Omit<UsageEntry, "ts">, now = new Date()): UsageEntry {
    const line: UsageEntry = { ts: now.toISOString(), ...entry };
    fs.appendFileSync(this.file, `${JSON.stringify(line)}\n`, { mode: 0o600 });
    return line;
  }
}
