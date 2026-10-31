// The usage log: one JSON line per authenticated call, appended to <stateDir>/usage.jsonl.
// ponytail: the file is never rotated or shipped anywhere; that is left to the operator.

import * as fs from "node:fs";

export interface UsageEntry {
  ts: string;
  /** The gateway's id for the request, also sent to the client as x-agent-gate-request-id. */
  id: string;
  /** The W3C trace this call belongs to: the client's (traceparent header), or a new one. Sent back as x-agent-gate-trace-id. */
  traceId: string;
  /** The gateway's span for this call: the parent id in the traceparent it sends upstream. */
  spanId: string;
  /** The client's span that made the call, from its traceparent. */
  parentSpanId?: string;
  /** The x-agent-session and x-run-id headers, when they fit the id format (src/gateway/context.ts). */
  session?: string;
  runId?: string;
  /** Headers the client sent in a shape the gateway does not accept, so their values were left out. */
  contextDropped?: string[];
  /** The x-agent-task header, on one line and at most 100 characters. */
  task?: string;
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
  /** 429 answers from the upstreams on the way (rate limits or quota), when there were any. */
  upstream429?: number;
  /** Leak-guard rules that redacted text in this call's messages. */
  redacted?: string[];
  /** Leak-guard rules that redacted text in the answer. */
  responseRedacted?: string[];
  /** For a leak-guard block: which side the secret was on, the request ("prompt") or the answer ("response"). */
  side?: "prompt" | "response";
  /** How the ledger booked the cost when it was not the usual way: "orphan" (the reservation had expired) or "duplicate". */
  settle?: "orphan" | "duplicate";
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
