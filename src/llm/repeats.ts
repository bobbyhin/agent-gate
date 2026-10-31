// The same request, again and again: a stop rule for a loop that resends one call unchanged.
//
// A key with repeatMax and repeatWindowSeconds lets the same request (model alias, messages, tools,
// tool_choice and n, as the client sent them) through at most repeatMax times in any window of that
// length; past that, the gateway refuses it with 429 loop_suspected until the oldest of them leaves
// the window. Only calls that were let through count. A request is identified by the SHA-256 of
// those fields as canonical JSON (object keys sorted), so key order does not matter.
// ponytail: the counts live in this process's memory, not in the ledger. One gateway process serves a
// state directory (docs/adr/0003-single-writer-state.md), and a restart forgets at most one window.

import { createHash } from "node:crypto";
import { canonicalJson } from "../gateway/approvals.js";

/** The fields that make two requests "the same" for this rule. */
export function requestHash(body: Record<string, unknown>): string {
  const same = { model: body.model, messages: body.messages, tools: body.tools, tool_choice: body.tool_choice, n: body.n };
  return createHash("sha256").update(canonicalJson(same)).digest("hex");
}

export class RepeatWindow {
  /** Key name -> request hash -> when calls with that hash were let through (ms, oldest first). */
  private readonly seen = new Map<string, Map<string, number[]>>();
  private calls = 0;

  /**
   * Whether a request may go through now. When it may not, how long until it may (whole seconds, at
   * least 1). It records nothing: call admit() once the call is really let through.
   */
  check(key: string, hash: string, max: number, windowMs: number, now: number): { ok: true } | { ok: false; count: number; retryAfterSeconds: number } {
    const times = this.recent(key, hash, windowMs, now);
    if (times.length < max) return { ok: true };
    const oldest = times[times.length - max] as number;
    return { ok: false, count: times.length, retryAfterSeconds: Math.max(1, Math.ceil((oldest + windowMs - now) / 1000)) };
  }

  admit(key: string, hash: string, windowMs: number, now: number): void {
    let byHash = this.seen.get(key);
    if (!byHash) this.seen.set(key, (byHash = new Map()));
    byHash.set(hash, [...this.recent(key, hash, windowMs, now), now]);
    // Now and then, forget the requests of this key that have left the window.
    if (++this.calls % 256 === 0) {
      for (const [h, times] of byHash) if (!times.some((t) => t > now - windowMs)) byHash.delete(h);
    }
  }

  private recent(key: string, hash: string, windowMs: number, now: number): number[] {
    return (this.seen.get(key)?.get(hash) ?? []).filter((t) => t > now - windowMs);
  }
}
