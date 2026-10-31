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
  /** Key name -> its window and, by request hash, when calls with that hash were let through (ms, oldest first). */
  private readonly seen = new Map<string, { windowMs: number; byHash: Map<string, number[]> }>();
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
    let entry = this.seen.get(key);
    if (!entry) this.seen.set(key, (entry = { windowMs, byHash: new Map() }));
    entry.windowMs = windowMs;
    entry.byHash.set(hash, [...this.recent(key, hash, windowMs, now), now]);
    // Now and then, forget every request that has left its key's window, for every key: a key that
    // went quiet does not keep its requests in memory.
    if (++this.calls % 256 === 0) {
      for (const [name, { windowMs: window, byHash }] of this.seen) {
        for (const [h, times] of byHash) if (!times.some((t) => t > now - window)) byHash.delete(h);
        if (byHash.size === 0) this.seen.delete(name);
      }
    }
  }

  /** How many request hashes are held, over every key. */
  size(): number {
    let n = 0;
    for (const { byHash } of this.seen.values()) n += byHash.size;
    return n;
  }

  private recent(key: string, hash: string, windowMs: number, now: number): number[] {
    return (this.seen.get(key)?.byHash.get(hash) ?? []).filter((t) => t > now - windowMs);
  }
}
