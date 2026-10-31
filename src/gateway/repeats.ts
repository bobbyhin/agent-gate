// The loop limits of a policy ("repeat", see policy.ts), applied: how many times a call has run lately.
//
// Everything lives in <stateDir>/repeats.json, changed with the same lock and atomic write as
// approvals.json (state-file.ts), so several gateways on one state directory count together, and the
// check and the count are one step: two copies of a call that arrive together cannot both slip under
// a limit. A damaged file is an error, so the gateway does not run the call, never an empty count.
// Times older than the longest window of the policy are dropped at each change (not the longest window
// of the call at hand: another tool's limit may need a longer memory).
// Each limit counts on its own, and so does each HTTP agent (serve --http): one agent's calls never use
// up another agent's limit. Calls that come with no agent (stdio) count together, across the gateway
// processes on one state directory.

import * as path from "node:path";
import type { RepeatLimit } from "./policy.js";
import { readIfExists, withLock, writeAtomic } from "./state-file.js";

const FILE_VERSION = 1;
/** At most this many times are kept per key; more cannot matter to a limit of at most 10000. */
const KEEP_PER_KEY = 10_000;

/** A limit the call has reached, and how many runs it counted. */
export interface RepeatHit {
  limit: RepeatLimit;
  count: number;
}

export class RepeatStore {
  readonly file: string;
  private readonly lockDir: string;

  /** `keepMs`: the longest window among the policy's limits. */
  constructor(
    readonly dir: string,
    readonly keepMs: number,
    private readonly now: () => number = Date.now,
  ) {
    this.file = path.join(dir, "repeats.json");
    this.lockDir = path.join(dir, "repeats.lock");
  }

  /**
   * The key a limit counts under: the limit, the agent (absent over stdio), and the exact call or the
   * tool. A JSON array, so that no id or name can run into the next part.
   */
  static key(limit: RepeatLimit, server: string, tool: string, argsHash: string, agent?: string): string {
    return JSON.stringify([limit.id, agent ?? null, `${server}__${tool}`, ...(limit.per === "tool" ? [] : [argsHash])]);
  }

  /**
   * One locked step: if any limit is reached (the call already ran `max` times within its window),
   * returns the first one and counts nothing; otherwise counts this run under every limit's key.
   */
  admit(limits: readonly RepeatLimit[], server: string, tool: string, argsHash: string, agent?: string): RepeatHit | undefined {
    return this.update((runs, now) => {
      for (const limit of limits) {
        const count = (runs[RepeatStore.key(limit, server, tool, argsHash, agent)] ?? []).filter((t) => t > now - limit.windowMs).length;
        if (count >= limit.max) return { limit, count };
      }
      this.count(runs, limits, server, tool, argsHash, agent, now);
      return undefined;
    });
  }

  /** Counts a run that a human let through after a limit had asked. */
  record(limits: readonly RepeatLimit[], server: string, tool: string, argsHash: string, agent?: string): void {
    this.update((runs, now) => this.count(runs, limits, server, tool, argsHash, agent, now));
  }

  private count(runs: Record<string, number[]>, limits: readonly RepeatLimit[], server: string, tool: string, argsHash: string, agent: string | undefined, now: number): void {
    for (const key of new Set(limits.map((limit) => RepeatStore.key(limit, server, tool, argsHash, agent)))) {
      runs[key] = [...(runs[key] ?? []), now].slice(-KEEP_PER_KEY);
    }
  }

  private read(): Record<string, number[]> {
    const content = readIfExists(this.file);
    if (content === undefined) return {};
    let data: unknown;
    try {
      data = JSON.parse(content);
    } catch (err) {
      throw new Error(`${this.file} is not valid JSON (${(err as Error).message}); fix or remove it`);
    }
    const file = data as { version?: unknown; runs?: unknown } | null;
    if (typeof file !== "object" || file === null || file.version !== FILE_VERSION || typeof file.runs !== "object" || file.runs === null || Array.isArray(file.runs)) {
      throw new Error(`${this.file} is not a version ${FILE_VERSION} repeats file; fix or remove it`);
    }
    return file.runs as Record<string, number[]>;
  }

  private update<T>(change: (runs: Record<string, number[]>, now: number) => T): T {
    return withLock(this.dir, this.lockDir, () => {
      const runs = this.read();
      const now = this.now();
      const result = change(runs, now);
      // Keep what the policy's longest window can still see; drop keys left empty.
      for (const [key, times] of Object.entries(runs)) {
        const recent = times.filter((t) => t > now - this.keepMs);
        if (recent.length === 0) delete runs[key];
        else runs[key] = recent;
      }
      writeAtomic(this.file, `${JSON.stringify({ version: FILE_VERSION, runs })}\n`);
      return result;
    });
  }
}
