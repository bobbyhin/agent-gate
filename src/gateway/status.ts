// What "agent-gate status" shows: the state of each downstream server, as the gateway processes on a
// state directory see them. Each serving process keeps its own entry, keyed by its process id, in
// <stateDir>/status.json (the approvals' lock and atomic write, state-file.ts), so several "serve"
// processes on one state directory never overwrite each other. An entry whose process is no longer
// running is left out when the file is read, and dropped at the next write; a process that stops
// normally removes its own.

import * as path from "node:path";
import { isRunning, readIfExists, withLock, writeAtomic } from "./state-file.js";

const FILE_VERSION = 1;

/** up: connected. restarting: it went away; a restart is due at nextTryAt. down: an optional server
 * that did not start; it is tried again when needed, from nextTryAt. failed: given up until the
 * gateway restarts. starting: the first connection is being made. */
export type ServerState = "starting" | "up" | "restarting" | "down" | "failed";

export interface ServerStatus {
  state: ServerState;
  /** Times it came back after going away. */
  restarts: number;
  /** Failed tries in a row since it was last up. */
  tries: number;
  /** The most it gets ("maxRestarts"). */
  maxTries: number;
  /** When it went into this state. */
  since: string;
  /** Why it is not up: the last error, with header values cut out. */
  lastError?: string;
  /** When it is tried next. */
  nextTryAt?: string;
}

export interface ProcessStatus {
  pid: number;
  /** "stdio": one client; "http": serve --http. */
  mode: "stdio" | "http";
  startedAt: string;
  updatedAt: string;
  servers: Record<string, ServerStatus>;
}

export class StatusFile {
  readonly file: string;
  private readonly lockDir: string;

  constructor(
    readonly dir: string,
    private readonly self: Pick<ProcessStatus, "mode" | "startedAt"> & { pid?: number },
    private readonly now: () => number = Date.now,
  ) {
    this.file = path.join(dir, "status.json");
    this.lockDir = path.join(dir, "status.lock");
  }

  /** Replaces this process's entry. */
  write(servers: Record<string, ServerStatus>): void {
    const pid = this.self.pid ?? process.pid;
    this.update((processes) => {
      processes[String(pid)] = { pid, mode: this.self.mode, startedAt: this.self.startedAt, updatedAt: new Date(this.now()).toISOString(), servers };
    });
  }

  /** Removes this process's entry: it is stopping. */
  remove(): void {
    const pid = this.self.pid ?? process.pid;
    this.update((processes) => {
      delete processes[String(pid)];
    });
  }

  private update(change: (processes: Record<string, ProcessStatus>) => void): void {
    withLock(this.dir, this.lockDir, () => {
      const processes = Object.fromEntries(readStatus(this.file).map((p) => [String(p.pid), p]));
      change(processes);
      writeAtomic(this.file, `${JSON.stringify({ version: FILE_VERSION, processes }, null, 2)}\n`);
    });
  }
}

/** The entries of the processes that are still running, oldest first. A damaged file is an error. */
export function readStatus(file: string): ProcessStatus[] {
  const content = readIfExists(file);
  if (content === undefined) return [];
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch (err) {
    throw new Error(`${file} is not valid JSON (${(err as Error).message}); remove it, and the gateways write it again`);
  }
  const status = data as { version?: unknown; processes?: unknown } | null;
  if (typeof status !== "object" || status === null || status.version !== FILE_VERSION || typeof status.processes !== "object" || status.processes === null) {
    throw new Error(`${file} is not a version ${FILE_VERSION} status file; remove it, and the gateways write it again`);
  }
  return Object.values(status.processes as Record<string, ProcessStatus>)
    .filter((p) => Number.isSafeInteger(p.pid) && isRunning(p.pid))
    .sort((a, b) => a.startedAt.localeCompare(b.startedAt));
}
