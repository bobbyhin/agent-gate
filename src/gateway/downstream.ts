// The downstream servers of one gateway process, kept connected.
//
// Every server is connected at startup. A required server (the default) that cannot be started or
// reached stops the gateway: fail closed, as before. A server with "optional": true that fails is left
// "down" and tried again when it is needed (a tools/list, or a call to one of its tools), once its
// backoff time has passed. A server whose connection closes later (for a local server: its process
// exited) is "restarting": it is started again after 1 s, then 2 s, 4 s ... (at most 30 s apart), and
// after "maxRestarts" failed tries in a row (default 3) it is "failed" until the gateway restarts. A
// server that goes away again within 10 s of coming back counts as a failed try, so a crash loop
// ends in "failed" too.
// While a server is not up, its tools are not listed and a call to one gets an error that says what
// state it is in and when the next try is. Each change goes to <stateDir>/status.json, for "agent-gate
// status", with the last error: a remote server's error can carry its own text, so it is cut to one
// line of at most 300 characters with control characters removed (no terminal escapes reach the
// CLI), and it is never put into what the agent is told.
// ponytail: a remote server (url) has no process to watch: each request reaches it anew, so it is
// "up" once connected, and a call to it while it is unreachable fails on its own.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ListToolsResultSchema, ToolListChangedNotificationSchema, type Tool } from "@modelcontextprotocol/sdk/types.js";
import { cleanNote } from "./approvals.js";
import { DEFAULT_MAX_RESTARTS, type GatewayConfig, type ServerConfig } from "./config.js";
import type { ServerStatus, StatusFile } from "./status.js";

export const VERSION = "0.2.0";
// ponytail: a server that keeps returning a nextCursor is cut off after this many pages.
const MAX_LIST_PAGES = 100;
const MAX_BACKOFF_MS = 30_000;
/** Up for this long, a server that goes away is a new story: its failed tries start again from 0. */
const STABLE_MS = 10_000;

export type Log = (message: string) => void;

export interface DownstreamOptions {
  /** The first wait before a try; it doubles with each failed try (default 1000). */
  backoffMs?: number;
  now?: () => number;
  /** Where the states are written for "agent-gate status". */
  status?: StatusFile;
}

interface Link {
  config: ServerConfig;
  client?: Client;
  status: ServerStatus;
  /** An optional server that has not been up yet: tried on demand, not on a timer. */
  lazy: boolean;
  /** When it last came up. */
  upAt?: number;
  /** Failed tries before it last came up: a restart that does not hold goes on from there. */
  carry: number;
  timer?: NodeJS.Timeout;
  trying?: Promise<void>;
}

export class Downstreams {
  private readonly links = new Map<string, Link>();
  private closing = false;
  private readonly backoffMs: number;
  private readonly now: () => number;

  constructor(
    private readonly config: GatewayConfig,
    private readonly headers: ReadonlyMap<string, Record<string, string>>,
    private readonly scrub: (message: string) => string,
    private readonly log: Log,
    /** A server's tool list changed, or a server came or went: tell the clients to list again. */
    private readonly onToolsChanged: () => void,
    private readonly options: DownstreamOptions = {},
  ) {
    this.backoffMs = options.backoffMs ?? 1000;
    this.now = options.now ?? Date.now;
  }

  /** Connects every server. Throws, closing what it opened, when a required one fails. */
  async start(): Promise<void> {
    const at = new Date(this.now()).toISOString();
    for (const s of this.config.servers) {
      this.links.set(s.name, { config: s, lazy: false, carry: 0, status: { state: "starting", restarts: 0, tries: 0, maxTries: s.maxRestarts ?? DEFAULT_MAX_RESTARTS, since: at } });
    }
    const results = await Promise.all([...this.links.values()].map(async (link) => [link, await this.connect(link)] as const));
    const failures = results.filter(([link, ok]) => !ok && !link.config.optional).map(([link]) => `"${link.config.name}": ${link.status.lastError ?? "unknown error"}`);
    if (failures.length > 0) {
      await this.close();
      throw new Error(`could not start downstream server ${failures.join("; ")}`);
    }
    for (const [link, ok] of results) {
      if (ok) {
        link.upAt = this.now();
        this.set(link, "up");
      } else {
        link.lazy = true;
        this.log(`optional server "${link.config.name}" did not start (${link.status.lastError ?? "unknown error"}); it is tried again when needed`);
        this.wait(link, "down");
      }
    }
    this.save();
  }

  has(name: string): boolean {
    return this.links.has(name);
  }

  names(): string[] {
    return [...this.links.keys()];
  }

  /** The server's client when it is up. An optional server that is due for a try is tried first. */
  async client(name: string): Promise<Client | undefined> {
    const link = this.links.get(name);
    if (!link) return undefined;
    if (link.client) return link.client;
    if (link.lazy && link.status.state === "down" && !this.closing && this.now() >= Date.parse(link.status.nextTryAt ?? "")) {
      link.trying ??= this.retry(link).finally(() => {
        link.trying = undefined;
      });
      await link.trying;
    }
    return link.client;
  }

  /**
   * Why a server is not up, in words for the agent and the log: its state and the next try. The last
   * error is left out: it can hold the server's own text, which agent-gate does not pass off as its
   * own words to the agent ("agent-gate status" shows it).
   */
  whyDown(name: string): string {
    const link = this.links.get(name);
    if (!link) return `there is no server "${name}"`;
    const s = link.status;
    const next = s.nextTryAt ? Math.max(0, Math.ceil((Date.parse(s.nextTryAt) - this.now()) / 1000)) : 0;
    switch (s.state) {
      case "restarting":
        return `server "${name}" went away and is being restarted: try ${s.tries + 1} of ${s.maxTries} in ${next} s`;
      case "down":
        return `optional server "${name}" is not running: it is tried again when needed, ${next > 0 ? `in ${next} s` : "now"} (try ${s.tries + 1} of ${s.maxTries})`;
      case "failed":
        return `server "${name}" is down: ${s.maxTries} tries in a row to start it failed; restart the gateway to try again`;
      case "starting":
        return `server "${name}" is starting`;
      default:
        return `server "${name}" is up`;
    }
  }

  statuses(): Record<string, ServerStatus> {
    return Object.fromEntries([...this.links].map(([name, link]) => [name, { ...link.status }]));
  }

  async close(): Promise<void> {
    this.closing = true;
    for (const link of this.links.values()) if (link.timer) clearTimeout(link.timer);
    await Promise.allSettled([...this.links.values()].map((link) => link.client?.close()));
  }

  /** One try to connect; true when the server is up. On failure, lastError says why. */
  private async connect(link: Link): Promise<boolean> {
    const s = link.config;
    const client = new Client({ name: "agent-gate", version: VERSION });
    client.setNotificationHandler(ToolListChangedNotificationSchema, async () => this.onToolsChanged());
    try {
      await client.connect(transportFor(s, this.headers.get(s.name) ?? {}), s.timeoutMs === undefined ? {} : { timeout: s.timeoutMs });
    } catch (err) {
      await client.close().catch(() => undefined);
      // Header values out first, then one line without control characters (terminal escapes), cut short.
      link.status.lastError = cleanNote(this.scrub(errorText(err)), 300) ?? "unknown error";
      return false;
    }
    if (this.closing) {
      await client.close().catch(() => undefined);
      return false;
    }
    link.client = client;
    client.onclose = () => this.wentAway(link, client);
    return true;
  }

  private wentAway(link: Link, client: Client): void {
    if (this.closing || link.client !== client) return;
    link.client = undefined;
    link.status.lastError = link.config.url ? "the connection closed" : "the server's process exited";
    // Gone again right after a restart: that restart did not hold, so it counts as a failed try.
    const quick = link.upAt !== undefined && this.now() - link.upAt < STABLE_MS && link.status.restarts > 0;
    link.status.tries = quick ? link.carry + 1 : 0;
    this.log(`downstream server "${link.config.name}" went away (${link.status.lastError}); restarting it`);
    this.restartLater(link);
    this.onToolsChanged();
  }

  /** After a server went away: the next try on a timer, or "failed" once the tries are used up. */
  private restartLater(link: Link): void {
    if (link.status.tries >= link.status.maxTries) {
      this.set(link, "failed");
      this.log(`downstream server "${link.config.name}" failed: ${link.status.maxTries} tries in a row; restart the gateway to try again`);
      this.save();
      return;
    }
    const delay = this.wait(link, "restarting");
    link.timer = setTimeout(() => {
      link.timer = undefined;
      void this.retry(link);
    }, delay);
    link.timer.unref?.();
    this.save();
  }

  private async retry(link: Link): Promise<void> {
    if (this.closing) return;
    const wasUpBefore = !link.lazy;
    if (await this.connect(link)) {
      link.lazy = false;
      link.upAt = this.now();
      link.carry = link.status.tries;
      link.status.tries = 0;
      if (wasUpBefore) link.status.restarts++;
      delete link.status.lastError;
      this.set(link, "up");
      this.log(`downstream server "${link.config.name}" is up again`);
      this.save();
      this.onToolsChanged();
      return;
    }
    link.status.tries++;
    if (link.lazy) {
      if (link.status.tries >= link.status.maxTries) this.set(link, "failed");
      else this.wait(link, "down");
      this.save();
    } else this.restartLater(link);
  }

  /** Enters a waiting state; returns the wait, which doubles with each failed try. */
  private wait(link: Link, state: "restarting" | "down"): number {
    const delay = Math.min(MAX_BACKOFF_MS, this.backoffMs * 2 ** link.status.tries);
    this.set(link, state);
    link.status.nextTryAt = new Date(this.now() + delay).toISOString();
    return delay;
  }

  private set(link: Link, state: ServerStatus["state"]): void {
    if (link.status.state !== state) link.status.since = new Date(this.now()).toISOString();
    link.status.state = state;
    if (state === "up" || state === "failed") delete link.status.nextTryAt;
  }

  private save(): void {
    if (!this.options.status) return;
    try {
      this.options.status.write(this.statuses());
    } catch (err) {
      // The gateway goes on; only "agent-gate status" is out of date.
      this.log(`could not write the status file: ${errorText(err)}`);
    }
  }
}

/** stdio for a local server; Streamable HTTP for one with a url, with its headers, and no redirects (a token must not travel). */
export function transportFor(s: ServerConfig, headers: Record<string, string>): StdioClientTransport | StreamableHTTPClientTransport {
  if (s.url) return new StreamableHTTPClientTransport(new URL(s.url), { requestInit: { headers, redirect: "error" } });
  return new StdioClientTransport({ command: s.command as string, args: s.args ?? [], ...(s.env ? { env: s.env } : {}), stderr: "inherit" });
}

export async function listTools(name: string, client: Client, log: Log, timeoutMs?: number, scrub: (message: string) => string = (m) => m): Promise<Tool[]> {
  const tools: Tool[] = [];
  try {
    let cursor: string | undefined;
    for (let page = 0; page < MAX_LIST_PAGES; page++) {
      const result = await client.request({ method: "tools/list", params: cursor === undefined ? {} : { cursor } }, ListToolsResultSchema, timeoutMs === undefined ? {} : { timeout: timeoutMs });
      tools.push(...result.tools); // the server's own names; the gateway adds the prefix
      cursor = result.nextCursor;
      if (cursor === undefined) break;
    }
  } catch (err) {
    // One broken server should not hide the tools of the others.
    log(`could not list the tools of "${name}": ${scrub(errorText(err))}`);
  }
  return tools;
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
