// Pinned tool definitions: a defence against a downstream server that changes a tool after the
// agent and its human have come to trust it (a "rug pull", or tool poisoning through a description).
//
// The first time the gateway lists a tool, it keeps a SHA-256 of everything the model reads about it:
// name, title, description, input and output schema, annotations. Trust on first use: a definition
// that is hostile from the start is not caught here. When a later listing gives a different hash, the
// tool is "changed": it is left out of tools/list, so the model never reads the new text, and a call
// to it is asked about (rule "tool-changed") until a human compares the two definitions and accepts
// the new one with "agent-gate tools accept". Both definitions are kept, so the human can see what
// changed. Everything lives in <stateDir>/tools.json, with the approvals' lock and atomic write.

import * as path from "node:path";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { canonicalJson } from "./approvals.js";
import { hashJson } from "./audit.js";
import { readIfExists, withLock, writeAtomic } from "./state-file.js";

const FILE_VERSION = 1;

/** What the model reads about a tool; the hash covers exactly this. */
export type Definition = Pick<Tool, "name" | "title" | "description" | "inputSchema" | "outputSchema" | "annotations">;

export interface PinnedDefinition {
  sha256: string;
  definition: Definition;
  /** When it was pinned: first seen, or accepted by a human. */
  at: string;
  /** Who accepted it, for a definition a human accepted after a change. */
  acceptedBy?: string;
}

export interface PinRecord {
  pinned: PinnedDefinition;
  /** A different definition seen since; the tool is withheld while this is set. */
  changed?: PinnedDefinition;
}

/** What a listing found: tools to show, and what is new about the pins. */
export interface PinCheck {
  /** The server's tools minus the ones withheld for a change. */
  visible: Tool[];
  /** Tools pinned for the first time by this listing. */
  pinned: Array<{ tool: string; sha256: string }>;
  /** Tools whose definition changed since the pin (or changed again), first seen by this listing. */
  changed: Array<{ tool: string; pinnedSha256: string; sha256: string }>;
}

export function definitionOf(tool: Tool): Definition {
  const { name, title, description, inputSchema, outputSchema, annotations } = tool;
  return JSON.parse(canonicalJson({ name, title, description, inputSchema, outputSchema, annotations })) as Definition;
}

export class ToolPins {
  readonly file: string;
  private readonly lockDir: string;

  constructor(
    readonly dir: string,
    private readonly now: () => number = Date.now,
  ) {
    this.file = path.join(dir, "tools.json");
    this.lockDir = path.join(dir, "tools.lock");
  }

  /** Called with each listing of a server: pins new tools, finds changed ones, says what to show. */
  check(server: string, tools: readonly Tool[]): PinCheck {
    return this.update((servers, now) => {
      const pins = (servers[server] ??= {});
      const result: PinCheck = { visible: [], pinned: [], changed: [] };
      for (const tool of tools) {
        const definition = definitionOf(tool);
        const { hash } = hashJson(definition);
        const record = Object.prototype.hasOwnProperty.call(pins, tool.name) ? pins[tool.name] : undefined;
        if (!record) {
          pins[tool.name] = { pinned: { sha256: hash, definition, at: new Date(now).toISOString() } };
          result.pinned.push({ tool: tool.name, sha256: hash });
          result.visible.push(tool);
        } else if (record.pinned.sha256 === hash) {
          // Back to the pinned definition: whatever changed has been undone.
          delete record.changed;
          result.visible.push(tool);
        } else {
          if (record.changed?.sha256 !== hash) {
            record.changed = { sha256: hash, definition, at: new Date(now).toISOString() };
            result.changed.push({ tool: tool.name, pinnedSha256: record.pinned.sha256, sha256: hash });
          }
        }
      }
      return result;
    });
  }

  /** "changed" while a tool waits for a human; "pinned" when it matches its pin; "unknown" before it was listed. */
  status(server: string, tool: string): "pinned" | "changed" | "unknown" {
    const record = this.read()[server]?.[tool];
    return record === undefined ? "unknown" : record.changed ? "changed" : "pinned";
  }

  get(server: string, tool: string): PinRecord | undefined {
    return this.read()[server]?.[tool];
  }

  list(): Record<string, Record<string, PinRecord>> {
    return this.read();
  }

  /** A human accepts the changed definition: it becomes the pin. */
  accept(server: string, tool: string, by?: string): PinRecord {
    return this.update((servers, now) => {
      const record = servers[server]?.[tool];
      if (!record) throw new Error(`no pinned tool ${server}__${tool}`);
      if (!record.changed) throw new Error(`${server}__${tool} has not changed since it was pinned; there is nothing to accept`);
      record.pinned = { ...record.changed, at: new Date(now).toISOString(), ...(by ? { acceptedBy: by } : {}) };
      delete record.changed;
      return record;
    });
  }

  private read(): Record<string, Record<string, PinRecord>> {
    const content = readIfExists(this.file);
    if (content === undefined) return {};
    let data: unknown;
    try {
      data = JSON.parse(content);
    } catch (err) {
      throw new Error(`${this.file} is not valid JSON (${(err as Error).message}); fix or remove it`);
    }
    // Fail closed: a damaged file is an error, never an empty one, which would trust every tool anew.
    const file = data as { version?: unknown; servers?: unknown } | null;
    if (typeof file !== "object" || file === null || file.version !== FILE_VERSION || typeof file.servers !== "object" || file.servers === null) {
      throw new Error(`${this.file} is not a version ${FILE_VERSION} tools file; fix or remove it`);
    }
    return file.servers as Record<string, Record<string, PinRecord>>;
  }

  private update<T>(change: (servers: Record<string, Record<string, PinRecord>>, now: number) => T): T {
    return withLock(this.dir, this.lockDir, () => {
      const servers = this.read();
      const before = JSON.stringify(servers);
      const result = change(servers, this.now());
      if (JSON.stringify(servers) !== before) writeAtomic(this.file, `${JSON.stringify({ version: FILE_VERSION, servers }, null, 2)}\n`);
      return result;
    });
  }
}
