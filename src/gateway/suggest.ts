// agent-gate policy suggest: before an unfamiliar MCP server goes behind the gateway, show what the
// policy would decide for each of its tools, and draft a stricter starting policy.
//
// The tools come from the downstream servers in the gateway config (tools/list, as the gateway lists
// them), or from an OpenAPI document, whose operations become tools named by their operationId (as
// servers generated from one usually name them). For each tool:
//   - what the policy decides from the name alone (evaluate() with no arguments), and which rule;
//   - which rules could change that once arguments are known: a rule with argument conditions, a
//     shell rule or a rewrite rule that matches the name, before the rule that decided;
//   - what the draft decides.
// The draft is the policy's own rules unchanged, then one allow rule per server for the tools whose
// names read (get, list, read, search, find, describe, show, view, count, with no word that changes
// something) or, from an OpenAPI document, GET and HEAD operations; and "default": "ask", so a tool
// that no rule names waits for a human instead of running. Tool annotations (readOnlyHint,
// destructiveHint) are shown, never used: the server declares them about itself.
// Tool names come from the server, so they are untrusted text. A name goes into the draft only when it
// is plain (letters, digits, "_", "." and "-", at most 128 characters): the draft's tool lists are
// globs, and a name such as "get*" would allow every other "get..." tool of that server, while a run
// of "*" makes a pattern that takes exponential time to match. Other names are not drafted (the
// default asks about them) and are listed, quoted, so that what the output prints is the name.
// ponytail: names only. A read that is not named like one is left to the default (ask), and a
// write named like a read is allowed by the draft: the draft is a starting point for a human.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { GatewayConfig } from "./config.js";
import { evaluate, globToRegExp, matchesName, parsePolicy, splitWords, type Decision, type Policy } from "./policy.js";
import { listTools, transportFor, VERSION } from "./server.js";
import { fail, object } from "./validate.js";

const READ_VERBS = new Set(["get", "list", "read", "search", "find", "describe", "show", "view", "count"]);
/** Words that change something; a name with one of them is not a read, whatever its first word. */
const CHANGE_WORDS = new Set(
  (
    "create update delete remove set write add put post send edit move rename replace patch insert upsert save push merge deploy publish " +
    "run exec execute start stop kill reset apply install upload sync submit approve grant revoke drop truncate purge clear import export " +
    "download fetch call invoke trigger enable disable pay buy order book invite schedule share reply comment email tweet like follow " +
    "subscribe mark archive close lock unlock assign transfer"
  ).split(" "),
);
const READ_METHODS = new Set(["get", "head"]);
const HTTP_METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];

/** A tool to decide: from a server's tools/list, or an OpenAPI operation. */
export interface Candidate {
  server: string;
  tool: string;
  /** For an OpenAPI operation: its method and path. */
  http?: { method: string; path: string };
  /** What the server says about the tool (shown, never used to decide). */
  hints?: string[];
}

export interface Suggestion extends Candidate {
  decision: Decision;
  rule: string;
  /** Rules that name this tool and could change the decision once the arguments are known. */
  dependsOn: string[];
  /** What the draft policy decides for the name. */
  draft: Decision;
}

export interface SuggestReport {
  suggestions: Suggestion[];
  /** Rules that look only at arguments: they can change any tool's decision when its arguments match. */
  argumentRules: string[];
  /** The tools that no rule matched: the policy's default decides them. */
  unmatched: string[];
  /** Reads whose names are not plain (see PLAIN_NAME), so the draft leaves them to its default. */
  notDrafted: string[];
  draft: { default: "ask"; rules: unknown[]; repeat?: unknown[] };
}

/** A name the draft may put in a glob list as it is: no "*" or "?", nothing a terminal would act on. */
export const PLAIN_NAME = /^[A-Za-z0-9_.-]{1,128}$/;

/** A tool's full name for the output: as it is when plain, else quoted as JSON, so control characters show as escapes. */
export function shownName(server: string, tool: string): string {
  return PLAIN_NAME.test(tool) ? `${server}__${tool}` : `${server}__${JSON.stringify(tool)}`;
}

/** True when the name reads like a read: a read verb first, and no word that changes something. */
export function readsByName(tool: string): boolean {
  const words = splitWords(tool);
  return words.length > 0 && READ_VERBS.has(words[0] as string) && !words.some((word) => CHANGE_WORDS.has(word));
}

/**
 * The report for these tools under this policy. `rawPolicy` is the policy file's JSON, copied into the
 * draft; `expose` is the config's expose globs per server (a tool they leave out is blocked).
 */
export function suggest(policy: Policy, rawPolicy: unknown, candidates: readonly Candidate[], expose: ReadonlyMap<string, string[]> = new Map()): SuggestReport {
  const raw = object(rawPolicy, "policy") as { rules?: unknown[]; repeat?: unknown[] };
  const ids = new Set(policy.rules.map((rule) => rule.id));
  const reads = new Map<string, string[]>();
  const notDrafted: string[] = [];
  for (const c of candidates) {
    const read = c.http ? READ_METHODS.has(c.http.method) && !splitWords(c.tool).some((word) => CHANGE_WORDS.has(word)) : readsByName(c.tool);
    if (!read) continue;
    // A name that is not plain would become a pattern in the draft's glob list: leave it to the default.
    if (PLAIN_NAME.test(c.tool)) reads.set(c.server, [...(reads.get(c.server) ?? []), c.tool]);
    else notDrafted.push(`${c.server}__${c.tool}`);
  }
  const added = [...reads].map(([server, tools]) => {
    let id = `suggested-reads-${server}`;
    while (ids.has(id)) id = `${id}-2`;
    ids.add(id);
    return { id, server, tool: tools, decision: "allow", why: "Suggested by agent-gate policy suggest: these names read. Check each one before you keep it." };
  });
  const draft = { default: "ask" as const, rules: [...(raw.rules ?? []), ...added], ...(raw.repeat ? { repeat: raw.repeat } : {}) };
  const draftPolicy = parsePolicy(draft);

  const suggestions = candidates.map((c): Suggestion => {
    const globs = expose.get(c.server);
    if (globs && !globs.some((glob) => globToRegExp(glob).test(c.tool))) {
      return { ...c, decision: "block", rule: "not-exposed", dependsOn: [], draft: "block" };
    }
    const verdict = evaluate(policy, { server: c.server, tool: c.tool, args: {} });
    const decider = policy.rules.findIndex((rule) => rule.id === verdict.rule);
    const before = decider < 0 ? policy.rules : policy.rules.slice(0, decider + 1);
    const dependsOn = before.filter((rule) => namesTools(rule) && matchesName(rule, c.server, c.tool) && (rule.args.length > 0 || rule.fixed === undefined)).map((rule) => rule.id);
    return { ...c, decision: verdict.decision, rule: verdict.rule, dependsOn, draft: evaluate(draftPolicy, { server: c.server, tool: c.tool, args: {} }).decision };
  });
  return {
    suggestions,
    argumentRules: policy.rules.filter((rule) => !namesTools(rule) && rule.args.length > 0).map((rule) => rule.id),
    unmatched: suggestions.filter((s) => s.rule === "default").map((s) => `${s.server}__${s.tool}`),
    notDrafted,
    draft,
  };
}

/** True when a rule says which servers or tools it is about; false for one that looks only at arguments. */
function namesTools(rule: Policy["rules"][number]): boolean {
  return rule.server !== undefined || rule.tool !== undefined || rule.toolWords !== undefined;
}

/**
 * The operations of an OpenAPI (or Swagger 2) document in JSON, as tools of `server` named by their
 * operationId: the server in the gateway config that serves them, so the draft's rule names it.
 */
export function openApiCandidates(spec: unknown, server: string): Candidate[] {
  const doc = object(spec, "the OpenAPI document");
  if (doc.openapi === undefined && doc.swagger === undefined) fail('the OpenAPI document has no "openapi" or "swagger" field');
  const paths = object(doc.paths, "the OpenAPI document's paths");
  const candidates: Candidate[] = [];
  for (const [route, item] of Object.entries(paths)) {
    if (typeof item !== "object" || item === null) continue;
    for (const method of HTTP_METHODS) {
      const operation = (item as Record<string, unknown>)[method];
      if (typeof operation !== "object" || operation === null) continue;
      const id = (operation as { operationId?: unknown }).operationId;
      const tool = typeof id === "string" && /^[A-Za-z0-9_.-]{1,128}$/.test(id) ? id : `${method}_${route}`.replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
      candidates.push({ server, tool, http: { method, path: route } });
    }
  }
  return candidates;
}

/**
 * Lists the tools of every downstream server in the config, as the gateway would reach them: a local
 * server's command is run (whatever it does when it starts, it does), a remote one is sent its headers.
 * A server that cannot be reached or listed is named in `failures`.
 */
export async function downstreamCandidates(config: GatewayConfig, env: NodeJS.ProcessEnv = process.env): Promise<{ candidates: Candidate[]; failures: string[] }> {
  const candidates: Candidate[] = [];
  const failures: string[] = [];
  for (const s of config.servers) {
    const missing = Object.values(s.headersFromEnv ?? {}).filter((variable) => !env[variable]);
    if (missing.length > 0) {
      failures.push(`"${s.name}": set the environment variables named by headersFromEnv: ${missing.join(", ")}`);
      continue;
    }
    const headers = Object.fromEntries(Object.entries(s.headersFromEnv ?? {}).map(([header, variable]) => [header, env[variable] as string]));
    const secrets = Object.values(headers).filter((value) => value.length >= 4);
    const scrub = (message: string) => secrets.reduce((text, secret) => text.split(secret).join("[REDACTED:header]"), message);
    const client = new Client({ name: "agent-gate-suggest", version: VERSION });
    try {
      await client.connect(transportFor(s, headers), s.timeoutMs === undefined ? {} : { timeout: s.timeoutMs });
      const problems: string[] = [];
      const tools: Tool[] = await listTools(s.name, client, (message) => problems.push(message), s.timeoutMs, scrub);
      if (problems.length > 0) failures.push(...problems);
      for (const tool of tools) candidates.push({ server: s.name, tool: tool.name, ...hintsOf(tool) });
    } catch (err) {
      failures.push(`"${s.name}": could not start or reach it: ${scrub(err instanceof Error ? err.message : String(err))}`);
    } finally {
      await client.close().catch(() => undefined);
    }
  }
  return { candidates, failures };
}

function hintsOf(tool: Tool): { hints?: string[] } {
  const a = tool.annotations;
  const hints = [a?.readOnlyHint === true ? "read-only" : undefined, a?.destructiveHint === true ? "destructive" : undefined].filter((h): h is string => h !== undefined);
  return hints.length > 0 ? { hints } : {};
}
