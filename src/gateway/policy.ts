// The policy engine: decides allow / warn / ask / block for one MCP tool call.
//
// A policy is JSON: a default decision and an ordered list of rules. The first rule that matches
// a call decides; when none matches, the default decides. parsePolicy() checks the JSON once and
// compiles its patterns. evaluate() is a pure function (no I/O, no clock, no randomness): the same
// policy and the same call always get the same verdict, which is what makes it table-testable.
//
// A rule matches on any combination of these, all of which must match:
//   server     the downstream server's name             glob or regex, or a list of them
//   tool       the tool's name on that server            glob or regex, or a list of them
//   toolWords  words in the tool's name                  ["delete", "create pull request"]
//   args       argument values, by argument name         { "path": "*.env" }
// A rule then either has a fixed "decision" and "why", or is a shell rule ("type": "shell") that
// runs the slice-1 shell analyzer on one string argument and maps its answer.

import { analyze, legacyDecide, type GuardAction, type GuardDecision } from "#command-guard";
import { array, fail, object, onlyKeys, text } from "./validate.js";

export type Decision = "allow" | "warn" | "ask" | "block";
export const DECISIONS: readonly Decision[] = ["allow", "warn", "ask", "block"];

export interface ToolCall {
  /** The downstream server's name from the gateway config. */
  server: string;
  /** The tool's name on that server, without the gateway's "<server>__" prefix. */
  tool: string;
  args: Record<string, unknown>;
}

export interface Verdict {
  decision: Decision;
  /** The id of the rule that decided, or "default". */
  rule: string;
  /** Why, in words that the agent and the human approver can act on. */
  why: string;
}

type Test = (value: string) => boolean;

export interface CompiledRule {
  readonly id: string;
  readonly server?: Test;
  readonly tool?: Test;
  readonly toolWords?: readonly string[][];
  readonly args: ReadonlyArray<{ name: string; test: Test }>;
  readonly verdict: (call: ToolCall) => Verdict;
}

export interface Policy {
  readonly default: Decision;
  readonly rules: readonly CompiledRule[];
}

/** How the shell analyzer's four answers map onto gateway decisions. */
export const SHELL_TO_DECISION: Readonly<Record<GuardAction, Decision>> = {
  pass: "allow",
  warn: "warn",
  ask: "ask",
  block: "block",
};

export function evaluate(policy: Policy, call: ToolCall): Verdict {
  for (const rule of policy.rules) {
    if (matches(rule, call)) return rule.verdict(call);
  }
  return { decision: policy.default, rule: "default", why: `no rule matched; the policy default is ${policy.default}` };
}

function matches(rule: CompiledRule, call: ToolCall): boolean {
  if (rule.server && !rule.server(call.server)) return false;
  if (rule.tool && !rule.tool(call.tool)) return false;
  if (rule.toolWords) {
    const words = splitWords(call.tool);
    if (!rule.toolWords.some((phrase) => containsPhrase(words, phrase))) return false;
  }
  for (const { name, test } of rule.args) {
    // Own properties only: an argument named "constructor" must not match Object.prototype.
    if (!Object.prototype.hasOwnProperty.call(call.args, name)) return false;
    if (!test(argumentText(call.args[name]))) return false;
  }
  return true;
}

/**
 * Strings are matched as they are; any other argument value is matched as its JSON text.
 * ponytail: text only. Paths are not resolved, so a symlink into a protected directory, or a
 * relative path used from inside it, does not look like that directory to a rule.
 */
function argumentText(value: unknown): string {
  return typeof value === "string" ? value : (JSON.stringify(value) ?? "");
}

/**
 * Splits a tool name into lowercase words at "_", "-", ".", spaces and camelCase humps, so that
 * delete_file, deleteFile, DeleteFile and delete-file all read as "delete file". Matching whole
 * words is what keeps "post" from matching postgres_query and "comment" from matching list_comments.
 */
export function splitWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((word) => word !== "");
}

function containsPhrase(words: readonly string[], phrase: readonly string[]): boolean {
  for (let start = 0; start + phrase.length <= words.length; start++) {
    if (phrase.every((word, i) => words[start + i] === word)) return true;
  }
  return false;
}

// ── shell rules ─────────────────────────────────────────────────────────────────────────────

function shellVerdict(rule: string, argument: string, call: ToolCall): Verdict {
  const command = Object.prototype.hasOwnProperty.call(call.args, argument) ? call.args[argument] : undefined;
  if (typeof command !== "string") {
    return { decision: "ask", rule, why: `shell tool called without a string "${argument}" argument, so it cannot be inspected` };
  }
  let answer: GuardDecision;
  try {
    answer = analyze(command);
  } catch (err) {
    // The same fallback as the slice-1 hook: if the analyzer itself breaks, the legacy rules
    // decide, and anything they do not block goes to a human.
    let legacy: GuardDecision = { action: "pass" };
    try {
      legacy = legacyDecide(command);
    } catch {
      // fall through to ask
    }
    if (legacy.action === "block") return { decision: "block", rule, why: `shell guard: ${legacy.label}` };
    return { decision: "ask", rule, why: `shell guard failed (${String(err).slice(0, 120)}), so a human should look at the command` };
  }
  const why =
    answer.action === "pass"
      ? "shell guard: no rule matched the command"
      : `shell guard: ${answer.label}${answer.why ? `: ${answer.why}` : ""}`;
  return { decision: SHELL_TO_DECISION[answer.action], rule, why };
}

// ── parsing ─────────────────────────────────────────────────────────────────────────────────

const MATCH_KEYS = ["id", "server", "tool", "toolWords", "args", "decision", "why"] as const;
const SHELL_KEYS = ["id", "type", "server", "tool", "toolWords", "args", "argument"] as const;

/** Checks policy JSON and compiles it. Throws ConfigError naming the bad field. */
export function parsePolicy(json: unknown): Policy {
  const policy = object(json, "policy");
  onlyKeys(policy, ["default", "rules"], "policy");
  const fallback = decision(policy.default, "policy.default");
  const ids = new Set<string>();
  const rules = array(policy.rules ?? [], "policy.rules").map((raw, i) => compileRule(raw, `policy.rules[${i}]`, ids));
  return { default: fallback, rules };
}

function compileRule(raw: unknown, at: string, ids: Set<string>): CompiledRule {
  const rule = object(raw, at);
  if (rule.type !== undefined && rule.type !== "shell") fail(`${at}.type must be "shell" or left out`);
  const shell = rule.type === "shell";
  onlyKeys(rule, shell ? SHELL_KEYS : MATCH_KEYS, at);

  const id = text(rule.id, `${at}.id`);
  if (id === "default") fail(`${at}.id "default" is reserved for the policy default`);
  if (ids.has(id)) fail(`${at}.id "${id}" is already used by an earlier rule`);
  ids.add(id);

  const match = {
    id,
    server: rule.server === undefined ? undefined : matcher(rule.server, `${at}.server`),
    tool: rule.tool === undefined ? undefined : matcher(rule.tool, `${at}.tool`),
    toolWords: rule.toolWords === undefined ? undefined : phrases(rule.toolWords, `${at}.toolWords`),
    args: rule.args === undefined ? [] : argumentMatchers(rule.args, `${at}.args`),
  };

  if (shell) {
    // A shell rule without a tool filter would send every other tool's call to a human.
    if (!match.tool && !match.toolWords) fail(`${at} is a shell rule, so it needs "tool" or "toolWords"`);
    const argument = rule.argument === undefined ? "command" : text(rule.argument, `${at}.argument`);
    return { ...match, verdict: (call) => shellVerdict(id, argument, call) };
  }
  const fixed: Verdict = { decision: decision(rule.decision, `${at}.decision`), rule: id, why: text(rule.why, `${at}.why`) };
  return { ...match, verdict: () => ({ ...fixed }) };
}

function decision(value: unknown, at: string): Decision {
  if (!DECISIONS.includes(value as Decision)) fail(`${at} must be one of ${DECISIONS.join(", ")}`);
  return value as Decision;
}

/** A glob or regex, or a non-empty list of them (any one may match). */
function matcher(value: unknown, at: string): Test {
  const list = Array.isArray(value) ? value : [value];
  if (list.length === 0) fail(`${at} must not be an empty list`);
  const tests = list.map((one, i) => singleMatcher(one, Array.isArray(value) ? `${at}[${i}]` : at));
  return (candidate) => tests.some((test) => test(candidate));
}

/**
 * A string is a glob: it must match the whole value, case-insensitively; "*" matches any run of
 * characters (including "/" and line breaks) and "?" matches one character.
 * { "regex": "...", "flags": "i" } is a JavaScript regular expression, unanchored unless it says
 * otherwise. Regexes are objects, not "/.../" strings, so that a path such as "/etc/" is never
 * mistaken for one.
 */
function singleMatcher(value: unknown, at: string): Test {
  if (typeof value === "string") {
    const re = globToRegExp(text(value, at));
    return (candidate) => re.test(candidate);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${at} must be a glob string or { "regex": "...", "flags": "..." }`);
  }
  const spec = value as Record<string, unknown>;
  onlyKeys(spec, ["regex", "flags"], at);
  const source = text(spec.regex, `${at}.regex`);
  const flags = spec.flags === undefined ? "" : spec.flags;
  // g and y make RegExp.test() remember where it stopped, so a rule would match only every other time.
  if (typeof flags !== "string" || !/^[imsu]*$/.test(flags)) fail(`${at}.flags may only contain i, m, s and u`);
  let re: RegExp;
  try {
    re = new RegExp(source, flags);
  } catch (err) {
    fail(`${at}.regex is not a valid regular expression: ${(err as Error).message}`);
  }
  return (candidate) => re.test(candidate);
}

export function globToRegExp(glob: string): RegExp {
  let source = "";
  for (const ch of glob) {
    source += ch === "*" ? ".*" : ch === "?" ? "." : ch.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
  }
  return new RegExp(`^${source}$`, "is");
}

function phrases(value: unknown, at: string): string[][] {
  const list = array(value, at);
  if (list.length === 0) fail(`${at} must not be empty`);
  return list.map((entry, i) => {
    const words = splitWords(text(entry, `${at}[${i}]`));
    if (words.length === 0) fail(`${at}[${i}] has no letters or digits`);
    return words;
  });
}

function argumentMatchers(value: unknown, at: string): Array<{ name: string; test: Test }> {
  const entries = Object.entries(object(value, at));
  if (entries.length === 0) fail(`${at} must name at least one argument`);
  return entries.map(([name, spec]) => ({ name, test: matcher(spec, `${at}.${name}`) }));
}
