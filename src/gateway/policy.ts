// The policy engine: decides allow / warn / ask / block for one MCP tool call.
//
// A policy is JSON: a default decision and an ordered list of rules. The first rule that matches
// a call decides; when none matches, the default decides. Rules after it that also match are listed
// in the verdict (alsoMatched) for the human and the audit log; they decide nothing. parsePolicy()
// checks the JSON once and compiles its patterns. evaluate() is a pure function (no I/O, no clock,
// no randomness): the same policy and the same call always get the same verdict, which is what makes
// it table-testable. The one exception is a path matcher that resolves symlinks (below): it reads
// the file system, so its answer follows the disk.
//
// A rule with "decision": "rewrite" does not decide. It edits the call's arguments ("rewrite": set,
// clamp, drop, redact) and evaluation goes on with the next rule, on the edited arguments: the call
// that runs, and any approval it needs, is the edited one. A rewrite that cannot make the call safe
// (a clamp on a value that is not a number) asks instead.
//
// "repeat" (optional) is a list of loop limits, a circuit breaker kept apart from the rules: when the
// same call (or with "per": "tool", any call to the tool) has already run `max` times in the last
// `windowSeconds`, a call that the rules would let run (allow or warn) is asked about or blocked
// instead. Counting needs state, so the gateway applies them (src/gateway/repeats.ts); this file only
// says which limits a call falls under.
//
// A rule matches on any combination of these, all of which must match:
//   server     the downstream server's name             glob or regex, or a list of them
//   tool       the tool's name on that server            glob or regex, or a list of them
//   toolWords  words in the tool's name                  ["delete", "create pull request"]
//   args       argument values, by argument name         { "path": "*.env" }, or a path matcher:
//              { "path": { "under": ["/srv/agent-work"] } } (also "outside" and "touches", below)
// A rule then either has a fixed "decision" and "why", or is a shell rule ("type": "shell") that
// runs the slice-1 shell analyzer on one string argument and maps its answer. A rule that can ask may
// set "ttlMinutes": how long its approval requests live, instead of the config's approvalTtlHours.

import * as fs from "node:fs";
import * as path from "node:path";
import { analyze, legacyDecide, type GuardAction, type GuardDecision } from "#command-guard";
import { array, fail, object, onlyKeys, text } from "./validate.js";

export type Decision = "allow" | "warn" | "ask" | "block";
export const DECISIONS: readonly Decision[] = ["allow", "warn", "ask", "block"];
/** What a rule can say: one of the four decisions, or "rewrite" (edit the arguments, then go on). */
export type RuleDecision = Decision | "rewrite";

/** A rule after the deciding one that matched the call too. */
export interface AlsoMatched {
  rule: string;
  decision: RuleDecision;
  why: string;
}

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
  /** For an ask: how long the approval request lives (the rule's ttlMinutes). Absent: the config's approvalTtlHours. */
  ttlMs?: number;
  /** For an ask: a standing approval (a bounded grant, ADR 0006) may answer it. Only rules that say so. */
  standing?: true;
  /** Every later rule that matched the call too, in policy order. Information for the human; it changes nothing. */
  alsoMatched?: AlsoMatched[];
  /** With rewrite rules that changed something: the arguments the call runs with, and those rules in order. */
  args?: Record<string, unknown>;
  rewrittenBy?: string[];
}

type Test = (value: string) => boolean;
/** Tests an argument's value as the call has it: a path matcher needs strings and arrays as they are. */
type ValueTest = (value: unknown) => boolean;

export interface CompiledRule {
  readonly id: string;
  readonly server?: Test;
  readonly tool?: Test;
  readonly toolWords?: readonly string[][];
  readonly args: ReadonlyArray<{ name: string; test: ValueTest }>;
  /** A rule that decides. */
  readonly verdict?: (call: ToolCall) => Verdict;
  /** A rule that decides with a fixed decision (not a shell rule): that decision. */
  readonly fixed?: Decision;
  /** A rule that rewrites the arguments instead. */
  readonly rewrite?: { why: string; apply: (args: Record<string, unknown>) => RewriteResult };
}

export type RewriteResult = { ok: true; args: Record<string, unknown>; changed: boolean } | { ok: false; why: string };

/** A loop limit: see the comment at the top. */
export interface RepeatLimit {
  readonly id: string;
  readonly server?: Test;
  readonly tool?: Test;
  readonly toolWords?: readonly string[][];
  readonly args: ReadonlyArray<{ name: string; test: ValueTest }>;
  readonly max: number;
  readonly windowMs: number;
  readonly decision: "ask" | "block";
  readonly why?: string;
  /** "call": the same server, tool and arguments; "tool": any call to the same tool. */
  readonly per: "call" | "tool";
}

export interface Policy {
  readonly default: Decision;
  readonly rules: readonly CompiledRule[];
  readonly repeat: readonly RepeatLimit[];
}

/**
 * True when every call to this tool is blocked, whatever its arguments: the gateway then leaves it out
 * of tools/list (pure). A shell rule, or a rule that does not block and matches only some arguments,
 * means some calls may get through, so the tool stays listed. Loop limits never block every call.
 */
export function alwaysBlocked(policy: Policy, server: string, tool: string): boolean {
  const call: ToolCall = { server, tool, args: {} };
  for (const rule of policy.rules) {
    if (!matches({ ...rule, args: [] }, call)) continue;
    if (rule.rewrite) continue; // edits arguments, never the server or tool name
    if (rule.fixed === undefined) return false; // a shell rule: its verdict depends on the command
    if (rule.args.length > 0) {
      if (rule.fixed === "block") continue; // blocks the calls it matches; the others go on to the next rule
      return false;
    }
    return rule.fixed === "block";
  }
  return policy.default === "block";
}

/** The loop limits that a call falls under (pure). */
export function repeatLimitsFor(policy: Policy, call: ToolCall): RepeatLimit[] {
  return policy.repeat.filter((limit) => matches(limit, call));
}

/** How the shell analyzer's four answers map onto gateway decisions. */
export const SHELL_TO_DECISION: Readonly<Record<GuardAction, Decision>> = {
  pass: "allow",
  warn: "warn",
  ask: "ask",
  block: "block",
};

export function evaluate(policy: Policy, call: ToolCall): Verdict {
  let current = call;
  let decided: Verdict | undefined;
  const also: AlsoMatched[] = [];
  const rewrittenBy: string[] = [];
  for (const rule of policy.rules) {
    if (!matches(rule, current)) continue;
    if (rule.rewrite) {
      // A rewrite after the deciding rule changes nothing: the decision was made on the call as it was.
      if (decided) {
        also.push({ rule: rule.id, decision: "rewrite", why: rule.rewrite.why });
        continue;
      }
      const result = rule.rewrite.apply(current.args);
      if (!result.ok) decided = { decision: "ask", rule: rule.id, why: result.why };
      else if (result.changed) {
        current = { ...current, args: result.args };
        rewrittenBy.push(rule.id);
      }
      continue;
    }
    const verdict = (rule.verdict as (call: ToolCall) => Verdict)(current);
    if (decided) also.push({ rule: rule.id, decision: verdict.decision, why: verdict.why });
    else decided = verdict;
  }
  return {
    ...(decided ?? { decision: policy.default, rule: "default", why: `no rule matched; the policy default is ${policy.default}` }),
    ...(also.length > 0 ? { alsoMatched: also } : {}),
    ...(rewrittenBy.length > 0 ? { args: current.args, rewrittenBy } : {}),
  };
}

function matches(rule: Pick<CompiledRule, "server" | "tool" | "toolWords" | "args">, call: ToolCall): boolean {
  if (rule.server && !rule.server(call.server)) return false;
  if (rule.tool && !rule.tool(call.tool)) return false;
  if (rule.toolWords) {
    const words = splitWords(call.tool);
    if (!rule.toolWords.some((phrase) => containsPhrase(words, phrase))) return false;
  }
  for (const { name, test } of rule.args) {
    // Own properties only: an argument named "constructor" must not match Object.prototype.
    if (!Object.prototype.hasOwnProperty.call(call.args, name)) return false;
    if (!test(call.args[name])) return false;
  }
  return true;
}

/** True when a rule's server, tool and toolWords conditions match this tool; its argument conditions are left aside (pure). */
export function matchesName(rule: CompiledRule, server: string, tool: string): boolean {
  return matches({ ...rule, args: [] }, { server, tool, args: {} });
}

/**
 * For globs and regexes: strings are matched as they are; any other argument value is matched as its
 * JSON text. A glob reads text only: it does not resolve paths, so a symlink into a protected folder,
 * or a ".." out of an allowed one, does not look like that folder to it. The path matchers below do.
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

const MATCH_KEYS = ["id", "server", "tool", "toolWords", "args", "decision", "why", "ttlMinutes", "standing", "rewrite"] as const;
const SHELL_KEYS = ["id", "type", "server", "tool", "toolWords", "args", "argument", "ttlMinutes"] as const;

/** Checks policy JSON and compiles it. Throws ConfigError naming the bad field. */
export function parsePolicy(json: unknown): Policy {
  const policy = object(json, "policy");
  onlyKeys(policy, ["default", "rules", "repeat"], "policy");
  const fallback = decision(policy.default, "policy.default");
  const ids = new Set<string>();
  const rules = array(policy.rules ?? [], "policy.rules").map((raw, i) => compileRule(raw, `policy.rules[${i}]`, ids));
  const repeat = array(policy.repeat ?? [], "policy.repeat").map((raw, i) => compileRepeat(raw, `policy.repeat[${i}]`, ids));
  return { default: fallback, rules, repeat };
}

function compileRepeat(raw: unknown, at: string, ids: Set<string>): RepeatLimit {
  const limit = object(raw, at);
  onlyKeys(limit, ["id", "server", "tool", "toolWords", "args", "max", "windowSeconds", "decision", "why", "per"], at);
  const id = text(limit.id, `${at}.id`);
  if (id === "default") fail(`${at}.id "default" is reserved for the policy default`);
  if (ids.has(id)) fail(`${at}.id "${id}" is already used by an earlier rule or limit`);
  ids.add(id);
  const max = limit.max;
  if (typeof max !== "number" || !Number.isInteger(max) || max < 1 || max > 10_000) fail(`${at}.max must be a whole number from 1 to 10000`);
  const seconds = limit.windowSeconds;
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds <= 0 || seconds > 86_400) fail(`${at}.windowSeconds must be more than 0 and at most 86400`);
  if (limit.decision !== "ask" && limit.decision !== "block") fail(`${at}.decision must be ask or block`);
  const per = limit.per ?? "call";
  if (per !== "call" && per !== "tool") fail(`${at}.per must be "call" or "tool"`);
  return {
    id,
    ...(limit.server === undefined ? {} : { server: matcher(limit.server, `${at}.server`) }),
    ...(limit.tool === undefined ? {} : { tool: matcher(limit.tool, `${at}.tool`) }),
    ...(limit.toolWords === undefined ? {} : { toolWords: phrases(limit.toolWords, `${at}.toolWords`) }),
    args: limit.args === undefined ? [] : argumentMatchers(limit.args, `${at}.args`),
    max,
    windowMs: Math.round(seconds * 1000),
    decision: limit.decision,
    ...(limit.why === undefined ? {} : { why: text(limit.why, `${at}.why`) }),
    per,
  };
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

  const ttlMs = rule.ttlMinutes === undefined ? undefined : minutes(rule.ttlMinutes, `${at}.ttlMinutes`);
  // The lifetime belongs to approval requests, so it is attached only to an ask.
  const withTtl = (verdict: Verdict): Verdict => (ttlMs !== undefined && verdict.decision === "ask" ? { ...verdict, ttlMs } : verdict);
  if (shell) {
    // A shell rule without a tool filter would send every other tool's call to a human.
    if (!match.tool && !match.toolWords) fail(`${at} is a shell rule, so it needs "tool" or "toolWords"`);
    const argument = rule.argument === undefined ? "command" : text(rule.argument, `${at}.argument`);
    return { ...match, verdict: (call) => withTtl(shellVerdict(id, argument, call)) };
  }
  if (rule.decision === "rewrite") {
    for (const key of ["ttlMinutes", "standing"] as const) if (rule[key] !== undefined) fail(`${at}.${key} does not apply to a rewrite rule, which decides nothing`);
    if (rule.rewrite === undefined) fail(`${at} is a rewrite rule, so it needs "rewrite"`);
    const why = text(rule.why, `${at}.why`);
    return { ...match, rewrite: { why, apply: compileRewrite(rule.rewrite, `${at}.rewrite`, id) } };
  }
  if (rule.rewrite !== undefined) fail(`${at}.rewrite only applies to a rule whose decision is rewrite`);
  const fixed: Verdict = { decision: decision(rule.decision, `${at}.decision`), rule: id, why: text(rule.why, `${at}.why`) };
  if (ttlMs !== undefined && fixed.decision !== "ask") fail(`${at}.ttlMinutes only applies to a rule whose decision is ask`);
  if (rule.standing !== undefined) {
    if (rule.standing !== true && rule.standing !== false) fail(`${at}.standing must be true or false`);
    if (rule.standing && fixed.decision !== "ask") fail(`${at}.standing only applies to a rule whose decision is ask`);
    if (rule.standing) fixed.standing = true;
  }
  return { ...match, fixed: fixed.decision, verdict: () => withTtl({ ...fixed }) };
}

// ── rewrite rules ───────────────────────────────────────────────────────────────────────────

/**
 * The edits of a rewrite rule, applied in this order: drop (remove arguments), set (give arguments a
 * value), clamp (bring a number into [min, max]), redact (replace what a regex matches in the strings
 * of the listed arguments, or of all of them, with [REDACTED:<rule id>]).
 */
function compileRewrite(raw: unknown, at: string, id: string): (args: Record<string, unknown>) => RewriteResult {
  const spec = object(raw, at);
  onlyKeys(spec, ["set", "clamp", "drop", "redact"], at);
  if (spec.set === undefined && spec.clamp === undefined && spec.drop === undefined && spec.redact === undefined) {
    fail(`${at} needs at least one of set, clamp, drop and redact`);
  }
  const set = spec.set === undefined ? [] : Object.entries(object(spec.set, `${at}.set`));
  if (spec.set !== undefined && set.length === 0) fail(`${at}.set must name at least one argument`);
  const clamp = spec.clamp === undefined ? [] : Object.entries(object(spec.clamp, `${at}.clamp`)).map(([name, raw]) => bounds(raw, `${at}.clamp.${name}`, name));
  if (spec.clamp !== undefined && clamp.length === 0) fail(`${at}.clamp must name at least one argument`);
  const drop = spec.drop === undefined ? [] : array(spec.drop, `${at}.drop`).map((name, i) => text(name, `${at}.drop[${i}]`));
  for (const [name] of set) if (drop.includes(name)) fail(`${at} both sets and drops "${name}"`);
  const redact = spec.redact === undefined ? [] : array(spec.redact, `${at}.redact`).map((raw, i) => redaction(raw, `${at}.redact[${i}]`));
  const marker = `[REDACTED:${id}]`;

  return (input) => {
    const args: Record<string, unknown> = JSON.parse(JSON.stringify(input));
    let changed = false;
    for (const name of drop) {
      if (Object.prototype.hasOwnProperty.call(args, name)) {
        delete args[name];
        changed = true;
      }
    }
    for (const [name, value] of set) {
      if (!Object.prototype.hasOwnProperty.call(args, name) || JSON.stringify(args[name]) !== JSON.stringify(value)) changed = true;
      args[name] = JSON.parse(JSON.stringify(value));
    }
    for (const { name, min, max } of clamp) {
      if (!Object.prototype.hasOwnProperty.call(args, name)) continue;
      const value = args[name];
      if (typeof value !== "number" || !Number.isFinite(value)) {
        return { ok: false, why: `rule ${id} keeps "${name}" within bounds, and this value is not a number, so it cannot be made safe` };
      }
      const kept = Math.min(max ?? value, Math.max(min ?? value, value));
      if (kept !== value) {
        args[name] = kept;
        changed = true;
      }
    }
    for (const { re, names } of redact) {
      for (const name of Object.keys(args)) {
        if (names && !names.includes(name)) continue;
        const next = redactDeep(args[name], re, marker);
        if (JSON.stringify(next) !== JSON.stringify(args[name])) {
          args[name] = next;
          changed = true;
        }
      }
    }
    return { ok: true, args, changed };
  };
}

function bounds(raw: unknown, at: string, name: string): { name: string; min?: number; max?: number } {
  const b = object(raw, at);
  onlyKeys(b, ["min", "max"], at);
  const number = (value: unknown, field: string): number | undefined => {
    if (value === undefined) return undefined;
    if (typeof value !== "number" || !Number.isFinite(value)) fail(`${at}.${field} must be a number`);
    return value;
  };
  const min = number(b.min, "min");
  const max = number(b.max, "max");
  if (min === undefined && max === undefined) fail(`${at} needs "min", "max" or both`);
  if (min !== undefined && max !== undefined && min > max) fail(`${at}.min is more than its max`);
  return { name, ...(min === undefined ? {} : { min }), ...(max === undefined ? {} : { max }) };
}

function redaction(raw: unknown, at: string): { re: RegExp; names?: string[] } {
  const r = object(raw, at);
  onlyKeys(r, ["regex", "flags", "arguments"], at);
  const flags = r.flags === undefined ? "" : r.flags;
  if (typeof flags !== "string" || !/^[imsu]*$/.test(flags)) fail(`${at}.flags may only contain i, m, s and u`);
  let re: RegExp;
  try {
    re = new RegExp(text(r.regex, `${at}.regex`), `${flags}g`);
  } catch (err) {
    fail(`${at}.regex is not a valid regular expression: ${(err as Error).message}`);
  }
  if (new RegExp(re.source, flags).test("")) fail(`${at}.regex matches empty text, so it would match every value`);
  if (r.arguments === undefined) return { re };
  const names = array(r.arguments, `${at}.arguments`).map((name, i) => text(name, `${at}.arguments[${i}]`));
  if (names.length === 0) fail(`${at}.arguments must name at least one argument`);
  return { re, names };
}

/** Replaces every match in every string inside `value` (arrays and objects included) with `marker`. */
function redactDeep(value: unknown, re: RegExp, marker: string): unknown {
  if (typeof value === "string") return value.replace(re, marker);
  if (Array.isArray(value)) return value.map((item) => redactDeep(item, re, marker));
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [key, redactDeep(item, re, marker)]));
  }
  return value;
}

function minutes(value: unknown, at: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) fail(`${at} must be a positive number of minutes`);
  return Math.round(value * 60 * 1000);
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

function argumentMatchers(value: unknown, at: string): Array<{ name: string; test: ValueTest }> {
  const entries = Object.entries(object(value, at));
  if (entries.length === 0) fail(`${at} must name at least one argument`);
  return entries.map(([name, spec]) => ({ name, test: valueMatcher(spec, `${at}.${name}`) }));
}

/** An argument's matcher: a glob, a regex or a path matcher, or a non-empty list of them (any one may match). */
function valueMatcher(value: unknown, at: string): ValueTest {
  const list = Array.isArray(value) ? value : [value];
  if (list.length === 0) fail(`${at} must not be an empty list`);
  const tests = list.map((one, i): ValueTest => {
    const where = Array.isArray(value) ? `${at}[${i}]` : at;
    if (typeof one === "object" && one !== null && !Array.isArray(one) && PATH_KINDS.some((kind) => kind in one)) {
      return pathMatcher(one as Record<string, unknown>, where);
    }
    const test = singleMatcher(one, where);
    return (candidate) => test(argumentText(candidate));
  });
  return (candidate) => tests.some((test) => test(candidate));
}

// ── path matchers ───────────────────────────────────────────────────────────────────────────
//
// { "under": [folders] }, { "outside": [folders] } or { "touches": [folders] }, each with
// "symlinks": "resolve" (the default) or "ignore". A glob reads a path as text, so "/srv/work/*"
// matches "/srv/work/../../etc/passwd". These read it as a path instead.
//
// The gateway cannot know how the downstream server will read a path, so it reads it every way it
// knows, and each way is a "reading":
//   - as written, and decoded when it has %XX escapes (up to three times, for double encoding);
//     cut at a NUL character too, when it has one, because C code stops there;
//   - lexically: "." and ".." and repeated "/" removed, as path.resolve() does it;
//   - with symlinks resolved (unless "ignore"): the lexical form's real path, and the written form
//     walked as the kernel walks it, where a ".." after a symlink goes to the parent of its target.
//     The part that does not exist yet keeps its name after the real path of the part that does.
// A reading is unknown when the gateway cannot place it: a relative path (the server's working
// folder is not known here), a path that starts with "~" (the server's home is not known either), a
// NUL, an escape that does not decode, a ".." after a folder that does not exist, a loop of symlinks.
//   under     every reading is known and inside a folder: the path stays in, however it is read.
//   outside   the opposite of under: some reading may land outside, or is unknown.
//   touches   some known reading is inside a folder: the path may reach in.
// A value that is not a string is not under and touches nothing. A list is under when it has items
// and each one is, and touches when one item does. The folders must be absolute paths; with symlinks
// resolved, they are resolved once, when the policy is loaded.

const PATH_KINDS = ["under", "outside", "touches"] as const;
type PathKind = (typeof PATH_KINDS)[number];
const ESCAPE = /%[0-9a-f]{2}/i;

function pathMatcher(spec: Record<string, unknown>, at: string): ValueTest {
  onlyKeys(spec, [...PATH_KINDS, "symlinks"], at);
  const kinds = PATH_KINDS.filter((kind) => spec[kind] !== undefined);
  if (kinds.length !== 1) fail(`${at} needs exactly one of "under", "outside" and "touches"`);
  const kind = kinds[0] as PathKind;
  const symlinks = spec.symlinks ?? "resolve";
  if (symlinks !== "resolve" && symlinks !== "ignore") fail(`${at}.symlinks must be "resolve" or "ignore"`);
  const links = symlinks === "resolve";
  const list = array(spec[kind], `${at}.${kind}`);
  if (list.length === 0) fail(`${at}.${kind} must list at least one folder`);
  const roots = list.map((raw, i) => {
    const root = text(raw, `${at}.${kind}[${i}]`);
    if (root.includes("\0") || !path.isAbsolute(root)) fail(`${at}.${kind}[${i}] must be an absolute path`);
    // Readings are compared with real paths, so the folder's own symlinks are resolved too.
    return links ? (realPrefix(path.resolve(root)) ?? fail(`${at}.${kind}[${i}] cannot be resolved: ${root}`)) : path.resolve(root);
  });
  const inside = (reading: string | undefined): boolean =>
    reading !== undefined && roots.some((root) => reading === root || reading.startsWith(root.endsWith(path.sep) ? root : root + path.sep));
  const one = (value: unknown): { under: boolean; touches: boolean } => {
    if (typeof value !== "string") return { under: false, touches: false };
    const readings = pathReadings(value, links);
    return { under: readings.every(inside), touches: readings.some(inside) };
  };
  return (value) => {
    const items = Array.isArray(value) ? value.map(one) : [one(value)];
    const under = items.length > 0 && items.every((item) => item.under);
    if (kind === "under") return under;
    if (kind === "outside") return !under;
    return items.some((item) => item.touches);
  };
}

/** Every way the gateway knows to read a path: see above. undefined stands for a reading it cannot place. */
export function pathReadings(value: string, links: boolean): Array<string | undefined> {
  const written: string[] = [value];
  const readings: Array<string | undefined> = [];
  let current = value;
  for (let round = 0; round < 3 && ESCAPE.test(current); round++) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      readings.push(undefined);
      break;
    }
    if (decoded === current) break;
    written.push(decoded);
    current = decoded;
  }
  for (const form of written) readings.push(...place(form, links));
  return readings;
}

function place(form: string, links: boolean): Array<string | undefined> {
  const nul = form.indexOf("\0");
  if (nul >= 0) return [undefined, ...place(form.slice(0, nul), links)];
  if (!path.isAbsolute(form)) return [undefined];
  const lexical = path.resolve(form);
  return links ? [realPrefix(lexical), realPrefix(form)] : [lexical];
}

/**
 * The real path of the longest part of `p` that exists, followed by the rest of `p`, walked like the
 * kernel walks it (realpath(3), so a ".." after a symlink leads to the parent of its target).
 * undefined when it cannot be known: a ".." in the part that does not exist, a loop, no permission.
 */
function realPrefix(p: string): string | undefined {
  const parts = p.split(path.sep);
  for (let i = parts.length; i >= 1; i--) {
    const head = parts.slice(0, i).join(path.sep) || path.sep;
    let real: string;
    try {
      real = fs.realpathSync.native(head);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") continue;
      return undefined;
    }
    const rest = parts.slice(i).filter((part) => part !== "" && part !== ".");
    if (rest.includes("..")) return undefined;
    return path.join(real, ...rest);
  }
  return undefined;
}
