// The leak guard: looks for secrets in a chat request before the request leaves for a provider.
//
// The rules are regexes in the policy file (llm-policy.example.json), each with an id and an
// action:
//   block   the request is refused (HTTP 400) with the rule id. The matched text is never echoed.
//   redact  every match is replaced with [REDACTED:<id>] and the request goes on. If the regex has
//           capture groups, only the first group that took part in the match is replaced, so
//           api_key = "..." keeps its name and quotes, and JSON in tool-call arguments stays JSON.
// Block rules are checked first, on the original text, so a redaction can never hide a secret that
// a block rule would have caught. guardMessages() is a pure function: no I/O, no clock.
// A rule may name a "validator" (src/llm/validators.ts): then a match counts only when the validator
// accepts it, for blocking and for redacting alike, so that a 16-digit order number is not taken for
// a card number unless its checksum says it could be one. A match that fails its check can still hold
// a number that passes it, such as a card number followed by its expiry date (the regex takes in the
// month as more digits): then the runs of whole digit groups inside the match are tried too, longest
// first. Such a rule also reads full-width digits, letters, hyphens and the ideographic space (as
// Japanese text often writes numbers) as their ASCII forms; the fold keeps every character in its
// place, so a redaction lands on the original text.
//
// Scanned: message "content" (a string, or the "text" of text parts) and the "arguments" string of
// assistant tool calls. Not scanned: images, audio and file parts, tool definitions, and any other
// request field. guardResponse() runs the same rules over an answer: the message of every choice,
// read the same way, so one rule catches a secret on either side.
// ponytail: the rules run on JavaScript's backtracking regex engine. The request body size limit
// (maxBodyBytes) bounds the work, but a badly written rule can still be slow; keep rules anchored
// on a literal prefix, as the shipped ones are.

import { array, fail, object, onlyKeys, text } from "../gateway/validate.js";
import { VALIDATOR_NAMES, VALIDATORS, type ValidatorName } from "./validators.js";

export type LeakAction = "block" | "redact";
export const LEAK_ACTIONS: readonly LeakAction[] = ["block", "redact"];

export interface LeakRule {
  readonly id: string;
  readonly action: LeakAction;
  readonly description?: string;
  /**
   * Without the g flag, so test() keeps no state between calls. For a rule with a validator, test() is
   * true only when some match passes it (a ValidatedPattern), so every caller of test() honours it.
   */
  readonly pattern: RegExp;
  readonly validator?: ValidatorName;
}

/** A rule's regex when the rule has a validator: test() looks for a match that the validator accepts. */
class ValidatedPattern extends RegExp {
  // Methods that build a new regex from this one (split, matchAll) get a plain RegExp.
  static override get [Symbol.species](): RegExpConstructor {
    return RegExp;
  }
  readonly find: ValidatedFinder;
  constructor(
    source: string,
    flags: string,
    readonly valid: (match: string) => boolean,
  ) {
    super(source, flags);
    this.find = validatedFinder(source, flags, valid);
  }
  override test(text: string): boolean {
    return this.find(foldWidth(text)).length > 0;
  }
}

/**
 * Full-width forms (U+FF01 to U+FF5E: digits, letters, the hyphen-minus and the rest) and the
 * ideographic space, as their ASCII forms. One UTF-16 unit becomes one, so every offset in the result
 * is the same offset in the original.
 */
export function foldWidth(text: string): string {
  return /[\uFF01-\uFF5E\u3000]/.test(text) ? text.replace(/[\uFF01-\uFF5E\u3000]/g, (ch) => (ch === "\u3000" ? " " : String.fromCharCode(ch.charCodeAt(0) - 0xfee0))) : text;
}

/** A span to replace: the first capture group that took part in the match, else the whole match. */
interface Found {
  start: number;
  end: number;
}
type ValidatedFinder = (text: string) => Found[];

/**
 * Every place in `text` (already folded) where the pattern matches and the validator accepts the match,
 * left to right, without overlaps. When a match fails its check, the runs of whole digit groups inside
 * it (split at whatever the match has between digits) that the pattern matches on their own are tried,
 * longest first, then earliest, so a card number followed by an expiry date or a security code, or
 * after a stray number, is still found. Scanning goes on right after what was found, or one character
 * after the start of a match that held nothing.
 */
function validatedFinder(source: string, flags: string, valid: (match: string) => boolean): ValidatedFinder {
  const plain = flags.replace(/[gyd]/g, "");
  const scan = new RegExp(source, `${plain}gd`);
  const anchored = new RegExp(`^(?:${source})$`, `${plain}d`);
  const spanOf = (m: RegExpExecArray, offset: number): Found => {
    const span = m.indices?.slice(1).find((s) => s !== undefined) ?? m.indices?.[0] ?? [0, m[0].length];
    return { start: offset + span[0], end: offset + span[1] };
  };
  return (text) => {
    const found: Found[] = [];
    let pos = 0;
    while (pos <= text.length) {
      scan.lastIndex = pos;
      const m = scan.exec(text);
      if (!m) break;
      const start = m.index;
      const end = start + m[0].length;
      if (end === start) {
        pos = start + 1;
        continue;
      }
      if (valid(m[0])) {
        found.push(spanOf(m, 0));
        pos = end;
        continue;
      }
      const inner = innerCandidate(text, start, end, anchored, valid);
      if (inner) {
        found.push(spanOf(inner.match, inner.start));
        pos = inner.end;
        continue;
      }
      pos = start + 1;
    }
    return found;
  };
}

/** The longest (then earliest) run of whole digit groups inside text[start, end) that the pattern matches on its own and the validator accepts. */
function innerCandidate(text: string, start: number, end: number, anchored: RegExp, valid: (match: string) => boolean): { match: RegExpExecArray; start: number; end: number } | undefined {
  const groups = [...text.slice(start, end).matchAll(/\d+/g)].map((g): [number, number] => [start + (g.index as number), start + (g.index as number) + g[0].length]);
  const runs: Array<[number, number]> = [];
  for (let i = 0; i < groups.length; i++) {
    for (let j = i; j < groups.length; j++) {
      const s = (groups[i] as [number, number])[0];
      const e = (groups[j] as [number, number])[1];
      if (s !== start || e !== end) runs.push([s, e]); // the whole match was already refused
    }
  }
  runs.sort((a, b) => b[1] - b[0] - (a[1] - a[0]) || a[0] - b[0]);
  for (const [s, e] of runs) {
    const candidate = text.slice(s, e);
    const m = anchored.exec(candidate);
    if (m && valid(candidate)) return { match: m, start: s, end: e };
  }
  return undefined;
}

export interface LeakPolicy {
  readonly rules: readonly LeakRule[];
}

export type GuardResult =
  | { action: "block"; rule: string }
  | { action: "pass"; messages: unknown[]; redactions: Array<{ rule: string; count: number }> };

/** Every string the guard scans, in order. The gateway also counts these for its cost estimate. */
export function messageTexts(messages: readonly unknown[]): string[] {
  const texts: string[] = [];
  mapTexts(messages, (t) => {
    texts.push(t);
    return t;
  });
  return texts;
}

export function guardMessages(policy: LeakPolicy, messages: readonly unknown[]): GuardResult {
  const texts = messageTexts(messages);
  for (const rule of policy.rules) {
    if (rule.action === "block" && texts.some((t) => rule.pattern.test(t))) return { action: "block", rule: rule.id };
  }

  const counts = new Map<string, number>();
  const redacting = redactRules(policy);
  const result = mapTexts(messages, (original) => redactText(redacting, original, counts));
  return { action: "pass", messages: result, redactions: [...counts].map(([rule, count]) => ({ rule, count })) };
}

/** A redact rule compiled for redactText(): its regex, or for a rule with a validator, the finder that honours it. */
export interface RedactRule {
  id: string;
  all: RegExp;
  find?: ValidatedFinder;
}

/** The policy's redact rules, compiled for redactText(). */
export function redactRules(policy: LeakPolicy): RedactRule[] {
  // g to find every match, d for the positions of capture groups. matchAll() works on a copy of
  // the regex, so one per call is safe.
  return policy.rules
    .filter((rule) => rule.action === "redact")
    .map((rule) => ({ id: rule.id, all: new RegExp(rule.pattern.source, `${rule.pattern.flags}gd`), ...(rule.pattern instanceof ValidatedPattern ? { find: rule.pattern.find } : {}) }));
}

/** Replaces what each redact rule matches in `original` with [REDACTED:<id>], counting per rule. */
export function redactText(rules: readonly RedactRule[], original: string, counts: Map<string, number>): string {
  let t = original;
  for (const rule of rules) {
    // The first capture group that took part in the match, or else the whole match. A rule with a
    // validator finds its spans on the folded text, whose offsets are the original's.
    const spans: Found[] = rule.find
      ? rule.find(foldWidth(t))
      : [...t.matchAll(rule.all)].flatMap((match) => {
          const span = match.indices?.slice(1).find((s) => s !== undefined) ?? match.indices?.[0];
          return span ? [{ start: span[0], end: span[1] }] : [];
        });
    let out = "";
    let done = 0;
    for (const span of spans) {
      if (span.start === span.end || span.start < done) continue;
      out += `${t.slice(done, span.start)}[REDACTED:${rule.id}]`;
      done = span.end;
      counts.set(rule.id, (counts.get(rule.id) ?? 0) + 1);
    }
    t = out + t.slice(done);
  }
  return t;
}

export type ResponseGuardResult =
  | { action: "block"; rule: string }
  | { action: "pass"; body: Record<string, unknown>; redactions: Array<{ rule: string; count: number }> };

/**
 * The leak guard on an OpenAI-style answer: `choices[].message`, scanned like a request's messages.
 * With redactions, `body` is a copy with those messages replaced; otherwise it is `answer` itself.
 */
export function guardResponse(policy: LeakPolicy, answer: Record<string, unknown>): ResponseGuardResult {
  const choices = Array.isArray(answer.choices) ? answer.choices : [];
  const messages = choices.map((choice) => (isRecord(choice) ? choice.message : undefined));
  const guarded = guardMessages(policy, messages);
  if (guarded.action === "block") return guarded;
  if (guarded.redactions.length === 0) return { action: "pass", body: answer, redactions: [] };
  const redacted = choices.map((choice, i) => (isRecord(choice) && guarded.messages[i] !== messages[i] ? { ...choice, message: guarded.messages[i] } : choice));
  return { action: "pass", body: { ...answer, choices: redacted }, redactions: guarded.redactions };
}

/**
 * Calls `fn` on every scanned string and returns the messages with each string replaced by what
 * `fn` returned. Messages and parts that do not change are returned as they are (not copied).
 * This one function defines what is scanned, for both the check and the redaction.
 */
function mapTexts(messages: readonly unknown[], fn: (text: string) => string): unknown[] {
  return messages.map((message) => {
    if (!isRecord(message)) return message;
    let copy: Record<string, unknown> | undefined;
    const content = message.content;
    if (typeof content === "string") {
      const next = fn(content);
      if (next !== content) copy = { ...message, content: next };
    } else if (Array.isArray(content)) {
      const parts = mapEach(content, (part) =>
        isRecord(part) && part.type === "text" && typeof part.text === "string" ? withField(part, "text", fn(part.text)) : part,
      );
      if (parts !== content) copy = { ...message, content: parts };
    }
    if (Array.isArray(message.tool_calls)) {
      const calls = mapEach(message.tool_calls, (call) => {
        if (!isRecord(call) || !isRecord(call.function) || typeof call.function.arguments !== "string") return call;
        const fnPart = withField(call.function, "arguments", fn(call.function.arguments));
        return fnPart === call.function ? call : { ...call, function: fnPart };
      });
      if (calls !== message.tool_calls) copy = { ...(copy ?? message), tool_calls: calls };
    }
    return copy ?? message;
  });
}

/** Like Array.map, but returns the same array when no element changed. */
function mapEach(list: unknown[], fn: (item: unknown) => unknown): unknown[] {
  const mapped = list.map(fn);
  return mapped.every((item, i) => item === list[i]) ? list : mapped;
}

function withField(record: Record<string, unknown>, key: string, value: string): Record<string, unknown> {
  return record[key] === value ? record : { ...record, [key]: value };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// ── parsing ─────────────────────────────────────────────────────────────────────────────────

const RULE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * Checks the policy JSON, { "leakGuard": [ { "id", "regex", "flags"?, "action", "description"? } ] },
 * and compiles it. Throws ConfigError naming the bad field.
 */
export function parseLeakPolicy(json: unknown): LeakPolicy {
  const policy = object(json, "policy");
  onlyKeys(policy, ["leakGuard"], "policy");
  const ids = new Set<string>();
  const rules = array(policy.leakGuard, "policy.leakGuard").map((raw, i) => {
    const at = `policy.leakGuard[${i}]`;
    const rule = object(raw, at);
    onlyKeys(rule, ["id", "regex", "flags", "action", "description", "validator"], at);
    const id = text(rule.id, `${at}.id`);
    // The id goes into [REDACTED:<id>], an HTTP header and the usage log, so keep it plain.
    if (!RULE_ID.test(id)) fail(`${at}.id must be 1 to 64 letters, digits, ".", "_" or "-", starting with a letter or digit`);
    if (ids.has(id)) fail(`${at}.id "${id}" is already used by an earlier rule`);
    ids.add(id);
    if (!LEAK_ACTIONS.includes(rule.action as LeakAction)) fail(`${at}.action must be one of ${LEAK_ACTIONS.join(", ")}`);
    const flags = rule.flags === undefined ? "" : rule.flags;
    // g and y make test() remember where it stopped; the guard adds g itself where it needs it.
    if (typeof flags !== "string" || !/^[imsu]*$/.test(flags)) fail(`${at}.flags may only contain i, m, s and u`);
    let pattern: RegExp;
    try {
      pattern = new RegExp(text(rule.regex, `${at}.regex`), flags);
    } catch (err) {
      fail(`${at}.regex is not a valid regular expression: ${(err as Error).message}`);
    }
    if (pattern.test("")) fail(`${at}.regex matches empty text, so it would match every request`);
    if (rule.validator !== undefined && !VALIDATOR_NAMES.includes(rule.validator as ValidatorName)) fail(`${at}.validator must be one of ${VALIDATOR_NAMES.join(", ")}`);
    const validator = rule.validator as ValidatorName | undefined;
    const compiled: LeakRule = {
      id,
      action: rule.action as LeakAction,
      pattern: validator ? new ValidatedPattern(pattern.source, pattern.flags, VALIDATORS[validator]) : pattern,
      ...(validator ? { validator } : {}),
    };
    return rule.description === undefined ? compiled : { ...compiled, description: text(rule.description, `${at}.description`) };
  });
  return { rules };
}
