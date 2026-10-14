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
//
// Scanned: message "content" (a string, or the "text" of text parts) and the "arguments" string of
// assistant tool calls. Not scanned: images, audio and file parts, tool definitions, and any other
// request field.
// ponytail: the rules run on JavaScript's backtracking regex engine. The request body size limit
// (maxBodyBytes) bounds the work, but a badly written rule can still be slow; keep rules anchored
// on a literal prefix, as the shipped ones are.

import { array, fail, object, onlyKeys, text } from "../gateway/validate.js";

export type LeakAction = "block" | "redact";
export const LEAK_ACTIONS: readonly LeakAction[] = ["block", "redact"];

export interface LeakRule {
  readonly id: string;
  readonly action: LeakAction;
  readonly description?: string;
  /** Without the g flag, so test() keeps no state between calls. */
  readonly pattern: RegExp;
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
  // g to find every match, d for the positions of capture groups. matchAll() works on a copy of
  // the regex, so one per call is safe.
  const redacting = policy.rules
    .filter((rule) => rule.action === "redact")
    .map((rule) => ({ id: rule.id, all: new RegExp(rule.pattern.source, `${rule.pattern.flags}gd`) }));
  const result = mapTexts(messages, (original) => {
    let t = original;
    for (const rule of redacting) {
      let out = "";
      let done = 0;
      for (const match of t.matchAll(rule.all)) {
        // The first capture group that took part in the match, or else the whole match.
        const span = match.indices?.slice(1).find((s) => s !== undefined) ?? match.indices?.[0];
        if (!span || span[0] === span[1]) continue;
        out += `${t.slice(done, span[0])}[REDACTED:${rule.id}]`;
        done = span[1];
        counts.set(rule.id, (counts.get(rule.id) ?? 0) + 1);
      }
      t = out + t.slice(done);
    }
    return t;
  });
  return { action: "pass", messages: result, redactions: [...counts].map(([rule, count]) => ({ rule, count })) };
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
    onlyKeys(rule, ["id", "regex", "flags", "action", "description"], at);
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
    const compiled: LeakRule = { id, action: rule.action as LeakAction, pattern };
    return rule.description === undefined ? compiled : { ...compiled, description: text(rule.description, `${at}.description`) };
  });
  return { rules };
}
