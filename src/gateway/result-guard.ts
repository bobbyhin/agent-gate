// The result guard (optional, "resultGuard" in the gateway config): what a forwarded call's result may
// carry back into the model's context.
//
// It reads the text of a result: text content, the text of embedded resources, and every string in
// structuredContent. With the LLM gateway's leak-guard rules (llm-policy.example.json):
//   a block rule  withholds the whole result: the agent gets an error result naming the rule. The call
//                 has already run, so it cannot be refused; and cutting out only the match is not
//                 safe for every rule (the service-account rule matches the key's first line only).
//   a redact rule replaces what it matches with [REDACTED:<id>], as in the LLM gateway.
// With flagInstructions (default true), text that reads like instructions to the model (ignore your
// previous instructions, run this command, pipe a download into a shell) is flagged: the gateway logs a
// WARN, the call-result line lists the flags, and the result's _meta says so. A flag changes nothing
// else; it is a hint, not a filter, because legitimate pages and documents contain such text too.
// guardResult() is a pure function.

import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { redactRules, redactText, type LeakPolicy } from "../llm/leak-guard.js";

/** Phrases that tell a model what to do: a hint that a result carries an injection. */
export const INSTRUCTION_PATTERNS: ReadonlyArray<{ id: string; re: RegExp }> = [
  { id: "ignore-previous-instructions", re: /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions|prompts|messages|rules)\b/i },
  { id: "new-instructions", re: /\b(?:new|updated|real)\s+(?:system\s+)?instructions?\s*:/i },
  { id: "hide-from-user", re: /\bdo\s+not\s+(?:tell|inform|show|mention\s+(?:this|it)\s+to)\s+the\s+user\b/i },
  { id: "run-this", re: /\b(?:run|execute)\s+(?:the\s+following|this)\s+(?:command|code|script)\b/i },
  { id: "pipe-to-shell", re: /\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/i },
];

export interface ResultGuard {
  leak?: LeakPolicy;
  flagInstructions: boolean;
}

export interface GuardedResult {
  /** What the agent gets. The same object when nothing changed. */
  result: CallToolResult;
  /** The block rule that withheld the result. */
  withheld?: string;
  /** Redact rules that changed the result. */
  redacted: string[];
  /** Instruction-like patterns found. */
  flags: string[];
}

export function guardResult(guard: ResultGuard, result: CallToolResult): GuardedResult {
  const texts = textsOf(result);
  for (const rule of guard.leak?.rules ?? []) {
    if (rule.action === "block" && texts.some((t) => rule.pattern.test(t))) {
      return {
        result: {
          content: [
            {
              type: "text",
              text: `agent-gate withheld this tool result: it contains text that looks like a secret (rule ${rule.id}). The tool did run. If the secret is real, rotate it.`,
            },
          ],
          isError: true,
        },
        withheld: rule.id,
        redacted: [],
        flags: [],
      };
    }
  }
  const counts = new Map<string, number>();
  const rules = guard.leak ? redactRules(guard.leak) : [];
  const redact = (t: string): string => (rules.length > 0 ? redactText(rules, t, counts) : t);
  const content = result.content.map((item) => {
    if (item.type === "text") {
      const text = redact(item.text);
      return text === item.text ? item : { ...item, text };
    }
    if (item.type === "resource" && "text" in item.resource && typeof item.resource.text === "string") {
      const text = redact(item.resource.text);
      return text === item.resource.text ? item : { ...item, resource: { ...item.resource, text } };
    }
    return item;
  });
  const structured = result.structuredContent === undefined ? undefined : mapStrings(result.structuredContent, redact);
  const redacted = [...counts.keys()];
  const flags = guard.flagInstructions ? INSTRUCTION_PATTERNS.filter((p) => texts.some((t) => p.re.test(t))).map((p) => p.id) : [];
  if (redacted.length === 0 && flags.length === 0) return { result, redacted, flags };
  return {
    result: {
      ...result,
      content,
      ...(structured === undefined ? {} : { structuredContent: structured as Record<string, unknown> }),
      ...(flags.length > 0 ? { _meta: { ...(result._meta ?? {}), "agent-gate/flags": flags } } : {}),
    },
    redacted,
    flags,
  };
}

/** Every string the guard reads in a result. */
export function textsOf(result: CallToolResult): string[] {
  const texts: string[] = [];
  for (const item of result.content) {
    if (item.type === "text") texts.push(item.text);
    else if (item.type === "resource" && "text" in item.resource && typeof item.resource.text === "string") texts.push(item.resource.text);
  }
  if (result.structuredContent !== undefined) mapStrings(result.structuredContent, (t) => (texts.push(t), t));
  return texts;
}

function mapStrings(value: unknown, fn: (text: string) => string): unknown {
  if (typeof value === "string") return fn(value);
  if (Array.isArray(value)) return value.map((item) => mapStrings(item, fn));
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [key, mapStrings(item, fn)]));
  }
  return value;
}
