// Streamed answers: the server-sent events of an OpenAI-compatible upstream answering with
// "stream": true. Reading the events, putting each choice's message back together (for the leak
// guard and for the cost), and writing a stream out again after a redaction.
//
// The format: every event is "data: <JSON chunk>" followed by a blank line. A chunk's
// choices[].delta carries pieces of a message: the role, pieces of the content, and tool calls whose
// arguments arrive in fragments, keyed by the tool call's index; a choice ends with a finish_reason.
// With stream_options.include_usage, one more chunk has an empty choices array and the usage of the
// whole request. The stream ends with the literal "data: [DONE]". A failure after the stream started
// can arrive as a data frame that holds an "error" object, and an interrupted stream may end without
// [DONE] or the usage chunk (see docs/adr/0011-streaming.md for the sources).
// Everything here is pure: no I/O, no clock.

export interface SseEvent {
  /** The event's lines as received (line ends made "\n"), without the blank line that ends it. */
  raw: string;
  /** Its data lines, joined with "\n"; undefined when it has none (a comment, for example). */
  data?: string;
}

/** Splits a stream's text into events. Feed it text as it arrives; an event is complete at a blank line. */
export class SseParser {
  private buffer = "";

  push(text: string): SseEvent[] {
    let usable = this.buffer + text;
    // A "\r" at the very end may be the first half of a "\r\n" that the next piece completes.
    const keep = usable.endsWith("\r") ? "\r" : "";
    if (keep) usable = usable.slice(0, -1);
    usable = usable.replace(/\r\n?/g, "\n");
    const events: SseEvent[] = [];
    for (let at = usable.indexOf("\n\n"); at >= 0; at = usable.indexOf("\n\n")) {
      const event = parseBlock(usable.slice(0, at));
      usable = usable.slice(at + 2);
      if (event) events.push(event);
    }
    // An event cut off by the end of the stream is never complete, so it is dropped (as the SSE spec says).
    this.buffer = usable + keep;
    return events;
  }
}

function parseBlock(block: string): SseEvent | undefined {
  if (block.trim() === "") return undefined;
  const data: string[] = [];
  for (const line of block.split("\n")) {
    if (line === "data" || line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
  }
  return data.length > 0 ? { raw: block, data: data.join("\n") } : { raw: block };
}

/** A chunk that carries only the usage of the whole request: what stream_options.include_usage adds. */
export function isUsageOnly(chunk: unknown): boolean {
  return isRecord(chunk) && Array.isArray(chunk.choices) && chunk.choices.length === 0 && isRecord(chunk.usage);
}

interface AssembledToolCall {
  id?: string;
  type?: string;
  name: string;
  arguments: string;
}

interface AssembledChoice {
  role?: string;
  content?: string;
  toolCalls: Map<number, AssembledToolCall>;
  finishReason?: unknown;
}

/** Puts a streamed answer back together from its chunks, in the shape of a non-streamed answer. */
export class StreamAssembler {
  /** The first chunk's id, object, created, model and system_fingerprint: for chunks the gateway writes itself. */
  meta: Record<string, unknown> | undefined;
  /** The last usage object a chunk carried, if any. */
  usage: Record<string, unknown> | undefined;
  private readonly choices = new Map<number, AssembledChoice>();

  add(chunk: unknown): void {
    if (!isRecord(chunk)) return;
    if (this.meta === undefined) {
      this.meta = Object.fromEntries(["id", "object", "created", "model", "system_fingerprint"].filter((k) => chunk[k] !== undefined).map((k) => [k, chunk[k]]));
    }
    if (isRecord(chunk.usage)) this.usage = chunk.usage;
    if (!Array.isArray(chunk.choices)) return;
    for (const raw of chunk.choices) {
      if (!isRecord(raw) || !Number.isInteger(raw.index)) continue;
      const index = raw.index as number;
      const choice: AssembledChoice = this.choices.get(index) ?? { toolCalls: new Map() };
      this.choices.set(index, choice);
      if (raw.finish_reason != null) choice.finishReason = raw.finish_reason;
      const delta = raw.delta;
      if (!isRecord(delta)) continue;
      if (typeof delta.role === "string") choice.role = delta.role;
      if (typeof delta.content === "string") choice.content = (choice.content ?? "") + delta.content;
      if (!Array.isArray(delta.tool_calls)) continue;
      for (const part of delta.tool_calls) {
        if (!isRecord(part) || !Number.isInteger(part.index)) continue;
        const call: AssembledToolCall = choice.toolCalls.get(part.index as number) ?? { name: "", arguments: "" };
        choice.toolCalls.set(part.index as number, call);
        if (typeof part.id === "string") call.id = part.id;
        if (typeof part.type === "string") call.type = part.type;
        if (isRecord(part.function)) {
          if (typeof part.function.name === "string") call.name += part.function.name;
          if (typeof part.function.arguments === "string") call.arguments += part.function.arguments;
        }
      }
    }
  }

  /** True when every choice seen so far has a finish_reason. */
  get finished(): boolean {
    return this.choices.size > 0 && [...this.choices.values()].every((c) => c.finishReason != null);
  }

  /** The answer as a non-streamed one would look: { choices: [{ index, message, finish_reason }] }, by index. */
  answer(): { choices: Array<{ index: number; message: Record<string, unknown>; finish_reason: unknown }> } {
    const choices = [...this.choices.entries()]
      .sort(([a], [b]) => a - b)
      .map(([index, c]) => ({
        index,
        message: {
          role: c.role ?? "assistant",
          content: c.content ?? null,
          ...(c.toolCalls.size > 0
            ? {
                tool_calls: [...c.toolCalls.entries()]
                  .sort(([a], [b]) => a - b)
                  .map(([, t]) => ({ ...(t.id === undefined ? {} : { id: t.id }), type: t.type ?? "function", function: { name: t.name, arguments: t.arguments } })),
              }
            : {}),
        },
        finish_reason: c.finishReason ?? null,
      }));
    return { choices };
  }
}

/**
 * A stream written out again from whole messages: one chunk per choice with its whole (redacted)
 * message, one chunk per choice with its finish_reason, then the usage chunk when there is one to
 * send, then [DONE]. Used when a redact rule changed the answer, so the original pieces cannot be
 * replayed. Each string is one event, without the blank line that ends it.
 */
export function rebuildEvents(
  meta: Record<string, unknown> | undefined,
  choices: ReadonlyArray<{ index: number; message: unknown; finish_reason: unknown }>,
  usageChunk: Record<string, unknown> | undefined,
): string[] {
  const base = { ...(meta ?? {}), object: "chat.completion.chunk" };
  const events: string[] = [];
  for (const choice of choices) {
    const message = isRecord(choice.message) ? choice.message : {};
    const delta: Record<string, unknown> = { role: typeof message.role === "string" ? message.role : "assistant" };
    if (typeof message.content === "string") delta.content = message.content;
    if (Array.isArray(message.tool_calls)) delta.tool_calls = message.tool_calls.map((call, i) => (isRecord(call) ? { index: i, ...call } : call));
    events.push(`data: ${JSON.stringify({ ...base, choices: [{ index: choice.index, delta, finish_reason: null }] })}`);
  }
  for (const choice of choices) events.push(`data: ${JSON.stringify({ ...base, choices: [{ index: choice.index, delta: {}, finish_reason: choice.finish_reason }] })}`);
  if (usageChunk) events.push(`data: ${JSON.stringify(usageChunk)}`);
  events.push("data: [DONE]");
  return events;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
