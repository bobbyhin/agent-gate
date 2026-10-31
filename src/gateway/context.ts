// Correlation ids a client may send with a call, so that the gateways' logs can be joined with the
// agent's own traces: a W3C traceparent, a session id, a run id and, for MCP tool calls, the path of
// agents that handed the call down (main>research-sub).
//
//   MCP gateway: in the _meta of tools/call: "traceparent", "agent-gate/session",
//                "agent-gate/run-id" and "agent-gate/agent-path" (a string a>b, or a list of names)
//   LLM gateway: HTTP headers traceparent, x-agent-session and x-run-id
//
// They come from the client, so they are the client's claim: the gateway checks their format, not
// their truth. A value that does not fit the format is not written anywhere; the record names the
// field in "contextDropped" instead. That keeps line breaks, terminal escapes and very long text out
// of the audit log, the usage log and what the CLI prints.

/** A parsed W3C traceparent, version 00: https://www.w3.org/TR/trace-context/#traceparent-header */
export interface TraceParent {
  /** 32 lowercase hex digits, not all zero. */
  traceId: string;
  /** The caller's span: 16 lowercase hex digits, not all zero. */
  parentId: string;
  /** 2 hex digits; 01 means the caller sampled (recorded) the trace. */
  flags: string;
}

const TRACEPARENT = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;
const ALL_ZERO = /^0+$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const AGENT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
export const AGENT_PATH_MAX = 16;

/** A version-00 traceparent, or undefined for anything else (other versions, upper case, zero ids). */
export function parseTraceparent(value: unknown): TraceParent | undefined {
  if (typeof value !== "string") return undefined;
  const m = TRACEPARENT.exec(value);
  if (!m || ALL_ZERO.test(m[1] as string) || ALL_ZERO.test(m[2] as string)) return undefined;
  return { traceId: m[1] as string, parentId: m[2] as string, flags: m[3] as string };
}

/** A session or run id: 1 to 128 letters, digits, ".", "_", ":" or "-", starting with a letter or digit. */
export function parseId(value: unknown): string | undefined {
  return typeof value === "string" && ID.test(value) ? value : undefined;
}

/**
 * The agents a call passed through, outermost first, as "main>research-sub": a string in that form
 * or a list of names. At most 16 names of 1 to 64 letters, digits, ".", "_" or "-".
 */
export function parseAgentPath(value: unknown): string | undefined {
  const names = typeof value === "string" ? value.split(">") : Array.isArray(value) ? value : undefined;
  if (!names || names.length === 0 || names.length > AGENT_PATH_MAX) return undefined;
  if (!names.every((name) => typeof name === "string" && AGENT_NAME.test(name))) return undefined;
  return names.join(">");
}

/** The correlation fields as they are written to the audit and usage logs. */
export interface CallContext {
  /** From the client's traceparent. The LLM gateway starts a new trace when there is none. */
  traceId?: string;
  /** The client's span that made the call (the traceparent's parent id). */
  parentSpanId?: string;
  session?: string;
  runId?: string;
  agentPath?: string;
  /** Fields the client sent in a shape the gateway does not accept, so their values were left out. */
  contextDropped?: string[];
}

/** The _meta keys the MCP gateway reads, by the field they fill. */
export const META_KEYS = {
  traceparent: "traceparent",
  session: "agent-gate/session",
  runId: "agent-gate/run-id",
  agentPath: "agent-gate/agent-path",
} as const;

/** Reads the correlation fields from the _meta of an MCP request. Missing fields are simply absent. */
export function contextFromMeta(meta: unknown): CallContext {
  const record = typeof meta === "object" && meta !== null && !Array.isArray(meta) ? (meta as Record<string, unknown>) : {};
  const get = (key: string): unknown => (Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined);
  return collect({
    traceparent: get(META_KEYS.traceparent),
    session: get(META_KEYS.session),
    runId: get(META_KEYS.runId),
    agentPath: get(META_KEYS.agentPath),
  });
}

/** The same for the LLM gateway's request headers (Node gives repeated headers as a list: refused). */
export function contextFromHeaders(headers: Record<string, string | string[] | undefined>): CallContext {
  return collect({ traceparent: headers.traceparent, session: headers["x-agent-session"], runId: headers["x-run-id"] });
}

function collect(raw: { traceparent: unknown; session: unknown; runId: unknown; agentPath?: unknown }): CallContext {
  const context: CallContext = {};
  const dropped: string[] = [];
  if (raw.traceparent !== undefined) {
    const parent = parseTraceparent(raw.traceparent);
    if (parent) {
      context.traceId = parent.traceId;
      context.parentSpanId = parent.parentId;
    } else dropped.push("traceparent");
  }
  if (raw.session !== undefined) {
    const session = parseId(raw.session);
    if (session) context.session = session;
    else dropped.push("session");
  }
  if (raw.runId !== undefined) {
    const runId = parseId(raw.runId);
    if (runId) context.runId = runId;
    else dropped.push("runId");
  }
  if (raw.agentPath !== undefined) {
    const agentPath = parseAgentPath(raw.agentPath);
    if (agentPath) context.agentPath = agentPath;
    else dropped.push("agentPath");
  }
  if (dropped.length > 0) context.contextDropped = dropped;
  return context;
}
