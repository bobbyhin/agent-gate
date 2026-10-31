// A fake OpenAI-compatible provider for the LLM gateway's tests and for trying the example config.
// It never calls a real model and costs nothing.
//
//   mode "ok"       answers POST /v1/chat/completions like a provider, with a "usage" block
//   mode "fail"     answers every call with HTTP 500
//   mode "limited"  answers every call with HTTP 429 and a Retry-After (a provider's rate limit)
//
// In mode "ok", a request with "stream": true gets server-sent events, as an OpenAI-style provider
// streams: a role chunk, one chunk per piece of the content (and the tool call's arguments in two
// fragments), a finish chunk, the usage chunk when stream_options.include_usage asks for it, and
// "data: [DONE]". `stream` can make it misbehave: slow, quiet for a while, cut off, or failing mid-stream.
// Every mode quotes the key it was sent in its error bodies (401, 429, 500, the 400 for a max_tokens
// above 100000, and a mid-stream error frame), the way a careless provider might, so the tests can
// prove that the gateway never passes the key on.
// It records every request it receives, so a test can prove which calls reached it, and whether the
// gateway closed a stream before it was finished.
//
// On its own: node dist/test/llm/fake-upstream.js [--port 9101] [--mode ok|fail|limited] [--host 127.0.0.1]
// (the compose demo passes --host 0.0.0.0, because there the gateway runs in another container).

import * as http from "node:http";
import type { AddressInfo } from "node:net";

export interface FakeUpstreamOptions {
  mode: "ok" | "fail" | "limited";
  /** Mode "limited": the Retry-After header, in seconds (default "1"). */
  retryAfter?: string;
  /** Mode "ok": answer with this text instead of "fake answer <n> from <model>" (streamed as one piece, unless stream.pieces says otherwise). */
  content?: string;
  /** Mode "ok": also answer with one tool call whose arguments are this string. */
  toolCallArguments?: string;
  /** Accepted bearer keys; any other key gets a 401. Left out or empty: any non-empty key. */
  keys?: string[];
  /** The usage block to report. Left out: derived from the request (characters / 4 + 7, and 9). */
  usage?: { prompt_tokens: number; completion_tokens: number };
  port?: number;
  /** The address to listen on. Left out: 127.0.0.1. */
  host?: string;
  /** Mode "ok", for a request with "stream": true. */
  stream?: FakeStreamOptions;
}

export interface FakeStreamOptions {
  /** The content, one chunk per piece. Left out: "fake answer <n>" and " from <model>". */
  pieces?: string[];
  /** Wait this long before each piece. */
  delayMs?: number;
  /** Wait this long before answering at all (before the status and headers). */
  headerDelayMs?: number;
  /** Never send the usage chunk, even when asked (a provider that ignores include_usage). */
  noUsage?: boolean;
  /** Close the connection instead of sending piece number `cutAfter` (0-based): a stream cut short. */
  cutAfter?: number;
  /** Send an error frame (quoting the key) instead of piece number `errorAfter`, then end. */
  errorAfter?: number;
  /** Go quiet for gapMs before piece number `gapAfter`. */
  gapAfter?: number;
  gapMs?: number;
}

export interface ReceivedRequest {
  authorization: string;
  /** The traceparent header the gateway sent, if any. */
  traceparent?: string;
  /** The parsed JSON body. */
  body: Record<string, unknown>;
  /** A streamed answer: content pieces sent so far, and whether the gateway closed it before the end. */
  piecesSent?: number;
  closedEarly?: boolean;
}

export interface FakeUpstream {
  /** For example http://127.0.0.1:9101; the gateway's baseUrl is this plus /v1. */
  url: string;
  requests: ReceivedRequest[];
  close(): Promise<void>;
}

export async function startFakeUpstream(options: FakeUpstreamOptions): Promise<FakeUpstream> {
  const requests: ReceivedRequest[] = [];
  let served = 0;
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const reply = (status: number, body: unknown, headers: Record<string, string> = {}) => {
        const text = JSON.stringify(body);
        res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text), ...headers });
        res.end(text);
      };
      if (req.method !== "POST" || req.url !== "/v1/chat/completions") return reply(404, { error: { message: "not found" } });
      const authorization = req.headers.authorization ?? "";
      let body: Record<string, unknown>;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        return reply(400, { error: { message: "invalid JSON" } });
      }
      const traceparent = typeof req.headers.traceparent === "string" ? req.headers.traceparent : undefined;
      requests.push({ authorization, body, ...(traceparent === undefined ? {} : { traceparent }) });

      const key = authorization.replace(/^Bearer /, "");
      if (options.mode === "fail") return reply(500, { error: { message: `upstream exploded while serving key ${key}` } });
      if (options.mode === "limited") {
        return reply(429, { error: { message: `Rate limit reached for key ${key}`, type: "requests", code: "rate_limit_exceeded" } }, { "retry-after": options.retryAfter ?? "1" });
      }
      if (key === "" || (options.keys?.length && !options.keys.includes(key))) {
        return reply(401, { error: { message: `Incorrect API key provided: ${key}`, type: "invalid_request_error", code: "invalid_api_key" } });
      }
      if (typeof body.max_tokens === "number" && body.max_tokens > 100_000) {
        return reply(400, { error: { message: `max_tokens is too large for this model (key ${key})`, type: "invalid_request_error", param: "max_tokens", code: "invalid_value" } });
      }
      served++;
      const model = String(body.model);
      const chars = JSON.stringify(body.messages ?? []).length;
      const usage = options.usage ?? { prompt_tokens: Math.ceil(chars / 4) + 7, completion_tokens: 9 };
      if (body.stream === true) {
        streamAnswer(res, requests[requests.length - 1] as ReceivedRequest, body, key, served, model, { ...usage, total_tokens: usage.prompt_tokens + usage.completion_tokens });
        return;
      }
      reply(200, {
        id: `chatcmpl-fake-${served}`,
        object: "chat.completion",
        created: 1760400000,
        model,
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content: options.content ?? `fake answer ${served} from ${model}`,
              ...(options.toolCallArguments === undefined ? {} : { tool_calls: [{ id: "call_1", type: "function", function: { name: "save_note", arguments: options.toolCallArguments } }] }),
            },
            finish_reason: options.toolCallArguments === undefined ? "stop" : "tool_calls",
          },
        ],
        usage: { ...usage, total_tokens: usage.prompt_tokens + usage.completion_tokens },
      });
    });
  });
  /** Streams the answer as server-sent events, misbehaving as options.stream says. */
  function streamAnswer(res: http.ServerResponse, received: ReceivedRequest, body: Record<string, unknown>, key: string, n: number, model: string, usage: Record<string, number>): void {
    const s = options.stream ?? {};
    const base = { id: `chatcmpl-fake-${n}`, object: "chat.completion.chunk", created: 1760400000, model };
    const pieces = s.pieces ?? (options.content !== undefined ? [options.content] : [`fake answer ${n}`, ` from ${model}`]);
    const frame = (data: unknown): string => `data: ${JSON.stringify(data)}\n\n`;
    const wait = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
    let finished = false;
    received.piecesSent = 0;
    res.on("close", () => {
      if (!finished) received.closedEarly = true;
    });
    const send = (text: string): boolean => {
      if (res.destroyed) return false;
      res.write(text);
      return true;
    };
    void (async () => {
      if (s.headerDelayMs) await wait(s.headerDelayMs);
      if (res.destroyed) return;
      res.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache" });
      if (!send(frame({ ...base, choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }] }))) return;
      for (const [i, piece] of pieces.entries()) {
        if (s.gapAfter === i && s.gapMs) await wait(s.gapMs);
        if (s.delayMs) await wait(s.delayMs);
        if (s.cutAfter === i) {
          finished = true; // the fake's own doing, not the gateway's
          // Let what was written reach the gateway first, then drop the connection.
          await new Promise<void>((resolve) => res.write("", () => resolve()));
          await wait(20);
          res.destroy();
          return;
        }
        if (s.errorAfter === i) {
          finished = true;
          send(frame({ error: { message: `upstream exploded mid-stream while serving key ${key}`, type: "server_error", code: null } }));
          res.end();
          return;
        }
        if (!send(frame({ ...base, choices: [{ index: 0, delta: { content: piece }, finish_reason: null }] }))) return;
        received.piecesSent = i + 1;
      }
      if (options.toolCallArguments !== undefined) {
        const args = options.toolCallArguments;
        const half = Math.floor(args.length / 2);
        send(frame({ ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name: "save_note", arguments: args.slice(0, half) } }] }, finish_reason: null }] }));
        send(frame({ ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: args.slice(half) } }] }, finish_reason: null }] }));
      }
      send(frame({ ...base, choices: [{ index: 0, delta: {}, finish_reason: options.toolCallArguments === undefined ? "stop" : "tool_calls" }] }));
      const asked = typeof body.stream_options === "object" && body.stream_options !== null && (body.stream_options as Record<string, unknown>).include_usage === true;
      if (asked && !s.noUsage) send(frame({ ...base, choices: [], usage }));
      finished = true;
      send("data: [DONE]\n\n");
      res.end();
    })();
  }

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, options.host ?? "127.0.0.1", () => resolve());
  });
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}

if (require.main === module) {
  const arg = (name: string): string | undefined => {
    const at = process.argv.indexOf(name);
    return at >= 0 ? process.argv[at + 1] : undefined;
  };
  const mode = arg("--mode") === "fail" ? "fail" : arg("--mode") === "limited" ? "limited" : "ok";
  const host = arg("--host") ?? "127.0.0.1";
  startFakeUpstream({ mode, host, port: Number(arg("--port") ?? 9101) }).then(
    (fake) => process.stderr.write(`fake upstream (${mode}) on ${host}, port ${new URL(fake.url).port}, path /v1\n`),
    (err: unknown) => {
      process.stderr.write(`fake-upstream: ${String(err)}\n`);
      process.exit(1);
    },
  );
}
