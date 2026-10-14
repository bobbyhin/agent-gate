// A fake OpenAI-compatible provider for the LLM gateway's tests and for trying the example config.
// It never calls a real model and costs nothing.
//
//   mode "ok"    answers POST /v1/chat/completions like a provider, with a "usage" block
//   mode "fail"  answers every call with HTTP 500
//
// Both modes quote the key they were sent in their error bodies (401, 500, and the 400 for a
// max_tokens above 100000), the way a careless provider might, so the tests can prove that the
// gateway never passes the key on.
// It records every request it receives, so a test can prove which calls reached it.
//
// On its own: node dist/test/llm/fake-upstream.js [--port 9101] [--mode ok|fail] [--host 127.0.0.1]
// (the compose demo passes --host 0.0.0.0, because there the gateway runs in another container).

import * as http from "node:http";
import type { AddressInfo } from "node:net";

export interface FakeUpstreamOptions {
  mode: "ok" | "fail";
  /** Accepted bearer keys; any other key gets a 401. Left out or empty: any non-empty key. */
  keys?: string[];
  /** The usage block to report. Left out: derived from the request (characters / 4 + 7, and 9). */
  usage?: { prompt_tokens: number; completion_tokens: number };
  port?: number;
  /** The address to listen on. Left out: 127.0.0.1. */
  host?: string;
}

export interface ReceivedRequest {
  authorization: string;
  /** The parsed JSON body. */
  body: Record<string, unknown>;
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
      const reply = (status: number, body: unknown) => {
        const text = JSON.stringify(body);
        res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text) });
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
      requests.push({ authorization, body });

      const key = authorization.replace(/^Bearer /, "");
      if (options.mode === "fail") return reply(500, { error: { message: `upstream exploded while serving key ${key}` } });
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
      reply(200, {
        id: `chatcmpl-fake-${served}`,
        object: "chat.completion",
        created: 1760400000,
        model,
        choices: [{ index: 0, message: { role: "assistant", content: `fake answer ${served} from ${model}` }, finish_reason: "stop" }],
        usage: { ...usage, total_tokens: usage.prompt_tokens + usage.completion_tokens },
      });
    });
  });
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
  const mode = arg("--mode") === "fail" ? "fail" : "ok";
  const host = arg("--host") ?? "127.0.0.1";
  startFakeUpstream({ mode, host, port: Number(arg("--port") ?? 9101) }).then(
    (fake) => process.stderr.write(`fake upstream (${mode}) on ${host}, port ${new URL(fake.url).port}, path /v1\n`),
    (err: unknown) => {
      process.stderr.write(`fake-upstream: ${String(err)}\n`);
      process.exit(1);
    },
  );
}
