// Streaming ("stream": true) through two live gateways in front of fake upstreams that stream:
// one gateway with scanResponses on (the default: the answer is held until it is complete and
// scanned), one with it off (events are passed on as they arrive, unscanned). The fakes misbehave on
// purpose: no usage chunk, cut short, an error frame, a quiet gap, slow headers, a secret split
// across two chunks.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as http from "node:http";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { costUsd } from "../../src/llm/budget.js";
import { hashKey, parseLlmConfig, type LlmConfig } from "../../src/llm/config.js";
import { loadLeakPolicy } from "../../src/llm/config.js";
import { openLedger, startLlmGateway, type LlmGateway } from "../../src/llm/server.js";
import { SseParser, StreamAssembler } from "../../src/llm/stream.js";
import { readUsageLog, verifyUsage } from "../../src/llm/usage-report.js";
import { FAKE, FAKE_GATEWAY_KEYS } from "./fake-secrets.js";
import { startFakeUpstream, type FakeStreamOptions, type FakeUpstream } from "./fake-upstream.js";

// This file runs from dist/test/llm/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const KEY = FAKE_GATEWAY_KEYS.teamA;
const TINY = FAKE_GATEWAY_KEYS.teamB;
const USAGE = { prompt_tokens: 40, completion_tokens: 12 };
const PRICE = { input: 1, output: 2 };
const SECRET = FAKE.githubToken;
const half = (text: string): [string, string] => [text.slice(0, Math.floor(text.length / 2)), text.slice(Math.floor(text.length / 2))];

const FAKES: Record<string, { stream?: FakeStreamOptions; toolCallArguments?: string; noUsage?: boolean }> = {
  normal: {},
  nousage: { stream: { noUsage: true } },
  slow: { stream: { pieces: ["one ", "two ", "three ", "four ", "five ", "six"], delayMs: 120 } },
  late: { stream: { headerDelayMs: 1500 } },
  cut: { stream: { cutAfter: 1 } },
  broken: { stream: { errorAfter: 1 } },
  quiet: { stream: { gapAfter: 1, gapMs: 1500 } },
  secret: { stream: { pieces: ["Here it is: ", ...half(SECRET), " (keep it safe)"] } },
  keyline: { stream: { pieces: ['config: api_key = "', ...half(FAKE.apiKeyValue), '" and nothing else'] } },
  tool: { toolCallArguments: JSON.stringify({ note: `token ${SECRET}` }) },
};

interface Streamed {
  status: number;
  headers: Headers;
  text: string;
  /** The data of each event, in order ("[DONE]" as it is). */
  data: string[];
  /** The JSON chunks among them. */
  chunks: Array<Record<string, any>>;
}

describe("streaming through the LLM gateway", () => {
  const fakes = new Map<string, FakeUpstream>();
  let tmp: string;
  let buffered: LlmGateway;
  let relayed: LlmGateway;
  let bufferedConfig: LlmConfig;
  let relayedConfig: LlmConfig;

  before(async () => {
    for (const [name, options] of Object.entries(FAKES)) fakes.set(name, await startFakeUpstream({ mode: "ok", usage: USAGE, ...options }));
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-stream-"));
    const config = (stateDir: string, scanResponses: boolean) =>
      parseLlmConfig(
        {
          listen: { port: 0 },
          stateDir,
          policy: path.join(ROOT, "llm-policy.example.json"),
          upstreams: [...fakes].map(([name, fake]) => ({ name, baseUrl: `${fake.url}/v1`, apiKeyEnv: "STREAM_KEY", models: { small: `fake-small-${name}` }, pricePerMTok: PRICE })),
          routes: [...[...fakes.keys()].map((name) => ({ id: name, when: { task: name }, use: { upstream: name } })), { id: "default", use: { upstream: "normal" } }],
          keys: [
            { name: "streamer", sha256: hashKey(KEY), dailyUsd: 5, monthlyUsd: 50 },
            { name: "tiny", sha256: hashKey(TINY), dailyUsd: 0.000001, monthlyUsd: 1 },
          ],
          timeoutMs: 5000,
          retries: 0,
          backoffMs: 10,
          streamIdleMs: 300,
          scanResponses,
        },
        tmp,
      );
    bufferedConfig = config("state-buffered", true);
    relayedConfig = config("state-relayed", false);
    const policy = loadLeakPolicy(path.join(ROOT, "llm-policy.example.json"));
    const env = { STREAM_KEY: "fake-provider-key-stream-0001" };
    buffered = await startLlmGateway(bufferedConfig, policy, { env, log: () => undefined });
    relayed = await startLlmGateway(relayedConfig, policy, { env, log: () => undefined });
  });

  after(async () => {
    await buffered?.close();
    await relayed?.close();
    for (const fake of fakes.values()) await fake.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const fake = (name: string) => fakes.get(name) as FakeUpstream;
  const lastRequest = (name: string) => fake(name).requests[fake(name).requests.length - 1]!;
  const usageFile = (config: LlmConfig) => path.join(config.stateDir, "usage.jsonl");
  const lines = (config: LlmConfig) => readUsageLog(usageFile(config)).lines as Array<Record<string, any>>;
  const lineFor = (config: LlmConfig, id: string | null) => lines(config).find((l) => l.id === id);

  function request(gateway: LlmGateway, task: string, extra: Record<string, unknown> = {}, key: string = KEY, signal?: AbortSignal): Promise<Response> {
    return fetch(`${gateway.url}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json", "x-agent-task": task },
      body: JSON.stringify({ model: "small", messages: [{ role: "user", content: `stream a short answer (${task})` }], max_tokens: 50, stream: true, ...extra }),
      ...(signal ? { signal } : {}),
    });
  }

  async function stream(gateway: LlmGateway, task: string, extra: Record<string, unknown> = {}, key: string = KEY): Promise<Streamed> {
    const res = await request(gateway, task, extra, key);
    const text = await res.text();
    const data = new SseParser().push(text).flatMap((e) => (e.data === undefined ? [] : [e.data]));
    const chunks = data.filter((d) => d !== "[DONE]").map((d) => JSON.parse(d) as Record<string, any>);
    return { status: res.status, headers: res.headers, text, data, chunks };
  }

  const content = (chunks: Array<Record<string, any>>) => chunks.flatMap((c) => (c.choices ?? []).map((ch: any) => ch.delta?.content ?? "")).join("");

  async function waitFor(condition: () => boolean, what: string, ms = 5000): Promise<void> {
    for (let waited = 0; waited < ms && !condition(); waited += 20) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.ok(condition(), `timed out waiting for ${what}`);
  }

  it("holds the stream until it is complete and scanned, then sends it event for event, settled from the usage chunk", async () => {
    const r = await stream(buffered, "normal", { stream_options: { include_usage: true } });
    assert.equal(r.status, 200, r.text);
    assert.match(r.headers.get("content-type") ?? "", /^text\/event-stream/);
    assert.equal(r.data.at(-1), "[DONE]");
    assert.equal(content(r.chunks), `fake answer ${fake("normal").requests.length} from fake-small-normal`);
    assert.deepEqual(r.chunks.at(-1), { id: r.chunks[0]!.id, object: "chat.completion.chunk", created: 1760400000, model: "fake-small-normal", choices: [], usage: { ...USAGE, total_tokens: 52 } });
    // The upstream was asked to stream, with the usage chunk.
    assert.deepEqual([lastRequest("normal").body.stream, lastRequest("normal").body.stream_options], [true, { include_usage: true }]);
    const line = lineFor(bufferedConfig, r.headers.get("x-agent-gate-request-id"));
    assert.deepEqual(
      line && [line.status, line.stream, line.streamEnd, line.usage, line.inputTokens, line.outputTokens, line.costUsd],
      [200, true, "done", "upstream", 40, 12, costUsd(PRICE, 40, 12)],
    );
    assert.equal(r.headers.get("x-agent-gate-cost-usd"), "0.000064");
  });

  it("asks the upstream for the usage chunk even when the client does not, and then keeps it from the client", async () => {
    const r = await stream(buffered, "normal");
    assert.equal(r.status, 200);
    assert.equal(r.chunks.some((c) => Array.isArray(c.choices) && c.choices.length === 0), false, "no usage-only chunk for a client that did not ask");
    assert.deepEqual(lastRequest("normal").body.stream_options, { include_usage: true });
    assert.equal(lineFor(bufferedConfig, r.headers.get("x-agent-gate-request-id"))?.usage, "upstream");
  });

  it("books a stream that ends without a usage chunk at its estimate", async () => {
    const r = await stream(buffered, "nousage", { stream_options: { include_usage: true } });
    assert.equal(r.status, 200);
    const line = lineFor(bufferedConfig, r.headers.get("x-agent-gate-request-id"))!;
    assert.deepEqual([line.usage, line.outputTokens, line.streamEnd], ["estimate", 50, "done"]);
    assert.equal(line.costUsd, costUsd(PRICE, line.inputTokens, line.outputTokens));
  });

  it("without scanResponses, passes events on as they arrive", async () => {
    const res = await request(relayed, "slow", { stream_options: { include_usage: true } });
    assert.equal(res.status, 200);
    const reader = res.body!.getReader();
    const parser = new SseParser();
    const decoder = new TextDecoder();
    let firstPieceAt: number | undefined;
    const data: string[] = [];
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      for (const e of parser.push(decoder.decode(value, { stream: true }))) {
        if (e.data === undefined) continue;
        data.push(e.data);
        if (firstPieceAt === undefined && e.data.includes('"one "')) firstPieceAt = lastRequest("slow").piecesSent;
      }
    }
    assert.equal(firstPieceAt, 1, "the first piece reached the client while the upstream was still writing the rest");
    assert.equal(data.at(-1), "[DONE]");
    const line = lineFor(relayedConfig, res.headers.get("x-agent-gate-request-id"));
    assert.deepEqual(line && [line.streamEnd, line.usage, line.costUsd], ["done", "upstream", costUsd(PRICE, 40, 12)]);
    assert.equal(res.headers.get("x-agent-gate-cost-usd"), null, "the cost is not known when the headers go out");
  });

  it("a secret split across two chunks: withheld when buffered (and booked), passed through unscanned when relayed", async () => {
    const held = await stream(buffered, "secret");
    assert.equal(held.status, 502);
    assert.equal(JSON.parse(held.text).error.code, "response_blocked");
    assert.equal(JSON.parse(held.text).error.rule, "github-token");
    for (const part of half(SECRET)) assert.equal(held.text.includes(part), false);
    const line = lineFor(bufferedConfig, held.headers.get("x-agent-gate-request-id"))!;
    assert.deepEqual([line.error, line.rule, line.side, line.streamEnd], ["response_blocked", "github-token", "response", "done"]);
    assert.ok(line.costUsd > 0, "the call was paid for");

    // The trade-off of relaying: nothing reads the answer before the client does.
    const passed = await stream(relayed, "secret");
    assert.equal(passed.status, 200);
    assert.ok(content(passed.chunks).includes(SECRET));
  });

  it("puts tool-call arguments back together from their fragments and scans them", async () => {
    const r = await stream(buffered, "tool");
    assert.equal(r.status, 502);
    assert.equal(JSON.parse(r.text).error.rule, "github-token");
  });

  it("redacts a key assignment split across chunks, and sends the answer rebuilt around the redaction", async () => {
    const r = await stream(buffered, "keyline", { stream_options: { include_usage: true } });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.headers.get("x-agent-gate-response-redacted"), "api-key-assignment");
    assert.equal(r.text.includes(FAKE.apiKeyValue), false);
    for (const part of half(FAKE.apiKeyValue)) assert.equal(r.text.includes(part), false);
    assert.equal(content(r.chunks), 'config: api_key = "[REDACTED:api-key-assignment]" and nothing else');
    // One chunk with the whole message, one with the finish reason, the usage chunk, [DONE].
    assert.deepEqual(r.chunks.map((c) => (c.choices.length === 0 ? "usage" : c.choices[0].finish_reason ?? "message")), ["message", "stop", "usage"]);
    assert.equal(r.data.at(-1), "[DONE]");
    assert.deepEqual(lineFor(bufferedConfig, r.headers.get("x-agent-gate-request-id"))?.responseRedacted, ["api-key-assignment"]);
  });

  it("stops the upstream at once when the client goes away mid-stream, and books the estimate", async () => {
    const controller = new AbortController();
    const res = await request(relayed, "slow", {}, KEY, controller.signal);
    const id = res.headers.get("x-agent-gate-request-id");
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let seen = "";
    while (!seen.includes('"one "')) seen += decoder.decode((await reader.read()).value, { stream: true });
    controller.abort();
    await waitFor(() => lastRequest("slow").closedEarly === true, "the upstream to see its request closed");
    assert.ok((lastRequest("slow").piecesSent ?? 0) < 6, "the upstream did not get to finish");
    await waitFor(() => lineFor(relayedConfig, id) !== undefined, "the usage line");
    const line = lineFor(relayedConfig, id)!;
    assert.deepEqual([line.status, line.streamEnd, line.error, line.usage, line.outputTokens], [200, "client_closed", "client_closed", "estimate", 50]);
    assert.equal(openLedger(relayedConfig).usage(relayedConfig.keys).find((k) => k.key === "streamer")?.inFlight, 0);
  });

  it("a buffered stream whose client goes away: 499 in the usage line, the upstream stopped", async () => {
    const before = lines(bufferedConfig).length;
    const n = fake("slow").requests.length;
    const controller = new AbortController();
    const pending = request(buffered, "slow", {}, KEY, controller.signal).catch(() => undefined);
    await waitFor(() => (fake("slow").requests[n]?.piecesSent ?? 0) >= 1, "the stream to start");
    controller.abort();
    await pending;
    await waitFor(() => lines(bufferedConfig).length > before, "the usage line");
    const line = lines(bufferedConfig).at(-1)!;
    assert.deepEqual([line.status, line.streamEnd, line.usage], [499, "client_closed", "estimate"]);
    await waitFor(() => fake("slow").requests[n]?.closedEarly === true, "the upstream to see its request closed");
  });

  it("a client that leaves before any upstream answers: nothing is booked", async () => {
    const before = lines(relayedConfig).length;
    const n = fake("late").requests.length;
    const controller = new AbortController();
    const pending = request(relayed, "late", {}, KEY, controller.signal).catch(() => undefined);
    await waitFor(() => fake("late").requests.length === n + 1, "the request to reach the upstream");
    controller.abort();
    await pending;
    await waitFor(() => lines(relayedConfig).length > before, "the usage line");
    const line = lines(relayedConfig).at(-1)!;
    assert.deepEqual([line.status, line.error, line.streamEnd, line.costUsd], [499, "client_closed", "client_closed", 0]);
    await waitFor(() => fake("late").requests[n]?.closedEarly === true, "the upstream to see its request closed");
  });

  it("a stream cut short: the relayed client gets the gateway's error frame and no [DONE]; the buffered one a 502", async () => {
    const relayedCut = await stream(relayed, "cut");
    assert.equal(relayedCut.status, 200);
    assert.notEqual(relayedCut.data.at(-1), "[DONE]");
    assert.equal(relayedCut.chunks.at(-1)?.error?.code, "upstream_error");
    const line = lineFor(relayedConfig, relayedCut.headers.get("x-agent-gate-request-id"))!;
    assert.deepEqual([line.status, line.streamEnd, line.error, line.usage], [200, "upstream_error", "upstream_error", "estimate"]);

    const bufferedCut = await stream(buffered, "cut");
    assert.equal(bufferedCut.status, 502);
    assert.match(JSON.parse(bufferedCut.text).error.message, /broke off before it finished\. It was booked at its estimate/);
  });

  it("an error frame mid-stream: the provider's words, and the key they quote, never reach the client", async () => {
    for (const gateway of [relayed, buffered]) {
      const r = await stream(gateway, "broken");
      assert.equal(r.text.includes("fake-provider-key-stream-0001"), false);
      assert.equal(r.text.includes("exploded"), false);
      assert.match(r.text, /upstream_error/);
    }
  });

  it("stops an upstream that goes quiet for longer than streamIdleMs", async () => {
    const started = Date.now();
    const r = await stream(relayed, "quiet");
    assert.ok(Date.now() - started < 1400, "stopped before the upstream's gap ended");
    assert.equal(r.chunks.at(-1)?.error?.code, "upstream_timeout");
    assert.equal(lineFor(relayedConfig, r.headers.get("x-agent-gate-request-id"))?.streamEnd, "idle_timeout");
    await waitFor(() => lastRequest("quiet").closedEarly === true, "the upstream to see its request closed");
  });

  it("refuses a stream that does not fit the budget before any upstream call, and checks the request", async () => {
    const calls = fake("normal").requests.length;
    const refused = await stream(buffered, "normal", {}, TINY);
    assert.deepEqual([refused.status, JSON.parse(refused.text).error.code], [429, "budget_exceeded"]);
    const notBoolean = await stream(buffered, "normal", { stream: "yes" });
    assert.deepEqual([notBoolean.status, JSON.parse(notBoolean.text).error.param], [400, "stream"]);
    const badOptions = await stream(buffered, "normal", { stream_options: "usage please" });
    assert.deepEqual([badOptions.status, JSON.parse(badOptions.text).error.param], [400, "stream_options"]);
    assert.equal(fake("normal").requests.length, calls);
  });

  it("leaves the usage log and the ledger in agreement, and no reservation behind", () => {
    for (const config of [bufferedConfig, relayedConfig]) {
      const ledger = openLedger(config).usage(config.keys);
      assert.deepEqual(verifyUsage(lines(config), ledger).map((row) => [row.key, row.ok]), [["streamer", true], ["tiny", true]]);
      assert.deepEqual(ledger.map((row) => row.inFlight), [0, 0]);
    }
  });
});

describe("SseParser and StreamAssembler", () => {
  it("splits events at blank lines, whatever the line ends and wherever a read ends", () => {
    const parser = new SseParser();
    assert.deepEqual(parser.push('data: {"a":1}\r'), []);
    assert.deepEqual(parser.push('\n\r\ndata: {"b":2}\n\n: a comment\n\ndata: one\ndata: two\n\ndata: half'), [
      { raw: 'data: {"a":1}', data: '{"a":1}' },
      { raw: 'data: {"b":2}', data: '{"b":2}' },
      { raw: ": a comment" },
      { raw: "data: one\ndata: two", data: "one\ntwo" },
    ]);
    // An event is complete only at its blank line.
    assert.deepEqual(parser.push(" done\n\n"), [{ raw: "data: half done", data: "half done" }]);
  });

  it("puts choices and interleaved tool-call fragments back together, by index", () => {
    const a = new StreamAssembler();
    const chunk = (choices: unknown[], extra: Record<string, unknown> = {}) => ({ id: "c-1", object: "chat.completion.chunk", created: 1, model: "m", choices, ...extra });
    a.add(chunk([{ index: 1, delta: { role: "assistant", content: "B" } }, { index: 0, delta: { role: "assistant", content: "A" } }]));
    a.add(chunk([{ index: 0, delta: { tool_calls: [{ index: 1, id: "t2", type: "function", function: { name: "two", arguments: '{"y"' } }, { index: 0, id: "t1", type: "function", function: { name: "one", arguments: '{"x"' } }] } }]));
    a.add(chunk([{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: ":1}" } }, { index: 1, function: { arguments: ":2}" } }] } }]));
    assert.equal(a.finished, false);
    a.add(chunk([{ index: 0, delta: {}, finish_reason: "tool_calls" }, { index: 1, delta: { content: "b" }, finish_reason: "stop" }]));
    a.add(chunk([], { usage: { prompt_tokens: 3, completion_tokens: 4 } }));
    assert.equal(a.finished, true);
    assert.deepEqual(a.usage, { prompt_tokens: 3, completion_tokens: 4 });
    assert.deepEqual(a.meta, { id: "c-1", object: "chat.completion.chunk", created: 1, model: "m" });
    assert.deepEqual(a.answer(), {
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: "A",
            tool_calls: [
              { id: "t1", type: "function", function: { name: "one", arguments: '{"x":1}' } },
              { id: "t2", type: "function", function: { name: "two", arguments: '{"y":2}' } },
            ],
          },
          finish_reason: "tool_calls",
        },
        { index: 1, message: { role: "assistant", content: "Bb" }, finish_reason: "stop" },
      ],
    });
  });
});

// A held stream sends only what was scanned. The upstream here sends exactly the shapes under test:
// pieces the gateway cannot put together (no index), content as text parts, text in reasoning or in
// a field nobody defined, and the gateway's own upstream key split across two chunks.
describe("a held stream is passed on only as it was scanned", () => {
  const UPSTREAM_KEY = "fake-provider-key-shapes-0001";
  const [keyStart, keyEnd] = half(UPSTREAM_KEY);
  const base = { id: "c1", object: "chat.completion.chunk", created: 1, model: "m" };
  const CASES: Record<string, Array<Record<string, unknown>>> = {
    toolNoIndex: [{ index: 0, delta: { role: "assistant", tool_calls: [{ id: "t1", type: "function", function: { name: "save", arguments: `{"t":"${SECRET}"}` } }] } }],
    choiceNoIndex: [{ delta: { role: "assistant", content: `token ${SECRET}` } }],
    contentParts: [{ index: 0, delta: { role: "assistant", content: [{ type: "text", text: `token ${SECRET}` }] } }],
    contentPartsClean: [{ index: 0, delta: { role: "assistant", content: [{ type: "text", text: "plain " }, { type: "text", text: "words" }] } }],
    reasoning: [{ index: 0, delta: { role: "assistant", reasoning_content: `thinking about ${SECRET}`, content: "ok" } }],
    unknownField: [{ index: 0, delta: { role: "assistant", content: "ok", audio: { transcript: `say ${SECRET}` } } }],
    unknownFieldKeyLine: [{ index: 0, delta: { role: "assistant", content: "ok", notes: `api_key = "${FAKE.apiKeyValue}"` } }],
    upstreamKeySplit: [
      { index: 0, delta: { role: "assistant", content: `my key is ${keyStart}` } },
      { index: 0, delta: { content: `${keyEnd}, keep it` } },
    ],
  };
  const NON_STREAM: Record<string, Record<string, unknown>> = {
    toolNoIndex: { role: "assistant", content: null, tool_calls: [{ id: "t1", type: "function", function: { name: "save", arguments: `{"t":"${SECRET}"}` } }] },
    contentParts: { role: "assistant", content: [{ type: "text", text: `token ${SECRET}` }] },
    reasoning: { role: "assistant", reasoning_content: `thinking about ${SECRET}`, content: "ok" },
  };
  let upstream: http.Server;
  let gateway: LlmGateway;
  let tmp: string;

  before(async () => {
    upstream = http.createServer((req, res) => {
      let raw = "";
      req.on("data", (c: Buffer) => (raw += c.toString("utf8")));
      req.on("end", () => {
        const body = JSON.parse(raw) as { stream?: boolean; messages: Array<{ content: string }> };
        const name = body.messages[0]!.content;
        const usage = { prompt_tokens: 5, completion_tokens: 5, total_tokens: 10 };
        if (!body.stream) {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ id: "x", object: "chat.completion", created: 1, model: "m", choices: [{ index: 0, message: NON_STREAM[name], finish_reason: "stop" }], usage }));
          return;
        }
        res.writeHead(200, { "content-type": "text/event-stream" });
        for (const choice of CASES[name]!) res.write(`data: ${JSON.stringify({ ...base, choices: [choice] })}\n\n`);
        res.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\n`);
        res.write(`data: ${JSON.stringify({ ...base, choices: [], usage })}\n\n`);
        res.end("data: [DONE]\n\n");
      });
    });
    await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-shapes-"));
    const config = parseLlmConfig(
      {
        listen: { port: 0 },
        stateDir: "state",
        policy: path.join(ROOT, "llm-policy.example.json"),
        upstreams: [{ name: "u", baseUrl: `http://127.0.0.1:${(upstream.address() as net.AddressInfo).port}/v1`, apiKeyEnv: "SHAPES_KEY", models: { small: "m" }, pricePerMTok: PRICE }],
        routes: [{ id: "r", use: { upstream: "u" } }],
        keys: [{ name: "shapes", sha256: hashKey(KEY), dailyUsd: 5, monthlyUsd: 50 }],
      },
      tmp,
    );
    gateway = await startLlmGateway(config, loadLeakPolicy(path.join(ROOT, "llm-policy.example.json")), { env: { SHAPES_KEY: UPSTREAM_KEY }, log: () => undefined });
  });
  after(async () => {
    await gateway?.close();
    upstream?.closeAllConnections();
    await new Promise<void>((resolve) => upstream?.close(() => resolve()));
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const ask = async (name: string, stream = true) => {
    const res = await fetch(`${gateway.url}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "small", messages: [{ role: "user", content: name }], max_tokens: 20, stream }),
    });
    return { status: res.status, headers: res.headers, text: await res.text() };
  };

  it("refuses pieces it cannot put together (a tool call or a choice without an index): 502, nothing passed on", async () => {
    for (const name of ["toolNoIndex", "choiceNoIndex"]) {
      const r = await ask(name);
      assert.equal(r.status, 502, name);
      assert.equal(JSON.parse(r.text).error.code, "bad_upstream_response", name);
      assert.equal(r.text.includes(SECRET), false, name);
    }
  });

  it("reads content sent as text parts, reasoning text and fields nobody defined, as it reads content", async () => {
    for (const name of ["contentParts", "reasoning", "unknownField"]) {
      const r = await ask(name);
      assert.deepEqual([r.status, JSON.parse(r.text).error.code, JSON.parse(r.text).error.rule], [502, "response_blocked", "github-token"], name);
      assert.equal(r.text.includes(SECRET), false, name);
    }
    const clean = await ask("contentPartsClean");
    assert.equal(clean.status, 200);
    assert.ok(clean.text.includes('"text":"plain "') && clean.text.includes("[DONE]"), "a clean answer in text parts is passed on as it came");
  });

  it("redacts in a field nobody defined, in its own event, and names the rule", async () => {
    const r = await ask("unknownFieldKeyLine");
    assert.equal(r.status, 200);
    assert.equal(r.text.includes(FAKE.apiKeyValue), false);
    assert.ok(r.text.includes("[REDACTED:api-key-assignment]"));
    assert.equal(r.headers.get("x-agent-gate-response-redacted"), "api-key-assignment");
  });

  it("an upstream key split across two chunks is cut out of the answer, which is then sent whole", async () => {
    const r = await ask("upstreamKeySplit");
    assert.equal(r.status, 200);
    assert.equal(r.text.includes(UPSTREAM_KEY), false);
    assert.ok(r.text.includes("[REDACTED:upstream-key]"));
  });

  it("a non-streamed answer is read the same way: tool calls, text parts and reasoning", async () => {
    for (const name of Object.keys(NON_STREAM)) {
      const r = await ask(name, false);
      assert.deepEqual([r.status, JSON.parse(r.text).error.code], [502, "response_blocked"], name);
      assert.equal(r.text.includes(SECRET), false, name);
    }
  });
});

describe("a relayed stream whose client stops reading", () => {
  it("is cut off at the attempt's timeout and settled then: no late orphan, no spend past the cap", async () => {
    const fake = await startFakeUpstream({ mode: "ok", usage: USAGE, stream: { pieces: Array.from({ length: 2500 }, () => "x".repeat(8000)) } });
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-stall-"));
    const config = parseLlmConfig(
      {
        listen: { port: 0 },
        stateDir: "state",
        policy: path.join(ROOT, "llm-policy.example.json"),
        upstreams: [{ name: "u", baseUrl: `${fake.url}/v1`, apiKeyEnv: "STALL_KEY", models: { small: "m" }, pricePerMTok: PRICE }],
        routes: [{ id: "r", use: { upstream: "u" } }],
        keys: [{ name: "stall", sha256: hashKey(KEY), dailyUsd: 5, monthlyUsd: 50 }],
        timeoutMs: 1000,
        retries: 0,
        rateLimitWaitMs: 0,
        streamIdleMs: 1000,
        scanResponses: false,
      },
      tmp,
    );
    const gateway = await startLlmGateway(config, loadLeakPolicy(path.join(ROOT, "llm-policy.example.json")), { env: { STALL_KEY: "fake-provider-key-stall-0001" }, log: () => undefined });
    const socket = net.connect(Number(new URL(gateway.url).port), "127.0.0.1");
    try {
      // A client that sends a streamed request and never reads the answer.
      socket.pause();
      const body = JSON.stringify({ model: "small", messages: [{ role: "user", content: "a long answer" }], max_tokens: 50, stream: true });
      socket.write(`POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${KEY}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
      const usageFile = path.join(config.stateDir, "usage.jsonl");
      const line = () => (fs.existsSync(usageFile) ? (readUsageLog(usageFile).lines as Array<Record<string, any>>)[0] : undefined);
      const started = Date.now();
      for (let waited = 0; waited < 5000 && !line(); waited += 20) await new Promise((resolve) => setTimeout(resolve, 20));
      const settled = line();
      assert.ok(settled, "the call was settled and recorded while its client still was not reading");
      assert.ok(Date.now() - started < 4000, "within the attempt's time, not when the client comes back");
      assert.deepEqual([settled.status, settled.streamEnd, settled.error, settled.settle], [200, "timeout", "upstream_timeout", undefined]);
      assert.equal(openLedger(config).usage(config.keys)[0]?.inFlight, 0, "no reservation left behind");
    } finally {
      socket.destroy();
      await gateway.close();
      await fake.close();
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("a streamed request answered with a whole JSON answer that never ends", () => {
  it("runs out of time like a stream does: 504, booked at its estimate, nothing left reserved", async () => {
    // An upstream that ignores "stream", answers 200 with JSON, and stops halfway through the body.
    const upstream = http.createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.write('{"id":"x","choices":[');
      });
    });
    await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-json-stall-"));
    const config = parseLlmConfig(
      {
        listen: { port: 0 },
        stateDir: "state",
        policy: path.join(ROOT, "llm-policy.example.json"),
        upstreams: [{ name: "u", baseUrl: `http://127.0.0.1:${(upstream.address() as net.AddressInfo).port}/v1`, apiKeyEnv: "JSON_KEY", models: { small: "m" }, pricePerMTok: PRICE }],
        routes: [{ id: "r", use: { upstream: "u" } }],
        keys: [{ name: "json", sha256: hashKey(KEY), dailyUsd: 5, monthlyUsd: 50 }],
        timeoutMs: 500,
        retries: 0,
        rateLimitWaitMs: 0,
      },
      tmp,
    );
    const gateway = await startLlmGateway(config, loadLeakPolicy(path.join(ROOT, "llm-policy.example.json")), { env: { JSON_KEY: "fake-provider-key-json-0001" }, log: () => undefined });
    try {
      const res = await fetch(`${gateway.url}/v1/chat/completions`, {
        method: "POST",
        headers: { authorization: `Bearer ${KEY}`, "content-type": "application/json" },
        body: JSON.stringify({ model: "small", messages: [{ role: "user", content: "hello" }], max_tokens: 20, stream: true }),
      });
      const body = (await res.json()) as { error: { code: string; message: string } };
      assert.deepEqual([res.status, body.error.code], [504, "upstream_timeout"]);
      assert.match(body.error.message, /booked at its estimate/);
      const line = (readUsageLog(path.join(config.stateDir, "usage.jsonl")).lines as Array<Record<string, any>>)[0]!;
      assert.deepEqual([line.status, line.error, line.streamEnd, line.usage], [504, "upstream_timeout", "timeout", "estimate"]);
      assert.ok(line.costUsd > 0, "the 2xx answer was paid for");
      assert.equal(openLedger(config).usage(config.keys)[0]?.inFlight, 0);
    } finally {
      await gateway.close();
      upstream.closeAllConnections();
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
