#!/usr/bin/env node
"use strict";
// Writes the transcript that docs/demo/llm.html replays: a real run of the LLM gateway with the example
// config (llm-gateway.config.example.json, its upstreams pointed at the fake provider from the tests)
// and the example leak policy, request by request, with what each request wrote to the usage log and
// the ledger, whether it reached the provider, and the lines of code that decided it.
//
// Usage, after `npm run build`: node scripts/demo-llm-transcript.js   (or: npm run demo:llm)
// It rewrites the <script id="transcript"> block of docs/demo/llm.html in place. Run it again after
// changing any code the page quotes: test/demo-llm.test.js fails while a quoted excerpt is out of date.
// The gateway key is the example's documented demo key; the upstream keys are made up for the run and
// never reach the page (the test checks).
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const PAGE = path.join(ROOT, "docs", "demo", "llm.html");
/** The example config accepts this key; README.md documents it as not a secret. */
const GATEWAY_KEY = "demo-gateway-key-not-a-secret";
/** Made-up upstream keys for this run only. */
const UPSTREAM_ENV = Object.fromEntries(["CHEAP", "STRONG", "BACKUP"].map((name) => [`${name}_API_KEY`, `made-up-${name.toLowerCase()}-upstream-for-the-demo`]));

/** The code the page shows: a file, the first line to find, and how many lines to quote from there. */
const EXCERPTS = {
  route: ["src/llm/routing.ts", 'export function route(config: Pick<LlmConfig, "routes" | "upstreams">, request: RouteRequest): Route | undefined {', 12],
  leakStep: ["src/llm/server.ts", "    // 4. Leak guard. The error names the rule, never the text it matched.", 13],
  guardMessages: ["src/llm/leak-guard.ts", "export function guardMessages(policy: LeakPolicy, messages: readonly unknown[]): GuardResult {", 5],
  estimate: ["src/llm/server.ts", "    // 5. Reserve the most this call can cost on any upstream it may reach.", 6],
  capCheck: ["src/llm/budget.ts", "      const checks: Array<[Cap, number, number, number]> = [", 11],
  streamHeld: ["src/llm/server.ts", "    // Buffered: nothing has been sent yet.", 14],
  settle: ["src/llm/server.ts", "    const used = readUsage({ usage: assembler.usage });", 9],
};

/** Finds an excerpt in its file now: its 1-based first line and its text. */
function excerpt(id) {
  const [file, first, count] = EXCERPTS[id];
  const lines = fs.readFileSync(path.join(ROOT, file), "utf8").split("\n");
  const at = lines.findIndex((line) => line.includes(first));
  if (at < 0) throw new Error(`${file} no longer has a line with ${JSON.stringify(first)}`);
  return { id, file, line: at + 1, text: lines.slice(at, at + count).join("\n") };
}

async function main() {
  const { startFakeUpstream } = require("../dist/test/llm/fake-upstream.js");
  const { loadLeakPolicy, parseLlmConfig } = require("../dist/src/llm/config.js");
  const { openLedger, startLlmGateway } = require("../dist/src/llm/server.js");

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gate-llm-demo-"));
  const fake = await startFakeUpstream({ mode: "ok" });
  const json = JSON.parse(fs.readFileSync(path.join(ROOT, "llm-gateway.config.example.json"), "utf8"));
  json.listen = { host: "127.0.0.1", port: 0 };
  json.stateDir = path.join(tmp, "state");
  json.policy = path.join(ROOT, "llm-policy.example.json");
  for (const upstream of json.upstreams) upstream.baseUrl = `${fake.url}/v1`;
  const configFile = path.join(tmp, "llm-gateway.config.json");
  fs.writeFileSync(configFile, JSON.stringify(json, null, 2));
  const config = parseLlmConfig(json, tmp);
  const logs = [];
  const gateway = await startLlmGateway(config, loadLeakPolicy(config.policyFile), { env: UPSTREAM_ENV, log: (message) => logs.push(message) });

  const user = os.userInfo().username;
  const clean = (text) => text.split(tmp).join("/tmp/demo").split(user).join("alice");
  const usageFile = path.join(config.stateDir, "usage.jsonl");
  let seenUsage = 0;
  /** Usage lines written since the last step. */
  const newUsage = () => {
    const all = fs.existsSync(usageFile) ? fs.readFileSync(usageFile, "utf8").trim().split("\n").filter(Boolean) : [];
    const fresh = all.slice(seenUsage);
    seenUsage = all.length;
    return fresh.map((line) => JSON.parse(clean(line)));
  };
  let seenLogs = 0;
  const newLogs = () => {
    const fresh = logs.slice(seenLogs).filter((line) => !line.startsWith("listening on"));
    seenLogs = logs.length;
    return fresh.map(clean);
  };
  const ledger = () => openLedger(config).usage(config.keys).map((row) => ({ key: row.key, day: row.day, dayUsd: row.dayUsd, dailyUsd: row.dailyUsd, inFlight: row.inFlight }));
  newLogs();

  const steps = [];
  const shown = ["retry-after", "content-type", "x-agent-gate-route", "x-agent-gate-upstream", "x-agent-gate-cost-usd", "x-agent-gate-redacted"];
  const call = async (body, headers, step) => {
    const before = fake.requests.length;
    const res = await fetch(`${gateway.url}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${GATEWAY_KEY}`, "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    steps.push({
      actor: "agent",
      request: { headers: { authorization: "Bearer $GATEWAY_KEY", ...headers }, body },
      response: { status: res.status, headers: Object.fromEntries(shown.filter((h) => res.headers.has(h)).map((h) => [h, res.headers.get(h)])), body: clean(text) },
      upstreamCalls: fake.requests.length - before,
      usage: newUsage(),
      ledger: ledger(),
      log: newLogs(),
      ...step,
    });
  };
  const human = (command, args, step) => {
    const out = spawnSync(process.execPath, [path.join(ROOT, "bin", "agent-gate.js"), ...args, "--config", configFile], { encoding: "utf8" });
    steps.push({ actor: "human", command: `$ agent-gate ${command}`, answer: clean(out.stdout).trimEnd(), exitCode: out.status, upstreamCalls: 0, usage: newUsage(), ledger: ledger(), log: newLogs(), ...step });
  };

  await call({ model: "large", messages: [{ role: "user", content: "Label this ticket: printer on fire" }], max_tokens: 20 }, { "x-agent-task": "classify" }, {
    title: "A classification goes to the cheap model",
    note: "The agent asks for the large model, but its x-agent-task header says classify, and the first route that applies sends that to the cheap upstream. The cost is reserved first and settled from the provider's own token count.",
    code: ["route", "settle"],
  });
  // The first line of a private key, built here so that this file holds none.
  const keyHeader = ["-----BEGIN OPENSSH ", "PRIVATE KEY-----"].join("");
  await call({ model: "small", messages: [{ role: "user", content: `Why does ssh reject this key? ${keyHeader} (rest cut)` }] }, {}, {
    title: "A secret in the prompt never leaves",
    note: "The leak guard reads the messages before anything is sent. A block rule matched, so the request is refused with the rule's name, never the text it matched, and the provider gets nothing.",
    code: ["leakStep", "guardMessages"],
  });
  await call({ model: "large", messages: [{ role: "user", content: "Write the release notes for version 2." }], max_tokens: 1000 }, {}, {
    title: "A call that could pass the budget is refused before it is sent",
    note: "This call could produce 1000 output tokens at $15 per million, more than the key's whole daily cap of $0.01. The gateway reserves the most a call can cost before sending it, so it refuses now, with the numbers and a Retry-After, and nothing is charged.",
    code: ["estimate", "capCheck"],
  });
  await call({ model: "small", messages: [{ role: "user", content: "Say hello in five words." }], stream: true }, {}, {
    title: "A streamed answer is held until it has been read",
    note: "With stream: true the client gets server-sent events. The gateway asks the provider for a usage chunk, reads the whole stream, runs the leak guard over the answer, and only then sends the events, with the cost settled from the provider's count.",
    code: ["streamHeld", "settle"],
  });
  human("usage --verify", ["usage", "--verify"], {
    title: "The books balance",
    note: "usage --verify adds up the usage log and compares it with the ledger, per key, for today and this month: the two refused calls cost nothing, and the two that ran were booked once each.",
    code: [],
  });

  await gateway.close();
  await fake.close();
  fs.rmSync(tmp, { recursive: true, force: true });

  const transcript = {
    about: "A real run of agent-gate's LLM gateway with llm-gateway.config.example.json (upstreams pointed at the fake provider from the tests) and llm-policy.example.json, written by scripts/demo-llm-transcript.js. Times, ids and trace ids are from that run.",
    steps,
    excerpts: Object.fromEntries(Object.keys(EXCERPTS).map((id) => [id, excerpt(id)])),
  };
  const page = fs.readFileSync(PAGE, "utf8");
  const text = JSON.stringify(transcript, null, 1).replace(/</g, "\\u003c");
  const next = page.replace(/(<script type="application\/json" id="transcript">)[\s\S]*?(<\/script>)/, (_, open, close) => `${open}\n${text}\n${close}`);
  if (next === page && !page.includes(text)) throw new Error(`${PAGE} has no <script type="application/json" id="transcript"> block`);
  fs.writeFileSync(PAGE, next);
  process.stdout.write(`wrote ${steps.length} steps and ${Object.keys(EXCERPTS).length} excerpts into ${path.relative(ROOT, PAGE)}\n`);
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`demo-llm-transcript: ${err.stack ?? err}\n`);
    process.exit(1);
  });
}

module.exports = { EXCERPTS, excerpt, GATEWAY_KEY, UPSTREAM_ENV };
