#!/usr/bin/env node
"use strict";
// agent-gate example: a small, real MCP server to put behind the gateway. It reports the state of a
// set of scheduled jobs from a status folder, so an agent reads a few fields of JSON instead of long
// log files, and it has one tool that changes something, so the gateway has a call to hold.
//
//   slo_now             read   service-level objectives: target, actual, met
//   bot_status          read   each job's last run, whether it went well, whether it is overdue
//   inbox_unread_count  read   how many inbox items nobody has read yet, and the oldest
//   mark_inbox_read     write  marks one item read (or all of them, with "all": true)
//
// Usage: node examples/status-mcp/server.js [--dir <status folder>] [--writable] [--now <ISO time>]
// The folder defaults to sample-status/ next to this file and holds slo.json, bots.json and
// inbox.jsonl. Without --writable the server changes nothing: mark_inbox_read says what it would
// have marked. --now fixes the clock that "overdue" is measured against, for repeatable output.
const fs = require("node:fs");
const path = require("node:path");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
const { z } = require("zod");

const option = (name) => {
  const at = process.argv.indexOf(name);
  return at >= 0 ? process.argv[at + 1] : undefined;
};
const dir = path.resolve(option("--dir") ?? path.join(__dirname, "sample-status"));
const writable = process.argv.includes("--writable");
const now = () => (option("--now") ? Date.parse(option("--now")) : Date.now());

const readJson = (name) => JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
const inboxFile = path.join(dir, "inbox.jsonl");
const readInbox = () =>
  fs
    .readFileSync(inboxFile, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line));
const answer = (data) => ({ content: [{ type: "text", text: JSON.stringify(data) }], structuredContent: data });

const server = new McpServer({ name: "status-mcp", version: "1.0.0" });

server.registerTool(
  "slo_now",
  { description: "Service-level objectives of the scheduled jobs: target, actual and whether each is met.", inputSchema: {}, annotations: { readOnlyHint: true } },
  async () => {
    const slo = readJson("slo.json");
    return answer({ window: slo.window, objectives: slo.objectives.map((o) => ({ name: o.name, target: o.target, actual: o.actual, met: o.actual >= o.target })) });
  },
);

server.registerTool(
  "bot_status",
  { description: "Each scheduled job: when it last ran, whether that run went well, and whether it is overdue.", inputSchema: {}, annotations: { readOnlyHint: true } },
  async () => {
    const { staleAfterHours, bots } = readJson("bots.json");
    return answer({
      bots: bots.map((b) => {
        const hours = Math.round(((now() - Date.parse(b.lastRun)) / 3_600_000) * 10) / 10;
        return { name: b.name, lastRun: b.lastRun, ok: b.ok, hoursSinceLastRun: hours, overdue: hours > staleAfterHours };
      }),
    });
  },
);

server.registerTool(
  "inbox_unread_count",
  { description: "How many inbox items nobody has read yet, and the oldest of them.", inputSchema: {}, annotations: { readOnlyHint: true } },
  async () => {
    const unread = readInbox().filter((item) => !item.read);
    return answer({ unread: unread.length, oldest: unread[0] ? { id: unread[0].id, subject: unread[0].subject } : null });
  },
);

server.registerTool(
  "mark_inbox_read",
  {
    description: 'Marks one inbox item read by its id, or every item with "all": true.',
    inputSchema: { id: z.string().optional(), all: z.boolean().optional() },
  },
  async ({ id, all }) => {
    const items = readInbox();
    const chosen = items.filter((item) => !item.read && (all === true || item.id === id));
    if (chosen.length === 0) return { content: [{ type: "text", text: `nothing to mark: no unread item ${all ? "at all" : JSON.stringify(id)}` }], isError: true };
    if (!writable) {
      return answer({ marked: 0, wouldMark: chosen.map((item) => item.id), note: "this server was started without --writable, so it changed nothing" });
    }
    const ids = new Set(chosen.map((item) => item.id));
    fs.writeFileSync(inboxFile, `${items.map((item) => JSON.stringify(ids.has(item.id) ? { ...item, read: true } : item)).join("\n")}\n`);
    return answer({ marked: chosen.length, ids: [...ids] });
  },
);

server.connect(new StdioServerTransport()).catch((err) => {
  process.stderr.write(`status-mcp: ${String(err)}\n`);
  process.exit(1);
});
