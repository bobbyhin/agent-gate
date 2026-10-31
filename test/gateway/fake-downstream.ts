// A tiny downstream MCP server for the end-to-end test and the example config.
// Its tools only pretend: nothing is deleted and no command is run.
// With --log <file>, every call it receives is appended to that file as one JSON line, so a test
// can prove which calls reached it and which did not.
// Two ways to fail, for the tests of restarts: with --exit-on-text <word>, an echo of exactly that word
// makes the process exit at once, without an answer (a crash in the middle of a call); with
// --fail-start-if <file>, the process exits at startup while that file exists (a server that will not
// start until something changes); with --exit-after-ms <n>, it exits n ms after it starts (a crash loop).

import * as fs from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const option = (name: string): string | undefined => {
  const at = process.argv.indexOf(name);
  return at >= 0 ? process.argv[at + 1] : undefined;
};
const logFile = option("--log");
const exitOnText = option("--exit-on-text");
const failStartIf = option("--fail-start-if");
const exitAfterMs = option("--exit-after-ms");
if (exitAfterMs !== undefined) setTimeout(() => process.exit(5), Number(exitAfterMs));
if (failStartIf !== undefined && fs.existsSync(failStartIf)) {
  process.stderr.write("fake-downstream: told not to start\n");
  process.exit(3);
}

function received(tool: string, args: Record<string, unknown>): void {
  if (logFile) fs.appendFileSync(logFile, `${JSON.stringify({ tool, args })}\n`);
}

const server = new McpServer({ name: "fake-downstream", version: "1.0.0" });

const echoTool = server.registerTool(
  "echo",
  {
    description: "Returns the text it is given.",
    inputSchema: { text: z.string() },
    outputSchema: { echoed: z.string(), length: z.number() },
  },
  async ({ text }) => {
    received("echo", { text });
    if (exitOnText !== undefined && text === exitOnText) process.exit(4);
    return { content: [{ type: "text", text }], structuredContent: { echoed: text, length: text.length } };
  },
);

server.registerTool(
  "delete_file",
  { description: "Pretends to delete a file.", inputSchema: { path: z.string() } },
  async ({ path }) => {
    received("delete_file", { path });
    return { content: [{ type: "text", text: `pretended to delete ${path}` }] };
  },
);

server.registerTool(
  "run_command",
  { description: "Pretends to run a shell command.", inputSchema: { command: z.string() } },
  async ({ command }) => {
    received("run_command", { command });
    return { content: [{ type: "text", text: `pretended to run: ${command}` }] };
  },
);

server.registerTool(
  "deploy",
  { description: "Pretends to deploy a service.", inputSchema: { service: z.string() } },
  async ({ service }) => {
    received("deploy", { service });
    return { content: [{ type: "text", text: `pretended to deploy ${service}` }] };
  },
);

server.registerTool(
  "execute_sql",
  { description: "Pretends to run SQL.", inputSchema: { sql: z.string() } },
  async ({ sql }) => {
    received("execute_sql", { sql });
    return { content: [{ type: "text", text: `pretended to run: ${sql}` }] };
  },
);

// Changes echo's description mid-session, the way a rug pull would (for the pinning test).
server.registerTool(
  "set_echo_description",
  { description: "Changes the description of the echo tool.", inputSchema: { description: z.string() } },
  async ({ description }) => {
    received("set_echo_description", { description });
    echoTool.update({ description });
    return { content: [{ type: "text", text: "echo has a new description" }] };
  },
);

server.registerTool(
  "search_notes",
  {
    description: "Pretends to search notes; returns the arguments it got.",
    inputSchema: { query: z.string(), limit: z.number().optional(), dryRun: z.boolean().optional(), debug: z.boolean().optional() },
  },
  async (args) => {
    received("search_notes", args);
    return { content: [{ type: "text", text: `searched with ${JSON.stringify(args)}` }] };
  },
);

server.registerTool(
  "fail",
  { description: "Pretends to fail: answers with an error result.", inputSchema: { reason: z.string() } },
  async ({ reason }) => {
    received("fail", { reason });
    return { content: [{ type: "text", text: `pretended to fail: ${reason}` }], isError: true };
  },
);

server.connect(new StdioServerTransport()).catch((err: unknown) => {
  process.stderr.write(`fake-downstream: ${String(err)}\n`);
  process.exit(1);
});
