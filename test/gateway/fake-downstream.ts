// A tiny downstream MCP server for the end-to-end test and the example config.
// Its tools only pretend: nothing is deleted and no command is run.
// With --log <file>, every call it receives is appended to that file as one JSON line, so a test
// can prove which calls reached it and which did not.

import * as fs from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const logAt = process.argv.indexOf("--log");
const logFile = logAt >= 0 ? process.argv[logAt + 1] : undefined;

function received(tool: string, args: Record<string, unknown>): void {
  if (logFile) fs.appendFileSync(logFile, `${JSON.stringify({ tool, args })}\n`);
}

const server = new McpServer({ name: "fake-downstream", version: "1.0.0" });

server.registerTool(
  "echo",
  {
    description: "Returns the text it is given.",
    inputSchema: { text: z.string() },
    outputSchema: { echoed: z.string(), length: z.number() },
  },
  async ({ text }) => {
    received("echo", { text });
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

server.connect(new StdioServerTransport()).catch((err: unknown) => {
  process.stderr.write(`fake-downstream: ${String(err)}\n`);
  process.exit(1);
});
