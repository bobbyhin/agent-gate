// A small remote MCP server for the Streamable HTTP tests: the SDK's own server transport, stateless,
// on 127.0.0.1 at a port the system picks. With `token`, a request without "Authorization: Bearer
// <token>" gets a 401 that quotes what it was sent, the way a careless server might, so a test can
// prove the gateway never passes a header value on. Its tools only pretend.

import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

export interface FakeHttpDownstream {
  /** The MCP endpoint, for example http://127.0.0.1:43123/mcp */
  url: string;
  /** The Authorization headers it received, in order. */
  authorizations: string[];
  close(): Promise<void>;
}

export async function startFakeHttpDownstream(options: { token?: string } = {}): Promise<FakeHttpDownstream> {
  const authorizations: string[] = [];
  const server = http.createServer((req, res) => {
    const authorization = req.headers.authorization ?? "";
    authorizations.push(authorization);
    if (options.token !== undefined && authorization !== `Bearer ${options.token}`) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: `unauthorized: got ${JSON.stringify(authorization)}` }));
      return;
    }
    if ((req.url ?? "").split("?")[0] !== "/mcp") {
      res.writeHead(404).end();
      return;
    }
    // Stateless: a server and a transport per request, closed with it.
    const mcp = new McpServer({ name: "fake-http-downstream", version: "1.0.0" });
    mcp.registerTool("echo", { description: "Returns the text it is given.", inputSchema: { text: z.string() } }, async ({ text }) => ({ content: [{ type: "text", text }] }));
    mcp.registerTool("slow", { description: "Answers after a while.", inputSchema: { ms: z.number() } }, async ({ ms }) => {
      await new Promise((resolve) => setTimeout(resolve, ms));
      return { content: [{ type: "text", text: `answered after ${ms} ms` }] };
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      void transport.close();
      void mcp.close();
    });
    mcp
      .connect(transport)
      .then(() => transport.handleRequest(req, res))
      .catch(() => {
        if (!res.headersSent) res.writeHead(500).end();
      });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    authorizations,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}
