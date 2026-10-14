// The agent-gate command line: run the gateway, and let a human answer approval requests.

import { parseArgs } from "node:util";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ApprovalError, ApprovalStore, canonicalJson, isLive, type Approval } from "./approvals.js";
import { loadConfig, loadPolicy } from "./config.js";
import { createGateway, SEPARATOR } from "./server.js";
import { ConfigError } from "./validate.js";

const USAGE = `Usage:
  agent-gate serve [--config <file>]                  run the MCP gateway on stdin/stdout
  agent-gate approvals list [--all] [--json] [--config <file>]
  agent-gate approvals show <id> [--config <file>]    print one request in full
  agent-gate approvals approve <id> [--config <file>]
  agent-gate approvals deny <id> [--config <file>]

"list" shows the requests that are waiting; --all also shows decided, used and expired ones.
The config file is --config, else $AGENT_GATE_CONFIG, else ./gateway.config.json.
`;

export interface Io {
  out: (text: string) => void;
  err: (text: string) => void;
}

const processIo: Io = {
  out: (text) => process.stdout.write(text),
  err: (text) => process.stderr.write(text),
};

/** Runs one command and returns the exit code: 0 done, 1 failed, 2 bad usage. */
export async function main(argv: string[], io: Io = processIo): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        config: { type: "string" },
        all: { type: "boolean", default: false },
        json: { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (err) {
    io.err(`agent-gate: ${(err as Error).message}\n\n${USAGE}`);
    return 2;
  }
  const { values, positionals } = parsed;
  if (values.help) {
    io.out(USAGE);
    return 0;
  }
  const configFile = values.config ?? process.env.AGENT_GATE_CONFIG ?? "gateway.config.json";
  const [command, action, id, ...extra] = positionals;
  const isServe = command === "serve" && action === undefined;
  const isApprovals =
    command === "approvals" &&
    extra.length === 0 &&
    (action === "list" ? id === undefined : ["show", "approve", "deny"].includes(action ?? "") && id !== undefined);
  if (!isServe && !isApprovals) {
    io.err(USAGE);
    return 2;
  }

  try {
    if (isServe) return await serve(configFile);
    const config = loadConfig(configFile);
    const store = new ApprovalStore(config.stateDir, config.approvalTtlMs);
    if (action === "list") return list(store, values.all, values.json, io);
    if (action === "show") {
      io.out(`${JSON.stringify(store.get(id as string), null, 2)}\n`);
    } else if (action === "approve") {
      const approval = store.approve(id as string);
      io.out(`approved ${describeCall(approval)}\nThe agent can now make this exact call once, until ${approval.expiresAt}.\n`);
    } else {
      const approval = store.deny(id as string);
      io.out(`denied ${describeCall(approval)}\nIf the agent makes this call again, it is told that a human said no.\n`);
    }
    return 0;
  } catch (err) {
    if (err instanceof ApprovalError || err instanceof ConfigError) {
      io.err(`agent-gate: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
}

async function serve(configFile: string): Promise<number> {
  const config = loadConfig(configFile);
  const gateway = await createGateway(config, loadPolicy(config.policyFile));
  await gateway.server.connect(new StdioServerTransport());
  // The SDK's stdio transport does not notice when the client goes away, so watch stdin here.
  await new Promise<void>((resolve) => {
    process.stdin.once("end", resolve);
    process.stdin.once("close", resolve);
    process.once("SIGINT", resolve);
    process.once("SIGTERM", resolve);
  });
  await gateway.close();
  return 0;
}

function list(store: ApprovalStore, all: boolean, json: boolean, io: Io): number {
  const now = Date.now();
  const shown = store.list().filter((a) => all || (a.status === "pending" && isLive(a, now)));
  if (json) {
    io.out(`${JSON.stringify(shown.map((a) => ({ ...a, expired: a.status !== "used" && !isLive(a, now) })), null, 2)}\n`);
    return 0;
  }
  if (shown.length === 0) {
    io.out(all ? "No approval requests.\n" : "No requests are waiting for a decision.\n");
    return 0;
  }
  for (const a of shown) {
    const state = a.status !== "used" && !isLive(a, now) ? `${a.status}, expired` : a.status;
    io.out(
      [
        `${a.id}  ${state}  ${a.server}${SEPARATOR}${a.tool}`,
        `  why:     ${a.why} (rule ${a.rule})`,
        `  args:    ${preview(canonicalJson(a.args))}`,
        `  created: ${a.createdAt}  expires: ${a.expiresAt}`,
        "",
      ].join("\n"),
    );
  }
  return 0;
}

function describeCall(a: Approval): string {
  return `${a.id}: ${a.server}${SEPARATOR}${a.tool} ${preview(canonicalJson(a.args))}`;
}

const PREVIEW_CHARS = 300;
function preview(json: string): string {
  return json.length <= PREVIEW_CHARS ? json : `${json.slice(0, PREVIEW_CHARS)}... (${json.length} characters; "approvals show <id>" prints all of it)`;
}
