// The gateway config file, for example gateway.config.example.json:
//
//   {
//     "servers": [{ "name": "demo", "command": "node", "args": ["server.js"] }],
//     "policy": "policy.example.json",
//     "stateDir": ".agent-gate"
//   }
//
// Optional fields: "approvalTtlHours" (default 24), "auditArguments" (default false), and per
// server "env" (extra environment variables; a downstream server otherwise gets only the SDK's
// short list of safe variables such as PATH and HOME, not the gateway's whole environment).
// Relative "policy" and "stateDir" paths are resolved against the config file's directory.
// "command" and "args" are passed to the downstream process unchanged.

import * as fs from "node:fs";
import * as path from "node:path";
import { parsePolicy, type Policy } from "./policy.js";
import { array, ConfigError, fail, object, onlyKeys, text } from "./validate.js";

export interface ServerConfig {
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
}

export interface GatewayConfig {
  servers: ServerConfig[];
  policyFile: string;
  stateDir: string;
  approvalTtlMs: number;
  auditArguments: boolean;
}

export const DEFAULT_APPROVAL_TTL_HOURS = 24;

// Tools are published as "<server>__<tool>" and split again at the first "__", so a server name
// must not contain "__" or start or end with "_".
const SERVER_NAME = /^[A-Za-z0-9-]+(?:_[A-Za-z0-9-]+)*$/;

export function loadConfig(file: string): GatewayConfig {
  const absolute = path.resolve(file);
  return parseConfig(readJson(absolute, "config"), path.dirname(absolute));
}

export function loadPolicy(file: string): Policy {
  return parsePolicy(readJson(file, "policy"));
}

export function parseConfig(json: unknown, baseDir: string): GatewayConfig {
  const config = object(json, "config");
  onlyKeys(config, ["servers", "policy", "stateDir", "approvalTtlHours", "auditArguments"], "config");

  const servers = array(config.servers, "config.servers").map((raw, i) => server(raw, `config.servers[${i}]`));
  if (servers.length === 0) fail("config.servers must list at least one server");
  const names = new Set<string>();
  for (const s of servers) {
    if (names.has(s.name)) fail(`config.servers: the name "${s.name}" is used twice`);
    names.add(s.name);
  }

  const hours = config.approvalTtlHours ?? DEFAULT_APPROVAL_TTL_HOURS;
  if (typeof hours !== "number" || !Number.isFinite(hours) || hours <= 0) fail("config.approvalTtlHours must be a positive number");
  const auditArguments = config.auditArguments ?? false;
  if (typeof auditArguments !== "boolean") fail("config.auditArguments must be true or false");

  return {
    servers,
    policyFile: path.resolve(baseDir, text(config.policy, "config.policy")),
    stateDir: path.resolve(baseDir, text(config.stateDir, "config.stateDir")),
    approvalTtlMs: Math.round(hours * 60 * 60 * 1000),
    auditArguments,
  };
}

function server(raw: unknown, at: string): ServerConfig {
  const s = object(raw, at);
  onlyKeys(s, ["name", "command", "args", "env"], at);
  const name = text(s.name, `${at}.name`);
  if (!SERVER_NAME.test(name)) fail(`${at}.name must use letters, digits, "-" and single "_" between them (no "__")`);
  const args = array(s.args ?? [], `${at}.args`).map((arg, i) => {
    if (typeof arg !== "string") fail(`${at}.args[${i}] must be a string`);
    return arg;
  });
  const result: ServerConfig = { name, command: text(s.command, `${at}.command`), args };
  if (s.env !== undefined) {
    const env = object(s.env, `${at}.env`);
    for (const [key, value] of Object.entries(env)) {
      if (typeof value !== "string") fail(`${at}.env.${key} must be a string`);
    }
    result.env = env as Record<string, string>;
  }
  return result;
}

/** Reads and parses a JSON file; any failure is a ConfigError that names the file. */
export function readJson(file: string, what: string): unknown {
  let content: string;
  try {
    content = fs.readFileSync(file, "utf8");
  } catch (err) {
    throw new ConfigError(`cannot read the ${what} file ${file}: ${(err as Error).message}`);
  }
  try {
    return JSON.parse(content);
  } catch (err) {
    throw new ConfigError(`the ${what} file ${file} is not valid JSON: ${(err as Error).message}`);
  }
}
