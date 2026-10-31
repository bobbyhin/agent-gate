// The gateway config file, for example gateway.config.example.json:
//
//   {
//     "servers": [{ "name": "demo", "command": "node", "args": ["server.js"] }],
//     "policy": "policy.example.json",
//     "stateDir": ".agent-gate"
//   }
//
// Optional fields: "approvalTtlHours" (default 24), "auditArguments" (default false), "pinTools"
// (default true: pin tool definitions, see src/gateway/tool-pins.ts), per server "expose" (globs of
// the tool names the agent may see and call; the others are hidden and blocked),
// "fileBinding" ({ "roots": [...], "arguments": [...] }: bind approvals to the content of the files
// those arguments name, see src/gateway/files.ts), and per server "env" (extra environment
// variables; a downstream server otherwise gets only the SDK's short list of safe variables such as
// PATH and HOME, not the gateway's whole environment).
// Relative "policy", "stateDir" and fileBinding roots are resolved against the config file's directory.
// "command" and "args" are passed to the downstream process unchanged.

import * as fs from "node:fs";
import * as path from "node:path";
import type { FileBindingConfig } from "./files.js";
import { parsePolicy, type Policy } from "./policy.js";
import { array, ConfigError, fail, object, onlyKeys, text } from "./validate.js";

export interface ServerConfig {
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
  /** Globs of the tool names the agent may see and call. Absent: all of them. */
  expose?: string[];
}

export interface GatewayConfig {
  servers: ServerConfig[];
  policyFile: string;
  stateDir: string;
  approvalTtlMs: number;
  auditArguments: boolean;
  /** Pin tool definitions and withhold tools whose definition changed (default true). */
  pinTools: boolean;
  fileBinding?: FileBindingConfig;
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
  onlyKeys(config, ["servers", "policy", "stateDir", "approvalTtlHours", "auditArguments", "pinTools", "fileBinding"], "config");

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
  const pinTools = config.pinTools ?? true;
  if (typeof pinTools !== "boolean") fail("config.pinTools must be true or false");

  return {
    servers,
    policyFile: path.resolve(baseDir, text(config.policy, "config.policy")),
    stateDir: path.resolve(baseDir, text(config.stateDir, "config.stateDir")),
    approvalTtlMs: Math.round(hours * 60 * 60 * 1000),
    auditArguments,
    pinTools,
    ...(config.fileBinding === undefined ? {} : { fileBinding: fileBinding(config.fileBinding, baseDir) }),
  };
}

function fileBinding(raw: unknown, baseDir: string): FileBindingConfig {
  const at = "config.fileBinding";
  const spec = object(raw, at);
  onlyKeys(spec, ["roots", "arguments"], at);
  const list = (value: unknown, field: string): string[] => {
    const items = array(value, `${at}.${field}`).map((item, i) => text(item, `${at}.${field}[${i}]`));
    if (items.length === 0) fail(`${at}.${field} must list at least one entry`);
    return items;
  };
  // Roots are compared with real paths, so resolve their own symlinks once, here.
  const roots = list(spec.roots, "roots").map((root, i) => {
    try {
      const real = fs.realpathSync(path.resolve(baseDir, root));
      if (!fs.statSync(real).isDirectory()) fail(`${at}.roots[${i}] is not a folder: ${root}`);
      return real;
    } catch (err) {
      if (err instanceof ConfigError) throw err;
      return fail(`${at}.roots[${i}] does not exist: ${root}`);
    }
  });
  return { roots, arguments: list(spec.arguments, "arguments") };
}

function server(raw: unknown, at: string): ServerConfig {
  const s = object(raw, at);
  onlyKeys(s, ["name", "command", "args", "env", "expose"], at);
  const name = text(s.name, `${at}.name`);
  if (!SERVER_NAME.test(name)) fail(`${at}.name must use letters, digits, "-" and single "_" between them (no "__")`);
  const args = array(s.args ?? [], `${at}.args`).map((arg, i) => {
    if (typeof arg !== "string") fail(`${at}.args[${i}] must be a string`);
    return arg;
  });
  const result: ServerConfig = { name, command: text(s.command, `${at}.command`), args };
  if (s.expose !== undefined) {
    const expose = array(s.expose, `${at}.expose`).map((glob, i) => text(glob, `${at}.expose[${i}]`));
    if (expose.length === 0) fail(`${at}.expose must list at least one glob; leave it out to expose every tool`);
    result.expose = expose;
  }
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
