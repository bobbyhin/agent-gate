// The gateway config file, for example gateway.config.example.json:
//
//   {
//     "servers": [{ "name": "demo", "command": "node", "args": ["server.js"] },
//                 { "name": "docs", "url": "https://mcp.example.com/mcp", "headersFromEnv": { "Authorization": "DOCS_MCP_AUTH" } }],
//     "policy": "policy.example.json",
//     "stateDir": ".agent-gate"
//   }
//
// Optional fields: "approvalTtlHours" (default 24), "auditArguments" (default false), "pinTools"
// (default true: pin tool definitions, see src/gateway/tool-pins.ts), per server "expose" (globs of
// the tool names the agent may see and call; the others are hidden and blocked),
// "resultGuard" ({ "leakPolicy": "<file>", "flagInstructions": true }: what a tool's result may carry
// back to the model, see src/gateway/result-guard.ts),
// "fileBinding" ({ "roots": [...], "arguments": [...] }: bind approvals to the content of the files
// those arguments name, see src/gateway/files.ts), and per server "env" (extra environment
// variables; a downstream server otherwise gets only the SDK's short list of safe variables such as
// PATH and HOME, not the gateway's whole environment).
// Relative "policy", "stateDir" and fileBinding roots are resolved against the config file's directory.
// "command" and "args" are passed to the downstream process unchanged. A server with "url" instead is
// reached over Streamable HTTP; "headersFromEnv" names, for each header, the environment variable
// that holds its value, so no token is ever in this file. Plain http:// is accepted only for a
// server on this machine. "timeoutSeconds" (default 60) bounds each request to a server.
// "profiles" ({ "<name>": { "<server>": ["glob", ...] } }) are named sets of tools: a connection that
// runs with a profile (serve --profile <name>) sees and may call only the tools its globs match, on the
// servers it names, on top of each server's "expose".

import * as fs from "node:fs";
import * as path from "node:path";
import type { FileBindingConfig } from "./files.js";
import { parsePolicy, type Policy } from "./policy.js";
import { array, ConfigError, fail, integerIn, object, onlyKeys, text } from "./validate.js";

export interface ServerConfig {
  name: string;
  /** stdio: the command that starts the server (absent for a server with a url). */
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  /** Streamable HTTP: the server's endpoint, and header name to the environment variable that holds its value. */
  url?: string;
  headersFromEnv?: Record<string, string>;
  /** How long one request to this server may take (timeoutSeconds). Absent: the SDK's 60 seconds. */
  timeoutMs?: number;
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
  /** Read results: withhold or redact secrets (leak-guard rules) and flag instruction-like text. */
  resultGuard?: { leakPolicyFile?: string; flagInstructions: boolean };
  fileBinding?: FileBindingConfig;
  /** Profile name -> server name -> globs of the tool names a connection with that profile may see and call. */
  profiles?: ReadonlyMap<string, ReadonlyMap<string, string[]>>;
}

export const DEFAULT_APPROVAL_TTL_HOURS = 24;

/** A profile's or an HTTP agent's name: it goes into the audit log, so it is kept plain. */
export const PLAIN_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

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
  onlyKeys(config, ["servers", "policy", "stateDir", "approvalTtlHours", "auditArguments", "pinTools", "resultGuard", "fileBinding", "profiles"], "config");

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
    ...(config.resultGuard === undefined ? {} : { resultGuard: resultGuard(config.resultGuard, baseDir) }),
    ...(config.fileBinding === undefined ? {} : { fileBinding: fileBinding(config.fileBinding, baseDir) }),
    ...(config.profiles === undefined ? {} : { profiles: profiles(config.profiles, names) }),
  };
}

/** { "<profile>": { "<server>": ["glob", ...] } }: a server the profile does not name shows it nothing. */
function profiles(raw: unknown, servers: ReadonlySet<string>): Map<string, Map<string, string[]>> {
  const at = "config.profiles";
  const result = new Map<string, Map<string, string[]>>();
  for (const [name, value] of Object.entries(object(raw, at))) {
    if (!PLAIN_NAME.test(name)) fail(`${at} has a profile name that is not valid: ${JSON.stringify(name)} (1 to 64 letters, digits, ".", "_" or "-")`);
    const perServer = new Map<string, string[]>();
    for (const [server, globs] of Object.entries(object(value, `${at}.${name}`))) {
      if (!servers.has(server)) fail(`${at}.${name} names "${server}", which is not one of the servers`);
      const list = array(globs, `${at}.${name}.${server}`).map((glob, i) => text(glob, `${at}.${name}.${server}[${i}]`));
      if (list.length === 0) fail(`${at}.${name}.${server} must list at least one glob; leave the server out to show none of its tools`);
      perServer.set(server, list);
    }
    if (perServer.size === 0) fail(`${at}.${name} must name at least one server`);
    result.set(name, perServer);
  }
  if (result.size === 0) fail(`${at} must define at least one profile; leave it out to have none`);
  return result;
}

function resultGuard(raw: unknown, baseDir: string): { leakPolicyFile?: string; flagInstructions: boolean } {
  const at = "config.resultGuard";
  const spec = object(raw, at);
  onlyKeys(spec, ["leakPolicy", "flagInstructions"], at);
  const flagInstructions = spec.flagInstructions ?? true;
  if (typeof flagInstructions !== "boolean") fail(`${at}.flagInstructions must be true or false`);
  if (spec.leakPolicy === undefined && !flagInstructions) fail(`${at} with no leakPolicy and flagInstructions false would do nothing`);
  return { ...(spec.leakPolicy === undefined ? {} : { leakPolicyFile: path.resolve(baseDir, text(spec.leakPolicy, `${at}.leakPolicy`)) }), flagInstructions };
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

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;

function server(raw: unknown, at: string): ServerConfig {
  const s = object(raw, at);
  onlyKeys(s, ["name", "command", "args", "env", "url", "headersFromEnv", "timeoutSeconds", "expose"], at);
  const name = text(s.name, `${at}.name`);
  if (!SERVER_NAME.test(name)) fail(`${at}.name must use letters, digits, "-" and single "_" between them (no "__")`);
  if (s.url !== undefined && (s.command !== undefined || s.args !== undefined || s.env !== undefined)) fail(`${at} has both "url" and a command; a server is either local (command) or remote (url)`);
  const result: ServerConfig = s.url !== undefined ? remote(s, at, name) : { name, ...local(s, at) };
  if (s.timeoutSeconds !== undefined) result.timeoutMs = integerIn(s.timeoutSeconds, `${at}.timeoutSeconds`, 1, 3600) * 1000;
  if (s.expose !== undefined) {
    const expose = array(s.expose, `${at}.expose`).map((glob, i) => text(glob, `${at}.expose[${i}]`));
    if (expose.length === 0) fail(`${at}.expose must list at least one glob; leave it out to expose every tool`);
    result.expose = expose;
  }
  return result;
}

function local(s: Record<string, unknown>, at: string): { command: string; args: string[]; env?: Record<string, string> } {
  const args = array(s.args ?? [], `${at}.args`).map((arg, i) => {
    if (typeof arg !== "string") fail(`${at}.args[${i}] must be a string`);
    return arg;
  });
  if (s.command === undefined) fail(`${at} needs "command" (a local server, over stdio) or "url" (a remote one, over Streamable HTTP)`);
  const result: { command: string; args: string[]; env?: Record<string, string> } = { command: text(s.command, `${at}.command`), args };
  if (s.env !== undefined) {
    const env = object(s.env, `${at}.env`);
    for (const [key, value] of Object.entries(env)) {
      if (typeof value !== "string") fail(`${at}.env.${key} must be a string`);
    }
    result.env = env as Record<string, string>;
  }
  return result;
}

function remote(s: Record<string, unknown>, at: string, name: string): ServerConfig {
  let url: URL;
  try {
    url = new URL(text(s.url, `${at}.url`));
  } catch (err) {
    if (err instanceof ConfigError) throw err;
    return fail(`${at}.url is not a valid URL`);
  }
  if (url.username || url.password) fail(`${at}.url must not contain credentials; put them in a header with headersFromEnv`);
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const local = host === "localhost" || host === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) fail(`${at}.url must use https:// (plain http:// only for a server on this machine)`);
  const result: ServerConfig = { name, url: url.toString() };
  if (s.headersFromEnv !== undefined) {
    const headers = object(s.headersFromEnv, `${at}.headersFromEnv`);
    for (const [header, variable] of Object.entries(headers)) {
      if (!HEADER_NAME.test(header)) fail(`${at}.headersFromEnv has a header name that is not valid: ${JSON.stringify(header)}`);
      if (typeof variable !== "string" || !ENV_NAME.test(variable)) fail(`${at}.headersFromEnv.${header} must name an environment variable, such as DOCS_MCP_AUTH`);
    }
    result.headersFromEnv = headers as Record<string, string>;
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
