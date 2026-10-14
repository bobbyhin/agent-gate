// Routing: which upstream, and which model there, serves a chat completion request.
//
// Routes are tried in order. A route applies when every condition in its "when" matches (the
// requested model alias and the x-agent-task header) AND its upstream offers the alias it would
// use: the route's fixed "model", or else the alias the client asked for. The first route that
// applies decides; when none does, the request is refused (400). That last condition is what lets
// a route without "when" mean "any alias this upstream offers".
//
// route() is a pure function of the config and the request: no I/O, no clock, no randomness.

import type { LlmConfig, Target, Upstream } from "./config.js";

export interface RouteRequest {
  /** The "model" field of the request: an alias, not a provider's model name. */
  model: string;
  /** The x-agent-task header, if the client sent one. */
  task?: string;
}

export interface ResolvedTarget {
  upstream: Upstream;
  alias: string;
  /** The model name sent to the upstream. */
  model: string;
}

export interface Route {
  /** The id of the route rule that decided. */
  rule: string;
  primary: ResolvedTarget;
  /**
   * Tried when the primary fails with a 5xx or a timeout. Left out when the rule has none, or
   * when the fallback upstream does not offer the alias in use (only possible when the rule takes
   * the alias from the request; a fixed alias is checked when the config is loaded).
   */
  fallback?: ResolvedTarget;
}

export function route(config: Pick<LlmConfig, "routes" | "upstreams">, request: RouteRequest): Route | undefined {
  for (const rule of config.routes) {
    if (rule.model && !rule.model(request.model)) continue;
    if (rule.task && (request.task === undefined || !rule.task(request.task))) continue;
    const primary = resolve(config.upstreams, rule.use, request.model);
    if (!primary) continue;
    const fallback = rule.fallback && resolve(config.upstreams, rule.fallback, primary.alias);
    return fallback ? { rule: rule.id, primary, fallback } : { rule: rule.id, primary };
  }
  return undefined;
}

function resolve(upstreams: ReadonlyMap<string, Upstream>, target: Target, requested: string): ResolvedTarget | undefined {
  const upstream = upstreams.get(target.upstream);
  const alias = target.model ?? requested;
  const model = upstream?.models.get(alias);
  return upstream && model !== undefined ? { upstream, alias, model } : undefined;
}
