// Prometheus metrics for the LLM gateway: GET /metrics, in the Prometheus text format (0.0.4).
//
//   agent_gate_llm_requests_total{route,upstream,status}   counter  authenticated chat completion calls
//   agent_gate_llm_tokens_total{direction}                 counter  input and output tokens booked
//   agent_gate_llm_cost_usd_total                           counter  US dollars booked
//   agent_gate_llm_request_duration_seconds                histogram time from request to answer
//   agent_gate_llm_budget_remaining_usd{key,cap}           gauge    cap minus spent minus reserved
//
// The counters live in the process and start at zero when it starts, as Prometheus counters do; the
// budget gauge is read from the ledger at each scrape, so it is right across restarts. The usage log
// stays the record of each call; these are its running totals, for a dashboard and alerts.
// Who may read them is set in the config (config.ts): a key of their own on the gateway's port, or a
// listener of their own without a key, which the config only allows on a loopback address.

import type { KeyUsage } from "./budget.js";
import { roundUsd } from "./budget.js";

/** Upper bounds of the duration buckets, in seconds. */
export const DURATION_BUCKETS = [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60] as const;

export const CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";

/** What the metrics need from one usage line. */
export interface Observation {
  route?: string;
  upstream?: string;
  status: number;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  latencyMs: number;
}

export class Metrics {
  private readonly requests = new Map<string, { route: string; upstream: string; status: string; count: number }>();
  private inputTokens = 0;
  private outputTokens = 0;
  private costUsd = 0;
  private readonly buckets = DURATION_BUCKETS.map(() => 0);
  private durationSum = 0;
  private durationCount = 0;

  record(o: Observation): void {
    const labels = { route: o.route ?? "", upstream: o.upstream ?? "", status: String(o.status) };
    const id = JSON.stringify(labels);
    const row = this.requests.get(id);
    if (row) row.count++;
    else this.requests.set(id, { ...labels, count: 1 });
    this.inputTokens += o.inputTokens;
    this.outputTokens += o.outputTokens;
    this.costUsd = roundUsd(this.costUsd + o.costUsd);
    const seconds = o.latencyMs / 1000;
    DURATION_BUCKETS.forEach((le, i) => {
      if (seconds <= le) this.buckets[i] = (this.buckets[i] ?? 0) + 1;
    });
    this.durationSum += seconds;
    this.durationCount++;
  }

  /** The text a scrape gets. `budgets` comes from the ledger, read at scrape time. */
  render(budgets: readonly KeyUsage[]): string {
    const out: string[] = [];
    const family = (name: string, type: string, help: string) => out.push(`# HELP ${name} ${help}`, `# TYPE ${name} ${type}`);

    family("agent_gate_llm_requests_total", "counter", "Authenticated chat completion requests, by route, upstream and HTTP status.");
    const rows = [...this.requests.values()].sort((a, b) => a.route.localeCompare(b.route) || a.upstream.localeCompare(b.upstream) || a.status.localeCompare(b.status));
    for (const r of rows) out.push(`agent_gate_llm_requests_total${labels({ route: r.route, upstream: r.upstream, status: r.status })} ${r.count}`);

    family("agent_gate_llm_tokens_total", "counter", "Tokens booked: input and output.");
    out.push(`agent_gate_llm_tokens_total{direction="input"} ${this.inputTokens}`, `agent_gate_llm_tokens_total{direction="output"} ${this.outputTokens}`);

    family("agent_gate_llm_cost_usd_total", "counter", "US dollars booked against the gateway keys.");
    out.push(`agent_gate_llm_cost_usd_total ${this.costUsd}`);

    family("agent_gate_llm_request_duration_seconds", "histogram", "Time from receiving a request to answering it.");
    DURATION_BUCKETS.forEach((le, i) => out.push(`agent_gate_llm_request_duration_seconds_bucket{le="${le}"} ${this.buckets[i] ?? 0}`));
    out.push(
      `agent_gate_llm_request_duration_seconds_bucket{le="+Inf"} ${this.durationCount}`,
      `agent_gate_llm_request_duration_seconds_sum ${Math.round(this.durationSum * 1e6) / 1e6}`,
      `agent_gate_llm_request_duration_seconds_count ${this.durationCount}`,
    );

    family("agent_gate_llm_budget_remaining_usd", "gauge", "What a key may still spend: its cap minus settled spend minus what calls in flight hold.");
    for (const b of budgets) {
      out.push(`agent_gate_llm_budget_remaining_usd${labels({ key: b.key, cap: "daily" })} ${remaining(b.dailyUsd, b.dayUsd, b.reservedUsd)}`);
      out.push(`agent_gate_llm_budget_remaining_usd${labels({ key: b.key, cap: "monthly" })} ${remaining(b.monthlyUsd, b.monthUsd, b.reservedUsd)}`);
    }
    return `${out.join("\n")}\n`;
  }
}

function remaining(cap: number, spent: number, reserved: number): number {
  return Math.max(0, roundUsd(cap - spent - reserved));
}

/** {name="value",...} with the text format's escapes: backslash, double quote and line feed. */
function labels(values: Record<string, string>): string {
  const pairs = Object.entries(values).map(([name, value]) => `${name}="${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n")}"`);
  return `{${pairs.join(",")}}`;
}
