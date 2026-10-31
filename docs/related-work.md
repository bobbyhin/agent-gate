# Related work

What the tools around agent-gate already do, and where agent-gate differs. Every statement about
another product links the page it comes from; all of them were read on 2026-10-31. Products change
quickly, so check a page before quoting it. Nothing here was benchmarked: this is a comparison of what
each project documents, not of how well it works.

## MCP gateways: Docker MCP Gateway

[Docker MCP Gateway](https://github.com/docker/mcp-gateway) is open source (MIT), the gateway behind
Docker's MCP Toolkit. [docs.docker.com](https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/)
also describes it as part of a Docker AI Governance offering that it labels invite-only.

| | agent-gate MCP gateway | Docker MCP Gateway |
| --- | --- | --- |
| Where servers run | Starts local servers as ordinary processes (stdio) or reaches remote ones (Streamable HTTP). It isolates nothing. | Runs each local catalog server in its own container, with `no-new-privileges` and CPU and memory limits; network egress is not denied by default (`--block-network`, per-server `allowHosts`, `disableNetwork`). [security model](https://github.com/docker/mcp-gateway/blob/main/docs/security.md) |
| Which tools the agent sees | Per-server `expose` globs; tools the policy blocks whatever the arguments; a tool whose definition changed since it was pinned is withheld. | `--servers`, `--tools server:tool` and profiles choose among a catalog of [300+ verified servers](https://docs.docker.com/ai/mcp-catalog-and-toolkit/catalog/). |
| Deciding a call | A policy in JSON: allow, warn, ask or block from the tool's name and its arguments, a shell rule that runs the command analyzer, rewrite rules, loop limits. | [Interceptors](https://github.com/docker/mcp-gateway/blob/main/examples/interceptors/README.md): your own script, container or HTTP service before or after a call, which can return its own response or rewrite the result. There is no policy language. |
| A human in the loop | An approval queue: a held call, a CLI that reads the call back, a yes bound to the call's arguments and used once, with a lifetime. | The documentation describes no approval step. |
| Secrets | Optional: the result guard runs the LLM gateway's leak rules over results and withholds or redacts. | `--block-secrets`, on by default, scans arguments and text results and blocks the call. |
| Supply chain | None: it trusts the commands and URLs in its config. | Verifies the signatures of Docker's own `mcp/` images by default. |
| Record | One audit line per decision, written before the call is forwarded (no line, no call), with hashes of arguments and results instead of values; `audit verify` checks the log. | `--log-calls`, on by default, logs the tool name and the shape of the arguments; OpenTelemetry metrics and traces when an endpoint is configured. |

The difference in one line: Docker's gateway is about running servers safely (containers, a catalog,
signed images) and leaves decisions to code you plug in; agent-gate is about deciding calls (a
policy, a human, a record) and leaves running servers to whatever runs them. The two answer different
questions, and could in principle be stacked, agent-gate in front of a Docker gateway as one of its
downstream servers; that has not been tried here.

## LLM gateways: LiteLLM

The [LiteLLM proxy](https://github.com/BerriAI/litellm) is MIT-licensed outside its `enterprise/`
directory, whose features need a commercial license
([LICENSE](https://github.com/BerriAI/litellm/blob/main/LICENSE)).

| | agent-gate LLM gateway | LiteLLM proxy |
| --- | --- | --- |
| Scope | One endpoint, `POST /v1/chat/completions`, to upstreams that already speak the OpenAI format; no streaming. | Many providers and endpoints; it translates between provider APIs. |
| Budgets | Daily and monthly caps per key; a call reserves its estimate first and settles the real cost after, so calls in flight cannot pass a cap together; one host, one file. | `max_budget` and `budget_duration` per key, team and user, enforced against spend read from its database (Postgres); some kinds, such as per-model budgets, are Enterprise. [docs](https://docs.litellm.ai/docs/proxy/users) |
| Rate and loop limits | `maxCallsPerMinute` per key; `runMaxCalls` and `runMaxUsd` per run (`x-run-id`). | `rpm_limit`, `tpm_limit` and `max_parallel_requests` per key, team and user. |
| When an upstream fails | 5xx and timeouts are retried, then the fallback; a 429 goes to the fallback at once, or waits once (capped) for `Retry-After`. | Retries (`num_retries`, a retry policy per error type), then fallbacks, which also cover 429s; deployments cool down after a 429. [docs](https://docs.litellm.ai/docs/proxy/reliability) |
| Secret and content checks | A leak guard of regex rules, block or redact, on the request and on the answer; no other service needed. | Guardrails before, during and after the call; PII masking with Presidio (open source, needs Presidio services); secret detection is Enterprise. [docs](https://docs.litellm.ai/docs/proxy/guardrails/quick_start) |
| Metrics and traces | `GET /metrics` in the Prometheus text format; W3C trace ids in the usage log, and the gateway's own span sent upstream (`sendTraceparent` turns that off). | Prometheus metrics ([its feature list](https://www.litellm.ai/features) puts them under Enterprise; [its docs page](https://docs.litellm.ai/docs/proxy/prometheus) does not mark them); OpenTelemetry spans; an inbound `traceparent` is honoured, and sending it on to providers is opt-in, with a warning that some providers' calls can then fail. [docs](https://docs.litellm.ai/docs/proxy/logging) |

LiteLLM covers far more providers and deployment shapes. What agent-gate adds on this side is small and
specific: the reserve-then-settle ledger ([ADR 0002](adr/0002-reserve-then-settle-budgets.md)), the same
leak rules on both sides of a call with no extra service, and per-run stop rules. It could sit in front
of a LiteLLM proxy as one of its upstreams; that has not been tried here either.

## Approval models: what a "yes" covers

| | What one yes covers | For how long | Where it is kept |
| --- | --- | --- | --- |
| [Claude Code permissions](https://code.claude.com/docs/en/permissions) | A tool, or a tool and a pattern: `Bash(npm run test *)`, `WebFetch(domain:example.com)`. "Yes, and don't ask again" for a shell command saves a rule for that command prefix. | For shell commands and web domains, permanently for the repository; for file edits, until the session ends. | `.claude/settings.local.json`; decisions can be exported as OpenTelemetry events (`claude_code.tool_decision`), opt-in. |
| [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/human_in_the_loop/) | `needs_approval` (true, or a function of the arguments) pauses the run; `approve()` lets that call through; `always_approve` lets the tool through for the rest of the run. | One call, or the rest of the run. | In the application: the SDK returns a run state to store and resume; it has no queue or approval UI of its own. |
| [Antigravity](https://antigravity.google/docs/permissions/) | Allow, ask and deny rules such as `command(prefix)` and `mcp(server/tool)`. In the CLI, "always allow" is bound to a command prefix. | This conversation, or saved to the settings file. | Settings. |
| [Google Cloud Data Agent Kit](https://docs.cloud.google.com/data-agent-kit) | No approval step of its own: it relies on the host agent's prompts and on IAM. | | |
| agent-gate (one call) | One exact call: the server, the tool and the SHA-256 of the arguments, and with `fileBinding` the hashes of the files it names. It runs once. | `approvalTtlHours` (24 by default), or the rule's `ttlMinutes`. | `<stateDir>/approvals.json` (mode 0600), plus an append-only audit line for the request, the decision (who, how they confirmed) and the call. |
| agent-gate (standing) | A bounded set of calls to one tool: argument globs, at most 100 uses, only for rules that allow it ([ADR 0006](adr/0006-standing-approvals.md)). | At most 168 hours. | The same files. |

**The gap agent-gate closes.** A yes bound to a tool name or to a command prefix also covers calls the
human never saw: `git push` approved once covers every later push, `mcp(server/tool)` every argument
the tool can take. agent-gate binds the yes to the call that was read back to the human, spends it
once, lets it expire, and records who said yes and when; the confirmation happens out of band, at the
CLI, not in the chat the model reads ([ADR 0005](adr/0005-approvals-are-action-tokens.md)). Claude
Code's documentation says the same about its own rules from the other side: a deny or ask rule "isn't
a security boundary around the program", because `/bin/rm` or `bash -c` gets past a rule on `rm`.
agent-gate's shell guard reads the command line itself, which catches more of those, but it is a
heuristic reader too, not a sandbox (see [Known limits](../README.md#known-limits)).

**The price, and approval fatigue.** Exact-call approvals mean more questions, and a person who is
asked about everything learns to say yes without reading. That is an observation from using such
tools, not something this repository has measured. The answers here are to ask less (allow and warn
rules for what is known to be safe, rewrite rules that make a call safe instead of asking, loop limits
that ask only when something repeats), to make each question quicker to answer well (the read-back,
every rule that matched, which agent asked), and standing approvals for frequent, lower-risk calls.
