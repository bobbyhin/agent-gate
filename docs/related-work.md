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
| Scope | One endpoint, `POST /v1/chat/completions` (streamed or not), to upstreams that already speak the OpenAI format. | Many providers and endpoints, streaming included; it translates between provider APIs. [docs](https://docs.litellm.ai/docs/completion/stream) |
| Budgets | Daily and monthly caps per key; a call reserves its estimate first and settles the real cost after, so calls in flight cannot pass a cap together; one host, one file. | `max_budget` and `budget_duration` per key, team and user, enforced against spend read from its database (Postgres); some kinds, such as per-model budgets, are Enterprise. [docs](https://docs.litellm.ai/docs/proxy/users) |
| Rate and loop limits | `maxCallsPerMinute` and `repeatMax` (the same request sent again and again) per key; `runMaxCalls` and `runMaxUsd` per run (`x-run-id`). | `rpm_limit`, `tpm_limit` and `max_parallel_requests` per key, team and user. |
| When an upstream fails | 5xx answers, a 408 and timeouts are retried after a random wait up to a cap ([ADR 0010](adr/0010-retries.md)), then the fallback; a 429 goes to the fallback at once, or waits once (capped) for `Retry-After`. | Retries (`num_retries`, a retry policy per error type), then fallbacks, which also cover 429s; deployments cool down after a 429. [docs](https://docs.litellm.ai/docs/proxy/reliability) |
| Secret and content checks | A leak guard of regex rules, block or redact, on the request and on the answer, with checksum validators for card numbers, Japan's My Number and US SSNs and ITINs; `divert` sends calls that match chosen rules to a local model instead; no other service needed. | Guardrails before, during and after the call; PII masking with Presidio (open source, needs Presidio services); secret detection is Enterprise. [docs](https://docs.litellm.ai/docs/proxy/guardrails/quick_start) |
| Metrics and traces | `GET /metrics` in the Prometheus text format; W3C trace ids in the usage log, and the gateway's own span sent upstream (`sendTraceparent` turns that off). | Prometheus metrics ([its feature list](https://www.litellm.ai/features) puts them under Enterprise; [its docs page](https://docs.litellm.ai/docs/proxy/prometheus) does not mark them); OpenTelemetry spans; an inbound `traceparent` is honoured, and sending it on to providers is opt-in, with a warning that some providers' calls can then fail. [docs](https://docs.litellm.ai/docs/proxy/logging) |
| Streamed answers | Held until the leak guard has read the whole answer (the default), or relayed as they come and not read (`"scanResponses": false`); the usage chunk is always asked for, and a stream cut short is booked at its estimate ([ADR 0011](adr/0011-streaming.md)). | Depends on the guardrail: a `post_call` guardrail built on the event hooks runs on the assembled answer after every chunk reached the client, so on a stream it can log but not block; guardrails that implement `apply_guardrail` (Bedrock, for example) hold the stream until it passes; a separate hook filters chunks as they arrive, and `stream_holdback_chars` keeps a match from being split between two chunks. [custom guardrails](https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail), [Bedrock](https://docs.litellm.ai/docs/proxy/guardrails/bedrock). `always_include_stream_usage` (off by default) asks for usage on every streamed request. [docs](https://docs.litellm.ai/docs/completion/usage) |

LiteLLM covers far more providers and deployment shapes. What agent-gate adds on this side is small and
specific: the reserve-then-settle ledger ([ADR 0002](adr/0002-reserve-then-settle-budgets.md)), the same
leak rules on both sides of a call with no extra service, streamed answers held until those rules have
read them, and per-run stop rules. It could sit in front
of a LiteLLM proxy as one of its upstreams; that has not been tried here either.

## A managed platform: Google's Gemini Enterprise Agent Platform

Google Cloud's agent platform is [Gemini Enterprise Agent Platform](https://docs.cloud.google.com/gemini-enterprise-agent-platform/overview), which its documentation
calls "an evolution of Vertex AI"; Vertex AI and Agent Builder became part of it on 22 April 2026, and
Agent Engine was renamed Agent Runtime ([release notes](https://docs.cloud.google.com/gemini-enterprise-agent-platform/release-notes)). Its features are grouped in
four pillars, Build, Scale, Govern and Optimize. The Govern pillar is the one that does what agent-gate
does: [Agent Gateway, policies and Agent Registry](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern).

| | agent-gate | Gemini Enterprise Agent Platform, Govern |
| --- | --- | --- |
| Where calls are checked | A hook in Claude Code, an MCP gateway between an agent and its tool servers, and an LLM gateway between an agent and its model providers, all run by you, on one host. | [Agent Gateway](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/agent-gateway-overview), "the main entry and exit point" for an agent's traffic to tools, other agents and [its model](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/semantic-governance-overview). It is generally available as a Google-managed gateway for agents on Agent Runtime and Gemini Enterprise; for GKE, Cloud Run and other clouds its page says support "will be available soon through an early preview". |
| Deciding a tool call | A JSON policy on the server, the tool's name and its arguments: allow, warn, ask or block. | [IAM Unified Access Policies](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/iam-overview-uap) (generally available): allow and deny rules from an agent's identity to registered tools and servers, with everything blocked unless a policy grants it, and conditions that can name tools. The gateway reads MCP's JSON-RPC to find the tool's name ([supported protocols](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/agent-gateway-overview)). |
| A model in the decision | None at runtime ([ADR 0004](adr/0004-decisions-in-code.md)); a planned second reviewer may only make a decision stricter ([ADR 0008](adr/0008-second-reviewer-escalate-only.md)). | [Semantic governance](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/semantic-governance-overview) (Preview): rules in plain language that an LLM checks against each proposed tool call, with ALLOW or DENY as the only verdicts. Its page warns that "Verdicts may not be accurate" and that it does not support streamed model responses. |
| A human's yes for one call | An approval bound to the call's arguments (SHA-256), read back at a CLI, used once, with a lifetime. | Not described in the Govern pages read: IAM rules, Model Armor and semantic policies decide on their own. |
| A catalog of what may be called | The gateway config's servers, `expose` globs, and each tool's definition pinned in a local file ([ADR 0009](adr/0009-pin-tool-definitions.md)). | [Agent Registry](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/agent-registry) (generally available): a central catalog of approved agents, MCP servers, tools and endpoints, which the gateway checks before it allows a connection. |
| Content checks | The leak guard's regex rules on prompts, answers and, optionally, tool results; a streamed answer is held until it has been read. | [Model Armor](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/configure-model-armor) filters on the gateway (generally available) for prompts, responses and tool payloads. Its page lists what passes unscreened, including streaming chat completions (only their "non-streaming variants" are screened), "Streamable HTTP/SSE for MCP", and any payload it does not list; a payload over a filter's token limit skips that filter. |
| Budgets for model calls | Daily and monthly caps per key; each call reserves its estimate first, so calls in flight cannot pass a cap together ([ADR 0002](adr/0002-reserve-then-settle-budgets.md)); stop rules per minute, per run and for repeated requests. | [Token management policies](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/token-management-overview) (budgets per agent, API key or header, with a 429 when a pool is spent) are announced as "coming soon". The page notes that requests admitted at the same time "can exceed the limit before later requests are blocked". |
| Record | An audit line before each call (no line, no call), with hashes of arguments and results, and `audit verify`; a usage line for each model call. | [Gateway logs](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/monitor-agent-gateway) in Cloud Logging for each allow and deny decision, with the MCP method and the tool's name, and Identity-Aware Proxy decisions in Cloud Audit Logs. A dry-run mode logs what would have been denied without blocking it ([IAM policies](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/iam-overview-uap)). |

The platform and agent-gate are different sizes of the same idea: one place that every call of an agent
has to pass, where the rules live in configuration and every decision is logged. For agents hosted on
the platform, the managed gateway is where identity, network rules and content filters belong, and
agent-gate does not replace it. What the Govern pages read here do not describe, and agent-gate does, is
a human's yes for one exact call, budgets that hold calls in flight against a cap, and streamed answers
held until they are read. For agents the gateway does not cover yet, and for agents outside a cloud,
such as a coding agent on a laptop, agent-gate covers the same points itself. Putting agent-gate behind
Agent Gateway has not been tried.

Google's agent framework, ADK, has a human confirmation of its own, inside the agent (see the next
table).

## Approval models: what a "yes" covers

| | What one yes covers | For how long | Where it is kept |
| --- | --- | --- | --- |
| [Claude Code permissions](https://code.claude.com/docs/en/permissions) | A tool, or a tool and a pattern: `Bash(npm run test *)`, `WebFetch(domain:example.com)`. "Yes, and don't ask again" for a shell command saves a rule for that command prefix. | For shell commands and web domains, permanently for the repository; for file edits, until the session ends. | `.claude/settings.local.json`; decisions can be exported as OpenTelemetry events (`claude_code.tool_decision`), opt-in. |
| [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/human_in_the_loop/) | `needs_approval` (true, or a function of the arguments) pauses the run; `approve()` lets that call through; `always_approve` lets the tool through for the rest of the run. | One call, or the rest of the run. | In the application: the SDK returns a run state to store and resume; it has no queue or approval UI of its own. |
| [Antigravity](https://antigravity.google/docs/permissions/) | Allow, ask and deny rules such as `command(prefix)` and `mcp(server/tool)`. In the CLI, "always allow" is bound to a command prefix. | This conversation, or saved to the settings file. | Settings. |
| [ADK Tool Confirmation](https://adk.dev/tools-custom/confirmation/) | A tool set with `require_confirmation=True` pauses and asks a user or another system for confirmation. Marked experimental, and not supported with `DatabaseSessionService` or `VertexAiSessionService`. | The call that paused. | Inside the agent: it is a feature of the framework, not a gateway in front of it. |
| [Gemini Enterprise Agent Platform, Govern](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern) | No approval step is described in the governance pages read for this comparison: IAM rules, Model Armor and semantic policies decide on their own. | | Decisions are logged in Cloud Logging and Cloud Audit Logs. |
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
