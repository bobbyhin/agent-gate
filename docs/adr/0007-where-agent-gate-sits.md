# ADR 0007: agent-gate is a control plane in front of model and tool calls, not a place to run agents

Status: accepted
Date: 2026-10-31

## Context

Cloud platforms offer two things an agent project might reach for. A container platform such as
Cloud Run runs a service. A managed agent runtime (Google Cloud has one in Vertex AI) runs the agent
itself: it hosts the agent's loop, keeps its sessions and long-term memory, scales it, and adds
tracing and evaluation around it. The usual comparison: an agent deployed on a container platform,
where you build the HTTP wrapper, the container, the infrastructure code, CI, health checks, tracing
and dashboards yourself, and one on a managed runtime, which gives you most of that.

agent-gate is none of those. It is the layer the calls pass through on their way out of an agent,
wherever the agent runs: the shell guard in front of the agent's shell, the MCP gateway in front of
its tools, the LLM gateway in front of its model providers. The question is which pieces of the
"everything together" list it should build, and which it should leave to the platform the agent
runs on.

## Decision

agent-gate stays a control plane: policy, approvals, budgets and the leak guard, decided in code
(ADR 0004), in front of the calls. It does not host agents, keep their sessions or memory, or run
their loop. Of the production pieces, it builds the ones a gateway needs and leaves the rest to the
platform under the agent.

## Production readiness, one page

For the LLM gateway, the one part that runs as a network service. The MCP gateway and the shell guard
run next to the agent, on its machine.

| Piece | State | Where |
| --- | --- | --- |
| HTTP service | Done: a Node HTTP server, OpenAI-compatible, with gateway keys, routing, budgets and the leak guard | `src/llm/server.ts` |
| Container image | Done: multi-stage, distroless, non-root, pinned base images | `Dockerfile` |
| Infrastructure as code | Done, not applied: Cloud Run, registry, secrets, state bucket, least-privilege service account | `deploy/terraform/`, `deploy/README.md` |
| Kubernetes manifests | Done, not applied | `deploy/k8s/` |
| CI | Done: tests on Node 20 and 22; the deploy job (Terraform tests, kubeconform, image build, compose demo) waits for them | `.github/workflows/ci.yml` |
| Health check | Done: `GET /healthz`, used by the image's `HEALTHCHECK` and the Cloud Run probes | `src/llm/server.ts:91` |
| Cost control | Done: daily and monthly caps per key, reserve then settle (ADR 0002); an optional budget alert for the cloud project | `src/llm/budget.ts`, `deploy/terraform/budget.tf` |
| Audit | Done: a usage log without prompt text; the MCP gateway's audit log | `src/llm/usage-log.ts`, `src/gateway/audit.ts` |
| Tests as a gate | Done for the guards: table tests, a held-out set with a baseline, a differential hash, crash tests | `test/`, `npm test` |
| Tracing (spans per call, across services) | Not built | |
| Metrics and dashboards | Not built: `agent-gate usage` and `approvals stats` print totals; nothing is exported | `src/gateway/cli.ts` |
| Running in a real project | Not done: checked, never deployed (a deploy costs money and waits for its owner) | `deploy/README.md`, "What was checked" |
| Sessions, memory, the agent's loop, evaluation of the agent's answers | Not this project's job | |

## What it will not build, and why

- **Agent hosting, sessions and memory.** That is the runtime's job, and agent-gate has to work for
  agents that run anywhere: a coding agent on a laptop, a service on Cloud Run, a managed runtime.
  If it hosted the agent, it would also be the thing it is meant to check.
- **Evaluation of the agent's work** (trajectories, answer quality, LLM judges). agent-gate evaluates
  its own rules (the tables, the held-out set), not the agent's answers.

## What is next, if the gateway is deployed for real

- **Tracing.** One span per call, with the decision, the rule, the upstream and the cost, so a slow or
  refused call can be followed from the agent to the provider. OpenTelemetry would let it join the
  agent's own traces.
- **Metrics.** Calls, refusals, spend against the caps and approval waits, exported for a dashboard
  instead of printed by the CLI.

## Consequences

- A team that runs agents on a managed runtime keeps it for hosting, sessions and evaluation, and puts
  agent-gate in front of the calls those agents make. The two do not overlap.
- Until tracing and metrics exist, the only views are the logs and the CLI.
- The production pieces that exist have been validated without credentials (Terraform tests with a
  mocked provider, kubeconform, image checks in CI), not run in a real project.
