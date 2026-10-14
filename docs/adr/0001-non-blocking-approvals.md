# ADR 0001: An "ask" answers at once with an error; it does not wait for the human

Status: accepted
Date: 2026-10-14

## Context

The MCP gateway's policy can decide that a tool call needs a human before it runs (`ask`). The
call arrives as a `tools/call` request from the agent's MCP client, and that client is waiting for
a response. There are two ways to bring a human in:

1. **Blocking.** Hold the request open, notify a human, wait for the answer, then forward the call
   or refuse it.
2. **Non-blocking.** Refuse the call at once with an error result that names a pending approval.
   A human approves or denies it whenever they get to it. After an approval, the agent makes the
   same call again.

## Decision

Non-blocking. On `ask`, the gateway does not forward the call. It records a pending approval in
`<stateDir>/approvals.json` and returns a tool error result (`isError: true`) that names the
approval id and tells the agent to retry the exact same call once it is approved. A human answers
with `agent-gate approvals approve <id>` or `deny <id>`. An approval is bound to the exact call
(server, tool, and a SHA-256 hash of the canonical JSON arguments) and lets that call through
once.

## Why

- **No hung tool calls.** MCP clients put timeouts on requests. The TypeScript SDK's default is
  60 seconds, and agent hosts add their own. A human answers in minutes or hours. A blocking
  gateway would either time out, which the agent sees as a transport error that says nothing
  about a human, or stall the agent's turn until the human answers.
- **The human decides asynchronously.** Nobody has to sit next to the agent. Requests wait in a
  queue, can be reviewed later or several at once, and survive a restart of the gateway, the
  agent or the terminal, because a pending approval is a record in a file, not a suspended
  request in memory.
- **The agent is told clearly.** The MCP specification asks servers to report tool errors inside
  the result with `isError`, so that the model can see them and adjust. The agent reads the reason
  and the approval id, can pass them on to its human, and knows what to do next. Any MCP client
  works; nothing in the client has to change.
- **Approvals are bound to exact arguments.** An approval does not mean "delete_file is allowed
  for a while". It means "this delete_file call, with these arguments, once". An agent cannot get
  approval for one thing and then run another: changing any argument value changes the hash and
  needs a new approval, and a used approval is gone. That also keeps a vague request ("can I clean
  up the old notes?") from being stretched to cover more than the human saw.

## Consequences

- The agent has to retry. The error text says how, and it says not to reach the same result
  another way. An agent that ignores that is a problem the policy has to catch elsewhere, as with
  any refusal.
- The agent cannot see when the human answers; it finds out by retrying. An early retry costs
  nothing: it gets the same approval id back, and no second request is queued.
- An approval is used up before the call is forwarded. A call that then fails downstream needs a
  new approval. This is at most once, not exactly once, and that is the safe side.
- Denials stick. Repeating a denied call is answered with "a human denied this exact call" and
  queues nothing, until the denial expires, so an agent cannot wear a human down by asking again.
- The approval id is visible to the agent. The id alone cannot approve anything; that takes the
  CLI and write access to the state directory. An agent that has its own shell outside the gateway
  could run the CLI, which is why the state directory has to be out of its reach (see the README).
- Every request has a lifetime (`approvalTtlHours`, default 24). An approval granted long after
  the request was made does not stay usable indefinitely.

## Alternatives considered

- **Blocking with a timeout.** It has every problem above, and a timeout shorter than a human's
  response time turns most asks into failures.
- **MCP elicitation** (`elicitation/create`). The server can ask the user a question through the
  client in the middle of a call. That still holds the call open, works only with clients that
  support elicitation, and asks whoever is at the agent's client, through the same host process the
  agent runs in. It could be added later as a fast path when a client supports it, with the queue
  kept as the fallback.
- **The client's own permission prompt** (for example, Claude Code asking before an MCP tool runs).
  It depends on the client, usually works per tool rather than per set of arguments, and is not
  there for an agent running headless.
