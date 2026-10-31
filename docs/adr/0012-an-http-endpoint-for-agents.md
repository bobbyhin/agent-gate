# ADR 0012: An HTTP endpoint for agents, each known by its key

Status: accepted (the endpoint); deploying it is not done
Date: 2026-10-31

## Context

Over stdio, an MCP gateway process serves exactly one client: the agent that started it. That fits one
person's coding agent. It does not fit a gateway that several agents share, which is the usual shape
of an "MCP gateway" on an agent platform: agents run elsewhere (a CI job, a worker, another team's
service), they reach their tools over the network, and they should not all have the same rights. A
research agent may read; a release agent may also ask to deploy.

Three things are needed for that: a network transport, an identity for each caller, and a way to give
each identity its own policy and its own set of tools, without losing what the stdio gateway already
guarantees (an audit line before every call, approvals bound to one exact call and used once).

## Decision

`agent-gate serve --http` listens on Streamable HTTP, the MCP transport for remote servers, at `/mcp`
(`src/gateway/http-server.ts`), with the agents listed in the config's `http` section.

- **An agent is its key.** Each agent has a name and the SHA-256 of its key; the key itself is never
  in the config. Every request needs `Authorization: Bearer <key>`, looked up by its hash, as the LLM
  gateway does with its keys. No key or an unknown one gets 401 and opens nothing.
- **Each agent has its own policy file and profile.** The policy decides its calls; the profile
  (config `profiles`, built for `serve --profile`) decides which tools it sees and may call.
- **One SDK `Server` per MCP session**, with its own `connId` and call numbers in the audit log,
  in front of downstream servers that are connected once and shared (`createCore` in
  `src/gateway/server.ts`; the stdio gateway is the same core with one session).
- **A session belongs to the agent that opened it.** A request with another agent's session id gets
  the same 404 as an unknown id: a session id is not a key.
- **Approvals are bound to the agent.** An approval is for one exact call (ADR 0005) *from one agent*:
  another agent's identical call asks anew, and the approval record, the card the human reads and the
  `approval-decided` line all name the agent. A standing approval (ADR 0006) covers the agent named
  with `approvals grant --agent`, or, naming none, only calls with no agent (the stdio gateway).
  `audit verify` fails a call that ran under another agent's approval or grant.
- **Every call line names the agent** (`"agent": "builder"`) and, when there is one, the profile.
- **Loopback by default, and a Host check.** The listener binds 127.0.0.1 unless the config says
  otherwise. Every request's `Host` header must be one of the listener's own names (all loopback
  spellings for a loopback address) or of `http.allowedHosts`, which a non-loopback address must list;
  an `Origin` header, when present, must name one of them too. That stops DNS rebinding, a web page
  that gets a browser to send requests to a port on 127.0.0.1. It is done before the SDK's transport
  sees the request (the SDK's own options for it are deprecated in favour of such a check).
- **One JSON answer per request** (`enableJsonResponse`): the gateway relays no progress
  notifications or server-to-client requests, so there is nothing to stream.
- **Sessions live in memory**, and one a client left open is closed after `sessionIdleMinutes`
  (default 60). The state directory is shared, so ADR 0003 still holds: one gateway process per state
  directory.

## Why

- **The key is the identity; the client's claims are not.** The correlation ids a client sends in
  `_meta` (an agent path, a session, a run; see ADR 0007 and `src/gateway/context.ts`) are what it says
  about itself, checked for format only. An
  approval has to be bound to something the agent cannot claim, or one agent could spend another's
  yes by repeating its call. The key is that thing.
- **The gateway's guarantees stay where they were.** Decisions are the same code path as over stdio
  (the same `decide()`), so every guarantee the tests prove for stdio holds per session: no line, no
  call; a block is never forwarded; an approval runs one call once.
- **A wrong Host is cheap to refuse and expensive to allow.** A local listener with a bearer key is
  already hard to reach from a browser, but the check costs one comparison and closes the whole class.

## Consequences

- Plain HTTP and static keys. Put a TLS proxy in front for anything beyond this machine, and rotate a
  key by replacing its hash in the config and restarting. There is no OAuth flow.
- A restart ends every session; MCP clients start a new one with `initialize`.
- The human still answers at the CLI, next to the state directory. That is fine on one host. It is
  the open question of a remote deployment (below).
- `test/gateway/http-endpoint.test.ts` runs everything on 127.0.0.1 with keys made at run time: two
  agents under different policies and profiles, 401 without or with a wrong key, 403 for another Host
  or Origin, 404 for another agent's session, an approval that one agent cannot use for another, and
  `audit verify` passing on the whole log. The idle-session sweep has no test of its own.

## What deploying it would take (not done)

Running this on Cloud Run, next to the LLM gateway's Terraform, is a deploy and a bill, so it waits for
a person to decide. What it would need, from what this repository already has:

- The image's command would be `serve --http`, listening on `0.0.0.0` with `allowedHosts` set to the
  service's host name, and the agents' key hashes and policies in the config (hashes are not
  secrets; the policies are files, as for the LLM gateway).
- At most one instance and the state directory on a Cloud Storage volume, as the LLM gateway does
  (ADR 0003, with the same caveat: Cloud Storage FUSE has no file locking, and a brief overlap of two
  instances can lose a write).
- Downstream stdio servers would run inside the container; remote ones need their headers from
  Secret Manager.
- **The human's answer.** Today a human approves with the CLI on the machine that holds the state
  directory. A remote deployment needs another way: an admin endpoint with a key of its own, or the
  CLI run against the mounted bucket. That is a design decision of its own, and it is not made here.
