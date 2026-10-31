# ADR 0009: Pin tool definitions, and withhold a tool whose definition changes

Status: accepted
Date: 2026-10-31

## Context

The model chooses its calls from what `tools/list` tells it. The policy decides each call from the
tool's name and arguments, but the words the model reads about a tool (its description, its schema)
are written by the downstream server, and the server can change them at any time: an update, a
server that turns hostile after it was trusted (a "rug pull"), or a description that carries
instructions for the model (tool poisoning). Until this change the gateway relayed whatever a server
listed, every time it listed it. A rule, an approval or a human's habit formed around a tool as it
looked last week said nothing about the tool as it looks now.

## Decision

- **Pin.** The first time the gateway lists a tool, it stores a SHA-256 of the canonical JSON (object
  keys sorted) of what the model reads about it: name, title, description, input schema, output schema
  and annotations. Pins are kept per server in `<stateDir>/tools.json`, with the same lock and atomic
  write as the approval queue (`src/gateway/tool-pins.ts`). Pinning is on by default;
  `"pinTools": false` in the gateway config turns it off.
- **Withhold a change.** When a later listing gives a different hash, the tool is marked changed. It
  is left out of `tools/list`, so the model never reads the new text. A call to it (from an agent that
  remembers the name) is asked about with the rule `tool-changed` when the policy would have let it
  run unattended; a call the policy blocks or asks about keeps that decision.
- **A human decides.** `agent-gate tools show <server>__<tool>` prints both definitions;
  `agent-gate tools accept <server>__<tool>` makes the new one the pin and records who accepted it.
  A definition that goes back to the pinned one is listed again, and a second, different change
  replaces the first one that was waiting.
- **Recorded.** The audit log gets a `tool-pinned`, `tool-changed` (with both hashes) or
  `tool-accepted` (with the OS user) line. The example policy's `no-self-approval` rule blocks an
  agent that runs `tools accept` through a shell tool.
- **Fail closed.** A damaged `tools.json` is an error: that server's tools are not listed and calls
  to them are not run. An empty file in its place would trust every tool anew.
- A tool that a listing leaves out keeps its pin. When it comes back unchanged, it is listed with no
  new pin; when it comes back changed, it is withheld. A call that names a tool the gateway has not
  listed yet makes it list that server first, so a first call is checked against a pin too.

`test/gateway/tool-pins.test.ts` covers the store (each pinned field, a tool that disappears and comes
back, a change undone, accepting, a damaged file); `test/gateway/tools.test.ts` runs it through a live
gateway whose server changes a description mid-session.

## Why

- **What the model reads is part of the attack surface.** The gateway cannot tell an honest
  description from a hostile one, but it can tell that one changed, and put the change in front of a
  human before the model sees it.
- **Withhold, not warn.** A warning in a log is read after the model has read the new text. Leaving
  the tool out of the list means injected words never reach the model through the gateway.
- **Exact, like the rest of the state.** Any change counts, however small, because the hash covers
  every field the model reads. There is no "close enough" (README, "Why the state is exact").
- **Cheap.** A listing reads `tools.json` under its lock and writes it only when something is new or
  changed (`tool-pins.test.ts` checks that a listing that changes nothing does not rewrite the file).
  A call reads it without the lock, at most twice.

## Consequences

- **Trust on first use.** A definition that is hostile the first time the gateway sees it is pinned
  like any other. Pinning catches changes, not bad first versions; looking at a new server's tools
  before an agent uses them is still a human's job (`agent-gate tools list`, and
  `agent-gate policy suggest` for what the policy will do with each one).
- **Updates need a human.** A server upgrade that rewords its descriptions withholds those tools
  until someone accepts them. For a server that changes often and is trusted, `"pinTools": false` is
  the way out, and it is per gateway, not per server.
- **Only what the model reads is hashed.** The MCP SDK this repository uses (1.32.1) also lists
  `icons`, `execution` and `_meta` for a tool; they are not in the hash, so a change there does not
  withhold anything. A client that shows `_meta` to its model would need it added.
- **One pin file, several copies of a server.** Gateways that share a state directory share the
  pins, but each stdio gateway starts its own copy of every downstream server. When two copies list
  different definitions, the last listing decides whether the tool counts as changed: a copy that
  still lists the pinned definition clears the mark that another copy set.
- **The pins are state.** Whoever can write `<stateDir>` or run the CLI can accept a change, so the
  state directory has to stay out of the agent's reach, as for approvals
  ([ADR 0005](0005-approvals-are-action-tokens.md)).

## Alternatives considered

- **Signed definitions.** A publisher's signature over each definition would also cover the first
  version, when the publisher is trusted. The tool listing has no field for one (the SDK's `Tool` has
  a name, title, description, input and output schema, annotations, execution, icons and `_meta`),
  and none of the servers agent-gate was tested with signs anything. A gateway could check signatures
  once servers carry them; pinning would still catch an unsigned change.
- **A shared registry of approved definitions.** An operator keeps the list ahead of time, and many
  gateways read it. That is pinning done centrally; `tools.json` is the local form. A shared copy
  needs the multi-host state that [ADR 0003](0003-single-writer-state.md) describes.
- **Trusting annotations such as `destructiveHint`.** They come from the same server whose words are
  in question (README, "What the gateway does not cover").
- **Hashing only the name and the input schema.** The description is where poisoning lives, so it
  has to be in the hash.
