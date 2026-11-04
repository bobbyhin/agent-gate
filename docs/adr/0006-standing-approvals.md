# ADR 0006: Standing approvals are bounded, and only rules that opt in accept them

Status: accepted
Date: 2026-10-31

## Context

An approval covers one exact call, once (ADR 0001). That is the safe end, and it is tiring for a
call that comes often and is not very risky: an agent seeding a development database with forty
`INSERT`s asks forty times. Agent clients often offer the other end, "allow all tools of this
server" or "always allow this tool", which stays on for the whole session and covers any arguments.

The middle is a single yes for a bounded set of calls.

## Decision

A human can grant a **standing approval** with the CLI:

```
agent-gate approvals grant demo__execute_sql --arg "sql=INSERT INTO events*" --uses 10 --hours 24
```

- It names one server and one tool exactly (no globs on the tool).
- `--arg name=glob` (any number): each listed argument must be present, be a string and match its
  glob, with the same globs as policy rules (the whole value, case-insensitive, `*` and `?`).
  Arguments it does not list are free.
- `--uses` (1 to 100) and `--hours` (more than 0, at most 168) are required. It covers at most that
  many calls, until it expires.
- It answers only an `ask` from a policy rule that says `"standing": true`. The example policy opts
  in `sql-write` and `browser-input`, and nothing else: not money, shipping, memory, deletes, posting,
  nor the shell rule.
- Order, for a call that a rule asks about: a denial of this exact call wins; then an approval of
  this exact call is used; then a standing approval that covers it; then the call waits for a human.
- Each use is written to the audit log as the call's line with the standing approval's id
  (`"approvalId": "sa-…"`). Granting and revoking (`approvals deny sa-…`) are lines of their own
  (`"event": "standing-approval"`). `approvals grants` lists those in force with their uses left.

The code is in `src/gateway/approvals.ts` (`grant`, `revoke`, `resolveCall`) and
`src/gateway/cli.ts`; the tests are in `test/gateway/approvals.test.ts`, `cli.test.ts` and
`e2e.test.ts`.

## Why

- **Risk tiers.** The rule decides whether a yes can stand. Lower-risk, frequent actions can take a
  standing approval; red lines keep one approval per call. This is the experiment's variable for
  risk-tiered human approval: which tiers can be granted in bulk, and at what bound.
- **Bounded twice.** A count and a lifetime, both required and both capped, so a grant cannot quietly
  become "always".
- **Narrow by default.** One exact tool, and patterns on the arguments that matter. A grant that lists
  no arguments says so when it is made ("with any arguments").
- **Every use is accounted for.** The audit line of each call names the grant, so "what did that yes
  let through" is a search, and `approvals grants` shows the uses left.
- **The agent cannot grant itself one.** `agent-gate approvals grant` is in the example policy's
  `no-self-approval` block rule, next to `approve` and `deny`. As for every approval, the state
  directory must be out of the agent's reach (docs/mcp-gateway.md, "What the gateway does not cover").

## Consequences

- A broad glob makes a broad grant: `--arg "sql=*"` covers any SQL the rule asks about. The person
  granting it decides how wide it is; the read-back of `approve` does not apply to `grant`, which
  prints what it granted instead.
- Arguments a grant does not list can take any value. List every argument that changes what the call
  does.
- Bindings to file content (`fileBinding`) are not checked for a standing approval: it covers many
  calls, not one set of files.
- An agent can spend all the uses at once. The count bounds the total, not the rate.
- A use is spent when the gateway lets the call through, whether or not the call then succeeds
  downstream, as with an exact approval.

## Alternatives considered

- **A time window only** ("allow this tool for an hour"). Without a count, a loop in the agent can make
  thousands of calls in that hour.
- **A count only.** Without an expiry, a grant made for one task waits around for the next.
- **Letting every rule accept standing approvals.** Simpler, but then a grant for a deploy tool is one
  command away; opting in per rule keeps the red lines at one approval per call.
- **Learning grants from repeated approvals** (offer a grant after the fifth identical yes). Possible
  later, on top of this; the bounds and the opt-in would stay.
