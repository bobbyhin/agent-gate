# ADR 0008: A second reviewer for tool calls may only make a decision stricter

Status: accepted; partly built (the combination rule and its tests; see "What is built")
Date: 2026-10-31

## Context

The MCP gateway's policy is code (ADR 0004): word lists and patterns on tool names and arguments.
It misses what it does not encode: a tool named `sync` that pushes, an argument that is harmless
text for one tool and a destructive command for another. A model reads such calls better than a
pattern does, and a small one can run on the same machine (through Ollama, say), so nothing leaves
it. Some agent designs go further and let several models vote before an irreversible tool runs,
inside the agent's prompt. That puts the vote where the agent can skip it, which is the problem ADR
0005 describes.

The question is how to use a model's reading of a call without giving the model the decision.

## Decision

A second reviewer, consulted by the gateway, never by the agent, that can only add a question:

| Policy decision | Reviewer says allow | Reviewer says ask | No answer (error, timeout, unreadable) |
| --- | --- | --- | --- |
| allow | allow | **ask** | allow |
| warn | warn | **ask** | warn |
| ask | ask | ask | ask |
| block | block | block | block |

- **When.** Only for rules that opt in (a field such as `"advise": true` on a policy rule), so the
  model's time is spent on the calls where a second reading is worth it, not on every read.
- **What it sees.** The server, the tool, the `argsHash`, the policy's decision and rule, and the
  arguments with secrets removed by the LLM gateway's leak-guard rules (`src/llm/leak-guard.ts`), as
  JSON on its standard input. It runs as a local command with a short timeout (about 3 seconds).
- **What it answers.** Exactly one JSON object, `{ "vote": "allow" | "ask", "why": "..." }`.
  Anything else counts as no answer.
- **What people see.** Both votes on the approval card (`approvals list`, the read-back of
  `approve`), with the reviewer's reason as one cleaned line. The agent is told only that a second
  reviewer asked for a human, not the reviewer's words: the reviewer read the same arguments that
  may have steered the agent.
- **What is measured.** Each call line in the audit log gets the reviewer's vote and whether it
  agreed with the policy (both wanted a human, or both did not). `approvals stats` can then report,
  per rule, how often the pattern and the model disagree, and how the human decided in those cases.

## Why

- **The model cannot open a door.** It is steerable by the text it reads (ADR 0004), so it may add
  friction and nothing else. A reviewer talked into "allow" changes nothing; a reviewer talked into
  "ask" costs a human a look.
- **Its failure is not the guard's failure.** The policy is the gate. A reviewer that is down,
  slow or confused leaves the policy's decision as it was, and the audit line records that it gave
  no answer, so an outage shows in the numbers.
- **The disagreements are the data.** How often the pattern and the model disagree, and which of
  them the human sides with, is what tells whether a rule needs fixing, a classifier would help, or
  the model is noise.

## What is built

`src/gateway/advisor.ts` holds `escalateOnly()`, the table above as code, and `parseOpinion()`, the
strict reading of the reviewer's answer. `test/gateway/advisor.test.ts` checks all twelve cells of the
table (the result is never looser than the policy), that the reviewer's words stay off the agent's
text, and that anything but a clear vote is no answer.

Not built yet: the config (the command, the timeout, which rules opt in), running the command and
reading its answer, the redaction step, the reviewer's vote in the approval record and the audit
line, and the agreement numbers in `approvals stats`. The gateway's `decide()` is synchronous today;
waiting for the reviewer makes it asynchronous for the rules that opt in.

## Consequences

- A call the reviewer escalates costs a human a look, and the reviewer adds up to its timeout to
  each call it reviews.
- A reviewer that always says "ask" turns opted-in rules into asks; the agreement numbers show that.
- Nothing about the call leaves the machine, as long as the reviewer is local. Pointing it at a
  hosted model would send redacted arguments to that provider, and would cost money per call.

## Alternatives considered

- **Votes inside the agent's prompt.** The agent can skip them, and text it reads can fake them.
- **Letting the reviewer relax a decision** (a model that says "allow" turns an ask into an allow).
  That hands the decision to a model, which ADR 0004 rules out.
- **A classifier instead of an LLM.** It fits the same slot and the same table; it needs labeled data,
  which the agreement numbers would start to collect.
