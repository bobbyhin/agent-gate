# ADR 0004: The guards decide in code, not in a prompt or a model

Status: accepted
Date: 2026-10-31

## Context

Something has to decide whether an agent's action may run: a shell command, an MCP tool call, a
request to a model provider. There are three places to put that decision:

1. **In the agent's prompt.** "Never push without asking first." The agent's model reads the rule
   and is trusted to follow it.
2. **In a model that judges each action.** A second model (an LLM, or a classifier) looks at the
   action and answers allow or ask.
3. **In code.** Rules written as code run on every action, outside the agent, and give the same
   answer to the same input.

## Decision

The decision is made in code, outside the agent: `analyze()` in `src/command-guard.js` for shell
commands, `evaluate()` in `src/gateway/policy.ts` for MCP tool calls, the budget and leak-guard
checks in `src/llm/` for model requests. No model runs when these decide, and none can override them.
A human, through the approval queue, decides what the rules leave open.

## Why

- **A prompt is followed by a model, and a model is not deterministic.** An instruction with several
  steps ("check, then ask, then run") is followed most of the time, not every time, and text the
  agent reads later (a web page, a tool result) can talk it out of the rule. The rule has to hold
  when the agent is wrong or has been manipulated, so it cannot live where the agent can rewrite or
  skip it. `test/gateway/e2e.test.ts` plays this case: a tool result tells the agent to upload its
  SSH key, the agent obeys, and the gateway blocks the call.
- **The steps run in a fixed order in code.** The gateway's `decide()` in `src/gateway/server.ts`
  always runs policy, then the approval queue, then the audit line, then forwards. A prompt chain
  that describes the same steps can drop one; the code cannot.
- **The same input gets the same answer.** That makes the rules testable as tables: 239 red-team
  cases, 73 upload cases, a policy table per red line, and a hash of the answers for 20,594
  generated commands (`npm test`). A changed answer is a failing test, not a drift nobody sees.
- **Every decision can be read back.** The first version of the shell guard blocked 33 times in 46
  days of the author's logs. Because each block came from a named rule with a logged reason, they
  could be reviewed one by one: about 32 were legitimate work, which is why most rules now ask
  instead of block (see the README). A model's judgment cannot be replayed and argued with that way.
- **It is cheap enough to run on every action.** The shell guard answers in milliseconds, without a
  network call or a model to load, and in time proportional to the command's length (v5.2, see
  `docs/red-team.md`). A guard that is slow or flaky gets turned off.

## Three lanes

Each kind of work has a lane, and the guards keep to the first:

| Lane | Good at | In agent-gate |
| --- | --- | --- |
| Code (rules) | Policy: the same answer every time, testable, cheap | All three guards |
| Classifier (a model that returns a probability) | Ambiguous cases the rules cannot see, such as intent hidden in a script | Not built. docs/shell-guard.md lists it as a separate layer the guard needs. |
| LLM (a model that writes text) | Reading a situation and explaining it | Not used at runtime. A second reviewer that can only make a decision stricter is how it would join (ADR 0008). |

The model reads the situation; the code holds the policy. Where neither can decide, the threshold is
a human: an approval in the queue, bound to the exact call (`argsHash`), used once.

## Consequences

- Rules miss what they do not encode. On a held-out set written against a broader hook, the shell
  guard stops 8 of 122 commands that it should (`npm run redteam`); most of the misses are kinds of
  action it does not look at (single-file overwrites, paid API calls, posting). The "Known
  limits" section of docs/shell-guard.md says what it does not see.
- A rule is a regular expression or a word list, not a parser: `sql-write` and the shell guard read
  text, so they can be fooled by forms they do not know, and they can ask about harmless text.
- Rules need upkeep. New tools and new tricks mean new rules and new test cases.
- AI was used to build this: the author designed it and directed Claude Code and Codex as coding
  agents, and Codex was one of the red teams. At runtime, there is no model in any of the three guards.

## Alternatives considered

- **Rules in the prompt only.** No extra process, but nothing enforces them; see "Why".
- **A model as the gate.** Better at intent and new forms, but its answers vary, cost time and money
  per call, and can be argued with by the same text that misleads the agent. It fits beside the rules,
  in a role where it can only add a question, not as the decider.
