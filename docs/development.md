Back to the [README](../README.md)

# Development

## Run the tests

```
npm install
npm test
```

`npm test` compiles the TypeScript and then runs `node --test` (Node 20 or newer) over three suites.

The shell guard suite needs no dependencies; `node --test test/command-guard.test.js` runs it on
its own. It runs 351 tests: the 239 cases in `test/cases.json` and a check that the file is well
formed; the 73 upload cases of suite G in `test/cases-exfil.json`, a check that that file is well
formed, and a hook test for a blocked upload; 5 tests that run the hook as a child process; 15 timing
tests on crafted long commands (each must finish within 0.5 or 3 seconds, where v5.1 took from 1.1
seconds to hours; on a machine too busy for that, its time must grow in step with its length); 10 tests of the 32-word reading limit; a differential test: the answers for
20,594 generated commands (`test/generated-commands.js`) must hash to the value recorded from v5.1;
2 tests of the held-out set: it is well formed, and its score is no worse than
`test/heldout-baseline.json` (`npm run redteam` prints that score per category); and 3 tests that
the guard needs no network: what it may load, and the hook run with every network module made to throw.
Each case has an `expect` of `pass`, `warn`, `ask` or `block`; `ask_or_block` accepts either of
the last two (3 cases).

The MCP gateway suite (`test/gateway/`) runs 637 tests: a policy table for each red line, for the
SQL and browser examples, for the shell rule and for rules that shorten a request's life (`ttlMinutes`); the
path matchers (`under`, `outside`, `touches`) on `..`, escapes, symlinks and their loops, and a red
team of path tricks against the real filesystem server (`npm install` puts it in `node_modules`); tool
lists with each tool labelled with the decision it should get (`test/gateway/tool-lists/`: a social
app's tools, names a review wrote to get round red line 2, the calendar tools of a real server held out from it, and the 48 tools of a real Gitea MCP server, recorded), and the
README's table of example rules checked against `policy.example.json`; a red team of 20 ways to get a
denied delete done another way (other tools, shell commands, the path written another way); `policy
suggest` (reads by name, an OpenAPI document, the draft it prints, a server that cannot start, tool names that would be patterns, `--server`); ten
trajectory fixtures replayed step by step through a running gateway; which
files an approval is bound to (symlinks, `..`, relative paths) and what a changed file does to it (every case in `test/cases.json` and
`test/cases-exfil.json` is also run through the gateway's shell rule), config and policy validation, the approval store with a clock the test
controls, standing approvals and their bounds, the escalate-only rule of a second reviewer, the CLI's exit codes, its read-back before an approval, and what a decision leaves behind
(the record, the `approval-decided` line, `stats`), the correlation ids a client may send (and what
is dropped), `audit stats`, every rule that matched next to the one that decided (and a check that
the decisions are first match's), rewrite rules on their own and through a running gateway, loop
limits (their counts with a clock the test controls, and a loop through a running gateway), tool
lists (the pin store on its own: a change to each field the model reads, a tool that disappears and
comes back, a change undone, a damaged file; a server that changes a tool's description mid-session,
`expose`, profiles, tools the policy always blocks), the result guard (secrets withheld or redacted in text, resources and
structured content, instruction-like text flagged, ordinary text left alone; 15 indirect injections
in tool results, with the 6 it misses and its false alarm recorded), `audit verify` (a log
the gateway wrote passes; each of ten hand edits fails it) and `audit trajectory` (the three modes,
precision and recall), a remote server over Streamable HTTP on 127.0.0.1 (its header from the
environment, a timeout, a 401 at startup whose quoted header value stays out of the log, a server
that goes away), agents over HTTP (`serve --http` on 127.0.0.1: each agent's own policy and profile,
401 without a key or with a wrong one, 403 for another `Host` or `Origin`, 404 for another agent's
session whatever the method, an approval or a standing approval that one agent cannot use for another,
`audit verify` on the whole log, loop limits per agent, the session caps and the idle sweep with a
clock the test moves, 413 for a body over the limit, a taken port), downstream servers that fail (one
that exits mid-call is started again while the others go on, and the call it crashed on reached it
once, an optional one starts once it can, one that never starts and a crash loop are given up, a
required one stops the gateway, a remote server's error text kept out of what the agent is told and
cleaned of terminal escapes in `status`, `status` and its file), what the gateway does when one of its own
parts fails, and an end-to-end test. That test starts `agent-gate serve`
against a fake downstream server, talks to it with a real MCP client, answers approvals with the
real CLI, and checks what reached the downstream server and what was written to the audit log,
including a call-result line, with the hash of what came back, for every forwarded call.
Crash tests (`test/gateway/crash.test.ts`) kill the gateway and a writer with `kill -9` and check
what survives. An action-token suite (`test/gateway/action-tokens.test.ts`) checks the key, the code
and the proof (bound to every field of the request), the `irreversible` flag in a policy (and that it
sticks past a standing rule), the store's refusals (reuse, expiry, other arguments, a forged record, a
replayed one, a nonce the gateway did not make, file hashes edited after the yes, a standing
approval), the CLI's (`--yes` alone, another request's token, a decided or expired request, a CLI
without the key, a record whose arguments do not match their hash, a call changed after the
read-back), each with its audit line, and running gateways: a forged approval refused, a replayed one
refused by the process that spent it, by a second process on the same state directory and after a
restart, a standing rule that cannot cover a `DROP` an irreversible rule also asks about, and an agent
that never sees a token.
One step plays a prompt injection: a tool result tells the agent to upload its SSH key, the agent
obeys, and the gateway blocks the call before it reaches the server. Another denies a call with a
reason written to sound like the system, and checks that the agent sees it as one quoted line and
the call stays denied.
An approvals-page suite (`test/gateway/approvals-ui.test.ts`) runs
`approvals ui` on 127.0.0.1: 403 for another `Host`, the page's policy header (its hashes those of the
script and style it serves), 401 for every API call without the session, no session for another
`Origin`, a missing one, a cross-site fetch or a body that is not JSON, a wrong key that does not spend
the link and a link that works once, a decision without the CSRF token that changes nothing, the CLI's
read-back, an irreversible request refused without its token, with a wrong one and with another
request's, then approved with its own and let through by the gateway once, the end of the id for any
other request, a denial's reason, a record changed since the read-back (for a denial, an approval not
used yet too; a decided one is refused as the CLI refuses it), the CLI's audit lines field for field for a denial, a typed approval and a token,
the terminal's lines escaped as the page escapes, the token in no file and no terminal line, standing
approvals shown but never granted and never answering an irreversible call, a body over 16 KiB, the end
of a session after its idle time with a clock the test moves (polls do not keep it); then the page's own
script, run against the server with a small stand-in for the browser (the key out of the address bar, a
spent link in a second tab, a new link's key before a session kept from an earlier start, a link pasted
into an open tab, a pasted link that opens nothing leaving the tab's session alone with no poll during
the trade, a service worker in control (the page removes it and stops, the link unspent), the token
typed into an empty field, the end of an id, a denial, markup and a right-to-left override shown as
text, values that are not text, a request decided at the CLI read back again by a poll), and the command
itself (its link printed once on a new port, the note a fixed `--port` prints before the link, SIGTERM, bad ports, and the example policy blocking an agent that starts it, with the quoted command
that gets past the rule recorded).

The LLM gateway suite (`test/llm/`) runs 349 tests: a routing table; config validation; budget
math and the ledger with a clock the test controls (reserve, settle, release, calls in flight, UTC
day and month rollover, reservations left by a crashed process, a damaged file, a settle that comes
twice or after its reservation expired, calls per minute and run caps); a leak-guard table
for every shipped rule, with 29 samples of prose and code that must pass untouched; retries and
the fallback with a scripted `fetch` (including 429s: to the fallback at once, one capped wait for
`Retry-After` on the last upstream, an HTTP-date `Retry-After`; a 408; the jittered backoff and its
cap, and that with any random value a call's waits fit inside the time its reservation is sized by),
plus a real timeout; the CLI; and
an end-to-end test. That
test starts `agent-gate llm serve` against three fake upstream HTTP servers, one healthy, one that
always answers 500 and one that always answers 429, and checks routing by alias and by
`x-agent-task`, the fallback after a 500 and after a 429, one wait for `Retry-After` when there is
no fallback,
costs settled from the upstream's `usage`, a 429 with no upstream call once a cap is reached,
secrets blocked before any upstream call, redaction, a usage log without prompt text, the trace
context (the client's trace kept, a new one started, the gateway's own span sent upstream, bad values
dropped), `usage --by task`, 401 for an unknown key, and that no provider key ever appears in a
response or a log. A metrics suite checks the Prometheus text, who may read `/metrics` (its own
key on the gateway's port, or a loopback listener with none) and the config rules behind that. A
stop-rule suite runs loops against a live gateway: cut at the sixth call of a minute, a run cut at its
third call and before it passes its dollars, the sixth copy of the same request cut and let through
again once its window moves on, each cut in the usage log; the end-to-end run also
checks that `usage --verify` finds the usage log and the ledger in agreement. A loop-exit suite
(`test/llm/loop-exits.test.ts`) drives a run to each exit through a live gateway (ship at the ship
score, stop on its scored rounds, its tokens and its time, stop on a flat line), holds a run that asks
for more than the key's cap to the cap, lets a run lower its own budget but not raise it back (a
budget declared on a refused call included), refuses a score for a run that made no call, and checks
that a stopped run stays stopped and that every stop is a usage line with its reason. A response-guard
suite runs every block rule on a request and on an answer, and a live gateway against providers
whose answers carry a secret (withheld, booked) or a key assignment (redacted). A failure suite
damages the ledger and the usage log and turns the upstream traceparent off. A PII suite checks each
validator (the Luhn and My Number check digits, the SSN and ITIN ranges) and the four rules on every way
their numbers are written, with look-alikes that fail their check left alone, and that a validator
holds for a block rule and in the MCP result guard; the threat matrix runs its 32 rows; and the README's
rule table is checked against the policy. A divert suite sends personal numbers unredacted to a local
fake and nothing to the cloud one, checks that a block still wins unless the divert lists it, that a
missing alias or a local upstream that is down is refused and never sent to the cloud, and that a
target that is not local is refused at startup. A streaming suite runs two
live gateways, one holding streams and one relaying them, against fakes that stream: the events passed
on as they came, the usage chunk asked for and kept from a client that did not ask, a secret split
across two chunks (withheld when held, passed when relayed), tool-call fragments put back together, a
redaction rebuilt into the stream, a client that leaves mid-stream or before the answer (the fake sees
its request closed), a stream cut short, an error event that quotes the key, a quiet upstream, and the
usage log and the ledger in agreement afterwards; then chunks in shapes the gateway cannot put together
(refused), text parts, reasoning text and fields nobody defined (read, and a secret in them withheld,
streamed or not), an upstream key split across chunks (cut out), a relayed client that stops reading
(settled at the attempt's timeout, not later), and a streamed request answered with JSON that never
ends (504, booked at its estimate). Six more check the
gateway configs under `deploy/`: they load, they use the container's paths, the deployable one
refuses the demo key, the Kubernetes copy of the leak-guard policy matches the example, and Cloud
Run's request timeout is longer than the gateway's longest call. Every
fake secret the tests use is in `test/llm/fake-secrets.ts`, assembled from pieces at run time, so
no secret-shaped string appears in the source and secret scanners need no exceptions for this
repository.

### The tests as an evaluation set

The shell guard's cases are a golden dataset with a gate in front of every change, in the shape that
agent evaluation frameworks use (for example Google's ADK: an eval set of cases, a test config with
thresholds, run by pytest):

| Evaluation framework | Here |
| --- | --- |
| eval set: inputs with the expected outcome | `test/cases.json` (239 commands, each with `expect`) and `test/cases-exfil.json` (73) |
| a held-out split | `test/cases-heldout.json` (163 commands the analyzer was never tuned on), with a baseline score |
| test config: metric and threshold | an exact match on the decision for every case; for the held-out set, recall and false asks no worse than `test/heldout-baseline.json` |
| the runner and the gate | `npm test`, in CI on Node 20 and 22; the deploy job does not start until it passes |

The difference is the judge. The analyzer is deterministic, so a case is checked by an exact match on
the decision, with no model judging and no tolerance band. And it is evaluated one call at a time.
For a sequence of calls, `agent-gate audit trajectory` scores what an agent did through the MCP
gateway against an expected list (exact, in order, in any order, precision and recall), from the
audit log; the end-to-end test scores its own run that way, and `test/gateway/trajectories.jsonl` is
an evaluation set of whole runs, each replayed and checked step by step. It checks which calls ran,
not whether the agent's answers were good.

Current result: **239/239 cases and 73/73 upload cases pass**, and 8 of 122 held-out attacks are
stopped (351/351 shell guard tests, 637/637 MCP gateway tests, 349/349 LLM gateway tests, 7/7 for
the change-review example, 6/6 for the status-mcp example, 5/5 for each of the three demo pages, 3/3 for the load
test), on Node 22. CI runs `npm ci` and `npm test` on
Node 20 and 22; a second job, which starts only after those pass, checks the deploy files (see
[Deploy](operations.md#deploy)).

## Repository layout

```
src/command-guard.js                          the analyzer: analyze(command) -> { action, label, why }
src/command-guard.d.ts                        its types, for the TypeScript gateway
bin/claude-pretooluse-hook.js                 the Claude Code PreToolUse hook
src/gateway/server.ts                         the MCP gateway: lists <server>__<tool>, decides, forwards (one core, a session per client)
src/gateway/http-server.ts                    serve --http: agents over Streamable HTTP, each known by its key
src/gateway/downstream.ts                     keeps the downstream servers connected: restarts, optional servers
src/gateway/status.ts                         <stateDir>/status.json, for agent-gate status
src/gateway/policy.ts                         the policy engine (pure but for path matchers): evaluate(policy, call) -> verdict
src/gateway/approvals.ts                      the approval queue in <stateDir>/approvals.json
src/gateway/action-tokens.ts                  action tokens for irreversible calls: the key, the code, the proof
src/gateway/decisions.ts                      a human's decision, shared by the CLI and the approvals page
src/gateway/approvals-ui.ts                   approvals ui: the approvals page's server, on 127.0.0.1
src/gateway/approvals-page.ts                 the approvals page itself: one document, its script and style inline
src/gateway/repeats.ts                        loop limits: recent runs per call in <stateDir>/repeats.json
src/gateway/files.ts                          binds approvals to the content of the files a call names
src/gateway/tool-pins.ts                      pinned tool definitions in <stateDir>/tools.json
src/gateway/result-guard.ts                   reads results: withholds or redacts secrets, flags instruction-like text
src/gateway/advisor.ts                        the escalate-only rule for a second reviewer (ADR 0008; not wired yet)
src/gateway/audit.ts                          the audit log, <stateDir>/audit.jsonl
src/gateway/audit-tools.ts                    reads the audit log back: audit stats, verify, trajectory
src/gateway/suggest.ts                        policy suggest: each tool's decision from its name, and a draft policy
src/gateway/context.ts                        correlation ids a client may send: trace, session, run, agent path
src/gateway/config.ts                         loads and checks the gateway config
src/gateway/validate.ts                       field-by-field checks for the configs and the policies
src/gateway/state-file.ts                     lock and atomic write for approvals.json and ledger.json
src/gateway/cli.ts                            agent-gate serve, approvals ..., llm serve, usage
src/llm/server.ts                             the LLM gateway: HTTP, keys, the steps of a call
src/llm/routing.ts                            routing (pure): route(config, request) -> upstream and model
src/llm/upstream.ts                           calls the upstreams: retries, backoff, fallback
src/llm/stream.ts                             streamed answers: reads the events, puts messages back together
src/llm/budget.ts                             the cost estimate and the ledger in <stateDir>/ledger.json; run limits and loop exits
src/llm/repeats.ts                            repeatMax: the same request let through at most so often, in memory
src/llm/leak-guard.ts                         the leak guard (pure): block or redact secrets in messages
src/llm/validators.ts                         checks behind the PII rules: Luhn, My Number check digit, SSN and ITIN ranges
src/llm/usage-log.ts                          the usage log, <stateDir>/usage.jsonl
src/llm/usage-report.ts                       reads the usage log back: agent-gate usage --by
src/llm/metrics.ts                            GET /metrics: running totals in the Prometheus text format
src/llm/config.ts                             loads and checks the LLM gateway config
bin/agent-gate.js                             the CLI entry point (runs the build in dist/)
policy.example.json                           the red lines as a gateway policy
gateway.config.example.json                   a config that proxies the fake test server
gateway.config.http.example.json              the same server for two agents over HTTP, with demo keys
llm-policy.example.json                       the leak guard rules
llm-gateway.config.example.json               an LLM gateway config for the fake upstream
llm-gateway.config.ollama.example.json        a cloud upstream for most calls, Ollama on this machine for personal numbers
Dockerfile                                    the LLM gateway image (and the demo's fake upstream image)
.dockerignore                                 what the image build may read: an allowlist
docker-compose.yml                            local demo: the gateway image in front of the fake upstream
deploy/README.md                              compose, Kubernetes and Cloud Run steps; what was checked
deploy/compose/llm-gateway.config.json        the demo's gateway config
deploy/k8s/                                   kustomize: Deployment, Service, PVC, NetworkPolicy, ConfigMap
deploy/k8s/llm-gateway.config.json            the config template for Kubernetes and Cloud Run
deploy/terraform/                             Cloud Run, Artifact Registry, Secret Manager, state bucket
deploy/terraform/tests/                       plan-only Terraform tests with a mocked provider
deploy/cloud-run-metrics/run-monitoring.yaml  a sample config for the Prometheus sidecar on Cloud Run (not applied)
test/cases.json                               239 cases: id, category, expect, cmd
test/cases-exfil.json                         suite G: 73 uploads of local files, same fields
test/cases-heldout.json                       163 held-out commands from a later red team (test/HELDOUT.md)
test/heldout-baseline.json                    the held-out score that npm test must not fall below
scripts/redteam.js                            npm run redteam: the held-out score per category
test/command-guard.test.js                    table tests over both case files, hook process tests, timing tests
test/generated-commands.js                    20,594 generated commands for the differential test against v5.1
test/gateway/*.test.ts                        gateway tests: policy, config, approvals, CLI, end to end
test/gateway/fake-downstream.ts               the fake MCP server for the end-to-end test
test/gateway/fake-http-downstream.ts          a fake remote MCP server over Streamable HTTP, on 127.0.0.1
test/gateway/tool-lists/                      tool lists of real or realistic servers, each tool labelled by hand
test/gateway/workarounds.json                 red team: 20 ways round a denied delete, before and after red-line-4-overwrite
test/gateway/trajectories.jsonl               whole runs, one per line: calls, expected outcomes, a human's answers
test/llm/*.test.ts                            LLM gateway tests: routing, budget, leak guard, upstream, end to end, deploy configs
test/llm/fake-upstream.ts                     a fake OpenAI-compatible provider for the tests, the example and the demo
test/llm/fake-secrets.ts                      every fake secret the tests use, in one file
test/llm/fake-pii.ts                          made-up personal numbers, built at run time with their check digits
test/llm/threat-matrix.json                   32 risky prompts and what the leak guard does with each, gaps included
scripts/loadtest.js                           npm run loadtest: the LLM gateway under concurrent load; the budget must hold
test/loadtest.test.js                         a small load in npm test: never overspent, booked exactly, no 5xx; --url stops before the load when it does not reach the gateway
scripts/bench.js                              npm run bench: what each gateway adds to one call, and what a state write costs
test/no-network-preload.js                    makes network modules throw, for the no-network test
test/change-review.test.js                    tests of the change-review example
examples/change-review/review.js              a change review as a workflow graph: checks, router, approval queue
examples/change-review/sample.diff            a sample change that the review escalates
examples/status-mcp/server.js                 a small, real MCP server: status reads and one write
examples/status-mcp/policy.json               its policy: reads allowed, a write asks, a bulk write blocked
examples/status-mcp/gateway.config.json       the gateway in front of it
examples/status-mcp/sample-status/            the status folder it reads by default
test/status-mcp.test.js                       the example through a running gateway
test/demo.test.js                             the demo page: quoted code still matches, its log verifies, it steps through
test/demo-llm.test.js                         the LLM demo page: quoted code still matches, its dollars add up, no key on it
test/demo-approvals.test.js                   the approvals demo: the page's code, its log verifies, it sends nothing
test/SANITIZED.md                             what was changed in the cases before publication
test/HELDOUT.md                               where the held-out cases come from, and their score
docs/red-team.md                              the case categories, with counts
docs/exploring-the-codebase.md                trace a decision: one line to reproduce it per guard, and its code and tests
docs/related-work.md                          Docker MCP Gateway, LiteLLM, and how other tools bind a human's yes
docs/demo/index.html                          a step-through replay of a real gateway run, with the code that decided
scripts/demo-transcript.js                    npm run demo: records that run and writes it into the page
docs/demo/llm.html                            the same for the LLM gateway: routing, a blocked secret, a budget refusal, a stream
scripts/demo-llm-transcript.js                npm run demo:llm: records that run and writes it into the page
docs/demo/approvals.html                      the approvals page in demo mode, read-only, with a recorded run
scripts/demo-approvals.js                     npm run demo:approvals: records that run and writes the page
docs/adr/0001-non-blocking-approvals.md       why "ask" answers with an error instead of waiting
docs/adr/0002-reserve-then-settle-budgets.md  why budgets reserve an estimate and settle after
docs/adr/0003-single-writer-state.md          why the gateway runs as one replica, and the way to more
docs/adr/0004-decisions-in-code.md            why the guards decide in code, not in a prompt or a model
docs/adr/0005-approvals-are-action-tokens.md  an approval is a server-side action token, not a yes in the chat
docs/adr/0006-standing-approvals.md           bounded standing approvals, and why only some rules accept them
docs/adr/0007-where-agent-gate-sits.md        a control plane in front of calls, not an agent host; production readiness
docs/adr/0008-second-reviewer-escalate-only.md a second reviewer that can only make a decision stricter (partly built)
docs/adr/0009-pin-tool-definitions.md         why a tool whose definition changes is withheld until a human accepts it
docs/adr/0010-retries.md                      why retries wait a random time up to a cap, and a 429 goes to the fallback first
docs/adr/0011-streaming.md                    why a streamed answer is held until it is scanned, unless scanning is off
docs/adr/0012-an-http-endpoint-for-agents.md  agents over HTTP: a key per agent, approvals bound to it; what deploying it needs
docs/adr/0013-action-tokens-for-irreversible-calls.md
                                              an irreversible call is confirmed with a token the gateway bound to it
docs/adr/0014-approvals-web-page.md           the approvals page: a local process whose link is the key
tsconfig.json                                 compiles src/ and test/ into dist/
AGENTS.md                                     build, layout and rules for coding agents
CLAUDE.md                                     one line that points Claude Code to AGENTS.md
.github/workflows/ci.yml                      npm test on Node 20 and 22; checks and a build of the deploy files
```

`package.json` maps `#command-guard` to `src/command-guard.js` (its `imports` field), so the
compiled gateway in `dist/` loads the analyzer straight from `src/`, with no copy.
