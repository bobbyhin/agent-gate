Back to the [README](../README.md)

# LLM gateway

The MCP gateway decides which tool calls an agent may make. The LLM gateway sits on the agent's
other way out: its calls to the model itself. It is an OpenAI-compatible HTTP endpoint in front of
one or more upstream providers, and for every chat completion it decides which upstream and model
serve it, whether the caller's budget allows it, and whether its text may leave the machine.

Every `POST /v1/chat/completions` goes through these steps, in this order. Nothing is sent upstream
until steps 1 to 5 have passed.

| Step | What happens | Refused with |
| --- | --- | --- |
| 1. Authenticate | The gateway key (`Authorization: Bearer <key>`) is looked up by its SHA-256 and mapped to a name, such as `search-agent`. | 401 |
| 2. Check | The body must be JSON with a `model` alias and `messages`. | 400, 413 |
| 3. Route | Route rules pick an upstream and a model from the alias and the `x-agent-task` header. | 404 |
| 4. Leak guard | The message text is scanned for secrets. A block rule refuses the call; a redact rule replaces the match. With `divert`, a call that matches a divert rule goes to a local model instead (see [Keeping personal data local](#keeping-personal-data-local)). | 400 |
| 5. Reserve | The call's estimated cost is reserved against the key's daily and monthly caps, after its stop rules (calls per minute, and the run's limits and exits). | 429 |
| 6. Call | The upstream is called, with retries and then the fallback on a 5xx, a timeout or a 429. A streamed answer is read as it comes (see [Streaming](#streaming)). | 502, 504; 429 if the upstreams keep rate limiting |
| 7. Settle | The reservation is settled with the real cost from the answer's `usage`, or released if the call failed. | |
| 8. Check the answer | The answer's text goes through the same leak guard. A block rule withholds it; a redact rule edits it. A stream is checked once it is complete. | 502 |
| 9. Record | One line goes to the usage log, with no prompt or completion text. | |

It is written in TypeScript on Node's own `http` module and global `fetch`, with no runtime
dependencies.

Status: new. It was built and tested against fake upstream servers on the local machine; no real
provider has been called through it yet.

To see it work without installing anything, open [docs/demo/llm.html](demo/llm.html) in a
browser: a replay of a real run with the example config against the fake provider (a call routed to
the cheap model, a secret stopped before it leaves, a call refused by its budget, a streamed answer held
until it has been read, `usage --verify`), with the code that decided each step. `npm run demo:llm`
records it again; `test/demo-llm.test.js` fails when a line it quotes no longer matches the code.

## Set it up

```
npm install
npm run build
cp llm-gateway.config.example.json llm-gateway.config.json
```

The example config points at the fake upstream from the tests, so the whole flow can be tried
without an account anywhere and at no cost. Start the fake on port 9101, then the gateway, with
the upstream keys in its environment (the fake accepts any key):

```
node dist/test/llm/fake-upstream.js --port 9101 &
CHEAP_API_KEY=fake-cheap STRONG_API_KEY=fake-strong BACKUP_API_KEY=fake-backup \
  node bin/agent-gate.js llm serve --config llm-gateway.config.json
```

Clients use `http://127.0.0.1:8787/v1` as their OpenAI base URL and a gateway key as their API
key. The example config accepts the key `demo-gateway-key-not-a-secret`, which the commands below
read from `$GATEWAY_KEY`. This is the example config:

```json
{
  "listen": { "host": "127.0.0.1", "port": 8787 },
  "stateDir": ".agent-gate",
  "policy": "llm-policy.example.json",
  "upstreams": [
    {
      "name": "cheap",
      "baseUrl": "http://127.0.0.1:9101/v1",
      "apiKeyEnv": "CHEAP_API_KEY",
      "models": { "small": "fake-small-1" },
      "pricePerMTok": { "input": 0.15, "output": 0.6 }
    },
    {
      "name": "strong",
      "baseUrl": "http://127.0.0.1:9101/v1",
      "apiKeyEnv": "STRONG_API_KEY",
      "models": { "large": "fake-large-1" },
      "pricePerMTok": { "input": 3, "output": 15 }
    },
    {
      "name": "backup",
      "baseUrl": "http://127.0.0.1:9102/v1",
      "apiKeyEnv": "BACKUP_API_KEY",
      "models": { "large": "fake-large-2" },
      "pricePerMTok": { "input": 3, "output": 15 }
    }
  ],
  "routes": [
    { "id": "classify-is-cheap", "when": { "task": "classify" }, "use": { "upstream": "cheap", "model": "small" } },
    { "id": "code-is-strong", "when": { "task": "code" }, "use": { "upstream": "strong", "model": "large" }, "fallback": { "upstream": "backup" } },
    { "id": "cheap-models", "use": { "upstream": "cheap" } },
    { "id": "strong-models", "use": { "upstream": "strong" }, "fallback": { "upstream": "backup" } }
  ],
  "keys": [
    {
      "name": "demo-agent",
      "sha256": "50f762c67f800bf8729d9abff1153a2a812d6b56a74c6422cce0dfd0cae4d6eb",
      "dailyUsd": 0.01,
      "monthlyUsd": 1
    }
  ],
  "defaultMaxTokens": 1024,
  "timeoutMs": 30000,
  "retries": 1,
  "backoffMs": 250
}
```

- `upstreams` are where calls go. `apiKeyEnv` names the environment variable that holds the
  upstream's API key; the key itself is never in the config. `models` maps the aliases clients ask
  for to the upstream's own model names. `pricePerMTok` is US dollars per million input and output
  tokens. There is one price per upstream entry, so a provider with a cheap and a strong model is
  two entries that share a `baseUrl`, like `cheap` and `strong` above.
- `routes` are explained under [Routing](#routing).
- `keys` has one entry per team or agent. `sha256` is the SHA-256 of the gateway key, not the key,
  so the config can be read without handing out access. `dailyUsd` and `monthlyUsd` are the caps;
  both are required. `maxCallsPerMinute`, `runMaxCalls`, `runMaxUsd`, `runMaxSeconds`,
  `runMaxTokens`, and `repeatMax` with `repeatWindowSeconds`, are optional stop rules, and
  `runShipScore`, `runMaxRounds`, `runFlatRounds` and `runMinGain` give a run its loop exits (see
  [Budgets](#budgets)).
- `policy` is the leak guard's rule file. It and `stateDir` are resolved against the config file's
  directory.
- Optional, with their defaults: `listen` (`127.0.0.1`, port 8787), `defaultMaxTokens` (1024),
  `timeoutMs` per attempt (60000), `retries` per upstream (1, at most 3), `backoffMs` (250),
  `maxBackoffMs` (10000),
  `rateLimitWaitMs` (2000: the longest wait after a 429, see [Routing](#routing)), `maxBodyBytes`
  (1 MiB), `scanResponses` (true, see [Leak guard](#leak-guard)), `streamIdleMs` (30000, see
  [Streaming](#streaming)), `sendTraceparent` (true, see [Tracing](#tracing)), `metrics` (off, see
  [Metrics](#metrics)) and `divert` (off, see [Keeping personal data local](#keeping-personal-data-local)).

To make a gateway key and the hash for the config:

```
KEY="agk_$(openssl rand -hex 24)"
echo "$KEY"
printf %s "$KEY" | shasum -a 256
```

As with the MCP gateway, a mistake in the config or the policy stops the gateway at startup with
the field named. So does an upstream key variable that is not set; the error names the variable,
never a value.

## A request, step by step

This is a real run with the example config and the fake upstream (the `Date` and connection
headers are left out). A classification task asks for the `large` alias, and the route for
`x-agent-task: classify` sends it to the cheap model instead:

```
$ export GATEWAY_KEY=demo-gateway-key-not-a-secret
$ curl -s -i http://127.0.0.1:8787/v1/chat/completions \
    -H "Authorization: Bearer $GATEWAY_KEY" \
    -H "content-type: application/json" \
    -H "x-agent-task: classify" \
    -d '{"model":"large","messages":[{"role":"user","content":"Label this ticket: printer on fire"}],"max_tokens":20}'
HTTP/1.1 200 OK
x-agent-gate-request-id: req-50a14662
x-agent-gate-trace-id: a8576eb80c1788fff01a9e61dc87c7ea
content-type: application/json
content-length: 286
x-agent-gate-route: classify-is-cheap
x-agent-gate-upstream: cheap
x-agent-gate-cost-usd: 0.00000885

{"id":"chatcmpl-fake-1","object":"chat.completion","created":1760400000,"model":"fake-small-1","choices":[{"index":0,"message":{"role":"assistant","content":"fake answer 1 from fake-small-1"},"finish_reason":"stop"}],"usage":{"prompt_tokens":23,"completion_tokens":9,"total_tokens":32}}
```

The body is the upstream's answer, unchanged: the leak guard found nothing in it (see
[Leak guard](#leak-guard)). The `x-agent-gate-*` headers say which trace the call
belongs to (see [Tracing](#tracing)), which route and upstream served it and what it cost: 23 input
tokens at $0.15 and 9 output tokens at $0.60 per million, from the upstream's own `usage`. The
gateway's log has one line per call:

```
[agent-gate] 200 req-50a14662 key=demo-agent route=classify-is-cheap upstream=cheap model=fake-small-1 cost=$0.00000885 26ms
```

## Routing

Routes are tried in order. A route applies when every condition in its `when` matches and its
upstream offers the alias it would use. The first route that applies decides.

- `when.model` matches the requested alias, and `when.task` the `x-agent-task` header. Each is a
  glob or a list of globs, matched like the MCP policy's (the whole value, ignoring case, with `*`
  and `?`). A route with `when.task` never matches a request without the header, and a route
  without `when` matches every request.
- `use.upstream` is where the call goes. `use.model` fixes the alias on that upstream. Without it,
  the alias the client asked for is used, and the route applies only if the upstream offers that
  alias. That is what makes `{ "id": "cheap-models", "use": { "upstream": "cheap" } }` mean "any
  alias the cheap upstream has".
- `fallback` is tried when the primary keeps failing. It uses the primary's alias unless it sets
  its own. When that alias is known at startup and the fallback lacks it, the config is refused;
  when it comes from the request and the fallback lacks it, the call simply has no fallback.
- When no route applies, the call is refused with 404 `model_not_found`.

The example's routes, for a request that asks for `large`:

| `x-agent-task` | Route | Upstream and model |
| --- | --- | --- |
| `classify` | `classify-is-cheap` | `cheap`, `fake-small-1` |
| `code` | `code-is-strong` | `strong`, `fake-large-1`; fallback `backup`, `fake-large-2` |
| none, or anything else | `strong-models` | `strong`, `fake-large-1`; fallback `backup`, `fake-large-2` |

The routing function (`src/llm/routing.ts`) is pure, like the policy engine, and has a table test.

A 5xx answer, a 408, a timeout or a failed connection is retried on the same upstream up to
`retries` times. (A 408 means the server did not get the whole request in time, so it never ran it.)
Before retry n the gateway waits a random time between 0 and `backoffMs` × 2^(n−1), at most
`maxBackoffMs`: full jitter, so that calls that failed together do not all come back together.
After that, the fallback gets the same treatment. When every attempt fails, the client gets 502, or
504 if the last attempt timed out, with the gateway's own message.

A 429 is a provider's rate limit or quota: the most common way a call fails, and one that another
upstream can often still serve. So a 429 moves on to the fallback at once. On the last upstream
there is nowhere to go: the gateway waits for the answer's `Retry-After` (`backoffMs` without one),
plus up to a fifth more at random so that callers refused together do not all come back together,
and tries once more, using one of that upstream's `retries`. It waits at most `rateLimitWaitMs`
(2 seconds by default); a longer `Retry-After` is not waited for. If the upstreams still answer 429,
the client gets the gateway's own 429 `upstream_rate_limited`, with the last upstream's
`Retry-After`, and nothing is charged. The usage line counts the 429s on the way (`upstream429`).
Any other 4xx is not retried: it would fail the same way again.

All of it fits in a known time: every attempt timing out, plus every wait at its ceiling, is the
longest a call can take (242.5 seconds with the defaults), and a call's budget reservation is sized
by it. Why full jitter, and how the bound is tested: [ADR 0010](adr/0010-retries.md).

## Budgets

Every gateway key has a daily and a monthly cap in US dollars. Before a call, the gateway reserves
an estimate of its cost; after the call, it settles the reservation with the real cost.

- **Estimate.** Input tokens are the characters of the message text divided by 4. Output tokens
  are the request's `max_tokens` (or `max_completion_tokens`) times `n`, or `defaultMaxTokens`
  when the request sets no limit, in which case that limit is also sent upstream as `max_tokens`.
  The estimate is priced at the most expensive upstream the route may use, primary or fallback.
- **Reserve.** If the key's settled spend, plus what calls in flight have reserved, plus this
  estimate, would pass either cap, the call is refused with 429 and nothing is sent.
- **Settle.** The real cost comes from the answer's `usage`, at the price of the upstream that
  answered. A 2xx answer without `usage` is booked at the estimate. A call that fails releases its
  reservation and costs nothing.

Days and months are UTC. Because calls in flight hold their reservations, concurrent calls can pass
a cap together only by how far their estimates were low: input is counted as characters / 4 and
image or audio parts not at all, so a settled cost can be higher than its reservation (output is
bounded by `max_tokens`). The price is that an estimate can refuse a call that would have fit. Why it
works this way: [docs/adr/0002-reserve-then-settle-budgets.md](adr/0002-reserve-then-settle-budgets.md).
The ledger is exact for the same reason as the approval queue (see Why the state is exact under
[Approval rules](mcp-gateway.md#approval-rules)): a cap is checked against dollars booked, never against a guess
from similar calls.

In the run above, the demo key has a daily cap of $0.01. A call to `large` with
`"max_tokens": 1000` could cost up to 1000 output tokens at $15 per million, so it is refused even
though the key has spent almost nothing (headers shortened):

```
HTTP/1.1 429 Too Many Requests
retry-after: 63272

{"error":{"message":"agent-gate: this call could cost up to $0.015015, and key \"demo-agent\" has $0.00977395 left of its daily budget of $0.01 ($0.00022605 spent, $0 held by calls in flight). Try again later, or with a lower max_tokens.","type":"insufficient_quota","param":null,"code":"budget_exceeded","cap":"daily"}}
```

`Retry-After` is the time until the next UTC day (or month) when the settled spend alone leaves no
room, and one second when calls in flight are what is in the way.

**Stop rules.** Caps bound what a key spends in a day or a month. An agent stuck in a loop spends it
fast, and a run that should have stopped after ten calls can make a thousand. A key can set more
limits. The first is checked before anything is reserved; the others are checked in this order
before the caps, under the ledger's lock:

| Field | What it bounds | Refused with |
| --- | --- | --- |
| `repeatMax` with `repeatWindowSeconds` | the same request let through in any window of that many seconds | 429 `loop_suspected`, `Retry-After` until the oldest copy leaves the window |
| `maxCallsPerMinute` | calls let through in any 60 seconds | 429 `rate_limited`, `Retry-After` until the oldest of them is a minute old |
| `runMaxCalls` | calls in one run | 429 `run_limit_reached`, no `Retry-After`: waiting does not help |
| `runMaxSeconds` | time since the run's first call (at most a day) | 429 `run_limit_reached`, no `Retry-After` |
| `runMaxTokens` | a run's booked input and output tokens, plus what its calls in flight hold, plus this call's estimate | 429 `run_limit_reached`, no `Retry-After` |
| `runMaxUsd` | a run's settled dollars, plus what its calls in flight hold, plus this call's estimate | 429 `run_limit_reached`, no `Retry-After` |

"The same request" means the same `model`, `messages`, `tools`, `tool_choice` and `n`, in any key
order, compared by the SHA-256 of their canonical JSON; only copies that went through count. It is
the loop that resends one failed call unchanged, which is cut at once. An agent that is getting
somewhere sends different messages each time, so this limit leaves it alone. Its counts live in the
gateway's memory, not in the ledger: one gateway process serves a state directory
([ADR 0003](adr/0003-single-writer-state.md)), and a restart forgets at most one window.

A run is what the client names in its `x-run-id` header (a plain id, see [Tracing](#tracing)); the
ledger forgets a run a day after its last call, admitted or refused, so a loop that keeps knocking on a
stopped run stays stopped. The run caps are a stop rule for a loop that keeps its
run id, not a security boundary: a client that sends no `x-run-id`, or a new one for every call, is
held only to `maxCallsPerMinute` and the caps. Each refusal is a usage line with `error`, the limit
as `rule`, `exit` (`budget`), `why`, and `runId`. `test/llm/limits.test.ts` runs a loop against a live gateway and checks
that it is cut at the sixth call of a minute, that a run is cut at its third call and before it can
pass its dollars, and that another run is not; and that with `repeatMax` 5 in 60 seconds the sixth
copy of a request is refused, other requests and other keys are not, and the copy goes through again
once the window has moved on.

**Loop exits: ship, budget, flat line.** A loop that grades its own work (propose, judge, propose
again) needs an end that the loop does not decide for itself. A key can give its runs three exits, and
the loop asks the gateway after each graded round: `POST /v1/runs/score` with the same key and
`x-run-id`, and `{"score": <number>}`. The gateway answers `continue`, `ship` or `stop`, checking in
this order:

| Exit | Field | When |
| --- | --- | --- |
| ship | `runShipScore` | the round's score is at least this |
| budget | `runMaxRounds` | the run has reported this many scores; or a limit the gateway counts is used up: `runMaxCalls`, `runMaxSeconds`, `runMaxTokens`, `runMaxUsd` |
| flat line | `runFlatRounds`, with `runMinGain` (default 0) | this many scored rounds in a row gained no more than `runMinGain` over the best score |

From a run with `"runShipScore": 0.9, "runMaxRounds": 4, "runFlatRounds": 2, "runMinGain": 0.01` and
`"runMaxCalls": 12, "runMaxSeconds": 600` on the key, after rounds that scored 0.62 and 0.81:

```
$ curl -s http://127.0.0.1:8787/v1/runs/score -H "authorization: Bearer $KEY" -H "x-run-id: rewrite-7" -d '{"score": 0.93}'
{"run":"rewrite-7","decision":"ship","exit":"ship","rule":"runShipScore","why":"round 3 scored 0.93, at or above the ship score 0.9","stoppedAt":"2026-11-03T10:07:30.908Z","score":0.93,"round":3,"best":0.93,"flat":0,"spent":{"calls":3,"seconds":0,"tokens":330,"usd":0.00033},"limits":{"minGain":0.01,"calls":12,"rounds":4,"seconds":600,"shipScore":0.9,"flatRounds":2}}
```

A run starts with its first call (for a key with run limits, or a run that declared a budget), and a
score for a run the key has no record of is refused with 404 `run_not_found`: a report costs nothing,
so it cannot add runs to the ledger. Ship and stop end the run for good. Every later call in it is
refused, and says why:

```
HTTP/1.1 429 Too Many Requests

{"error":{"message":"agent-gate: run \"rewrite-7\" of key \"rewriter\" has shipped at 2026-11-03T10:07:30.908Z: round 3 scored 0.93, at or above the ship score 0.9 (runShipScore). Use its last result; the run takes no more calls.","type":"insufficient_quota","param":null,"code":"run_stopped","cap":"runShipScore","exit":"ship"}}
```

A later score changes nothing: the answer repeats the decision, with `"already": true`.

**The caps are the key's.** The numbers come from the gateway's config, which the agent cannot change.
A client may lower its run's limits with an `x-run-budget` header on its calls or its score reports
(`calls=12, rounds=4, seconds=600, tokens=50000, usd=0.25`), as a loop that sets its own budget does,
and the run keeps the lowest it ever declared. It can never raise them: a field above the key's cap
leaves the cap in force, and every usage line of the call says so (`"budgetClamped": ["calls"]`).
That is worth an alert: a loop that asks for more than it is allowed may have been changed to ask.
A budget that cannot be read, or one sent without `x-run-id`, is refused with 400
`invalid_run_budget`. The score is the client's claim, so it can only end a run early: a loop that
reports nothing, or reports a rising score every round, is still held by the limits the gateway counts
itself (calls, seconds, tokens, dollars), and those bound the money. A new run id is a new run; what
bounds all of a key's runs together is its daily and monthly caps and `maxCallsPerMinute`.

Every stop is in the usage log. A refused call has `error` (`run_limit_reached`, or `run_stopped`
for a run that a score report ended), the limit as `rule`, `exit` and `why`. A score report is a line
of its own, which costs nothing and which `usage --by` does not count as a call:

```json
{"ts":"2026-11-03T10:07:30.913Z","id":"req-5ad526e8","event":"run-score","key":"rewriter","status":200,"score":0.93,"round":3,"best":0.93,"flat":0,"decision":"ship","exit":"ship","rule":"runShipScore","why":"round 3 scored 0.93, at or above the ship score 0.9","inputTokens":0,"outputTokens":0,"costUsd":0,"latencyMs":5,"traceId":"b4aee0427bc401aac4d4d6a38b3cca07","spanId":"c58e2979434cba61","runId":"rewrite-7"}
```

`test/llm/loop-exits.test.ts` drives each exit on a live gateway, and checks that a run asking for
more than the key's cap is held to the cap, that a run can lower its own budget but not raise it back,
that a stopped run refuses its calls and ignores later scores, and that every stop is in the usage log
with its reason.

**Booked once.** A reservation is settled at most once. A second settle of the same id books
nothing, and a settle whose reservation had already expired (a call that outlived its reservation)
books the cost once and is marked `"settle": "orphan"` in its usage line. `agent-gate usage --verify`
checks the result from outside: for every key, today's and this month's dollars in the usage log
must equal the ledger's, and it exits 1 when they do not (a usage line was lost, a cost was booked
twice, or a file was edited). From the run above:

```
$ agent-gate usage --verify --config llm-gateway.config.json
key         day         ledger      usage log   month    ledger      usage log   result
demo-agent  2026-10-31  $0.0002346  $0.0002346  2026-10  $0.0002346  $0.0002346  ok
```

The ledger is `<stateDir>/ledger.json` (mode 0600). It is changed with the same locked
read-modify-write and atomic rename as the approval queue, and a damaged ledger is an error, never
an empty one, because an empty one would hand every key its whole budget again. Reservations of a
gateway that crashed mid-call expire on their own. The CLI shows the ledger:

```
$ agent-gate usage --config llm-gateway.config.json
key         today (2026-10-31 UTC)  this month (2026-10)  in flight
demo-agent  $0.0002346 of $0.01     $0.0002346 of $1      0
```

`--json` prints the same as JSON.

## Leak guard

Before a call is forwarded, its message text is scanned with the regex rules in the policy file.
A `block` rule refuses the call with 400 and names the rule, never the text it matched. A `redact`
rule replaces what it matches with `[REDACTED:<id>]` and lets the call go on, and the response
names the rules that redacted in an `x-agent-gate-redacted` header. If a redact rule's regex has
capture groups, only the first group that took part in the match is replaced, so
`api_key = "..."` keeps its name and quotes, and JSON in tool-call arguments stays valid JSON.
Block rules are checked first, on the original text, so a redaction cannot hide a blocked secret.

`llm-policy.example.json` ships thirteen rules:

| Rule | Matches | Action |
| --- | --- | --- |
| `gcp-service-account-key` | the `private_key` field of a Google Cloud service-account JSON key file: a PEM private key inside a JSON string | block |
| `private-key` | a PEM or OpenSSH private key block (RSA, EC, OPENSSH, PGP and others) | block |
| `aws-access-key-id` | an AWS access key id: `AKIA`, `ASIA`, `ABIA` or `ACCA` and 16 more characters | block |
| `github-token` | a GitHub token: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, or a fine-grained `github_pat_` | block |
| `slack-token` | a Slack token: `xoxb-`, `xoxp-`, `xoxa-`, `xoxo-`, `xoxs-` or `xoxr-` | block |
| `sk-style-key` | a provider key that starts with `sk-` (`sk-proj-`, `sk-ant-` and others), 20 or more characters with a digit | block |
| `huggingface-token` | a Hugging Face access token: `hf_` and exactly 34 letters or digits | block |
| `google-api-key` | a Google API key: `AIza` and 35 more letters, digits, `-` or `_` | block |
| `api-key-assignment` | a value given to a name such as `api_key`, `client_secret`, `access_token` or `password`: quoted with 12 or more characters, or unquoted with 16 or more, and containing a digit; only the value is replaced | redact |
| `credit-card` | a payment card number: 13 to 19 digits starting with 2 to 6, with spaces or dashes or none, that passes the Luhn check | redact |
| `jp-my-number` | a Japanese Individual Number (My Number): 12 digits, as 4-4-4 with spaces or dashes or none, whose last digit is the check digit of the official formula | redact |
| `us-ssn` | a US Social Security number written 3-2-4 with dashes or spaces, in the ranges the SSA assigns (never 000, 666 or 900 to 999 first, 00 in the middle or 0000 last) | redact |
| `us-itin` | a US Individual Taxpayer Identification Number written the same way: 9 first, and 50 to 65, 70 to 88, 90 to 92 or 94 to 99 as the fourth and fifth digits | redact |

The formats that are surely secrets block, because a key that was pasted into a prompt should be
rotated, not quietly dropped. The service-account rule comes before `private-key`, so a pasted
key file is reported under its own name. Model-hub and cloud keys tend to travel through setup
notes, notebooks and shell history (a token saved to a text file while deploying a model, for
example), which is how they end up in prompts; the Hugging Face rule takes exactly 34 characters
so that long `hf_...` names in code are not blocked. The heuristic rule redacts: it has more false positives, and a guess
should not refuse a whole request. Every rule is also tested against prose and code that must
pass untouched, such as `const apiKey = process.env.OPENAI_API_KEY;`,
`password = get_password_from_vault()`, a public key block and `"api_key": "<your-api-key-here>"`.

The last four find personal numbers that a support or HR agent may paste into a prompt. A regex alone
cannot tell a card number from a 16-digit order id, so each of these rules names a `validator`: the
regex finds what is shaped like the number, and the validator says whether it can be one. Card numbers
must pass the Luhn check; a My Number must end in the check digit that the Ministry of Internal Affairs
and Communications defines (Ordinance No. 85 of 2014, article 5); an SSN or an ITIN must be in the
ranges that the SSA or the IRS assigns. A number of the right shape picked at random passes the card or
the My Number check one time in ten. A number must also stand on its own: the tail of a UUID or of
another hyphenated id is not read as one. When a match fails its check, the runs of whole digit groups
inside it are tried too, longest first, so a card number followed by its expiry date or its security
code (`... 12/27`, `... 123`), which the regex takes in as more digits, is still found. These rules
also read full-width digits, hyphens and spaces, as Japanese forms often write a number, as their
ASCII forms. They redact rather than block, so that a conversation about an
order goes on without the number in it. A validator holds wherever its rule is used: for a block rule,
on the answer, and in the MCP gateway's result guard. `src/llm/validators.ts` cites its sources; every
number the tests use is built at run time with its check digit computed, so none appears in the
repository.

**What it is not for.** The threat matrix (`test/llm/threat-matrix.json`) holds 32 prompts: secrets,
personal numbers, prompt injections, jailbreaks and requests for dangerous instructions, each with what
the leak guard does with it, and the leak guard covers 17 of them: every secret format in the policy,
the four personal numbers (a card number also when its expiry date follows it, a My Number also in
full-width digits), and an order number that is left alone because it fails the card check. The
other 15 pass untouched, and each row says why: a secret that is encoded or split across two messages,
an email address, a phone number, a name and an address, and every injection, jailbreak and harmful
request. Those are matters of meaning that a regex cannot read; they belong to a classifier, to the
model provider's safety layer, or, for what an agent does next, to the MCP gateway's policy.
`test/llm/threat-matrix.test.ts` runs every row, so a gap cannot close, or open, without the matrix
saying so.

From the run above (headers shortened):

```
$ curl -s -i ... -d '{"model":"small","messages":[{"role":"user","content":"Why does ssh reject this key? -----BEGIN OPENSSH PRIVATE KEY----- (rest cut)"}]}'
HTTP/1.1 400 Bad Request

{"error":{"message":"agent-gate: the messages contain text that looks like a secret (rule private-key), so the request was not sent. Remove it and try again; if it was a real secret, rotate it.","type":"invalid_request_error","param":"messages","code":"secret_detected","rule":"private-key"}}

$ curl -s -i ... -d '{"model":"small","messages":[{"role":"user","content":"Is this config line right? api_key = \"fake0000fake0000\""}]}'
HTTP/1.1 200 OK
x-agent-gate-route: cheap-models
x-agent-gate-upstream: cheap
x-agent-gate-cost-usd: 0.0000102
x-agent-gate-redacted: api-key-assignment
```

The upstream received `Is this config line right? api_key = "[REDACTED:api-key-assignment]"`.

The guard scans message `content` (a string, or the `text` of text parts), the `arguments` of
assistant tool calls (and of the older `function_call`), and `reasoning_content`, `reasoning` and
`refusal`. It does not scan image, audio or file parts, tool definitions or other request fields. A rule is `{ "id", "regex", "flags", "action", "description", "validator" }` (the last two
optional); `flags` may use `i`, `m`,
`s` and `u`, as in the MCP policy, and a regex that matches empty text is refused at startup.

**The answer goes through the same rules.** A model can write a secret it was never sent in the
text the guard read: one it read off an image or a file part, one it repeats from earlier in a long
context, or one it makes up in a known shape. So after a call is settled, every string in the
answer is scanned: the content and tool-call arguments of every choice, its reasoning or refusal text,
and any field a provider adds, so nothing the client gets is left unread. A block rule withholds the answer: the client gets 502 `response_blocked` with the rule's
name and never the text, and the call stays booked, because the provider was paid. A redact rule
edits the answer, and `x-agent-gate-response-redacted` names the rules. The usage line says which
side a block was on (`"side": "prompt"` or `"response"`) and lists redactions in the answer as
`responseRedacted`. `"scanResponses": false` turns this off; the cost of leaving it on is that a
model that writes an example key in a known shape gets it refused or edited, exactly as a prompt
with that key would be. `test/llm/response-guard.test.ts` checks every block rule on both sides.

## Keeping personal data local

Some text may be read by a model but may not leave the machine or the network: a customer's card
number, a My Number. Refusing the call stops the work, and redacting the number removes what the work
needs. `divert` sends such a call to a model you run yourself instead, with its text as it was:

```json
"divert": {
  "rules": ["credit-card", "jp-my-number", "us-ssn", "us-itin"],
  "to": { "upstream": "local", "model": "small" }
}
```

`llm-gateway.config.ollama.example.json` has this, an upstream named `local` at Ollama's
OpenAI-compatible address (`http://127.0.0.1:11434/v1`, priced at zero), and a cloud upstream that
every other call goes to as before.

- `rules` are leak-guard rule ids. When one of them matches a call's messages, the call goes to
  `to.upstream` and nowhere else: no fallback, and nothing redacted. Its reservation is priced at that
  upstream. If the upstream lacks the alias (`to.model`, else the one the client asked for) or does not
  answer, the call fails; it is never sent to the cloud instead.
- Block rules still come first: a private key next to a card number is refused, not diverted. A block
  rule that `rules` lists diverts instead of blocking, and does not withhold the local model's answer
  either: the answer is read with the rules the prompt was read with.
- The target must look local: a loopback address or `localhost`, a private IPv4 range (10/8,
  172.16/12, 192.168/16), an IPv6 unique local address, or a name with no dot in it (a container or a
  service). Anything else stops the gateway at startup. Only the address is checked; what answers
  there is the operator's to vouch for.
- The answer goes through the response guard like any other, with those rules, so a number the model
  repeats is redacted on its way back, and a secret that no divert rule lists is withheld.
- The response names the rules in `x-agent-gate-diverted`, and the usage line in `diverted`, with no
  text.

Ollama does not check API keys, but `apiKeyEnv` needs a value, and the gateway cuts that value out of
everything an upstream sends back (see [Keys](#keys)). Give it a long random one, such as
`OLLAMA_API_KEY=local-$(openssl rand -hex 16)`, not a word like `ollama` that the answers contain. A
real run against Ollama on this machine, with the example's model changed to `qwen2.5:3b` (one that
was installed); `request.json` asks whether a made-up number that passes the Luhn check is a card
number, and to repeat it (the `Date` and connection headers are left out):

```
$ curl -s -i http://127.0.0.1:8787/v1/chat/completions -H "Authorization: Bearer $GATEWAY_KEY" \
    -H "content-type: application/json" -d @request.json
HTTP/1.1 200 OK
x-agent-gate-request-id: req-36184c47
x-agent-gate-trace-id: 0e7d6cfefe50c1575fa390439a925e73
content-type: application/json
content-length: 397
x-agent-gate-route: cloud-models
x-agent-gate-upstream: local
x-agent-gate-cost-usd: 0
x-agent-gate-diverted: credit-card
x-agent-gate-response-redacted: credit-card

{"id":"chatcmpl-32","object":"chat.completion","created":1793429586,"model":"qwen2.5:3b","system_fingerprint":"fp_ollama","choices":[{"index":0,"message":{"role":"assistant","content":"No, that sequence is not a valid card number. [REDACTED:credit-card]"},"finish_reason":"stop"}],"usage":{"prompt_tokens":73,"prompt_tokens_details":{"cached_tokens":72},"completion_tokens":32,"total_tokens":105}}
```

Nothing went to the cloud upstream. The usage line:

```json
{"ts":"2026-10-31T06:53:06.780Z","id":"req-36184c47","key":"demo-agent","route":"cloud-models","upstream":"local","model":"qwen2.5:3b","status":200,"inputTokens":73,"outputTokens":32,"costUsd":0,"usage":"upstream","attempts":1,"fallback":false,"diverted":["credit-card"],"responseRedacted":["credit-card"],"latencyMs":356,"traceId":"0e7d6cfefe50c1575fa390439a925e73","spanId":"04986317c7e73252"}
```

## Streaming

A request with `"stream": true` gets its answer as server-sent events, in the format of OpenAI's chat
completions. Steps 1 to 5 do not change: a stream is authenticated, routed, checked by the leak guard
and reserved against the budget before anything is sent upstream. From the run above (the `Date`,
connection and transfer headers are left out):

```
$ curl -s -i -N http://127.0.0.1:8787/v1/chat/completions \
    -H "Authorization: Bearer $GATEWAY_KEY" \
    -H "content-type: application/json" \
    -d '{"model":"small","messages":[{"role":"user","content":"Say hello in five words."}],"stream":true}'
HTTP/1.1 200 OK
x-agent-gate-request-id: req-dcf34475
x-agent-gate-trace-id: dd177ac97093d07fabc9b5e8bb120cb5
content-type: text/event-stream; charset=utf-8
cache-control: no-cache
x-agent-gate-route: cheap-models
x-agent-gate-upstream: cheap
x-agent-gate-cost-usd: 0.00000855

data: {"id":"chatcmpl-fake-4","object":"chat.completion.chunk","created":1760400000,"model":"fake-small-1","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}

data: {"id":"chatcmpl-fake-4","object":"chat.completion.chunk","created":1760400000,"model":"fake-small-1","choices":[{"index":0,"delta":{"content":"fake answer 4"},"finish_reason":null}]}

data: {"id":"chatcmpl-fake-4","object":"chat.completion.chunk","created":1760400000,"model":"fake-small-1","choices":[{"index":0,"delta":{"content":" from fake-small-1"},"finish_reason":null}]}

data: {"id":"chatcmpl-fake-4","object":"chat.completion.chunk","created":1760400000,"model":"fake-small-1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]
```

- The gateway always asks the upstream for the usage chunk (`stream_options.include_usage`), so the
  call is settled from the provider's own count, here 21 input and 9 output tokens. The client gets
  that chunk only if it asked for it too; this one did not.
- Retries, the fallback and the 429 handling work as for any call until an upstream answers. Once one
  has answered with a stream, nothing is retried.
- **Held until it is scanned.** With `scanResponses` on (the default), the gateway reads the whole
  stream before it sends any of it and runs the leak guard twice: over each choice's message put back
  together (the content, text parts, reasoning and refusal text, and each tool call's arguments, which
  arrive in fragments), so that a secret split across chunks is found; and over every string of every
  chunk, fields the gateway does not put together included. A chunk it cannot put together (a choice
  or a tool call without an index, content that is not text) is not guessed at: 502
  `bad_upstream_response`, booked. A block rule withholds the answer: 502 `response_blocked`, booked.
  A redact rule edits it: a match inside one chunk's own field is replaced in that chunk; a match in
  the message put together means the stream is rebuilt from what was scanned: one chunk per choice
  with the whole edited message, one with its finish reason, then the usage chunk if the client asked
  for it, and `[DONE]`. The same rebuild happens when one of the gateway's upstream keys appears split
  across chunks, so that it can be cut out. Otherwise the upstream's events go out as they came. The
  client keeps the format and loses the speed: the first token arrives with the last, which is why the
  answer above came with its cost in a header.
- **Relayed.** With `"scanResponses": false`, events go to the client as they arrive, and nothing
  reads the answer first, so a key that a model writes reaches the client. `test/llm/stream.test.ts`
  sends a token split across two chunks through both modes.
- **Stopped.** When the client goes away, the upstream request is aborted at once, so the model stops
  generating. A stream that sends nothing for `streamIdleMs` (30 seconds by default) is stopped too,
  and `timeoutMs` still bounds the whole answer, also for a relayed stream whose client stops reading:
  the gateway waits for such a client only until the attempt's time is up, then cuts the upstream off
  and settles the call, and a client that still has not taken the end of the stream `streamIdleMs`
  later is disconnected. A relayed stream that is stopped or breaks off ends with an error event in
  the gateway's own words (`upstream_error` or `upstream_timeout`) and no `[DONE]`; a held one gets 502
  or 504. A provider's own error event is never passed on, because it can quote the key it was sent.
  In a relayed stream, the gateway's upstream keys are cut out of each event on its own, so a key that
  a model writes across two events is not.
- **Booked.** A stream that ends without a usage chunk (cut short, stopped, its client gone, or from a
  provider that ignores `include_usage`) is booked at its estimate, the most it could have cost: the
  provider bills what it generated, which the gateway cannot see. A request that never got an answer
  costs nothing. `streamEnd` in the usage line says how a stream ended: `done`, `client_closed`,
  `upstream_error`, `idle_timeout` or `timeout`. A client that left before anything was sent is
  recorded with status 499.

Why the default holds the stream, and what other gateways do about the same problem:
[ADR 0011](adr/0011-streaming.md).

## Usage log

Every authenticated call appends one JSON line to `<stateDir>/usage.jsonl` (mode 0600). These are
the lines from the run above:

```json
{"ts":"2026-10-31T06:25:28.251Z","id":"req-50a14662","key":"demo-agent","task":"classify","route":"classify-is-cheap","upstream":"cheap","model":"fake-small-1","status":200,"inputTokens":23,"outputTokens":9,"costUsd":0.00000885,"usage":"upstream","attempts":1,"fallback":false,"latencyMs":26,"traceId":"a8576eb80c1788fff01a9e61dc87c7ea","spanId":"137e55b29d8a3bd8"}
{"ts":"2026-10-31T06:25:28.270Z","id":"req-d273624f","key":"demo-agent","route":"strong-models","upstream":"strong","model":"fake-large-1","status":200,"inputTokens":24,"outputTokens":9,"costUsd":0.000207,"usage":"upstream","attempts":1,"fallback":false,"latencyMs":11,"traceId":"adb88b2126f5a302f0181c0c747479e0","spanId":"78c764835910b6ff"}
{"ts":"2026-10-31T06:25:28.277Z","id":"req-71356535","key":"demo-agent","route":"cheap-models","upstream":"cheap","model":"fake-small-1","status":400,"error":"secret_detected","rule":"private-key","side":"prompt","inputTokens":0,"outputTokens":0,"costUsd":0,"latencyMs":0,"traceId":"86e26e1f7776d62c973b1ab40dab1d4c","spanId":"a8f5c5a54fbcc58a"}
{"ts":"2026-10-31T06:25:28.294Z","id":"req-463eb037","key":"demo-agent","route":"cheap-models","upstream":"cheap","model":"fake-small-1","status":200,"inputTokens":32,"outputTokens":9,"costUsd":0.0000102,"usage":"upstream","attempts":1,"fallback":false,"redacted":["api-key-assignment"],"latencyMs":12,"traceId":"cfeb7276234e9357a5f68c7aa8969116","spanId":"e7ac986e6e90516f"}
{"ts":"2026-10-31T06:25:28.305Z","id":"req-9b4eb8e3","key":"demo-agent","route":"strong-models","upstream":"strong","model":"fake-large-1","status":429,"error":"budget_exceeded","rule":"daily","inputTokens":0,"outputTokens":0,"costUsd":0,"latencyMs":5,"traceId":"3111766223a75731e4dc626d51db9960","spanId":"a7a52f8786d1071f"}
{"ts":"2026-10-31T06:25:28.324Z","id":"req-dcf34475","key":"demo-agent","route":"cheap-models","upstream":"cheap","model":"fake-small-1","status":200,"inputTokens":21,"outputTokens":9,"costUsd":0.00000855,"usage":"upstream","attempts":1,"fallback":false,"stream":true,"streamEnd":"done","latencyMs":13,"traceId":"dd177ac97093d07fabc9b5e8bb120cb5","spanId":"0674f18b5459dd24"}
```

There is no prompt or completion text in it, on purpose. Prompts carry whatever the agent read or
was told, including secrets and personal data, and completions repeat it. The usage log is for
cost and availability: it is kept for a long time and read by people who need the tokens and the
dollars, not the conversation. `id` ties a line to the `x-agent-gate-request-id` the client got.
`usage` says whether the tokens came from the upstream or, when it reported none, from the
estimate, and `attempts` and `fallback` show retries and fallbacks. `task` is the `x-agent-task`
header, on one line and cut at 100 characters. `traceId` and `spanId` are the call's trace and the
gateway's span in it (see [Tracing](#tracing)). A streamed call has `"stream": true` and `streamEnd`,
how it ended (see [Streaming](#streaming)). A call that a run limit refused has `exit` and `why`, and
a call whose `x-run-budget` asked for more than the key's caps has `budgetClamped`. A loop's score
report is a line with `"event": "run-score"` and no cost (see Loop exits under [Budgets](#budgets)).

`agent-gate usage --by task` adds the log up per task: which kind of work spends the money, and which
one trips the leak guard. From the run above:

```
$ agent-gate usage --by task --config llm-gateway.config.json
task      requests  ok  input tokens  output tokens  cost         leak blocked  leak redacted
(none)    5         3   77            27             $0.00022575  1             1
classify  1         1   23            9              $0.00000885  0             0
```

`--by` also takes `key`, `route`, `upstream`, `model`, `session` and `runId`; `--json` prints the
rows as JSON. It counts calls: score reports are left out.

## Tracing

Every call belongs to a [W3C Trace Context](https://www.w3.org/TR/trace-context/) trace, so a
usage line can be joined with the agent's own trace and with the provider's logs:

- A client that sends a valid `traceparent` header (version 00) puts the call in its trace: the usage
  line keeps the trace id and the client's span (`parentSpanId`). Without one, or with one that does
  not fit the format, the call starts a new trace.
- The gateway makes a span id of its own for each call (`spanId`) and sends the upstream a
  `traceparent` with the trace id and that span, keeping the client's sampled flag (a new trace is
  sent as not sampled). The answer carries the trace id in `x-agent-gate-trace-id`. An upstream
  that refuses unknown headers would refuse that one; `"sendTraceparent": false` keeps the trace in
  the usage log and sends nothing (LiteLLM documents such failures with some providers and makes
  forwarding opt-in; see [docs/related-work.md](related-work.md)).
- `x-agent-session` and `x-run-id` are written as `session` and `runId` when they are plain ids
  (letters, digits, `.`, `_`, `:` and `-`, up to 128 characters). A header that does not fit is left
  out, and `contextDropped` names it.

The gateway records ids; it does not export spans to a tracing backend. The MCP gateway reads the
same ids from a tool call's `_meta` (see [Audit log](mcp-gateway.md#audit-log)).

## Metrics

`GET /metrics` gives the usage log's running totals in the Prometheus text format, for a dashboard
and alerts: calls by route, upstream and status, tokens and dollars booked, a histogram of how long
calls take, and what each key may still spend today and this month. The counters start at zero when
the gateway starts; the budget figures are read from the ledger at each scrape.

It is not served unless the config says who may read it, because it names every key and its spend:

- `"metrics": { "sha256": "<SHA-256 of a metrics key>" }` serves it on the gateway's port to a client
  that sends that key as `Authorization: Bearer`. It must not be a gateway key: an agent's key does
  not read every key's spend.
- `"metrics": { "listen": { "host": "127.0.0.1", "port": 9464 } }` opens a listener of its own that
  serves `GET /metrics` only, with no key. Its host must be a loopback address (`127.0.0.1` or `::1`);
  anything else stops the gateway at startup. This is for a scraper next to the gateway, such as a
  sidecar in the same Cloud Run instance, which cannot send a key
  ([deploy/README.md](../deploy/README.md#metrics)).

A scrape at the end of the run above, which had the second form added to its config:

```
$ curl -s http://127.0.0.1:9464/metrics
# HELP agent_gate_llm_requests_total Authenticated chat completion requests, by route, upstream and HTTP status.
# TYPE agent_gate_llm_requests_total counter
agent_gate_llm_requests_total{route="cheap-models",upstream="cheap",status="200"} 2
agent_gate_llm_requests_total{route="cheap-models",upstream="cheap",status="400"} 1
agent_gate_llm_requests_total{route="classify-is-cheap",upstream="cheap",status="200"} 1
agent_gate_llm_requests_total{route="strong-models",upstream="strong",status="200"} 1
agent_gate_llm_requests_total{route="strong-models",upstream="strong",status="429"} 1
# HELP agent_gate_llm_tokens_total Tokens booked: input and output.
# TYPE agent_gate_llm_tokens_total counter
agent_gate_llm_tokens_total{direction="input"} 100
agent_gate_llm_tokens_total{direction="output"} 36
# HELP agent_gate_llm_cost_usd_total US dollars booked against the gateway keys.
# TYPE agent_gate_llm_cost_usd_total counter
agent_gate_llm_cost_usd_total 0.0002346
# HELP agent_gate_llm_request_duration_seconds Time from receiving a request to answering it.
# TYPE agent_gate_llm_request_duration_seconds histogram
agent_gate_llm_request_duration_seconds_bucket{le="0.05"} 6
agent_gate_llm_request_duration_seconds_bucket{le="0.1"} 6
agent_gate_llm_request_duration_seconds_bucket{le="0.25"} 6
agent_gate_llm_request_duration_seconds_bucket{le="0.5"} 6
agent_gate_llm_request_duration_seconds_bucket{le="1"} 6
agent_gate_llm_request_duration_seconds_bucket{le="2.5"} 6
agent_gate_llm_request_duration_seconds_bucket{le="5"} 6
agent_gate_llm_request_duration_seconds_bucket{le="10"} 6
agent_gate_llm_request_duration_seconds_bucket{le="30"} 6
agent_gate_llm_request_duration_seconds_bucket{le="60"} 6
agent_gate_llm_request_duration_seconds_bucket{le="+Inf"} 6
agent_gate_llm_request_duration_seconds_sum 0.067
agent_gate_llm_request_duration_seconds_count 6
# HELP agent_gate_llm_budget_remaining_usd What a key may still spend: its cap minus settled spend minus what calls in flight hold.
# TYPE agent_gate_llm_budget_remaining_usd gauge
agent_gate_llm_budget_remaining_usd{key="demo-agent",cap="daily"} 0.0097654
agent_gate_llm_budget_remaining_usd{key="demo-agent",cap="monthly"} 0.9997654
```

## Keys

- Gateway keys are stored only as SHA-256 hashes, and looked up by their hash.
- Upstream keys are read from the environment once, at startup. Each is sent only to its own
  upstream, as `Authorization: Bearer`, and is never logged or returned.
- An upstream's error body is never passed on as it is, because a provider can quote the key it
  was given. A 401 or 403 becomes a 502 `upstream_auth_failed` with the gateway's own message, a
  5xx becomes the gateway's 502 or 504, a 429 the gateway's 429 `upstream_rate_limited` (see
  [Routing](#routing)), and any other 4xx is passed on with the upstream keys cut out. So is every
  answer, streamed or not: each upstream key's value is replaced wherever it appears.
- Client headers are not forwarded (the client's `Authorization` holds the gateway key), and
  redirects from an upstream are refused. The one header the gateway adds of its own is a
  `traceparent`, built from the checked trace id and the gateway's span id.

The end-to-end test runs fake upstreams that quote the key they receive, and checks that no
provider key appears in any response, in the state files or in the gateway's log.

## What the LLM gateway does not cover

- Token by token delivery of a scanned answer. With `scanResponses` on, a stream reaches the client
  all at once, when it is complete; turning the scan off gives real streaming, unscanned (see
  [Streaming](#streaming)).
- Other endpoints: embeddings, images, audio, the Responses API, legacy completions. Only
  `POST /v1/chat/completions`, `POST /v1/runs/score` (a loop's score report, see Loop exits under
  [Budgets](#budgets)) and `GET /healthz` exist.
- Provider-specific features. The request body is forwarded as it is, apart from `model`, redacted
  `messages` and a missing `max_tokens`, so provider fields pass through, but nothing translates
  between provider APIs: an upstream has to speak the OpenAI chat completions format. A model that
  accepts only `max_completion_tokens` needs the client to send it, because the default limit is
  sent as `max_tokens`.
- Exact token counting. Before a call, input tokens are characters / 4, and image or audio parts
  count for nothing; after it, the upstream's own `usage` is booked. The ADR says what that means
  for the caps.
- Secrets the leak guard does not know. It is a list of regexes, on the request and the answer, so a
  secret in a format it does not know, split across messages, or encoded (base64, for example) gets
  through. A held stream is put back together before it is read; a relayed one is not read at all.
- Token rate limits, and budgets per route or per model. Budgets, calls per minute, run caps and
  repeats are per key.
- Prices are config values. Keep them in step with the providers' price lists.
- More than one host. The ledger is a file on one machine (see the ADR).
- TLS. The gateway speaks plain HTTP: bind it to localhost, as the example does, or put it behind a
  proxy that terminates TLS.
- Upstream health. `/healthz` reports that the process is up; it does not call the upstreams,
  because a probe that did would spend money.
- Cancelling a call that is not streamed. When its client disconnects, the upstream call goes on,
  finishes and is booked. A stream is cut off at once (see [Streaming](#streaming)).
