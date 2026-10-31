# ADR 0011: A streamed answer is held until it is scanned, unless scanning is turned off

Status: accepted
Date: 2026-10-31

## Context

Most chat clients and agent frameworks send `"stream": true`: the answer comes back as server-sent
events, a few tokens at a time, so the user sees it being written. Until now the LLM gateway refused
such requests with 400 `stream_not_supported`, because two of its jobs need the whole answer:

- **The budget.** A call is settled from the answer's `usage`. In a stream, usage comes only if the
  request sets `stream_options.include_usage`, and then in one extra chunk at the very end whose
  `choices` is empty ([OpenAI API reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create),
  `stream_options.include_usage`: "an additional chunk will be streamed before the `data: [DONE]`
  message", with "the `choices` field will always be an empty array"). "If the stream is
  interrupted, you may not receive the final usage chunk", and the reference for the chunk object
  adds "or cancelled".
- **The leak guard on the answer** (`scanResponses`, on by default). It runs regexes over each
  choice's message. In a stream that message arrives in pieces: the content in deltas, and the
  arguments of each tool call in fragments, keyed by the tool call's index.

Scanning pieces as they pass does not work safely:

- A secret can be split across two chunks. Each piece alone matches nothing; the whole does.
  `test/llm/stream.test.ts` sends a token split in half for exactly this reason.
- Holding back the last N characters of each piece (what LiteLLM calls `stream_holdback_chars`)
  catches a split only when the whole match fits in N characters. The redact rule
  `api-key-assignment` has no maximum length, and a private key block runs to thousands of
  characters, so no fixed N covers every rule.
- Once a piece has reached the client, it cannot be called back. A block found later can only end
  the stream; it cannot undo what was shown.

Other gateways meet the same problem and answer it in different ways (all read 2026-10-31). On
Google's Agent Gateway, Model Armor screens chat completions in their "non-streaming variants only"
and lets "Streamable HTTP/SSE for MCP" through unscreened
([configure Model Armor](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/configure-model-armor)),
and the semantic governance policy engine "doesn't support streamed model responses"
([semantic governance](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/semantic-governance-overview)).
In LiteLLM it depends on the guardrail: a `post_call` guardrail built on the standard hooks runs on
a stream "after all chunks have been delivered to the client", which the docs call audit-only
([custom guardrails](https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail)), while
built-in guardrails such as Bedrock's take the opposite default: LiteLLM "buffers every chunk until
the assembled response passes moderation", and "the client sees nothing until the scan completes"
([custom guardrails](https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail),
[Bedrock guardrail](https://docs.litellm.ai/docs/proxy/guardrails/bedrock)).

## Decision

Stream, with the safe behaviour as the default.

1. Steps 1 to 5 are unchanged: a streamed request is authenticated, routed, checked by the leak
   guard and reserved against the budget before anything is sent upstream.
2. The gateway always asks the upstream for the usage chunk (`stream_options.include_usage: true`),
   and passes it to the client only if the client asked for it too.
3. Retries, the fallback and the 429 handling work as for any call until an upstream answers with a
   status and headers. Once an upstream has answered with a stream, nothing is retried: part of the
   answer may already be with the client, and the provider has started to bill it.
4. **With `scanResponses` on (the default), the stream is held.** The gateway reads it to the end,
   puts each choice's message back together, and runs the leak guard over it exactly as over a
   non-streamed answer. A block rule withholds it (502 `response_blocked`, booked, since the
   provider was paid). A redact rule edits it, and the stream is rebuilt: one chunk per choice with
   the whole edited message, one with its finish reason, the usage chunk if the client asked for it,
   and `[DONE]`. Otherwise the upstream's events are sent as they came. The client keeps the
   streaming format and loses its speed: the first token arrives with the last.
5. **With `"scanResponses": false`, events are relayed as they arrive** and the answer is not read.
   That is the choice for a deployment that wants tokens on screen as they are written and accepts
   that the answers are not checked.
6. **Stopping.** When the client goes away, the upstream request is aborted at once, so it stops
   generating. A stream that sends nothing for `streamIdleMs` (30 s by default) is stopped, and the
   per-attempt `timeoutMs` still bounds the whole response, a stream included, so the longest a call
   can take, and the life of its reservation, are unchanged. A relayed stream that is stopped or
   breaks off ends with an error event in the gateway's own words and no `[DONE]`; a held one gets a
   502 or 504. A provider's own error frame is never passed on, because a provider's error can quote
   the key it was sent.
7. **Booking.** A stream is settled from its usage chunk. A stream that ended without one (cut short,
   stopped, the client gone, or a provider that ignores `include_usage`) is booked at its estimate:
   the rule that already applied to a 2xx answer without `usage`. The provider bills what it
   generated up to the moment it stopped, and the gateway cannot see how much that was, so the
   upper bound is the safe error for a cap. A request that never got an answer (the client left
   first, or every attempt failed) books nothing, as before.

The usage line of a streamed call has `"stream": true` and `streamEnd`: `done`, `client_closed`,
`upstream_error`, `idle_timeout` or `timeout`. A client that left before anything was sent is
recorded with status 499.

## Consequences

- With the default, a streaming client waits for the whole answer. That is a real cost for a chat
  interface, and no cost for an agent that acts only on complete answers.
- With `scanResponses` off, a secret in an answer reaches the client. The request side is still
  scanned in both modes, and `test/llm/stream.test.ts` shows both outcomes for the same split token.
- A stream stopped early is charged at the most it could have cost. A user who cancels a long
  answer after a few tokens uses up budget for all of them; the usage line says `"usage":
  "estimate"` so that this can be seen and argued with.
- Non-streamed calls are not cancelled when their client goes away: the call finishes and is
  booked, as before. Cutting them off would save little, since the provider has the whole request
  either way.
- `x-agent-gate-cost-usd` is sent with a held stream, whose cost is known before the headers go out,
  and not with a relayed one; the usage log has it for both.

## Alternatives considered

- **Scan pieces with a hold-back window.** It would keep most of streaming's speed, and it is
  right for rules with a short, bounded match. It is wrong for this rule set (see above), and a
  default should not depend on every rule being short. It could come back as an option for rule
  sets that are.
- **Relay by default and scan the whole answer afterwards, for the record.** That is detection, not
  prevention: the secret is already with the client when the scan finds it.
- **Keep refusing `"stream": true`.** Clients that stream would have to be changed or would go
  around the gateway, which leaves them with no budget, no leak guard and no record at all.
