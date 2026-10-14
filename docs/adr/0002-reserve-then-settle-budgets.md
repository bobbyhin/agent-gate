# ADR 0002: Budgets reserve an estimate before a call and settle the real cost after it

Status: accepted
Date: 2026-10-14

## Context

The LLM gateway gives every gateway key a daily and a monthly cap in US dollars. The real cost of
a call is only known after the upstream answers: its `usage` block says how many input and output
tokens it billed. Agents also make calls concurrently. A planning step can fan out dozens of calls
at once, and several agents can share one key.

The simple approach is to check the spend so far against the cap before each call and add the
real cost after it. Under concurrency it does not hold: every call that starts before the first
one finishes sees the same "spent so far", so all of them pass the check, and the cap is exceeded
by up to the cost of all of those calls together. The more parallel the agent, the bigger the
overshoot, which is the opposite of what a cap is for.

## Decision

Reserve, then settle.

1. **Before the call**, estimate its cost and reserve that amount against the key's caps:
   - input tokens: the characters of the message text (and of `tools`, if present) divided by 4;
   - output tokens: the request's `max_completion_tokens` or `max_tokens`, times `n`. When the
     request sets no limit, the gateway uses `defaultMaxTokens` and also sends it upstream as
     `max_tokens`, so the reserved output is a real upper bound;
   - price: the most expensive upstream the route may use (the primary or its fallback).

   If the settled spend in the period, plus everything still reserved by calls in flight, plus
   this estimate, would pass the daily or the monthly cap, the call is refused with HTTP 429 and a
   `Retry-After`. Nothing is sent upstream.
2. **After the call**, settle: drop the reservation and book the real cost, from the upstream's
   `usage` at the price of the upstream that answered. A 2xx answer without `usage` is booked at
   the estimate. A call that fails (a 4xx, or every attempt failing with a 5xx, a timeout or a
   connection error) releases its reservation and books nothing.

The check and the reservation are one step under the ledger's lock (and, inside one gateway
process, one synchronous function), so two calls cannot both see room that only one of them fits
in. Reservations live in `<stateDir>/ledger.json` with the settled spend, so every process that
shares the state directory sees them. Each reservation expires one minute after the longest time
a call can take (every attempt on both upstreams timing out, plus the backoff), so a gateway that
crashes mid-call does not hold budget forever.

## Why

- **Concurrent calls cannot overspend a cap.** Every call in flight holds its estimate, so the
  settled spend plus all reservations never passes the cap at the moment a call is admitted.
  Output tokens are bounded by `max_tokens`, which the provider enforces; the only slack left is
  how far the input estimate is off.
- **The books stay exact.** The estimate only decides whether a call may start. What is booked is
  what the upstream reported, so `agent-gate usage` and the usage log show real spend.
- **Failed calls cost nothing.** A provider outage does not eat a team's budget.

## Consequences

- **An estimate can refuse a call that would have fit.** `max_tokens` is usually far above what a
  model actually writes, so the estimate is usually high. Near the cap, calls are refused while
  there is still money left, and a request without a limit reserves the full `defaultMaxTokens`.
  The 429 message gives the estimate and what is left, so a client can retry with a lower
  `max_tokens`. Calls in flight also block others until they settle; for that case `Retry-After`
  is one second, not the end of the period.
- **The input estimate can be low.** Characters / 4 fits English text and code with GPT-style
  tokenizers. Other languages can take more tokens per character, and image or audio parts are not
  counted at all. A settled cost can then be higher than its reservation, and the cap can be passed
  by the sum of those errors for the calls in flight at that moment, never by more: the next
  reservation sees the settled spend and is refused.
- **A timed-out call is released, not booked.** The gateway cannot know whether the provider
  billed a call it cut off. Booking the whole estimate would charge teams for the provider's
  outages; if a provider does bill cut-off calls, the ledger under-counts them.
- **A crashed gateway leaves reservations behind** until they expire.
- **One host.** The ledger is one JSON file behind a lock directory, which is enough for one
  gateway and the CLI on one machine. Several gateway hosts sharing a budget would need a shared
  store with an atomic conditional increment, for example a database update of the form
  `reserved = reserved + x WHERE spent + reserved + x <= cap`.

## Alternatives considered

- **Check before, add after** (no reservations). Simple, and fine for one call at a time, but it
  overspends under exactly the load a cap exists for.
- **A fixed per-call limit** (refuse any call whose estimate is above some amount). It bounds a
  single call, not a day's or a month's total.
- **Rate limits** (requests or tokens per minute). They bound how fast money is spent, not how
  much. They are worth having next to budgets, and this gateway does not have them yet.
- **The provider's own spend limits.** They work per organization or project, usually per month,
  and stop everything at once. They are a good last line, but they cannot tell one agent or team
  from another.
- **Exact token counting before the call.** It needs each provider's tokenizer, and it still
  cannot know the output length; `max_tokens` is the bound either way.
