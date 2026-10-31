# ADR 0010: Retries wait a random time up to a cap, and a 429 goes to the fallback first

Status: accepted
Date: 2026-10-31

## Context

The LLM gateway calls a provider for every chat completion, and providers fail in a few distinct
ways: a 5xx or a dropped connection (the provider broke), a timeout (it is slow), a 408 (it did not
get the whole request in time), and a 429 (it refuses for now: a rate limit or a quota). Two things
bound what the gateway may do about them:

- **Time.** A call's budget reservation must outlive the call, so it lives `longestCallMs` plus a
  minute (ADR 0002), and on Cloud Run the request timeout must be longer than the longest call
  (`test/llm/deploy.test.ts` pins 300 s against 242.5 s). Whatever the retry rule, its total time
  has to be computable in advance.
- **Many callers at once.** A gateway serves many agents. When a provider blips, all of their calls
  fail at the same moment. If every one of them waits the same 250 ms, 500 ms, 1 s, they all come
  back at the same moments too, as waves on a provider that is trying to recover.

Until now the backoff doubled from `backoffMs` with no randomness. (Until commit 1971afb, 429s were
passed on to the client as they were; point 3 below is what that commit introduced.)

## Decision

1. **A 5xx, a 408, a timeout or a failed connection is retried** on the same upstream up to
   `retries` times (at most 3), then the route's fallback gets the same treatment. A 408 belongs
   here because the server says it never ran the request.
2. **Before retry n the gateway waits a random time between 0 and min(`maxBackoffMs`,
   `backoffMs` × 2^(n−1))**: full jitter. `maxBackoffMs` defaults to 10 s, which the defaults
   (`backoffMs` 250, `retries` 1) never reach; it matters only for configs with long backoffs.
3. **A 429 moves on to the fallback at once.** Another upstream can often serve what this one
   refuses. On the last upstream there is nowhere to go: the gateway waits once for the answer's
   `Retry-After` (or `backoffMs`), plus up to a fifth more at random, never longer than
   `rateLimitWaitMs` (2 s by default), and that retry is one of the upstream's `retries`. If 429s
   continue, the client gets the gateway's own 429 `upstream_rate_limited` with the last
   `Retry-After`, and nothing is charged.
4. **Any other 4xx is the answer.** It would fail the same way again.
5. **A stream is retried only until an upstream answers** (ADR 0011).

The bound: `longestCallMs` = 2 × ((`retries` + 1) × `timeoutMs` + the sum of the backoff ceilings)
+ `rateLimitWaitMs`. Jitter only shortens a wait, so the ceilings are the worst case.
`test/llm/upstream.test.ts` runs failing calls with random values from 0 to just under 1, a 408, a
timeout and a 429 wait among them, and checks that no wait passes its ceiling and that every
attempt timing out plus every wait stays within `longestCallMs`.

## Why full jitter

Marc Brooker's simulation of the jitter variants ("Exponential Backoff And Jitter", AWS
Architecture Blog, 4 March 2015, <https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/>)
concludes that jittered backoff "should be considered a standard approach for remote clients",
that "Of the jittered approaches, “Equal Jitter” is the loser", and that "The “Full Jitter” approach
uses less work, but slightly more time". Here the work saved is load on a provider that is already
failing, which matters more than a few hundred milliseconds on a call that failed anyway. Full
jitter also keeps the bound simple: its worst case is the plain exponential ceiling.

## Consequences

- A retry can come at once (a random 0). That is intended: spreading retries out means some come
  early.
- Tests fix the random source (`UpstreamOptions.random`), so the expected waits are exact.
- The 429 wait keeps its own small jitter (0 to 20 % on top of `Retry-After`), because a server
  that names a time should not be called before it.

## Alternatives considered

- **Equal jitter** (half fixed, half random) keeps a minimum wait, and Brooker's numbers show it
  doing worse than the other two.
- **Decorrelated jitter** (each wait random up to three times the last) adapts well over many
  retries; with at most three retries per upstream it buys little and makes the bound harder to
  state.
- **Retrying 429s on the same upstream with long waits.** A `Retry-After` of minutes would hold a
  client's request, and its budget reservation, for minutes. A capped single wait, then the
  gateway's own 429, lets the client decide.
