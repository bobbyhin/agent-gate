Back to the [README](../README.md)

# Operations

## Failure behavior

Every check fails closed: when a part of agent-gate cannot do its job, the call does not happen. A
guard that lets calls through when something it relies on is down (a callback that fails open when
the service it asks does not answer) turns an outage into a gap that nobody sees. The exceptions are
records written after a call has already happened; those fail loudly instead, on stderr.

| Part | What fails | What happens | Proved by |
| --- | --- | --- | --- |
| MCP shell rule | the analyzer throws | the older rules decide; what they do not block is asked about (the hook does the same, untested) | `test/gateway/failure.test.ts` |
| MCP gateway | the audit log cannot be written | no call runs | `test/gateway/failure.test.ts` |
| MCP gateway | `approvals.json` is damaged | a call that needs a human is not run and nothing is queued, because an empty queue would forget denials; calls the policy allows still run | `test/gateway/failure.test.ts`, `approvals.test.ts` |
| MCP gateway | `tools.json` (the pins) is damaged | that server's tools are not listed, and calls to them are not run | `test/gateway/tools.test.ts` |
| MCP gateway | `repeats.json` is damaged | calls under a loop limit are not run | `test/gateway/repeat.test.ts` |
| MCP gateway | it is killed (`kill -9`) mid-run | the queue survives; an approved call runs once after a restart; no state file is left half written | `test/gateway/crash.test.ts` |
| MCP gateway | a downstream server fails to start or refuses the gateway's header; the header's variable is not set | the gateway does not start, naming the server or the variable and never a header value | `test/gateway/http-downstream.test.ts` |
| MCP gateway | a remote downstream server goes away later | its calls fail, and their result lines say so; the other servers' calls go on | `test/gateway/http-downstream.test.ts` |
| MCP gateway | a local downstream server exits later | it is started again after 1 s, 2 s, 4 s ...; meanwhile its tools are not listed and a call to one is refused with the reason (rule `server-down`); after `maxRestarts` failed tries in a row it is given up; the other servers' calls go on | `test/gateway/restarts.test.ts` |
| MCP gateway | an `optional` server cannot be started | the gateway starts without it and tries it again when it is needed | `test/gateway/restarts.test.ts` |
| MCP gateway over HTTP | a request has no key or an unknown one, another `Host` or `Origin`, or another agent's session id | 401, 403 or 404 before the request reaches a session; nothing is opened or run | `test/gateway/http-endpoint.test.ts` |
| LLM gateway | `ledger.json` is damaged | the call is refused before anything is sent upstream, because an empty ledger would hand every key its whole budget again | `test/llm/failure.test.ts`, `budget.test.ts` |
| LLM gateway | a provider key's variable is not set | the gateway does not start, naming the variable | `test/llm/cli.test.ts` |
| LLM gateway | the upstream answers 5xx or 408, or times out | retries after a random wait, then the fallback; else 502 or 504, and nothing is charged | `test/llm/upstream.test.ts`, `e2e.test.ts` |
| LLM gateway | the upstream answers 429 | the fallback at once; on the last upstream, one capped wait; else the gateway's own 429, and nothing is charged | `test/llm/upstream.test.ts`, `e2e.test.ts` |
| LLM gateway | a stream breaks off, sends an error event, or goes quiet for `streamIdleMs` | the upstream is cut off; a relayed client gets an error event in the gateway's words and no `[DONE]`, a held one 502 or 504; booked at its estimate | `test/llm/stream.test.ts` |
| LLM gateway | the client of a stream goes away | the upstream request is aborted at once; booked at its estimate, or nothing if no answer had started | `test/llm/stream.test.ts` |
| After a call | an MCP result line, an LLM usage line or the ledger's settle cannot be written | the call has already run, so it is answered and the failure is reported on stderr; a settle that failed leaves its reservation until the reservation expires | `test/llm/failure.test.ts` (the usage line); the other two have no test |

## Performance

`npm run bench` and `npm run loadtest` measure the gateways with the fake servers on one machine. The
numbers below are from one run of each on 31 Oct 2026, on an Apple M5 Pro (18 cores, macOS on arm64)
with Node 22.23.1, while other work ran (load average about 3). They show where the time goes in the
gateways' own steps, not how a deployment performs: there is no network between the parts, no model
and no cloud disk.

**One call at a time** (`npm run bench`, 300 calls per path; p50, and p95 in brackets):

| Path | Straight to the fake server | Through the gateway |
| --- | --- | --- |
| an MCP call the policy allows (`echo`), example policy | 0.07 ms (0.11) | 5.96 ms (7.08) |
| the same, with the example's loop limit taken out | | 0.24 ms (0.45) |
| an MCP call that asks (`delete_file`): the request is queued | | 4.80 ms (5.75) |
| the approval: what `approvals approve --yes` does, in this process | | 4.89 ms (5.48) |
| the approved call made again, now forwarded | 0.18 ms (0.24) | 5.35 ms (6.26) |
| `approvals approve --yes` as a new process | | 85.5 ms (89.5) |
| an LLM call | 1.80 ms (2.40) | 14.70 ms (18.72) |

| `ledger.json` holds | One `reserve()` | One `settle()` |
| --- | --- | --- |
| nothing yet | 4.78 ms | 4.76 ms |
| 1,000 settled ids (50 KiB) | 4.96 ms | 4.97 ms |
| 10,000 settled ids (498 KiB) | 9.17 ms | 9.04 ms |
| 30,000 settled ids (1.5 MiB) | 21.43 ms | 21.10 ms |

- The gateways' own logic is cheap: the MCP gateway's policy, audit line and forwarding add about
  0.2 ms to a call. Making state durable is what costs. Every write of a state file (`approvals.json`,
  `repeats.json`, `ledger.json`) is a locked rewrite that ends with an `fsync`: about 5 ms on this
  disk, and the `fsync` of a 100-byte file alone takes 3.96 ms.
- The example policy's loop limit (`repeat`, see [Policy](mcp-gateway.md#policy)) counts each call it covers in
  `repeats.json`, so an allowed call costs one write: 6 ms instead of 0.24. A policy without loop
  limits, or with limits that cover only some tools, skips that write for the other calls.
- An ask, an approval and the approved call are one write each. A human approving at the CLI also
  starts Node: about 90 ms.
- An LLM call costs two ledger writes (reserve and settle): about 13 ms more than the upstream alone.
- The ledger grows with traffic. A settled reservation id stays in the file for 302.5 s, so that a
  second settle of the same id books nothing (see Booked once under [Budgets](llm-gateway.md#budgets)), and every
  write rewrites the whole file: past about 10,000 ids, the time of a write grows with the file.

**Under load** (`npm run loadtest`: 1,000 requests, 100 at a time, from a key whose daily cap fits
about half of them):

| | p50 | p95 | Answers per second |
| --- | --- | --- | --- |
| through the gateway, the 499 calls let through | 505 ms | 2,348 ms | 122 (all 1,000 answers) |
| the same requests, straight to the fake upstream | 4.1 ms | 72.7 ms | 9,283 |
| `GET /healthz`, every 100 ms during the load | 199 ms | 325 ms | |

- The cap held exactly. The key spent $0.062375 of its $0.0625: the cost of the 499 calls let through,
  and the sum of their `x-agent-gate-cost-usd` headers. The other 501 got 429 `budget_exceeded`,
  `usage --verify` found the usage log and the ledger in agreement, no reservation was left in
  flight, and nothing answered 5xx.
- The ledger writes run on Node's event loop, synchronously, so concurrent calls wait in line for
  them: with 100 calls at once, a call that was let through waited half a second at the median. A
  refused call costs a write too, because `reserve()` rewrites the ledger whether it admits the call
  or not.
- `/healthz` waits in the same line. A sustained run (15,000 requests, 50 at a time, under a cap that
  let all of them through) took 279 s: 84 answers per second over its first tenth and 39 over its
  last, as `ledger.json` grew to 750 KiB. `/healthz` answered in 663 ms at p95 and in 1.7 s at worst,
  past the 1-second timeout that Kubernetes probes have by default (`deploy/k8s/deployment.yaml` does
  not change it).
- So one gateway process on this machine keeps up a few dozen LLM calls a second. On Cloud Run the
  ledger is on Cloud Storage, where a write is several object operations; that has not been measured
  ([ADR 0003](adr/0003-single-writer-state.md)).

`npm test` runs a small load as well (`test/loadtest.test.js`: 200 requests, 50 at a time) and checks
the same budget invariants, never the timing. After a deploy, `npm run loadtest -- --url` checks the
running gateway: see [deploy/README.md](../deploy/README.md#a-smoke-test-under-load-after-a-deploy).

## Deploy

The LLM gateway ships as a container image, with three ways to run it.
[deploy/README.md](../deploy/README.md) has the steps and the details.

| What | Where |
| --- | --- |
| A multi-stage image: distroless Node 22, non-root, production dependencies only, `HEALTHCHECK` on `/healthz` | `Dockerfile`, `.dockerignore` |
| A local demo against the fake upstream, with no account and no key | `docker-compose.yml` |
| Kubernetes with kustomize: one replica, probes, resource limits, a locked-down `securityContext`, a NetworkPolicy | `deploy/k8s/` |
| Google Cloud Run with Terraform: Artifact Registry, a least-privilege service account, Secret Manager, a state bucket, 0 to 1 instance, an optional budget alert | `deploy/terraform/` |

The gateway runs as one replica, because its budget ledger is a file with a single writer;
[ADR 0003](adr/0003-single-writer-state.md) says what it takes to run more. Nothing has been
deployed to a real cloud project or cluster. The Terraform and the manifests are validated without
credentials, locally and in CI; the image build and the compose demo run in CI only.
deploy/README.md lists what ran where, and the shortcuts that cloud labs take which this setup does
not. Where agent-gate sits next to a managed agent runtime, what of a production setup it has and
what it lacks (tracing, metrics): [ADR 0007](adr/0007-where-agent-gate-sits.md).
