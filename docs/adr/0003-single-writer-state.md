# ADR 0003: One gateway process writes the state; more replicas need a shared store first

Status: accepted
Date: 2026-10-14

## Context

The LLM gateway keeps its state in files in its state directory:

- `ledger.json`: for every gateway key, the settled spend of the current UTC day and month, and a
  reservation for every call in flight (ADR 0002).
- `usage.jsonl`: one line per call, appended.

Every change to the ledger is a read-modify-write: take a lock (a directory created with `mkdir`,
broken after 10 seconds as left behind by a crashed process), read the file, change it, write a
temporary file, `fsync` it, rename it over the old one, release the lock (`state-file.ts`). That is
correct for any number of processes on one host with a local disk, which is where it was built and
tested: the gateway and a human running `agent-gate usage` next to it.

Packaging the gateway for Kubernetes and Cloud Run raises the question of how many copies may run
against one state directory.

## Decision

Exactly one gateway process per state directory, for now.

- Kubernetes: `replicas: 1`, `strategy: Recreate` (the old pod stops before the new one starts) and
  a `ReadWriteOnce` volume.
- Cloud Run: at most 1 instance (service-level `max_instance_count`), at least 0, and the state on a
  Cloud Storage volume, because the instance's own filesystem is gone when it stops.
- Compose: one container with a named volume.

Running more copies is not a matter of raising a number; it waits until the ledger lives in a shared
transactional store (see the upgrade path).

## Why

- **The caps are the point of the ledger, and two writers break them quietly.** Two gateways that
  each read the ledger, admit a call and write the file back can overwrite each other's booking.
  The spend is lost from the books, nothing fails, and the cap is passed by whatever was lost.
- **The lock does not reach across hosts.** Two pods each have their own disk, so their locks never
  meet. A shared `ReadWriteMany` volume (NFS, Filestore) would make the lock directory visible to
  both, but the stale-lock check compares timestamps written by different hosts' clocks, and none of
  this has been tested on a network filesystem. Cloud Storage FUSE has no file locking at all, and
  the last write wins.
- **One process is enough for the work.** The gateway does little per call: the provider does the
  work, and Node waits on the network. Adding replicas against one shared file would not add much
  throughput anyway, because every call takes the same lock twice.

## Consequences

- **One instance is a single point of failure.** On Kubernetes, a crashed container restarts in
  seconds; a lost node means waiting until the volume is released and the pod starts on another
  node, in the same zone if the disk is zonal, which can take minutes. Each rollout has a gap of a few seconds (Recreate). On Cloud Run, a request
  after an idle spell waits for a cold start, since the minimum is 0.
- **No horizontal scaling.** Throughput is what one Node process gets. On Cloud Run it is lower: every
  ledger update is several object operations on Cloud Storage, done with synchronous file calls that
  block the event loop, so expect a few calls per second at most. This has not been measured.
- **"At most one" is not strict on Cloud Run.** Cloud Run documents that the maximum can be exceeded
  for a brief period, for example during a traffic spike. In such a window two instances can each
  book calls, one can overwrite the other's bookings, and a cap can be passed by the calls made in
  that window. This is accepted for now and stated next to the setting.
- **The usage log grows in place.** On Cloud Storage FUSE, an append to a file under 2 MiB uploads the
  whole object again, so `usage.jsonl` gets slower to write as it grows until it passes that size.
  Rotating it, or writing usage lines to the log stream instead of a file, is left to the operator.
- The MCP gateway's `approvals.json` has the same single-host design, but the MCP gateway is not
  deployed as a service: an agent starts it locally as a stdio process.

## Upgrade path

Move the ledger to a store that can check and book in one atomic step, then add replicas.

1. **Reserve** becomes one conditional update per key and period. In SQL (Cloud SQL for PostgreSQL):
   `UPDATE budgets SET reserved = reserved + :estimate WHERE key = :key AND period = :period AND
   spent + reserved + :estimate <= :cap`. One row changed: admitted. None: 429. Each reservation is
   also a row with an expiry, so a crashed replica's reservations still lapse.
2. **Settle** is one transaction: delete the reservation, subtract it from `reserved`, add the real
   cost to `spent`.
3. **The usage log** goes to the platform's log stream as structured JSON (Cloud Logging picks up
   stdout), or to a table, instead of a file.
4. **Then** raise the replica count, switch to RollingUpdate, add a PodDisruptionBudget and an
   autoscaler on Kubernetes, raise `max_instance_count` on Cloud Run, and spread across zones.

The seam is the `Ledger` class in `src/llm/budget.ts`: `reserve`, `settle`, `release` and `usage`.
A store-backed class with the same methods can replace the file-backed one.

Trade-offs between the stores:

| Store | Fits because | Costs |
| --- | --- | --- |
| Cloud SQL (PostgreSQL) | The conditional `UPDATE` is atomic, and the books can be queried with SQL. | An instance that runs all the time, connection management, a network round trip per reserve and per settle. |
| Firestore | Serverless, priced per operation, and a transaction can read the budget and write the reservation together. | Transactions retry under contention, and many writes to one key's budget document contend with each other; Firestore's own guidance for that is to spread a counter across documents. |
| Redis (Memorystore) | A Lua script checks and increments atomically in well under a millisecond. | Durability depends on its persistence settings: a restart that loses data resets every budget. It also runs all the time. |

Whichever store is used, the gateway should fail closed when it cannot reach it, as it does now for
a damaged ledger file: refusing calls is the safe side of a budget.

## Alternatives considered

- **Several replicas on a shared `ReadWriteMany` volume with the current lock.** It keeps the code as
  it is, but the lock was never tested on a network filesystem, its stale-lock check depends on
  clocks agreeing across hosts, and every call still waits for the one lock.
- **Each replica owns some of the keys** (routing by key). No sharing, but the router has to know
  the key before the gateway does, and moving keys between replicas while scaling is its own
  problem.
- **Each replica gets a share of every cap** (cap divided by the replica count). No shared state,
  but a key whose traffic lands on one replica cannot use the other shares, and every change in the
  replica count changes the shares.
- **A StatefulSet instead of a Deployment.** It is stricter about never running a replacement pod
  while the old one may still be alive. With one replica and a `ReadWriteOnce` volume, which a second
  node cannot attach while the first holds it, the Deployment with Recreate behaves the same in the
  common cases, and it is the more familiar object.
