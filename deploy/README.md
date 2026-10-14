# Deploying the LLM gateway

This directory, together with the `Dockerfile` and `docker-compose.yml` at the repository root,
packages the [LLM gateway](../README.md#llm-gateway) as a container image and deploys it three ways:
a demo on one machine with Docker Compose, Kubernetes, and Google Cloud Run with Terraform.

**Status: checked, not deployed.** Nothing here has been applied to a real Google Cloud project or a
real cluster, and no image has been pushed anywhere. [What was checked](#what-was-checked) lists
what ran where.

## What is here

Paths are from the repository root, and so are the commands below unless they say otherwise.

| Path | What it is |
| --- | --- |
| `Dockerfile` | A multi-stage build: `npm ci` and `tsc` on Node 22 slim, production dependencies only, then distroless Node 22 (no shell, no package manager) running as uid 65532. `HEALTHCHECK` on `/healthz`; the state directory is a volume. Base images are pinned by digest. |
| `.dockerignore` | An allowlist: local configs, state, `.env` files and `node_modules` never reach the build. |
| `docker-compose.yml`, `deploy/compose/llm-gateway.config.json` | The local demo: the gateway in front of the fake provider from the tests. |
| `deploy/k8s/` | Kustomize: a Namespace (Pod Security `restricted`), a ServiceAccount, a PersistentVolumeClaim, the Deployment, a Service, a NetworkPolicy, and a ConfigMap generated from `llm-gateway.config.json` and `llm-policy.json`. |
| `deploy/terraform/` | Google Cloud: an Artifact Registry repository, a service account, Secret Manager secrets, a state bucket, the Cloud Run service and an optional budget alert. `deploy/terraform/tests/` has plan-only tests that use a mocked provider. |
| [`docs/adr/0003-single-writer-state.md`](../docs/adr/0003-single-writer-state.md) | Why one replica, and what it takes to run more. |

### Inside the container

| Path | What it is |
| --- | --- |
| `/etc/agent-gate/config/llm-gateway.config.json` | The gateway config, mounted read-only. The image sets `AGENT_GATE_LLM_CONFIG` to this path. |
| `/etc/agent-gate/policy/llm-policy.json` | The leak-guard policy, mounted read-only. |
| `/var/lib/agent-gate` | The state: `ledger.json` and `usage.jsonl`. The only path the gateway writes to. |

The gateway listens on port 8787. It reads each provider's API key from the environment variable
that the config names in `apiKeyEnv`, and stops at startup, naming the variable, if one is missing.
`npm test` checks that the configs under `deploy/` load and use these paths
(`test/llm/deploy.test.ts`).

`deploy/k8s/llm-gateway.config.json` is the config for both Kubernetes and Cloud Run. It is a
template: its upstreams are on `.example` hosts, which do not exist, and its one gateway key hash
is all zeros, which no key matches. Until you put in real upstreams and the SHA-256 of your own gateway
keys, it answers every call with 401. The main README shows how to make a key and its hash
([LLM gateway](../README.md#llm-gateway), under "Set it up").

## The compose demo

Needs Docker with Compose. No account, no provider key, no cost.

```
docker compose up --build --wait
curl -s http://127.0.0.1:8787/healthz
export GATEWAY_KEY=demo-gateway-key-not-a-secret
curl -s http://127.0.0.1:8787/v1/chat/completions \
    -H "Authorization: Bearer $GATEWAY_KEY" \
    -H "content-type: application/json" \
    -H "x-agent-task: classify" \
    -d '{"model":"large","messages":[{"role":"user","content":"Label this ticket: printer on fire"}],"max_tokens":20}'
docker compose exec llm-gateway /nodejs/bin/node bin/agent-gate.js usage
docker compose logs llm-gateway
docker compose down -v
```

- `fake-upstream` is the fake provider from `test/llm/fake-upstream.ts`, built as its own small image.
  It answers like a provider and never calls a model.
- The gateway uses `deploy/compose/llm-gateway.config.json`: the repository's example config with the
  container's paths and the fake upstream's host name. So the call above should get the same answer
  and cost as the run in the main README's "A request, step by step".
- The gateway's port is published on `127.0.0.1` only. Both containers run with a read-only root
  filesystem, no capabilities and `no-new-privileges`.
- The ledger lives in the named volume `gateway-state` until `docker compose down -v`.
- The image has no shell, so `exec` names the program: `/nodejs/bin/node bin/agent-gate.js usage`.

## Kubernetes

Needs a cluster with a default StorageClass and a network plugin that enforces NetworkPolicy (GKE
Dataplane V2, Calico or Cilium, for example), and a registry the cluster can pull from. Words in
capitals are placeholders.

1. Build and push the image (add `--platform linux/amd64` when building on an ARM machine for amd64
   nodes):

   ```
   docker build -t REGISTRY/llm-gateway:0.1.0 .
   docker push REGISTRY/llm-gateway:0.1.0
   ```

2. Edit `deploy/k8s/llm-gateway.config.json`: the upstreams (`baseUrl`, `models`, `pricePerMTok`),
   and one entry in `keys` per team or agent, with the SHA-256 of its gateway key and its caps.
3. Point the manifests at the image: in `deploy/k8s/kustomization.yaml`, set `newName` under
   `images` to `REGISTRY/llm-gateway`, or run
   `kustomize edit set image agent-gate-llm-gateway=REGISTRY/llm-gateway:0.1.0` in that directory.
4. Apply the manifests, and create the Secret with the provider keys. Its keys are the `apiKeyEnv`
   names from the config.

   ```
   kubectl apply -k deploy/k8s
   kubectl -n agent-gate create secret generic llm-gateway-provider-keys \
       --from-literal=PROVIDER_A_API_KEY="$PROVIDER_A_API_KEY" \
       --from-literal=PROVIDER_B_API_KEY="$PROVIDER_B_API_KEY"
   kubectl -n agent-gate rollout status deploy/llm-gateway
   ```

   Until the Secret exists, the pod waits in `CreateContainerConfigError`, and it starts on its own
   once the Secret is there. The values come from your shell's environment, not from a file in the
   repository. For production, sync them from a secret manager instead, for example with the
   External Secrets Operator or the Secret Manager add-on on GKE.
5. Let the agents in, and point them at the gateway:

   ```
   kubectl label namespace AGENTS_NAMESPACE agent-gate/llm-client=true
   ```

   Agents in that namespace use `http://llm-gateway.agent-gate.svc.cluster.local:8787/v1` as their
   OpenAI base URL and their gateway key as their API key. Pods in other namespaces cannot connect.
6. See the spend per key:

   ```
   kubectl -n agent-gate exec deploy/llm-gateway -- /nodejs/bin/node bin/agent-gate.js usage
   ```

An edit to the config or the policy changes the generated ConfigMap's name, so the next
`kubectl apply -k` rolls the Deployment.

What the manifests set:

- One replica, `strategy: Recreate`, and a `ReadWriteOnce` volume for the state: the ledger has a
  single writer ([ADR 0003](../docs/adr/0003-single-writer-state.md)).
- Readiness and liveness probes on `/healthz`. It reports that the process is up and does not call
  the providers, because a probe that did would spend money.
- Requests of 100m CPU and 128 MiB, limits of 1 CPU and 256 MiB.
- Non-root (uid and gid 65532, with `fsGroup` so the volume is writable), a read-only root
  filesystem, no privilege escalation, every capability dropped, the `RuntimeDefault` seccomp
  profile, and no service account token. The namespace enforces the `restricted` Pod Security
  profile, so a pod without these settings is refused.
- A NetworkPolicy: in, only from namespaces labelled `agent-gate/llm-client=true`, on port 8787;
  out, only DNS and HTTPS to public addresses. Apart from DNS, cluster services, private networks
  and the metadata server are out of reach.

## Cloud Run with Terraform

What `deploy/terraform` creates:

- An Artifact Registry repository, `agent-gate`, with immutable tags.
- A service account, `llm-gateway`, with no project-level role. It gets
  `roles/secretmanager.secretAccessor` on each of its own secrets and `roles/storage.objectUser` on
  its own bucket, and nothing else.
- One Secret Manager secret per provider key, named after the variable
  (`llm-gateway-provider-a-api-key`, and so on). The list comes from the `apiKeyEnv` values in the
  config, so it cannot drift from what the gateway reads. Terraform creates the secrets, never their
  values. The config and the policy are two more secrets, mounted as files, because Cloud Run has no
  ConfigMap. Neither holds anything secret, so Terraform does manage their content.
- A bucket, `PROJECT_ID-llm-gateway-state`, mounted at `/var/lib/agent-gate` with Cloud Storage
  FUSE. The instance's own filesystem is in memory and is gone when the instance stops, which with
  a minimum of 0 instances happens after every idle spell.
- The Cloud Run service, `llm-gateway`: 0 to 1 instance (ADR 0003), second-generation environment,
  1 CPU and 512 MiB, CPU only while requests are in flight, a 300-second request timeout (the
  gateway's longest call with the shipped config is 240.5 seconds), probes on `/healthz`, and the
  provider keys as environment variables from Secret Manager.
- `roles/run.invoker` for each principal in `invoker_members`. The default is nobody.
- Optional, off by default (`enable_budget_alert`): a billing budget that emails the billing
  account's admins at 50%, 90% and 100% of a monthly amount. It covers this project's Google Cloud
  charges, not the providers' bills; the gateway's own caps per key are what limit those.

At plan time, Terraform refuses a config that does not listen on `0.0.0.0` or that puts the state or
the policy anywhere other than the mounted volumes.

Steps. You need a project with billing, `gcloud`, Terraform 1.7 or newer and Docker, and an account
that may enable APIs, create these resources and act as the new service account. Words in capitals
are placeholders.

```
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars    # set project_id, region, invoker_members
gcloud auth application-default login
terraform init

# 1. The registry and the provider-key secrets first: the service needs an image and secret values to start.
terraform apply -target=google_artifact_registry_repository.images -target=google_secret_manager_secret.provider_key

# 2. The provider keys' values, out of band: they never pass through Terraform or its state.
printf %s "$PROVIDER_A_API_KEY" | gcloud secrets versions add llm-gateway-provider-a-api-key --project=PROJECT_ID --data-file=-
printf %s "$PROVIDER_B_API_KEY" | gcloud secrets versions add llm-gateway-provider-b-api-key --project=PROJECT_ID --data-file=-

# 3. The image. Cloud Run runs linux/amd64 images, so say so when building on an ARM machine.
gcloud auth configure-docker REGION-docker.pkg.dev
docker build --platform linux/amd64 -t REGION-docker.pkg.dev/PROJECT_ID/agent-gate/llm-gateway:0.1.0 ../..
docker push REGION-docker.pkg.dev/PROJECT_ID/agent-gate/llm-gateway:0.1.0

# 4. Everything else.
terraform apply
```

A caller sends two credentials: a Google ID token in `X-Serverless-Authorization`, which Cloud Run
checks against `invoker_members`, and its gateway key in `Authorization`, which the gateway checks.
To try it yourself, put `user:YOUR_EMAIL` in `invoker_members`:

```
URL=$(terraform output -raw service_url)
curl -s "$URL/v1/chat/completions" \
    -H "X-Serverless-Authorization: Bearer $(gcloud auth print-identity-token)" \
    -H "Authorization: Bearer $GATEWAY_KEY" \
    -H "content-type: application/json" \
    -d '{"model":"small","messages":[{"role":"user","content":"hello"}],"max_tokens":20}'
```

Cloud Run reserves some URL paths that end in `z`, so do not rely on `/healthz` from outside; the
startup and liveness probes use it on each instance.

Running it:

- **Config or policy change:** `terraform apply` writes a new version of the file secret. The service
  pins that version, so a new revision rolls out.
- **New image:** push a new tag (a pushed tag cannot be overwritten), set `image_tag`,
  `terraform apply`.
- **New provider key:** add a version with `gcloud secrets versions add`. An instance reads `latest`
  when it starts, so new instances (after an idle spell, or in a new revision) use it. Disable the
  old version after that.
- **Spend:** the ledger is `gs://PROJECT_ID-llm-gateway-state/ledger.json`, and
  `gcloud storage cat` shows it. The usage log is next to it.
- **Cost when idle:** no instance runs, so what remains is storage: the image, the secret versions
  and a few kilobytes in the bucket. Each call adds Cloud Run request time and a handful of Cloud
  Storage operations.
- **Removal:** set `deletion_protection = false` and apply, then `terraform destroy`. The bucket is
  not deleted while it still holds files, so the ledger is not lost by accident; empty it first if
  you mean it.

The Cloud Run setup has limits of its own, stated next to the settings in `cloud_run.tf`: "at most
one instance" can be exceeded briefly, Cloud Storage FUSE has no file locking, every ledger update
costs several object operations, and the usage log is uploaded again on each append while it is
small. ADR 0003 has the details and the way out.

## What was checked

On 2026-10-14, on macOS (Apple silicon), with no cloud account and no credentials:

| Check | Tool versions | Result |
| --- | --- | --- |
| `terraform fmt -check -recursive` | Terraform 1.16.6 | passed |
| `terraform init -backend=false`, `terraform validate` | Terraform 1.16.6, google provider 8.7.0 | valid |
| `terraform test`: plan only, mocked provider | Terraform 1.16.6 | 5 of 5 passed |
| `kubectl kustomize deploy/k8s` into `kubeconform -strict -summary` | kubectl 1.34.1 (kustomize 5.7.1), kubeconform 0.8.0 | 7 resources, 7 valid |
| `hadolint Dockerfile` | hadolint 2.15.1 | no findings |
| `docker compose config` (needs no daemon) | Docker Compose 5.1.4 | valid |
| The Dockerfile's stages repeated by hand, without Docker: the same `npm ci` commands and the same files copied, then the result started | Node 22.23.1 | ran with production dependencies only; `/healthz` 200, the `HEALTHCHECK` command exited 0, a chat call with the demo key 200, `agent-gate usage` read the ledger |
| `npm test`, which includes `test/llm/deploy.test.ts` | Node 22.23.1 and 20.20.2 | 524 of 524 passed on each |
| `actionlint` on the CI workflow | actionlint 1.7.12, shellcheck 0.11.0 | no findings |
| Deliberate breaks, on copies of the files: 3 in the Terraform (two instances allowed, the config checks removed, key names not taken from the config) and 6 in the deploy configs | the two test suites above | each break failed at least one test |

Not run locally: `docker build` and the compose demo, because the Docker daemon was not running on
that machine. The `deploy` job in `.github/workflows/ci.yml` runs them, with no credentials: the
Terraform checks and tests, kustomize with kubeconform, `docker build`, a check that the image runs
as uid 65532 and can write `/var/lib/agent-gate` but not `/app`, and the compose demo (`/healthz`,
a chat call with the demo key, `agent-gate usage`). The job was written with these files and had
not run yet when they were committed, because the repository had not been pushed; until it runs,
the image has not been built anywhere.

Never run, anywhere: `terraform plan` or `apply` against a real project, `kubectl apply` to a real
cluster, `docker push`, a Cloud Run deployment, or a call to a real provider.

## What is not covered

- More than one replica or instance (ADR 0003): no autoscaling and no PodDisruptionBudget, and each
  Kubernetes rollout has a gap of a few seconds.
- TLS inside the container. The gateway speaks plain HTTP on port 8787. Cloud Run terminates TLS in
  front of it; on Kubernetes the Service is reachable inside the cluster only, there is no Ingress,
  and encryption between pods is left to a service mesh.
- More than one region, and failover between zones. On Kubernetes the volume is usually a zonal
  disk, which keeps the pod in one zone.
- Graceful drain. On SIGTERM the gateway closes its connections at once, and its clients see them
  drop. Calls already sent upstream keep running until the platform's grace period ends (30 seconds
  by default on Kubernetes, 10 on Cloud Run): those that finish are booked, and the reservations of
  the rest lapse on their own.
- Backups. There are no volume snapshots and no bucket versioning, and losing `ledger.json` resets
  the month's spend.
- Secrets on Kubernetes beyond `kubectl create secret`.
- Supply chain: the base images are pinned by digest, but nothing updates them, and CI does not sign
  the image, make an SBOM or scan it.
- Monitoring and alerting beyond the optional budget: the platforms' own metrics and logs only, and
  `usage.jsonl` is not shipped anywhere.
- The MCP gateway. It is a stdio process that an agent starts on its own machine, not a network
  service, so it is not packaged here.
