# syntax=docker/dockerfile:1
#
# The LLM gateway as a container image.
#
#   docker build -t agent-gate-llm-gateway:0.1.0 .
#   docker build --platform linux/amd64 ...   for Cloud Run, which runs linux/amd64 images only
#
# Stages: build (npm ci, tsc) and prod-deps (npm ci --omit=dev) on Node 22 slim; then two small
# images on distroless Node 22, which has no shell and no package manager: fake-upstream (the fake
# provider from the tests, for the compose demo only) and runtime, the gateway. runtime is the last
# stage, so a plain "docker build" builds it.
#
# Paths inside the image (the same in compose, Kubernetes and Cloud Run):
#   /etc/agent-gate/config/llm-gateway.config.json   the gateway config, mounted read-only
#   /etc/agent-gate/policy/llm-policy.json           the leak-guard policy, mounted read-only
#   /var/lib/agent-gate                              state: ledger.json, usage.jsonl (a volume)
# Provider API keys come from environment variables named by "apiKeyEnv" in the config.
#
# Base images are pinned by digest (resolved on 2026-10-14), so a rebuild gets the same base;
# update them on purpose. Both are Debian 13.

FROM node:22.23.3-trixie-slim@sha256:154ba2f4d6fec323d28e4f4bb86bba4677f1223391a1979cf521304e03a98dfa AS node-build
FROM gcr.io/distroless/nodejs22-debian13:nonroot@sha256:ec2313763dd43931543bd03830466e0c409ce73a487e8d46f10db72d3b816c1c AS node-runtime

FROM node-build AS build
WORKDIR /app
COPY package.json package-lock.json ./
# --ignore-scripts: no dependency runs code at install time (none of them needs to).
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
COPY test ./test
# The state directory is made here because the distroless stages have no shell to run mkdir.
RUN npm run build \
 && mkdir -m 0700 /state \
 && chown 65532:65532 /state

FROM node-build AS prod-deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

# The fake OpenAI-compatible provider from the tests. It never calls a model and costs nothing.
# Only docker-compose.yml uses it; it is not part of the gateway image.
FROM node-runtime AS fake-upstream
COPY --from=build /app/dist/test/llm/fake-upstream.js /app/fake-upstream.js
USER 65532:65532
EXPOSE 9101
ENTRYPOINT ["/nodejs/bin/node", "/app/fake-upstream.js"]
CMD ["--host", "0.0.0.0", "--port", "9101"]

FROM node-runtime AS runtime
LABEL org.opencontainers.image.title="agent-gate LLM gateway" \
      org.opencontainers.image.description="OpenAI-compatible LLM gateway with routing, budget caps and a leak guard" \
      org.opencontainers.image.licenses="MIT"
# The base image's user is 65532. The files are laid out as root, so /app and everything in it
# belong to root and the gateway process (uid 65532) cannot change them, even where the root
# filesystem is writable, as on Cloud Run.
USER 0:0
WORKDIR /app
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/dist/src ./dist/src
# package.json maps #command-guard to src/command-guard.js (its "imports" field).
COPY package.json LICENSE ./
COPY bin/agent-gate.js ./bin/agent-gate.js
COPY src/command-guard.js ./src/command-guard.js
# The only directory the gateway writes to.
COPY --from=build --chown=65532:65532 /state /var/lib/agent-gate
USER 65532:65532
ENV AGENT_GATE_LLM_CONFIG=/etc/agent-gate/config/llm-gateway.config.json
VOLUME ["/var/lib/agent-gate"]
EXPOSE 8787
# For Docker and compose. Kubernetes and Cloud Run ignore HEALTHCHECK and run their own probes on
# the same path. Port 8787 is listen.port in every config under deploy/.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8787/healthz').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
ENTRYPOINT ["/nodejs/bin/node", "/app/bin/agent-gate.js"]
CMD ["llm", "serve"]
