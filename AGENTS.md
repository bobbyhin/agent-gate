# AGENTS.md

agent-gate guards an AI agent's actions: a shell command guard, an MCP gateway and an LLM gateway. README.md is the overview; the manual is in `docs/`, one file per guard (`shell-guard.md`, `mcp-gateway.md`, `llm-gateway.md`) plus `operations.md` and `development.md`.

## Build and test
- `npm ci`, then `npm test`: `tsc` into `dist/`, then `node --test` over every suite (the Node version `engines` in `package.json` names). Run it before each commit; it must pass.
- `npm test` writes `dist/`, so a sandboxed shell needs write access to the repository to run it.

## Layout
- `src/command-guard.js`: the shell analyzer, plain CommonJS with no dependencies. `bin/`: the Claude Code hook and the CLI.
- `src/gateway/`: the MCP gateway (policy, approvals, audit). `src/llm/`: the LLM gateway (routing, budgets, leak guard).
- `test/cases.json` (239 shell cases) and `test/cases-exfil.json` (suite G) run in `test/command-guard.test.js`; `test/gateway/` and `test/llm/` hold the TypeScript suites.
- Tracing a decision (why a command, tool call or model request got pass, ask or block): `docs/exploring-the-codebase.md` reproduces each guard's decision in one line and names the code and tests that pin it.

## Rules
- `test/cases.json` stays at exactly 239 cases, a number quoted outside this repository. New shell cases go in a suite file of their own (see `docs/red-team.md`).
- `analyze()`'s answers are pinned by a hash over `test/generated-commands.js` (in `test/command-guard.test.js`). A change meant to alter answers records the new hash and says why in `docs/red-team.md`. Tune nothing against `test/cases-heldout.json`; raise `test/heldout-baseline.json` when the score improves.
- Fake secrets are built at run time from pieces, in `test/llm/fake-secrets.ts`; `gitleaks git --pre-commit --staged .` must find nothing before a commit.
- The repository is public: English only, made-up names, hosts and paths (`example.com`, `/path/to/agent-gate`), no personal data or real credentials.
- The rule tables in `docs/mcp-gateway.md` and `docs/llm-gateway.md` mirror their policy files (`policy.example.json`, `llm-policy.example.json`), and `deploy/k8s/llm-policy.json` is a byte-identical copy of the latter: change them together.
