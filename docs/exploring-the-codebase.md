# Exploring the codebase: trace a decision

Each guard decides in one pure function. Reproduce the decision first, then read the code and the
tests that pin it. Run the TypeScript lines after `npm run build`.

| Guard | Reproduce one decision | Code | Pinned by |
| --- | --- | --- | --- |
| Shell | `node -e 'console.log(require("./src/command-guard").analyze(process.argv[1]))' 'git -C . push'` | `src/command-guard.js`: `analyze()`, layers in order CRITICAL, uploads, ASK_RED, LIMITS, WARN, then the legacy safety net | `test/cases.json`, `test/cases-exfil.json`, the answer hash and timing tests in `test/command-guard.test.js`, `npm run redteam` |
| MCP policy | `node -e 'const {loadPolicy}=require("./dist/src/gateway/config.js");const {evaluate}=require("./dist/src/gateway/policy.js");console.log(evaluate(loadPolicy("policy.example.json"),{server:"demo",tool:process.argv[1],args:JSON.parse(process.argv[2])}))' delete_file '{"path":"x"}'` | `src/gateway/policy.ts`: rewrite rules edit the arguments first, then the first matching rule decides; later matches are listed in `alsoMatched` | `test/gateway/policy.test.ts`, `rewrite.test.ts` |
| Approvals | `node bin/agent-gate.js approvals show <id> --config <file>`; every decision is also a line in `<stateDir>/audit.jsonl` | `src/gateway/approvals.ts`: `resolveCall()` tries a denial, an exact approval, a standing approval, then queues a request | `test/gateway/approvals.test.ts`, `e2e.test.ts`, `crash.test.ts` |
| LLM leak guard | `node -e 'const {loadLeakPolicy}=require("./dist/src/llm/config.js");const {guardMessages}=require("./dist/src/llm/leak-guard.js");console.log(guardMessages(loadLeakPolicy("llm-policy.example.json"),[{role:"user",content:process.argv[1]}]))' 'some text'` | `src/llm/leak-guard.ts` | `test/llm/leak-guard.test.ts` |
| LLM routing | `node -e 'const {loadLlmConfig}=require("./dist/src/llm/config.js");const {route}=require("./dist/src/llm/routing.js");console.log(route(loadLlmConfig("llm-gateway.config.example.json"),{model:process.argv[1],task:process.argv[2]}))' large classify` | `src/llm/routing.ts` | `test/llm/routing.test.ts` |

Why each guard is built this way is in `docs/adr/` (0004: decisions in code; 0001, 0005 and 0006:
approvals). Before changing a decision, read the rules in `AGENTS.md`. The change is done when
`npm test` passes and every pinned file above that it touches says why.
