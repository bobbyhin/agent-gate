# agent-gate

A guard that sits between an AI coding agent and the shell. Before the agent runs a shell
command, agent-gate reads the command and decides one of four things: **pass**, **warn**,
**ask** a human, or **block**.

This repository has four parts:

- `src/command-guard.js`: the analyzer. One function, no dependencies. `analyze(command)`
  returns `{ action, label, why }`.
- `bin/claude-pretooluse-hook.js`: a Claude Code `PreToolUse` hook built on the analyzer.
- `test/cases.json`: 239 commands, each with the decision it must get. They come from red-team
  rounds against earlier versions of the analyzer.
- `src/gateway/`: an MCP gateway (TypeScript) that brings the same four decisions to MCP tool
  calls and holds risky calls until a human approves them. See [MCP gateway](#mcp-gateway).

Status: v0.1.0. It is used daily on the author's own agent setup. It is a heuristic reader of
shell commands, not a sandbox. See [Known limits](#known-limits).

## The four decisions

| Decision | What happens | Examples |
| --- | --- | --- |
| pass | The command runs. | `ls -la`, `git status` |
| warn | A note goes to stderr and the command runs. | `kill -9 4242`, `taskkill /f /im node.exe` |
| ask | A human is asked to confirm first. | `git push origin main`, `npm publish` |
| block | The command is refused (exit code 2). | `rm -rf ~`, `git push --force origin main` |

What lands where:

- **block** is for things that are wrong whatever the context: `rm -rf` of `/`, `~` or `$HOME`,
  `find / -delete`, force push, `git reset --hard`, `git clean -f`, `git checkout .`, a bare
  `git stash drop`, `--no-gpg-sign`, `rmdir /s`, `del /s`.
- **ask** is for things that are often legitimate but should not happen without a human: any
  `git push`, `gh pr create|merge|ready`, `gh release`, `gh repo` changes, `gh api` writes,
  `gh workflow run`, deploys (vercel, netlify, wrangler, fly, firebase, gcloud), package
  publishing (`npm|pnpm|yarn|bun|uv|cargo|poetry|hatch|flit publish`, `twine upload`,
  `gem push`), `docker|podman push` and `build --push`, any `rm -r`, `git restore .`,
  `git branch -D`, `git stash clear`, `git commit --amend`, `--no-verify`.
- **warn** is for `DROP DATABASE|TABLE|SCHEMA`, `TRUNCATE TABLE`, `kill -9` and `taskkill /f`.

Why most of it asks instead of blocking: the first version blocked dangerous commands outright.
In 46 days of the author's own logs it blocked 34 times, and about 32 of those were legitimate
work (cleaning a scratch folder, `__pycache__`, a `.venv`). The author also noticed the agent
working around those blocks quietly, 32 times, without the operator knowing. Asking puts the
decision in front of a human instead of hiding it.

## The red lines

agent-gate is built around four kinds of action that should always involve a human, because they
are hard to undo or they leave the machine:

1. spending money
2. posting publicly to a real account
3. `git push`, merge, pull request, deploy, publish
4. permanently deleting or overwriting something the agent did not create

Everything else should flow without interruption. Rules that enforce a red line say so in their
`why` text ("Red line 3", "Red line 4").

The guard only sees shell commands. It enforces lines 3 and 4: pushes, PRs, releases, deploys,
package publishing, recursive deletes, and throwing away uncommitted work. It does nothing for
lines 1 and 2, because spending and posting usually go through APIs, MCP tools or a browser, not
through the shell. Those need other layers, such as credentials the agent never holds.

## How it reads a command

agent-gate is not a full shell parser. It reads a command the way a shell does, in seven steps:

1. **Heredocs.** Strip only the body that is not fed to a shell. The command line itself is
   always kept. A heredoc that never closes is kept whole.
2. **Line continuations.** Join lines that end in `\`.
3. **Quotes, one character at a time.** `$'\x2f'` is decoded like the shell does it. A `#` at the
   start of a word outside a string starts a comment. A string counts as one inert word, and a
   string that starts with `-` is data, not a flag. The exception is `$(...)` and backticks
   inside double quotes, which really run.
4. **Text fed to a shell.** When text is fed to a shell (`sh -c`, `eval`, `trap`, `| bash`,
   `bash <<<`, `bash <(...)`, `source`, `ssh`, `su -c`, `env -S`, `watch`, `parallel`), the
   strings are opened up as commands and every word is checked, not only the first.
5. **Command position.** Normally a rule only looks where a command can start: the start of the
   text, after `;` `&` `|` `(` `)` `{` `$(` or a backtick, and after wrapper commands such as
   `sudo`, `env`, `timeout`, `xargs`, `arch` or `noglob` with any number of options. Options
   glued on, like `-cX=Y` or `--repo=o/r`, count as options.
6. **Safety net.** The rule set from before the rewrite runs again on the text with data heredocs
   removed, and the stronger decision wins. Nothing the old rules caught can slip through.
7. **Failure and size.** If the guard itself breaks, the old rules decide, and anything they do
   not block goes to a human. A command longer than 100,000 characters also goes to a human.

What that means in practice (each of these is checked against the code):

- `git commit -m "docs: never git push without review"` passes: the words are inside a string.
- `echo "git push origin main" | bash` asks: the string is fed to a shell.
- `git \` followed by a newline and `push origin main` asks: the continuation is joined first.
- `sudo timeout 5 git push origin main` asks: the wrapper commands are skipped.
- `git -c core.editor=vim push origin main` asks: options before the subcommand are skipped.
- `git push origin main # just kidding` asks: a trailing comment does not hide the command.
- A heredoc such as `cat > notes.md <<'EOF'` with `git push origin main` inside passes: the body is
  data, not a command.

## Known limits

agent-gate is one layer. These are things it does not see. They need other layers: deny rules in
the agent's own settings, a classifier, and not letting the agent hold credentials in the first
place.

- An alias. After `alias g=git`, the command `g push origin main` passes.
- A variable. `$g push` passes.
- A script written earlier and run later. `./deploy.sh` and `make deploy` pass.
- Python or Node calling a shell itself. `python3 -c "import os; os.system('git push')"` passes.
- A quoted flag. `"--no-verify"` is treated as data.
- SQL inside quotes. `psql -c "DROP TABLE users"` passes, because a quoted string is one inert
  word. Only unquoted SQL triggers the warn rules.
- Anything that is not a shell command: HTTP calls such as `curl -X POST ...`, MCP tools, browser
  actions.

Treating quoted text as data is deliberate. It is what keeps a commit message that talks about
`git push` from being flagged, and it is also the source of several items above.

## Red-team history

This is the history of the analyzer's earlier versions, from the author's notes:

| Version | Attacked by | Result |
| --- | --- | --- |
| v2 (regex rules) | red team 1, 48 cases | 21 of 48 got through |
| v3 | Codex as the attacker, 55 cases | 43 of 55 got through |
| v4 | red team 2, 38 cases | 20 of 38 got through; in 16 cases it did worse than the hook it was meant to replace |
| v5 (this code) | all of the above plus the earlier suites, 239 cases | 239 of 239 get the expected decision |

Before v5, an oracle ran the real hook against 22 bypasses and all 22 passed silently, including
`bash -c "...git push"`, `git commit -m "Fix #123" && git -C . push` (the `#` inside the string
was read as a comment) and `sh -c 'rm -rf ~'`. Those 22 are the `vuln-1` to `vuln-4` cases in the
suite. The v4 failures that were worse than before included `arch -arm64 git push`,
`echo rm -rf ~ | bash` and `bash --norc -c`.

The bypass counts for v2 to v4 come from the author's notes. Those versions are not published
here, so only the last row can be reproduced from this repository (`npm test`). The categories in
`test/cases.json` are described in [docs/red-team.md](docs/red-team.md).

## Use it as a Claude Code hook

Put this repository somewhere on your machine, then add a `PreToolUse` hook for the `Bash` tool to
`.claude/settings.json` (or `~/.claude/settings.json`). Replace `/path/to/agent-gate` with the
real path:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "node /path/to/agent-gate/bin/claude-pretooluse-hook.js"
          }
        ]
      }
    ]
  }
}
```

The hook reads the tool call from stdin and answers like this:

| Decision | stdout | stderr | Exit code |
| --- | --- | --- | --- |
| pass | the input, unchanged | nothing | 0 |
| warn | the input, unchanged | `[Hook] WARN: <label> — proceeding` | 0 |
| ask | one line of JSON with `permissionDecision: "ask"` | nothing | 0 |
| block | nothing | `[Hook] BLOCKED: <label>` and the command | 2 |

Claude Code treats exit code 2 as a blocking error and a `permissionDecision` of `ask` as a
request to show its permission prompt. If the input cannot be read, the hook asks instead of
passing silently.

You can try it without Claude Code:

```
$ echo '{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}' | node bin/claude-pretooluse-hook.js
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"⚠️ git push (any form) — Red line 3 — a push needs a human decision\ngit push origin main"}}
```

### Decision log

Set `AGENT_GATE_LOG` to a file path and the hook appends one JSON line for every warn, ask or
block (pass is not logged):

```json
{"ts":"2026-10-14T06:00:00.000Z","action":"ask","label":"git push (any form)","why":"Red line 3 — a push needs a human decision","command":"git push origin main"}
```

The line holds the first 400 characters of the command, so treat the file as sensitive. Logging
never changes a decision, and write errors are ignored. Without the variable nothing is logged.

## Use the analyzer directly

```js
const { analyze } = require("./src/command-guard");

analyze("git push origin main");
// { action: 'ask', label: 'git push (any form)', why: 'Red line 3 — a push needs a human decision' }

analyze("ls");
// { action: 'pass' }
```

`action` is always one of `pass`, `warn`, `ask`, `block`. `label` is present unless the action is
`pass`, and `why` is present for `ask`.

## MCP gateway

The shell guard only sees shell commands. Spending money and posting usually happen through tools
instead: an MCP server for payments, email, chat or a code host. The MCP gateway is the layer for
those. It is a stdio MCP server that sits between the agent and one or more downstream MCP
servers. The agent sees every downstream tool as `<server>__<tool>`, and before a call is
forwarded, a policy decides one of four things:

| Decision | What happens |
| --- | --- |
| allow | The call is forwarded. The downstream result comes back unchanged. |
| warn | The same as allow, plus a note on the gateway's stderr. |
| ask | The call is not forwarded. A pending approval is recorded, and the agent gets an error result that names its id. A human answers it with the CLI. |
| block | The call is not forwarded and not queued. The agent gets an error result. |

Every decision is written to an audit log. The gateway is written in TypeScript on the official
MCP SDK (`@modelcontextprotocol/sdk`), which is its only runtime dependency besides `zod`.

Status: new. It is covered by the tests in [Run the tests](#run-the-tests), but unlike the shell
guard it has not been used day to day yet.

### Set it up

```
npm install
npm run build
cp gateway.config.example.json gateway.config.json
```

`gateway.config.json` lists the downstream servers, the policy file and a directory for state:

```json
{
  "servers": [
    {
      "name": "demo",
      "command": "node",
      "args": ["dist/test/gateway/fake-downstream.js"]
    }
  ],
  "policy": "policy.example.json",
  "stateDir": ".agent-gate",
  "approvalTtlHours": 24
}
```

The example proxies the fake server from the end-to-end test. Its three tools (`echo`,
`delete_file`, `run_command`) only pretend, so the whole flow can be tried safely; its path is
relative, so run the gateway from the repository root. For real use, list real servers, for
example `{ "name": "files", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/agent-work"] }`.

- `name` becomes the tool prefix. It may use letters, digits, `-` and single `_`, never `__`.
- `command` and `args` start the server. A server gets only a short list of safe environment
  variables (such as `PATH` and `HOME`), not the gateway's whole environment. Add an `env` object
  for the variables it needs.
- `policy` and `stateDir` are resolved against the config file's directory.
- `approvalTtlHours` (default 24) is how long a request stays open. `auditArguments` (default
  `false`) is explained under [Audit log](#audit-log).

Then give the agent the gateway instead of the downstream servers. For Claude Code, in `.mcp.json`:

```json
{
  "mcpServers": {
    "gate": {
      "command": "node",
      "args": ["/path/to/agent-gate/bin/agent-gate.js", "serve", "--config", "/path/to/gateway.config.json"]
    }
  }
}
```

Some clients add their own prefix (Claude Code shows `mcp__gate__demo__delete_file`) and limit
the length of tool names, so keep server names short.

### An approval, step by step

```mermaid
sequenceDiagram
    participant A as Agent
    participant G as agent-gate
    participant Q as approvals.json
    participant H as Human (CLI)
    participant D as Downstream server
    A->>G: demo__delete_file, path notes/old.md
    G->>Q: record a pending request
    G-->>A: error result: needs a human, approval id ap-f646780e
    H->>Q: agent-gate approvals approve ap-f646780e
    A->>G: the same call again
    G->>Q: find the approval, mark it used
    G->>D: delete_file, path notes/old.md
    D-->>G: result
    G-->>A: the result, unchanged
```

In a checkout, `agent-gate` is `node bin/agent-gate.js`. This is a real run with the example
policy and the fake server. The agent calls `demo__delete_file` with `{"path": "notes/old.md"}` and gets an error
result (`isError: true`) with this text:

```
agent-gate: this call needs a human decision, so it was not run.
Reason: Red line 4: this tool looks like it deletes or overwrites data. (rule red-line-4-delete)
Approval id: ap-f646780e (expires 2026-10-15T08:55:58.716Z)
A human can approve it with: agent-gate approvals approve ap-f646780e
Once it is approved, make exactly the same call again (same tool, same arguments) and it will run once. Different arguments need a new approval.
Do not try to get the same result another way.
```

The human looks at the queue and approves:

```
$ agent-gate approvals list
ap-f646780e  pending  demo__delete_file
  why:     Red line 4: this tool looks like it deletes or overwrites data. (rule red-line-4-delete)
  args:    {"path":"notes/old.md"}
  created: 2026-10-14T08:55:58.716Z  expires: 2026-10-15T08:55:58.716Z

$ agent-gate approvals approve ap-f646780e
approved ap-f646780e: demo__delete_file {"path":"notes/old.md"}
The agent can now make this exact call once, until 2026-10-15T08:55:58.716Z.
```

The agent makes the same call again. This time it is forwarded, and the agent gets the downstream
server's result, `pretended to delete notes/old.md`. If it makes the call a third time, it gets a
new approval id: the approval was used up.

The CLI commands are:

```
agent-gate approvals list [--all] [--json]   waiting requests (--all: also decided, used, expired)
agent-gate approvals show <id>               one request in full, with all of its arguments
agent-gate approvals approve <id>
agent-gate approvals deny <id>
```

Each takes `--config <file>` (default: `$AGENT_GATE_CONFIG`, then `./gateway.config.json`).

### Approval rules

- An approval is bound to one exact call: the server, the tool, and a SHA-256 hash of the
  arguments as canonical JSON (object keys sorted). Changing any argument value needs a new
  approval. The order of keys does not matter.
- It lets that call through once. It is marked used before the call is forwarded, so a call that
  then fails downstream has still used it up.
- Repeating a call that is still waiting does not queue a second request. The agent gets the same
  id back.
- A denied call stays denied. Repeating it gets "a human denied this exact call", and nothing new is
  queued until the denial expires. `deny` also takes back an approval that has not been used yet.
- A request expires `approvalTtlHours` after it was made. An expired request cannot be approved,
  and an expired approval lets nothing through. The next identical call queues a new request.
- `block` is never queued and cannot be approved.
- The queue is one file, `<stateDir>/approvals.json` (mode 0600). Every change is a locked
  read-modify-write, and every write goes to a temporary file that is flushed and then renamed
  over the old one. A damaged file is an error, never an empty queue, because an empty queue would
  forget denials.

Why the gateway answers with an error and lets the agent retry, instead of holding the call open
until a human answers: [docs/adr/0001-non-blocking-approvals.md](docs/adr/0001-non-blocking-approvals.md).

### Policy

A policy is JSON: a default decision and an ordered list of rules. The first rule that matches a
call decides; when none matches, the default decides. The engine (`src/gateway/policy.ts`) is a
pure function with no I/O, so the same policy and call always get the same verdict, and every
verdict carries the id of the rule that decided and a `why`.

`policy.example.json` maps the red lines:

| Rule | Matches | Decision |
| --- | --- | --- |
| `no-self-approval` | a shell tool whose command answers an approval or touches `.agent-gate` | block |
| `protect-gateway-state` | any tool whose `path` argument points into `.agent-gate` | block |
| `shell-guard` | a shell tool (`run_command`, `exec`, `bash` and others): its `command` goes through the shell guard | the guard's decision |
| `red-line-1-money` | tool names with pay, charge, purchase, buy, transfer, checkout, refund, create payment, place order, create order | ask |
| `red-line-2-public` | post, publish, send, tweet, retweet, reply, comment, email, share | ask |
| `red-line-3-ship` | push, merge, deploy, create pull request, create pr, create release | ask |
| `red-line-4-delete` | delete, remove, drop, destroy, overwrite, purge, erase, wipe, truncate | ask |
| default | everything else | allow |

A rule can match on any of these, and all that are present must match:

- `server` and `tool`: a glob, `{ "regex": "...", "flags": "i" }`, or a list of them. A glob must
  match the whole name, ignoring case; `*` matches any run of characters and `?` one character.
  Regexes are objects rather than `/.../` strings so that a path such as `/etc/` is never read as
  one. The `g` and `y` flags are refused: they make `test()` remember where it stopped, so a rule
  could match one call and miss the next.
- `toolWords`: words or phrases. The tool name is split into lowercase words at every character
  that is not a letter or digit and at camelCase humps, so `delete_file`, `deleteFile` and
  `delete-file` all read as "delete file". Whole
  words must match: `post` matches `post_message` and `publishPost` but not `postgres_query`, and
  `comment` matches `add_comment` but not `list_comments`.
- `args`: argument name to matcher. Each listed argument must be present and match. Strings are
  matched as they are; other values as their JSON text.

A rule with `"type": "shell"` has no fixed decision. It runs the shell guard's `analyze()` on one
string argument (`"argument"`, default `command`) and maps pass, warn, ask and block to allow,
warn, ask and block. A missing or non-string argument is asked about. If the analyzer itself fails,
the legacy rules decide and anything they do not block is asked about, as in the hook.

Mistakes in the policy or the config stop the gateway at startup with the field named, for
example `policy.rules[2].decision must be one of allow, warn, ask, block`. Unknown fields are
errors too, so a typo cannot silently turn a rule off.

### Audit log

Every decision appends one JSON line to `<stateDir>/audit.jsonl` (mode 0600). These are the
lines from the run above, plus a blocked shell call:

```json
{"ts":"2026-10-14T08:55:58.727Z","server":"demo","tool":"delete_file","decision":"ask","rule":"red-line-4-delete","why":"Red line 4: this tool looks like it deletes or overwrites data.","argsHash":"sha256:2982c72ec2280a4ac4c81c3a63b93294acee61a8bbbf879694d0653e48515ddb","forwarded":false,"approvalId":"ap-f646780e"}
{"ts":"2026-10-14T08:55:58.931Z","server":"demo","tool":"delete_file","decision":"ask","rule":"red-line-4-delete","why":"Red line 4: this tool looks like it deletes or overwrites data.","argsHash":"sha256:2982c72ec2280a4ac4c81c3a63b93294acee61a8bbbf879694d0653e48515ddb","forwarded":true,"approvalId":"ap-f646780e"}
{"ts":"2026-10-14T08:55:58.938Z","server":"demo","tool":"delete_file","decision":"ask","rule":"red-line-4-delete","why":"Red line 4: this tool looks like it deletes or overwrites data.","argsHash":"sha256:2982c72ec2280a4ac4c81c3a63b93294acee61a8bbbf879694d0653e48515ddb","forwarded":false,"approvalId":"ap-ed722973"}
{"ts":"2026-10-14T08:55:58.940Z","server":"demo","tool":"run_command","decision":"block","rule":"shell-guard","why":"shell guard: force push","argsHash":"sha256:2c29a8326969480173c60a2f1083c6dbf5b73aa28539723243a204c8793dc5e9","forwarded":false}
```

`forwarded` says whether the call reached the downstream server. Argument values are not logged:
tool arguments often carry secrets (tokens, passwords) and personal data (names, message bodies),
while an audit log is kept for a long time and read by more people than the call itself. The hash
is enough to tie a line to an approval, or to a call that someone already has in hand. Set
`"auditArguments": true` to log the values anyway. If a line cannot be written, the call is not
run.

### What the gateway does not cover

- It trusts the downstream server's tool names, and it cannot see what a tool does inside. A tool
  called `sync` that pushes, or `get_report` that also sends an email, gets the default decision.
  The filesystem reference server's `write_file` replaces a file's content, but its name has no
  red-line word, so the example policy allows it. For an unfamiliar server, consider
  `"default": "ask"` with allow rules for the tools you know only read.
- Word matching has false positives too: `get_email` and `get_comment` are asked about. Put an
  allow rule for them before the red-line rules.
- It does not use MCP tool annotations such as `destructiveHint`. They come from the same server
  whose names it already has to trust.
- Argument matching is text matching. It does not resolve paths, symlinks or the working
  directory.
- An approval is only as safe as the place it is stored. Anyone who can run the CLI or write
  `<stateDir>` can approve, including an agent that has its own shell or file tools outside the
  gateway. The example policy stops this through the gateway (`no-self-approval`,
  `protect-gateway-state`), but an agent's native shell, such as Claude Code's Bash tool, never
  passes through it. Keep the state directory out of the agent's reach, for example owned by
  another OS user.
- Only tools are proxied. Resources, prompts, and requests from a downstream server back to the
  client (sampling, elicitation) are not.
- Downstream servers are started once. If one fails to start, the gateway does not start; if one
  dies later, its calls fail until the gateway is restarted.
- Downstream calls use the SDK's default 60-second request timeout, and progress notifications
  are not relayed, so a tool that runs longer than a minute fails through the gateway.

## Run the tests

```
npm install
npm test
```

`npm test` compiles the TypeScript and then runs `node --test` (Node 20 or newer) over two suites.

The shell guard suite needs no dependencies; `node --test test/command-guard.test.js` runs it on
its own. It runs 245 tests: the 239 cases in `test/cases.json`, a check that the file is well
formed, and 5 tests that run the hook as a child process. Each case has an `expect` of `pass`,
`warn`, `ask` or `block`; `ask_or_block` accepts either of the last two (3 cases).

The gateway suite (`test/gateway/`) runs 118 tests: a policy table for each red line and for the
shell rule (every case in `test/cases.json` is also run through the gateway's shell rule), config
and policy validation, the approval store with a clock the test controls, the CLI's exit codes,
and an end-to-end test. That test starts `agent-gate serve` against a fake downstream server,
talks to it with a real MCP client, answers approvals with the real CLI, and checks what reached
the downstream server and what was written to the audit log.

Current result: **239/239 cases pass** (245/245 shell guard tests, 118/118 gateway tests), on Node
20 and 22. CI runs `npm ci` and `npm test` on both.

## Repository layout

```
src/command-guard.js                     the analyzer: analyze(command) -> { action, label, why }
src/command-guard.d.ts                   its types, for the TypeScript gateway
bin/claude-pretooluse-hook.js            the Claude Code PreToolUse hook
src/gateway/server.ts                    the MCP gateway: lists <server>__<tool>, decides, forwards
src/gateway/policy.ts                    the policy engine (pure): evaluate(policy, call) -> verdict
src/gateway/approvals.ts                 the approval queue in <stateDir>/approvals.json
src/gateway/audit.ts                     the audit log, <stateDir>/audit.jsonl
src/gateway/config.ts                    loads and checks the gateway config
src/gateway/validate.ts                  field-by-field checks for the config and the policy
src/gateway/cli.ts                       agent-gate serve, agent-gate approvals ...
bin/agent-gate.js                        the CLI entry point (runs the build in dist/)
policy.example.json                      the red lines as a gateway policy
gateway.config.example.json              a config that proxies the fake test server
test/cases.json                          239 cases: id, category, expect, cmd
test/command-guard.test.js               table test over the cases, plus hook process tests
test/gateway/*.test.ts                   gateway tests: policy, config, approvals, CLI, end to end
test/gateway/fake-downstream.ts          the fake MCP server for the end-to-end test
test/SANITIZED.md                        what was changed in the cases before publication
docs/red-team.md                         the case categories, with counts
docs/adr/0001-non-blocking-approvals.md  why "ask" answers with an error instead of waiting
tsconfig.json                            compiles src/ and test/ into dist/
.github/workflows/ci.yml                 npm ci and npm test on Node 20 and 22
```

`package.json` maps `#command-guard` to `src/command-guard.js` (its `imports` field), so the
compiled gateway in `dist/` loads the analyzer straight from `src/`, with no copy.

## Origin

agent-gate started as a private hook for the author's own Claude Code setup, called
`safety-blocker` there (the name still appears inside a few test commands). The author designed
it and directed Claude Code and Codex as coding agents, and Codex also served as one of the
attackers in the red-team rounds. The code here is its fifth version. The comments, labels and messages were written in Thai and have been translated to
English, and personal paths and names were removed from the test cases. `test/SANITIZED.md` lists
every case that was changed.

## License

MIT. See [LICENSE](LICENSE).
