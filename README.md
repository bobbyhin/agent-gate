# agent-gate

A guard that sits between an AI coding agent and the shell. Before the agent runs a shell
command, agent-gate reads the command and decides one of four things: **pass**, **warn**,
**ask** a human, or **block**.

This repository has three parts:

- `src/command-guard.js`: the analyzer. One function, no dependencies. `analyze(command)`
  returns `{ action, label, why }`.
- `bin/claude-pretooluse-hook.js`: a Claude Code `PreToolUse` hook built on the analyzer.
- `test/cases.json`: 239 commands, each with the decision it must get. They come from red-team
  rounds against earlier versions of the analyzer.

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
| v4 | red team 2, 38 cases | 20 of 38 got through; 16 cases were worse than in the previous version |
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

## Run the tests

```
npm test
```

This runs `node --test` (Node 20 or newer, no dependencies). It runs 245 tests: the 239 cases in
`test/cases.json`, a check that the file is well formed, and 5 tests that run the hook as a child
process. Each case has an `expect` of `pass`, `warn`, `ask` or `block`; `ask_or_block` accepts
either of the last two (3 cases).

Current result: **239/239 cases pass** (245/245 tests). CI runs the same command on Node 20 and 22.

## Repository layout

```
src/command-guard.js            the analyzer: analyze(command) -> { action, label, why }
bin/claude-pretooluse-hook.js   the Claude Code PreToolUse hook
test/cases.json                 239 cases: id, category, expect, cmd
test/command-guard.test.js      table test over the cases, plus hook process tests
test/SANITIZED.md               what was changed in the cases before publication
docs/red-team.md                the case categories, with counts
.github/workflows/ci.yml        npm test on Node 20 and 22
```

## Origin

agent-gate started as a private hook the author wrote for their own Claude Code setup, called
`safety-blocker` there (the name still appears inside a few test commands). The code here is its
fifth version. The comments, labels and messages were written in Thai and have been translated to
English, and personal paths and names were removed from the test cases. `test/SANITIZED.md` lists
every case that was changed.

## License

MIT. See [LICENSE](LICENSE).
