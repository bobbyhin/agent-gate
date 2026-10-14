# Red-team cases

`test/cases.json` holds 239 shell commands. Each has an `id`, a `category`, an `expect` (the
decision the analyzer must return) and the command itself (`cmd`). The cases were collected while
the analyzer was being attacked and repaired. `npm test` checks every one of them.

`expect` is one of `pass`, `warn`, `ask` or `block`. A few cases use `ask_or_block`, where either
`ask` or `block` is acceptable (for example `rm -rf ~/x` and `find / -delete`).

The cases come from the author's private run logs. Personal paths, names and Thai text were removed
before publication; see [test/SANITIZED.md](../test/SANITIZED.md) for every change.

## Expected decisions

| Expected decision | Cases |
| --- | --- |
| pass | 69 |
| warn | 1 |
| ask | 119 |
| ask or block | 3 |
| block | 47 |
| total | 239 |

## Categories

Categories are listed in the order they appear in the file.

| Category | Cases | Expected decisions |
| --- | --- | --- |
| control | 11 | 2 pass, 5 ask, 1 ask or block, 3 block |
| vuln-1 | 8 | 6 ask, 2 block |
| vuln-2 | 2 | 2 ask |
| vuln-3 | 5 | 5 ask |
| vuln-4 | 7 | 7 ask |
| augmented | 26 | 7 pass, 1 warn, 6 ask, 12 block |
| extra | 44 | 20 pass, 20 ask, 1 ask or block, 3 block |
| bypass-line-continuation | 6 | 4 ask, 2 block |
| bypass-shell-fed | 4 | 3 ask, 1 block |
| bypass-wrapper | 5 | 5 ask |
| bypass-git-prefix | 2 | 2 ask |
| bypass-publish | 4 | 4 ask |
| bypass-gh-api | 1 | 1 ask |
| bypass-rm-slash | 5 | 1 ask or block, 4 block |
| false-positive | 16 | 16 pass |
| codex-red-team | 55 | 12 pass, 34 ask, 9 block |
| red-team-2 | 38 | 12 pass, 15 ask, 11 block |

## What each category probes

- **control** (11): baseline checks every version must get right. A plain `git push`,
  `git -C . push` and `gh pr merge` ask. `git reset --hard`, a force push and `sudo rm -rf /`
  block. `ls -la` passes.
- **vuln-1** (8): dangerous commands hidden behind quoting. A push, a deploy, `gh pr merge`, a
  publish, a hard reset and `rm -rf ~` inside `bash -c "..."` or `sh -c '...'` (for example
  `bash -c "gh pr merge 12 --admin"`); a push that follows an apostrophe in a commit message; a
  quoted subcommand, `git "push" origin main`.
- **vuln-2** (2): a `#` inside a string, which the old comment stripping took for the start of a
  comment and so hid the rest of the line: `git commit -m "Fix #123" && git -C . push origin main`.
- **vuln-3** (5): heredocs and here-strings. `cat <<'EOF' | bash` with a push inside,
  `/bin/bash <<'EOF'`, a heredoc opener followed by `&& gh pr merge`, `read x <<< ok; npm publish`,
  and a `<<` inside a string followed by a real push.
- **vuln-4** (7): forms the old rules did not cover. `git -C <dir> branch -D main`,
  `git -C . restore .`, `gh api` with `-f` or `--method=PUT`, `gh workflow run`, `rm -v -r`, and a
  backslash-escaped `\git push`.
- **augmented** (26): taken from or modelled on real commands in the author's logs. Clear blocks
  (`rm -rf /`, `/*`, `~`, `"$HOME"`, force push, hard reset, `git clean -fd`, `git checkout -- .`,
  a bare `git stash drop`, `rm -rf /` inside a `bash` heredoc). Legitimate deletions that used to
  be blocked and now ask (`.venv`, `__pycache__`, a scratch directory, a cache directory), plus
  `--amend` and `--no-verify`. Commands that only mention a dangerous command in a commit message,
  a heredoc or a Python string, which pass. One `kill -9`, which warns.
- **extra** (44): more false positives and new variants. Commit messages, `echo` and `grep` that
  mention `git push` or `rm -rf` pass, and so do harmless commands such as `gh pr view`,
  `gh api -X GET ...`, `docker build`, `git branch -d` and `git stash drop stash@{1}`. New variants
  must not slip through: `timeout 30 git push`, `env GIT_DIR=x git push`, `if true; then git push; fi`,
  `git -c core.sshCommand=ssh push`, `git push origin +main` (block), `rm --recursive --force ~/old`,
  `gh api graphql` mutations, `docker compose push`, `uv publish`, `cargo publish`, `$(git push ...)`,
  backticks, `find ... -exec rm -rf {} +` and `npx vercel deploy --prod`.
- **bypass-line-continuation** (6): a backslash and a newline between the words of a command, such
  as `git \` then `push origin main`, with spaces or a tab on the next line.
- **bypass-shell-fed** (4): text piped or redirected into a shell, such as
  `echo '...' | bash`, `bash <<< '...'` and `echo '...' | sh`.
- **bypass-wrapper** (5): wrapper commands in front of the real one: `setsid`, `stdbuf -oL`,
  `flock /tmp/l`, `parallel git push ::: origin`, `chronic`.
- **bypass-git-prefix** (2): global git options that carry a quoted value with spaces, such as
  `git -c user.name="a b" push origin main`.
- **bypass-publish** (4): publish and deploy forms the first regex rules missed: `bun publish`,
  `wrangler pages publish`, a bare `vercel`, `npm --registry=... publish`.
- **bypass-gh-api** (1): a `gh api` write flag on a continuation line.
- **bypass-rm-slash** (5): spellings of the root and home directories: `rm -rf //`, `rm -rf /.`,
  `rm -rf -- /`, `rm -rf ~/..`, and `find / -delete`.
- **false-positive** (16): commands that only talk about something dangerous and must pass.
  Commit messages containing `git push`, `npm publish` or `rm -rf`; `echo`, `grep`, `rg` and
  `node -e` with that text; heredocs that write `git push origin main` or `vercel deploy --prod`
  into a file; `git log --oneline | grep push`; `gh pr view`.
- **codex-red-team** (55): the round where Codex attacked v3. Quoting and encoding tricks
  (`eval $'git\x20push ...'`, `bash -$'c' '...'`, `find $'\x2f' -delete`); shells that take text
  (`env -S`, `trap`, `case ... esac`, `bash <(...)`, `source <(...)`, `source /dev/stdin <<<`); more
  wrappers (`coproc`, `watch`, `parallel`, `flock`, `timeout`, `/usr/bin/time`, `xargs -a`); options
  glued to the command (`git -cprotocol.version=2 push`, `gh --repo=o/r pr create`); global options
  of docker, podman and package managers (`docker --context prod push`, `npm --workspace pkg publish`,
  `pnpm --filter pkg publish`); deploy tools (`firebase`, `gcloud`, `wrangler`, `flyctl`);
  `pnpm dlx vercel`, `npm exec vercel`, `git lfs push`, `gh --repo=o/r repo delete`. It also has false
  positives: `--no-gpg-sign` and `--no-verify` mentioned as data, and heredoc terminators with odd
  names (`EOF-1`, `END.docs`, `<<\EOF`).
- **red-team-2** (38): the round where a second red team attacked v4. Shell options before `-c`
  (`bash --norc -c`, `bash -o pipefail -c`, `bash -euo pipefail -c`, `sh --posix -c`,
  `zsh -o nocorrect -c`, `bash --login -c`); `arch -arm64 ...`; the wrappers `gtime`, `nocorrect`
  and `noglob`; unquoted text piped into a shell (`echo git push origin main | bash`,
  `printf '...' | bash`); `bash <(echo ...)`; `source <(echo rm -rf ~)`;
  `echo push origin main | xargs git`; a quoted shell name before a heredoc (`"bash" <<'EOF'`). It
  also has false positives (file names that contain `source` or `eval`, `vercel build`,
  `vercel env ls`, `docker run --rm`, `git restore --staged`, `find ... | xargs rm`,
  `grep -rn source`, `npm run publish:dry`, a commit message that ends in `push`) and one
  robustness case, an out-of-range code point in `$'\U110000'`, which once crashed the analyzer.

## Where the ids come from

The private suites reused ids, so every id in `test/cases.json` starts with the letter of the suite
it came from.

| Letter | Suite | Cases |
| --- | --- | --- |
| A | The 7 Oct audit: 6 controls and the 22 silent bypasses (`vuln-1` to `vuln-4`) | 28 |
| B | The August overhaul (`augmented`) | 26 |
| C | Extra false positives and variants added while fixing the holes (`extra`) | 44 |
| D | Red-team round 1, against v2: controls, `bypass-*` and `false-positive` | 48 |
| E | The Codex round, against v3 (`codex-red-team`) | 55 |
| F | Red-team round 2, against v4 (`red-team-2`) | 38 |

The sizes of D, E and F are the denominators in the history in the README (21 of 48, 43 of 55,
20 of 38).

## Adding a case

Add an object with a unique `id`, a `category`, an `expect` and the `cmd` to `test/cases.json`, then
run `npm test`. Keep a case free of real paths, names and credentials. If a case is a false
positive, keep the dangerous words in it: the point is that talking about a command must not
trigger the guard.
