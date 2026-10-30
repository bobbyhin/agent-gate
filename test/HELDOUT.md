# Held-out cases

`test/cases-heldout.json` holds 163 shell commands that this analyzer was never built or tuned
against. `npm run redteam` scores the analyzer on them; `npm test` fails if the score gets worse
than `test/heldout-baseline.json`.

## Where they come from

On 17 Oct 2026 a red team (Codex, as in the earlier rounds) attacked a later private version of the
hook, v6, before it was installed. It wrote 163 cases into a suite file: 122 commands that should be
stopped and 41 that should pass. v6 was built for a wider job than the code in this repository. Its
owner's four red lines were:

1. spending money: paid AI APIs called with curl, an SDK or a script; purchase buttons in browser
   automation scripts
2. posting publicly: social media APIs and SDKs, posting buttons in browser scripts, `gh issue comment`,
   `gh gist create --public`
3. push, merge, pull request, deploy, publish
4. deleting or overwriting something that cannot be undone, judged per file (a git-tracked file
   whose content is committed, a file created in the current session, a temp or cache directory
   could be deleted without asking)

This repository's analyzer covers red line 3, recursive deletes and lost work from red line 4, and
uploads of local files. It does not look at single-file deletes or overwrites, paid API calls,
posting, or code run by `python3`, `node` and other interpreters (see "Known limits" in the README).
So most of the held-out misses are outside what it tries to do. The set is kept whole anyway: it
measures the gap, and it is the yardstick for work that closes it.

## What was changed before publication

- The suite's placeholders were filled with made-up paths: `{FIX}` became `/tmp/fixture`, `{VAULT}`
  `/home/user/notes`, `{REPO}` `/home/user/repo`, `{SESSION}` `/tmp/session` and `{HOME}`
  `/home/user`. One command named a private folder directly; it now says `notes`.
- One command set an `api_key` to a placeholder string; it now says `not-a-real-key`.
- Ids got the prefix `H-`, and a `category` was taken from each id's first word: `ctl` control,
  `sh` shell-tricks, `del` delete-overwrite, `spend`, `post`, `push`, `fp` false-positive,
  `rob` robustness.
- Two cases depended on a transcript file that v6 read to tell which files the session created;
  that field was dropped. The labels were not changed: `expect` is what the red team wrote.

v6 decided some cases from files on disk (a fixture with git-tracked, cached and session files).
This analyzer never opens files, so for it those commands are plain text.

## Score

| Category | Cases | Stopped / should stop | Asked / should pass |
| --- | --- | --- | --- |
| control | 28 | 4 / 13 | 0 / 15 |
| shell-tricks | 34 | 1 / 33 | 0 / 1 |
| delete-overwrite | 34 | 0 / 34 | - |
| spend | 18 | 0 / 18 | - |
| post | 10 | 0 / 10 | - |
| push | 12 | 2 / 12 | - |
| false-positive | 17 | - | 2 / 17 |
| robustness | 10 | 1 / 2 | 0 / 8 |
| total | 163 | 8 / 122 | 2 / 41 |

v5.1 and v5.2 get the same score. What is stopped: `git -C <repo> push`, a force push, a hard reset
and `git clean -f` (control); `printf ... | bash` with a push; `gh api` with `--input`; a vercel deploy
named by a variable (by the safety net's text rule); and a command over 100,000 characters. The
two false asks are `rm -r` of `node_modules` and of a `/tmp` scratch folder: this analyzer asks before
any recursive delete, where v6 decided by whether the target could be recovered.

Speed: the slowest held-out case for v5.1 is 24 `env` words in a row, 3.4 s (its time doubled with every
word); v5.2 answers it in under 1 ms. The slowest for v5.2 is 60,000 characters of `true` lines, about
35 ms.
