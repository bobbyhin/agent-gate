// agent-gate · command guard
//
// Classifies one shell command as pass / warn / ask / block. It is meant to sit in front of
// an AI coding agent's shell tool (for example as a Claude Code PreToolUse hook).
// It reads a command the way a shell does. It is NOT a full shell parser.
//
// This is v5 of a hook the author wrote for their own agent setup. History:
//
// ── Overhaul, 22 Aug 2026 (the operator chose "ask instead of block") ─────────────────
// Evidence: 46 days of hook events showed 34 blocks, but ~32 of them were legitimate work
// (deleting a scratch directory, __pycache__, .venv) and ~5 were "text that merely talks
// about a command". Result: three layers, CRITICAL / ASK / WARN.
//
// ── v5 · 7 Oct 2026 (afternoon): closes the "blind because strings were stripped" hole ──
// (found in tier 2 of a security-audit field exercise)
// Evidence: an oracle ran the real hook and 22/22 bypasses passed silently:
//   bash -c "…git push" · git commit -m "Fix #123" && git -C . push · cat <<EOF | bash ·
//   git -C . restore . · gh api -f … · rm -v -r … · \git push · sh -c 'rm -rf ~'
//   (even the CRITICAL layer leaked).
// Four red-team rounds before installation: v2 regex (21/48 bypassed) → v3 (Codex bypassed
//   43/55) → v4 (red team 2 bypassed 20/38; 16 cases were worse than the previous version:
//   arch -arm64 git push · echo rm -rf ~ | bash · bash --norc -c) → this v5.
//
// How it reads a command the way a shell does (not a full parser):
//   1. heredoc: strip only the body that is not fed to a shell · the command line itself is
//      always kept · an unclosed heredoc = keep everything
//   2. join lines that end in \
//   3. scan quotes one character at a time (decode $'\x2f' like the shell):
//      a # at the start of a word outside a string = a comment · a string = "one inert word"
//      (a string starting with - is data, not a flag) · except $(…) / `…` inside "…", which
//      really run
//   4. if text is being fed to a shell (sh [options] -c · eval · trap · | bash · bash <<< ·
//      bash <(…) · source · ssh · su -c · env -S · watch · parallel) → open the strings up as
//      commands and check every word (not only at the start of a command)
//   5. normally a rule looks at "command position" (start of a command · after ; & | ( ) { $(
//      or a backtick · after wrapper commands such as sudo/env/timeout/xargs/arch/noglob/…
//      with any number of options) · options glued on like -cX=Y / --repo=o/r count as options
//   6. safety net: the legacy rule set (from before 7 Oct) is re-run on the text with data
//      heredocs stripped → take the "stronger" verdict, so nothing the old rules caught can
//      slip through (red team 2 showed the new reader alone could miss things)
//   7. if the guard itself breaks midway, the legacy rules decide; if they do not block, ask
//      the human · a command longer than 100k characters = ask
// Holes that remain (these need other layers: deny rules in the agent's settings · a
// classifier · not letting the agent hold credentials):
//   a git alias · a variable ($g push) · a script written earlier and run later ·
//   python/node calling a shell itself · a quoted flag ("--no-verify" is treated as data)
// Test suite and red-team results: test/cases.json and docs/red-team.md
// ─────────────────────────────────────────────────────────────────────────────────────
const fs = require("fs");

const SHELL = String.raw`(?:\S*\/)?(?:ba|z|k|da)?sh`;
const TOK = String.raw`[^\s;&|()]+`; // one word within a single command (does not cross a separator)
const SEG = String.raw`[^\n;&|]{0,300}`; // a stretch within a single command (length-capped so the regex cannot go quadratic, O(n²))
const SEGL = String.raw`[^\n;&|]{0,300}?`;
const KEYWORDS = String.raw`then|do|else|elif|if|while|until|!`;
const WRAPPERS = String.raw`(?:\S*\/)?(?:sudo|doas|env|nohup|g?time|chronic|unbuffer|setsid|nice|ionice|stdbuf|caffeinate|g?timeout|flock|parallel|watch|xargs|command|builtin|exec|coproc|eval|arch|nocorrect|noglob|script)`;
// Command position: start of text/line · after a shell separator · followed by any number of keywords/wrapper commands · after find -exec
const CMD =
  String.raw`(?:(?:^|[\n;&|(){\x60]|\$\()\s*(?:(?:` + KEYWORDS + String.raw`)\s+|` + WRAPPERS +
  String.raw`(?:\s+` + TOK + String.raw`)*?\s+)*|(?:^|\s)(?:-exec(?:dir)?|-ok)\s+)`;
const LOOSE = String.raw`(?:^|[\s;&|(){\x60]|\$\()`; // the start of any word (used when the text is fed to a shell)
const GIT = String.raw`(?:\S*\/)?git(?:\s+(?:-C|-c|--git-dir|--work-tree|--namespace|--exec-path|--config-env|--super-prefix)\s+\S+|\s+-\S+)*\s+`;
const GH = String.raw`(?:\S*\/)?gh(?:\s+(?:-R|--repo|--hostname)\s+\S+|\s+-\S+)*\s+`;
const DOCKER = String.raw`(?:\S*\/)?(?:docker|podman)(?:\s+(?:-c|--context|-H|--host|--config|-l|--log-level|--url|--connection|--identity)\s+\S+|\s+-\S+)*\s+`;
const NPX = String.raw`(?:(?:\S*\/)?(?:npx|bunx|pnpx|(?:pnpm|yarn)\s+dlx|npm\s+(?:exec|x))(?:\s+-\S+)*\s+)?`;
const ANY = String.raw`(?:\s+` + TOK + String.raw`)*?\s+`; // any options/arguments before the subcommand
const RM = String.raw`(?:\S*\/)?rm\b`;
const RFLAG = String.raw`(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)`;
const END = String.raw`(?=\s|$|[;&|)])`;
const ROOT = String.raw`(?:\/+\.?\/*|~(?:\/+\.{0,2})*\/*|\$\{?HOME\}?(?:\/+\.{0,2})*\/*)\*?` + END;
// One rule = two forms: must be at command position (normal) · may start at any word (when the text is fed to a shell)
const mk = (body, flags = "") => ({ re: new RegExp(CMD + body, flags), loose: new RegExp(LOOSE + body, flags) });
const plain = (re) => ({ re, loose: re });

// ── Layer 1: always wrong → exit 2, cannot be overridden ──────────────────────────
const CRITICAL = [
  { ...mk(RM + SEG + String.raw`\s` + RFLAG + String.raw`\b` + SEGL + String.raw`\s` + ROOT), label: "rm -rf / ~ $HOME (whole machine / whole home directory)" },
  { ...mk(String.raw`(?:\S*\/)?find\s+(?:\/+|~\/?|\$\{?HOME\}?\/?)(?=\s)` + SEG + String.raw`\s-delete\b`), label: "find / -delete" },
  { ...mk(GIT + String.raw`push\b` + SEG + String.raw`\s(?:--force(?!-with-lease)\b|-[a-zA-Z]*f[a-zA-Z]*\b|\+\S)`), label: "force push" },
  { ...mk(GIT + String.raw`reset\b` + SEG + String.raw`\s--hard\b`), label: "hard reset" },
  { ...mk(GIT + String.raw`clean\b` + SEG + String.raw`\s-[a-zA-Z]*f`), label: "git clean -f" },
  { ...mk(GIT + String.raw`checkout\s+(?:--\s+)?(?:\.|\*)` + END), label: "git checkout . (discards all changes)" },
  { ...mk(GIT + String.raw`stash\s+drop(?!\s+stash@\{)\b`), label: "bare stash drop" },
  { ...mk(GIT + String.raw`branch\s+-D(?:\s+(?:\.|\*|--all))?\s*$`, "m"), label: "git branch -D wildcard" },
  { ...plain(/(?:^|\s)--no-gpg-sign(?=\s|$)/), label: "skip signing" },
  { ...plain(/rmdir\s+\/s/), label: "rmdir /s" },
  { ...plain(/\bdel\s+\/[sfq]/i), label: "del with force flags" },
];

// ── Layer 2: depends on context → ask a human ─────────────────────────────────────
const ASK_RED = [
  { ...mk(GIT + String.raw`(?:(?:lfs|subtree)\s+)?push\b`), label: "git push (any form)", why: "Red line 3 — a push needs a human decision" },
  { ...mk(String.raw`(?:\S*\/)?xargs(?:\s+` + TOK + String.raw`)*?\s+(?:\S*\/)?(?:git|gh)(?=\s*(?:$|[;&|)\n]))`), label: "xargs git (subcommand comes from input)", why: "cannot see whether it will push or merge" },
  { ...mk(GH + String.raw`pr\s+(?:create|merge|ready)\b`), label: "gh pr create/merge", why: "Red line 3 — a PR or merge needs a human decision" },
  { ...mk(GH + String.raw`release\s+(?:create|upload|edit|delete)\b`), label: "gh release", why: "Red line 3 — publishing a release needs a human decision" },
  { ...mk(GH + String.raw`repo\s+(?:create|delete|edit|rename|archive|sync)\b`), label: "gh repo (modifies a repo)", why: "modifying a repo on GitHub = leaves the machine" },
  {
    // Write = an explicit write method · has -f/-F/--input (gh switches to POST by itself) · a GraphQL mutation — unless GET is explicit
    ...mk(GH + String.raw`api\b(?!` + SEG + String.raw`(?:-X|--method)[\s=]*GET\b)` + SEG + String.raw`(?:(?:-X|--method)[\s=]*(?:POST|PUT|PATCH|DELETE)\b|\s(?:-f|-F|--field|--raw-field|--input)(?=[\s=]|$)|\bmutation\b)`, "i"),
    label: "gh api write",
    why: "writes data to GitHub directly",
  },
  { ...mk(GH + String.raw`(?:workflow\s+run|run\s+rerun)\b`), label: "gh workflow run", why: "triggers a workflow on GitHub (may deploy)" },
  {
    // bare vercel = deploy · except subcommands that do not ship anything
    ...mk(NPX + String.raw`(?:\S*\/)?vercel(?:@\S+)?(?!\s+(?:login|logout|whoami|ls|list|logs|inspect|dev|build|pull|help|link|env|domains|dns|projects|teams|switch|--help|-h|--version|-v)\b)` + END),
    label: "vercel (deploy)",
    why: "Red line 3 — a deploy needs a human decision",
  },
  { ...mk(NPX + String.raw`(?:\S*\/)?netlify(?:@\S+)?` + ANY + String.raw`deploy\b`), label: "netlify deploy", why: "Red line 3 — a deploy needs a human decision" },
  { ...mk(NPX + String.raw`(?:\S*\/)?wrangler(?:@\S+)?` + ANY + String.raw`(?:deploy|publish|pages\s+(?:deploy|publish)|versions\s+deploy)\b`), label: "wrangler deploy", why: "Red line 3 — a deploy needs a human decision" },
  { ...mk(String.raw`(?:\S*\/)?(?:fly(?:ctl)?|firebase)` + ANY + String.raw`deploy\b`), label: "deploy (fly/firebase)", why: "Red line 3 — a deploy needs a human decision" },
  { ...mk(String.raw`(?:\S*\/)?gcloud` + ANY + String.raw`(?:app|run|functions)\s+deploy\b`), label: "gcloud deploy", why: "Red line 3 — a deploy needs a human decision" },
  { ...mk(NPX + String.raw`(?:\S*\/)?(?:npm|pnpm|yarn|bun|uv|cargo|poetry|hatch|flit)(?:@\S+)?` + ANY + String.raw`publish` + END), label: "publish package", why: "releases something publicly" },
  { ...mk(String.raw`(?:\S*\/)?(?:twine\s+upload|gem\s+push)\b`), label: "publish package", why: "releases something publicly" },
  { ...mk(DOCKER + String.raw`(?:(?:compose|image)\s+(?:-\S+\s+)*)?push\b`), label: "docker/podman push", why: "pushes an image to a registry" },
  { ...mk(DOCKER + String.raw`(?:buildx\s+)?build\b` + SEG + String.raw`\s--push\b`), label: "docker build --push", why: "pushes an image to a registry" },
  { ...mk(RM + SEG + String.raw`\s` + RFLAG + END), label: "rm -r (deletes a whole folder)", why: "Red line 4 — deleting a whole folder is hard to undo" },
  { ...mk(GIT + String.raw`restore\b` + SEG + String.raw`\s(?:\.|-W|--worktree|:\/)` + END), label: "git restore .", why: "discards uncommitted work" },
  { ...mk(GIT + String.raw`branch\b` + SEG + String.raw`\s(?:-[a-zA-Z]*D[a-zA-Z]*|--delete\s+--force|--force\s+--delete)` + END), label: "git branch -D", why: "deletes a branch without checking that it was merged" },
  { ...mk(GIT + String.raw`stash\s+clear\b`), label: "git stash clear", why: "throws away every stash" },
];
// Minor rules — checked only outside strings (they used to misfire because a commit message talked about them)
const ASK_NOISY = [
  { re: new RegExp(CMD + GIT + String.raw`commit\b` + SEG + String.raw`\s--amend\b`), label: "amend commit", why: "overwrites the previous commit" },
  { re: /(?:^|\s)--no-verify(?=\s|$|[;&|)])/, label: "skips pre-commit hooks", why: "bypasses secret/lint checks" },
];

// ── Layer 3: warn, then proceed ───────────────────────────────────────────────────
const WARN = [
  { pattern: /DROP\s+(DATABASE|TABLE|SCHEMA)/i, label: "DROP database/table" },
  { pattern: /TRUNCATE\s+TABLE/i, label: "TRUNCATE" },
  { pattern: /kill\s+-9/, label: "kill -9 (SIGKILL)" },
  { pattern: /taskkill\s+\/f/i, label: "taskkill /f" },
];

// Is any text being fed to a shell to run? (checks both the command that still has its quotes and the inert view)
const B = String.raw`(?:^|[^\w./-])`;
const SHELL_FED = new RegExp(
  [
    B + SHELL + String.raw`(?:\s+` + TOK + String.raw`)*?\s+-[a-zA-Z]*c(?=[\s'"$]|$)`, // bash --norc -c · bash -euo pipefail -c
    B + String.raw`(?:eval|trap)\b`,
    String.raw`\|\s*(?:sudo\s+)?` + SHELL + END,
    B + SHELL + String.raw`(?:\s+` + TOK + String.raw`)*?\s*<<<`,
    B + String.raw`(?:` + SHELL + String.raw`|source|\.)\s*<\(`,
    B + String.raw`(?:source|\.)\s+\/dev\/stdin`,
    B + String.raw`(?:\S*\/)?ssh\b`,
    B + String.raw`su\b` + SEG + String.raw`\s-c\b`,
    B + String.raw`script\b` + SEG + String.raw`\s-c\b`,
    B + String.raw`env\b` + SEG + String.raw`\s-[a-zA-Z]*S`,
    B + String.raw`(?:watch|parallel)\b`,
  ].join("|")
);
// A heredoc fed to a shell (checked on the line holding the << operator with quotes removed · source/eval must be a command, not a file name)
const HEREDOC_FED = new RegExp(
  String.raw`(?:^|[\s|;&(])` + SHELL + String.raw`(?=\s|$|[;&|)<])|(?:^|[\s|;&(])(?:\S*\/)?ssh(?=\s)|(?:^|[\s|;&(])(?:source|eval|\.)(?=\s)`
);

// ── Safety net: the legacy rule set (taken verbatim from the version before 7 Oct · only the names changed) ──
const LEGACY_CRITICAL = [
  // Wipes the whole machine or home (note: must be a bare / or ~ only, not a /sub/path)
  { pattern: /rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+\/(\s|$|;|&|\*)/, label: "rm -rf / (whole machine)" },
  { pattern: /rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+~\/?(\s|$|;|&|\*)/, label: "rm -rf ~ (whole home directory)" },
  { pattern: /rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+\$\{?HOME\}?\/?(\s|$|;|&|\*)/, label: "rm -rf $HOME" },
  // Red line 3 — pushes that overwrite other people's history
  { pattern: /git\s+push\s+--force(?!-with-lease)/, label: "force push" },
  { pattern: /git\s+push\s+-f\b/, label: "force push" },
  { pattern: /git\s+push\s+(-f|--force)\s+(origin\s+)?(main|master)\b/, label: "force push to main" },
  { pattern: /git\s+push\s+(origin\s+)?(main|master)\s+(-f|--force)/, label: "force push to main" },
  // Red line 4 — throws away uncommitted work with no way to recover it
  { pattern: /git\s+reset\s+--hard/, label: "hard reset" },
  { pattern: /git\s+clean\s+-[a-zA-Z]*f/, label: "git clean -f" },
  { pattern: /git\s+checkout\s+--\s+(\.|\*)(\s|$)/, label: "git checkout -- wildcard" },
  { pattern: /git\s+stash\s+drop(?!\s+stash@\{)/, label: "bare stash drop" },
  { pattern: /git\s+branch\s+-D(\s+(\.|\*|--all))?\s*$/m, label: "git branch -D wildcard" },
  { pattern: /--no-gpg-sign/, label: "skip signing" },
  { pattern: /rmdir\s+\/s/, label: "rmdir /s" },
  { pattern: /del\s+\/[sfq]/i, label: "del with force flags" },
];

// ── Layer 2: depends on context → ask a human (decided 22 Aug: "ask instead of block") ──
// These used to be exit 2 across the board, so the agent quietly worked around them 32 times without the operator knowing
const LEGACY_ASK = [
  { pattern: /rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+[^\s]/, label: "rm -rf", why: "deletes a whole folder without asking again" },
  { pattern: /git\s+commit\s+--amend/, label: "amend commit", why: "overwrites the previous commit" },
  { pattern: /--no-verify/, label: "skips pre-commit hooks", why: "bypasses secret/lint checks" },
  // ── 7 Oct 2026 (infrastructure audit; the operator said "handle all of them"): close the red line 3 holes ──
  // The agent settings only had a deny rule for "Bash(git push:*)", which matches only a command that starts exactly like that → `git -C . push` ·
  // `/usr/bin/git push` · `gh pr merge` · every deploy command could all slip through (tested: 15/15 got past the guard)
  { pattern: /(^|[\s;&|(])(\S*\/)?git\b[^\n;&|]*\spush\b/, label: "git push (any form)", why: "Red line 3 — a push needs a human decision" },
  { pattern: /\bgh\s+pr\s+(create|merge|ready)\b/, label: "gh pr create/merge", why: "Red line 3 — a PR or merge needs a human decision" },
  { pattern: /\bgh\s+release\s+(create|upload|edit|delete)\b/, label: "gh release", why: "Red line 3 — publishing a release needs a human decision" },
  { pattern: /\bgh\s+repo\s+(create|delete|edit|rename|archive)\b/, label: "gh repo (modifies a repo)", why: "modifying a repo on GitHub = leaves the machine" },
  { pattern: /\bgh\s+api\b[^\n]*(-X|--method)\s*['"]?(POST|PUT|PATCH|DELETE)\b/i, label: "gh api write", why: "writes data to GitHub directly" },
  { pattern: /\b(vercel|netlify)\b[^\n]*(\s--prod\b|\sdeploy\b)/, label: "deploy (vercel/netlify)", why: "Red line 3 — a deploy needs a human decision" },
  { pattern: /\b(wrangler\s+(deploy|publish|pages\s+deploy)|fly(ctl)?\s+deploy|firebase\s+deploy)\b/, label: "deploy", why: "Red line 3 — a deploy needs a human decision" },
  { pattern: /\b(npm|pnpm|yarn)\s+publish\b|\bdocker\s+push\b|\btwine\s+upload\b/, label: "publish/push package", why: "releases something publicly" },
  // Red line 4 — throws work away in a way that is hard to recover (forms that still slipped through)
  { pattern: /rm\s+-[a-zA-Z]*R[a-zA-Z]*\s+[^\s]/, label: "rm -R", why: "deletes a whole folder (the -R form)" },
  { pattern: /\bgit\s+restore\s+(\.|-W\b|--worktree\b)/, label: "git restore .", why: "discards uncommitted work" },
  { pattern: /\bgit\s+branch\s+-D\s+\S+/, label: "git branch -D", why: "deletes a branch without checking that it was merged" },
];

// ── Layer 3: warn, then proceed ───────────────────────────────────────────────────
const LEGACY_WARN = [
  { pattern: /DROP\s+(DATABASE|TABLE|SCHEMA)/i, label: "DROP database/table" },
  { pattern: /TRUNCATE\s+TABLE/i, label: "TRUNCATE" },
  { pattern: /kill\s+-9/, label: "kill -9 (SIGKILL)" },
  { pattern: /taskkill\s+\/f/i, label: "taskkill /f" },
];

// The old-style text stripper (used only by the safety net)
function legacyStrip(raw) {
  let s = raw;

  // 1) A heredoc is data, not a command of the outer shell → remove the whole block
  //    WARNING: except a heredoc fed to a shell (bash/sh/zsh/eval/source) — its body
  //    really runs, so it must not be removed, or it becomes a hole for evading the guard
  const FED_TO_SHELL = /(^|[|;&]|\s)(ba|z|k|da)?sh\b[^\n<]*$|(^|\s)(eval|source|exec)\b[^\n<]*$/;
  const stripHeredocs = (str, re) =>
    str.replace(re, (match, ...rest) => {
      const offset = rest[rest.length - 2];
      const head = str.slice(0, offset).split("\n").pop();
      return FED_TO_SHELL.test(head) ? match : " <heredoc> ";
    });

  //    (closed form)
  s = stripHeredocs(s, /<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1[\s\S]*?^[\t ]*\2[\t ]*$/gm);
  //    (unclosed form — happens when a log cuts the command at 200 characters, or the command is long)
  s = stripHeredocs(s, /<<-?\s*(['"]?)[A-Za-z_][A-Za-z0-9_]*\1[\s\S]*$/m);

  // 2) comments in scripts
  s = s.replace(/(^|\s)#[^\n]*/g, " ");

  // 3) strings in quotes: drop the prose but keep a path
  //    "rm -rf /home/x"  → must still be caught   |   -m "says that --no-verify is used" → must not be caught
  const keepIfPath = (inner) =>
    /^[/~]|^\$\{?HOME\}?/.test(inner.trim()) ? inner.trim().split(/\s+/)[0] : "<str>";
  s = s.replace(/'([^']*)'/g, (_m, inner) => " " + keepIfPath(inner) + " ");
  s = s.replace(/"([^"]*)"/g, (_m, inner) => " " + keepIfPath(inner) + " ");

  return s;
}

/** Legacy-rule safety net: the verdict of the hook as it was before 7 Oct. */
function legacyDecide(text) {
  const cmd = legacyStrip(text);
  for (const { pattern, label } of LEGACY_CRITICAL) if (pattern.test(cmd)) return { action: "block", label: `${label} (legacy rule)` };
  for (const { pattern, label, why } of LEGACY_ASK) if (pattern.test(cmd)) return { action: "ask", label: `${label} (legacy rule)`, why };
  for (const { pattern, label } of LEGACY_WARN) if (pattern.test(cmd)) return { action: "warn", label };
  return { action: "pass" };
}

/** Does this text end inside an unclosed quote? */
function quoteOpen(s) {
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\" && q !== "'") { i++; continue; }
    if (q) { if (c === q) q = null; }
    else if (c === "'" || c === '"') q = c;
  }
  return q !== null;
}

/** Step 1: remove the bodies of heredocs that are "data" (not fed to a shell) — the command line itself is always kept. */
function stripDataHeredocs(s) {
  const lines = s.split("\n");
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    out.push(line);
    i++;
    const ops = [];
    const re = /<<(-?)\s*\\?(['"]?)([^\s'"<>|;&()]+)\2/g;
    let m;
    while ((m = re.exec(line))) {
      if (line[m.index + 2] === "<" || (m.index > 0 && line[m.index - 1] === "<")) continue; // <<< here-string
      if (quoteOpen(line.slice(0, m.index))) continue; // inside a string
      ops.push({ dash: m[1] === "-", word: m[3] });
    }
    if (!ops.length) continue;
    const fed = HEREDOC_FED.test(line.replace(/['"\\]/g, ""));
    for (const op of ops) {
      const word = op.word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const term = new RegExp("^" + (op.dash ? "\\t*" : "") + word + "[\\t ]*$");
      let j = i;
      while (j < lines.length && !term.test(lines[j])) j++;
      if (j >= lines.length) break; // unclosed → keep everything that remains (safe by default)
      if (fed) for (let k = i; k <= j; k++) out.push(lines[k]);
      i = j + 1;
    }
  }
  return out.join("\n");
}

/** Decode $'…' like bash (\xHH \uHHHH \NNN \n \t …) · a code point beyond the Unicode range becomes U+FFFD (it used to crash the hook). */
function ansiDecode(b) {
  const map = { n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", v: "\v" };
  return b.replace(/\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|c.|[\s\S])/g, (_m, e) => {
    if (e[0] === "x") return String.fromCharCode(parseInt(e.slice(1), 16));
    if (e[0] === "u" || e[0] === "U") {
      const cp = parseInt(e.slice(1), 16);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : "\ufffd";
    }
    if (/^[0-7]/.test(e)) return String.fromCharCode(parseInt(e, 8) & 255);
    if (e[0] === "c" && e.length === 2) return String.fromCharCode(e.charCodeAt(1) & 31);
    return map[e] !== undefined ? map[e] : e;
  });
}

/** $(…) and `…` inside "…" still really run. */
function substitutions(body) {
  let out = "";
  const re = /\$\(([^()]*(?:\([^()]*\)[^()]*)*)\)|`([^`]*)`/g;
  let m;
  while ((m = re.exec(body))) out += "\n" + (m[1] !== undefined ? m[1] : m[2]) + "\n";
  return out;
}

/** Step 3: quote-aware scan → inert (strings kept as inert words) · fed (strings opened up as commands). */
function scan(s) {
  let inert = "";
  let fed = "";
  for (let i = 0; i < s.length; ) {
    const c = s[i];
    if (c === "\\") {
      if (i + 1 < s.length) { inert += s[i + 1]; fed += s[i + 1]; }
      i += 2;
      continue;
    }
    if (c === "#" && (i === 0 || /\s/.test(s[i - 1]))) {
      while (i < s.length && s[i] !== "\n") i++;
      continue;
    }
    const ansi = c === "$" && s[i + 1] === "'";
    if (c === "'" || c === '"' || ansi) {
      const q = ansi ? "'" : c;
      let j = ansi ? i + 2 : i + 1;
      let body = "";
      while (j < s.length && s[j] !== q) {
        if (ansi && s[j] === "\\" && j + 1 < s.length) { body += s[j] + s[j + 1]; j += 2; continue; }
        if (q === '"' && s[j] === "\\" && j + 1 < s.length) { body += s[j + 1]; j += 2; continue; }
        body += s[j];
        j++;
      }
      i = j + 1;
      if (ansi) body = ansiDecode(body);
      // A string = one word of data · one that starts with - (e.g. "--no-verify" in grep/echo/commit -m) does not count as a flag
      inert += (/^\s*-/.test(body) ? "\x02" : "") + body.replace(/\s/g, "\x01");
      if (q === '"' && !ansi) inert += substitutions(body);
      // Fed-to-a-shell view: a \n inside a string is often turned into a real newline by printf/echo -e
      fed += "\n" + scan(body.replace(/\\n/g, "\n")).fed + "\n";
      continue;
    }
    inert += c;
    fed += c;
    i++;
  }
  return { inert, fed };
}

const RANK = { pass: 0, warn: 1, ask: 2, block: 3 };

function analyze(raw) {
  if (raw.length > 100000) return { action: "ask", label: "command longer than 100k characters", why: "too long to inspect; a human should review it" };
  const pre = stripDataHeredocs(raw).replace(/\\\r?\n/g, " ");
  const { inert, fed } = scan(pre);
  const isFed = SHELL_FED.test(pre) || SHELL_FED.test(inert);
  const views = isFed ? [inert, fed] : [inert];
  const hit = (rule) => views.some((v) => rule.re.test(v)) || (isFed && views.some((v) => rule.loose.test(v)));
  let best = { action: "pass" };
  const crit = CRITICAL.find(hit);
  if (crit) best = { action: "block", label: crit.label };
  if (best.action === "pass") {
    const red = ASK_RED.find(hit) || ASK_NOISY.find((r) => r.re.test(inert));
    if (red) best = { action: "ask", label: red.label, why: red.why };
  }
  if (best.action === "pass") {
    const w = WARN.find((r) => r.pattern.test(inert));
    if (w) best = { action: "warn", label: w.label };
  }
  // Step 6: legacy-rule safety net (on the text with data heredocs already removed) — take the stronger verdict
  const legacy = legacyDecide(pre);
  return RANK[legacy.action] > RANK[best.action] ? legacy : best;
}

/**
 * Optional decision log. If the environment variable AGENT_GATE_LOG names a file, append one
 * JSON line to it for a warn / ask / block decision; otherwise do nothing. Logging is best
 * effort: it can never change a decision or break the guard, so every error is swallowed.
 * (The line contains the first 400 characters of the command: treat the file as sensitive.)
 */
function logDecision(command, decision) {
  const file = process.env.AGENT_GATE_LOG;
  if (!file) return;
  try {
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      action: decision.action,
      label: decision.label,
      why: decision.why,
      command: String(command).slice(0, 400),
    });
    fs.appendFileSync(file, line + "\n");
  } catch (_e) {
    /* best effort */
  }
}

module.exports = { analyze, legacyDecide, logDecision };
