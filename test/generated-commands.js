"use strict";
// A fixed, generated set of shell commands for the differential test in test/command-guard.test.js.
//
// It holds the commands of test/cases.json and test/cases-exfil.json, 40 rewrites of each (a wrapper in
// front, newlines for spaces, a directory prefix, git options, quotes, a heredoc, …) and 10,000 random
// mixes of words that the rules look for. The random part comes from a seeded generator, so the list
// is the same on every machine. Nothing here is a red-team case with an expected answer: the test only
// checks that the answers did not change between two versions of the guard.
const cases = [...require("./cases.json"), ...require("./cases-exfil.json")].map((c) => c.cmd);

// mulberry32: a small seeded random number generator (same numbers on every machine)
function random(seed) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const REWRITES = [
  (c) => "sudo " + c, (c) => "env A=1 " + c, (c) => "`" + c + "`", (c) => "{ " + c + "; }", (c) => "$(" + c + ")",
  (c) => "(" + c + ")", (c) => "x;" + c, (c) => "x\n" + c, (c) => c.replace(/ /g, "\n"), (c) => c.replace(/ /g, "\t"),
  (c) => "bash -c '" + c.replace(/'/g, "") + "'", (c) => "/usr/bin/" + c, (c) => c.replace(/\bgit /, "git -c a=b -C . "),
  (c) => c.replace(/\bgit /, "git -c "), (c) => c.replace(/\bgit /, "git -C -c "), (c) => "sudo -u `whoami` " + c,
  (c) => "xargs -I{} " + c, (c) => c.replace(/ /, " \n "), (c) => "echo x | " + c, (c) => "if true; then " + c + "; fi",
  (c) => "then\n" + c, (c) => "sudo\n" + c, (c) => c + " # comment", (c) => '"' + c + '"', (c) => "a;b/" + c,
  (c) => "a{b/" + c, (c) => "x`y/" + c, (c) => c.replace(/\bgh /, "gh -R -R "), (c) => c.replace(/\bdocker /, "docker -c -H "),
  (c) => "nohup time " + c, (c) => "sudo sudo " + c, (c) => "timeout 10 nice -n 5 " + c, (c) => c.replace(/ /g, "  "),
  (c) => "watch " + c, (c) => "cat <<EOF\n" + c + "\nEOF", (c) => "bash <<EOF\n" + c + "\nEOF", (c) => "ssh h " + c,
  (c) => c.replace(/\//g, "/./"), (c) => "{x " + c, (c) => c.replace(/ -/g, " \\\n -"),
];

const WORDS = ["git", "push", "-C", "-c", ".", "a=b", "--force", "-f", "gh", "pr", "merge", "-R", "o/r", "rm", "-rf", "-r", "~", "/", "$HOME", "x",
  "sudo", "env", "A=1", "xargs", "-I{}", "{}", "timeout", "10", "nice", "then", "if", "do", "!", "bash", "sh", "-c", "eval", "echo", "curl", "-d", "@x",
  "@~/.ssh/id_rsa", "docker", "podman", "-H", "npm", "publish", "npx", "vercel", "deploy", "gcloud", "run", "app", "/usr/bin/git", "./git", "a;b/git",
  "a{b/git", "x`/git", "reset", "--hard", "clean", "-fd", "checkout", "stash", "drop", "branch", "-D", "restore", "commit", "--amend", "--no-verify",
  "find", "-delete", "-exec", "netlify", "wrangler", "fly", "firebase", "twine", "upload", "kill", "-9", "DROP", "TABLE", "scp", "user@host:/tmp", "<<<",
  "<(", "cat", "|", "&&", ";", "\n", "`", "$(", ")", "(", "{", "}", "'", '"', "\\", "#", "<", ">", "2>&1", "--repo", "api", "-X", "POST", "-f", "release",
  "create", "lfs", "subtree", "build", "--push", "compose", "image", "su", "source", "/dev/stdin", "watch", "parallel", "exec", "command"];
const SEPARATORS = [" ", " ", " ", " ", "  ", "\t", "\n", ";", "|", "&&", "", " | ", "; "];
const WRAPPER_WORDS = new Set(["sudo", "env", "xargs", "timeout", "nice", "eval", "exec", "command", "watch", "parallel"]);

function generate() {
  const out = new Set(cases);
  for (const c of cases) for (const rewrite of REWRITES) out.add(rewrite(c));
  const next = random(12345);
  const pick = (list) => list[Math.floor(next() * list.length)];
  for (let k = 0; k < 10000; k++) {
    const n = 1 + Math.floor(next() * 18);
    let command = "";
    let wrappers = 0;
    for (let i = 0; i < n; i++) {
      let word = pick(WORDS);
      if (WRAPPER_WORDS.has(word) && ++wrappers > 6) word = "x"; // v5.1 needed exponential time for long runs of wrappers
      command += (i ? pick(SEPARATORS) : "") + word;
    }
    out.add(command);
  }
  return [...out];
}

module.exports = { generate };
