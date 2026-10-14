#!/usr/bin/env node
// Claude Code PreToolUse hook for agent-gate.
//
// Reads the hook payload from stdin, classifies tool_input.command with src/command-guard.js
// and answers with the stdin/stdout/exit-code protocol of the original v5 hook:
//
//   pass   exit 0, the payload is echoed on stdout
//   warn   "[Hook] WARN: ..." on stderr, exit 0, the payload is echoed on stdout
//   ask    one line of JSON on stdout (hookSpecificOutput.permissionDecision = "ask"), exit 0
//   block  "[Hook] BLOCKED: ..." and the command on stderr, exit 2
//
// If the input cannot be parsed or the analyzer throws, the legacy rules decide: block if they
// say block, otherwise ask a human. It asks instead of passing silently.
//
// Set AGENT_GATE_LOG=/path/to/file to append one JSON line per warn / ask / block decision.
const { analyze, legacyDecide, logDecision } = require("../src/command-guard");

function ask(raw, label, why) {
  logDecision(raw, { action: "ask", label, why });
  console.log(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "ask",
        permissionDecisionReason: `⚠️ ${label} — ${why || "red line — a human must decide"}\n${raw.slice(0, 300)}`,
      },
    })
  );
  process.exit(0);
}

function block(raw, label) {
  console.error(`[Hook] BLOCKED: ${label}`);
  console.error(`[Hook] Command: ${raw.slice(0, 200)}`);
  logDecision(raw, { action: "block", label });
  process.exit(2);
}

let data = "";
// Decode as UTF-8 so a multi-byte character that is split across two stdin chunks survives.
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (data += chunk));
process.stdin.on("end", () => {
  let raw = "";
  let r;
  try {
    raw = JSON.parse(data).tool_input?.command || "";
    r = analyze(raw);
  } catch (err) {
    // Step 7: broke midway = the legacy rules decide; if they do not block, ask the human
    let legacy = { action: "pass" };
    try { legacy = legacyDecide(raw); } catch (_e) { /* fall through to ask */ }
    if (legacy.action === "block") block(raw, legacy.label);
    // String(): a malformed payload whose "command" is not a string must be asked about, not crash the hook
    ask(String(raw || data.slice(0, 300)), "agent-gate could not read the command", String(err).slice(0, 120));
    return;
  }
  if (r.action === "block") block(raw, r.label);
  if (r.action === "ask") ask(raw, r.label, r.why);
  if (r.action === "warn") {
    console.error(`[Hook] WARN: ${r.label} — proceeding`);
    logDecision(raw, { action: "warn", label: r.label });
  }
  console.log(data);
});
