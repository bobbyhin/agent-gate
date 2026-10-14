#!/usr/bin/env node
// agent-gate CLI: the MCP gateway and its approval commands. Run "agent-gate --help".
// The code is TypeScript in src/gateway/, compiled to dist/ by "npm run build".
"use strict";
const fs = require("node:fs");
const path = require("node:path");

const entry = path.join(__dirname, "..", "dist", "src", "gateway", "cli.js");
if (!fs.existsSync(entry)) {
  console.error('agent-gate: the build is missing; run "npm install" and then "npm run build".');
  process.exit(1);
}

require(entry)
  .main(process.argv.slice(2))
  .then(
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      console.error(`agent-gate: ${err && err.message ? err.message : err}`);
      process.exitCode = 1;
    },
  );
