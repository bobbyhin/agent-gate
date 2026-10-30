"use strict";
// Loaded with `node --require` in front of the hook by test/command-guard.test.js. It makes every
// module that reaches the network or starts another process throw when loaded, and replaces the
// network globals with functions that throw, so the test shows that the guard needs neither.
const Module = require("node:module");

const BANNED = new Set(["net", "tls", "http", "https", "http2", "dgram", "dns", "child_process", "cluster", "worker_threads", "inspector"]);
const load = Module._load;
Module._load = function guardedLoad(request, parent, isMain) {
  const name = String(request).replace(/^node:/, "").split("/")[0];
  if (BANNED.has(name)) throw new Error(`no-network preload: "${request}" was loaded`);
  return load.call(this, request, parent, isMain);
};
for (const name of ["fetch", "WebSocket", "EventSource"]) {
  Object.defineProperty(globalThis, name, {
    configurable: true,
    writable: true,
    value: () => {
      throw new Error(`no-network preload: ${name} was used`);
    },
  });
}
