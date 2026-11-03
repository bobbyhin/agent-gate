// The approvals page: one HTML document with its style and its script inline. "agent-gate approvals ui"
// serves it in mode "live" (src/gateway/approvals-ui.ts); scripts/demo-approvals.js writes it to
// docs/demo/approvals.html in mode "demo", with a recorded run. The script and the style are the same
// text in both, so the public demo runs the page's real code, and the Content-Security-Policy can name
// them by hash.
//
// Live: the script reads the launch key from the link's fragment, takes it out of the address bar,
// trades it for a session (POST /api/session) and keeps the session and its CSRF token in the tab's
// sessionStorage. It sends them as headers, never as cookies. The read-back of an irreversible request
// shows its action token next to the call, for the human to type; the field starts empty and the page
// never fills it. The server checks what was typed.
// Demo: the script reads the recorded run from the page and sends nothing. The demo page has no fetch
// to make in any case: its policy (a meta element) allows no connection at all.
// Everything the agent sent is put into the page as text (createTextNode), never as HTML, and
// invisible or direction-changing characters are shown as \uXXXX escapes, so that a read-back reads as
// the call will run.

import { createHash } from "node:crypto";

export const PAGE_STYLE = String.raw`
  :root {
    --bg: #f7f7f5; --panel: #ffffff; --ink: #1d1d1b; --muted: #5f5f5a; --line: #e2e1dc;
    --code-bg: #f1f0ec; --accent: #2457c5;
    --allow: #1f7a45; --allow-bg: #e6f4ec; --ask: #8a5a00; --ask-bg: #fbf1dc; --block: #b0302a; --block-bg: #fbe8e6;
    --human: #5a3fa0; --human-bg: #efeafa;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #151514; --panel: #1e1e1c; --ink: #ecebe6; --muted: #a3a29b; --line: #34332f;
      --code-bg: #262624; --accent: #8fb0ff;
      --allow: #7fd3a1; --allow-bg: #1d3327; --ask: #f0c36b; --ask-bg: #3a2f17; --block: #ff9b93; --block-bg: #3d1f1d;
      --human: #c7b5ff; --human-bg: #2b2540;
    }
  }
  :root[data-theme="dark"] {
    --bg: #151514; --panel: #1e1e1c; --ink: #ecebe6; --muted: #a3a29b; --line: #34332f;
    --code-bg: #262624; --accent: #8fb0ff;
    --allow: #7fd3a1; --allow-bg: #1d3327; --ask: #f0c36b; --ask-bg: #3a2f17; --block: #ff9b93; --block-bg: #3d1f1d;
    --human: #c7b5ff; --human-bg: #2b2540;
  }
  * { box-sizing: border-box; }
  [hidden] { display: none !important; }
  html[data-mode="live"] .demo-only, html[data-mode="demo"] .live-only { display: none; }
  body { margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
  .page { max-width: 1180px; margin: 0 auto; padding: 0 16px; }
  header { padding-top: 24px; }
  h1 { font-size: 1.35rem; margin: 0 0 4px; }
  header p { margin: 0; color: var(--muted); max-width: 76ch; }
  .banner { margin: 12px 0 0; padding: 8px 12px; border-radius: 8px; background: var(--ask-bg); color: var(--ink); border: 1px solid var(--line); }
  .bar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px; margin: 16px 0; }
  button { font: inherit; border: 1px solid var(--line); background: var(--panel); color: var(--ink); border-radius: 8px; padding: 6px 14px; cursor: pointer; }
  button.primary { background: var(--accent); border-color: var(--accent); color: var(--bg); font-weight: 600; }
  button.danger { border-color: var(--block); color: var(--block); }
  button:disabled { opacity: 0.45; cursor: default; }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .status-line { color: var(--muted); }
  .status-line.error, p.error { color: var(--block); }
  .status-line.ok, p.ok { color: var(--allow); }
  main { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.15fr); gap: 16px; }
  @media (max-width: 860px) { main { grid-template-columns: minmax(0, 1fr); } }
  section { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 14px 16px; min-width: 0; }
  section.wide { margin-top: 16px; }
  h2 { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin: 0 0 10px; }
  h3 { font-size: 0.98rem; margin: 0 0 4px; }
  .empty { color: var(--muted); font-style: italic; }
  .note { color: var(--muted); margin: 4px 0 8px; }
  .item { display: block; width: 100%; text-align: left; margin: 0 0 8px; padding: 10px 12px; border-radius: 10px; }
  .item.selected { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
  .item-head { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
  .item-why, .item-meta { display: block; color: var(--muted); font-size: 0.86rem; margin-top: 2px; }
  .item-args { display: block; margin-top: 4px; white-space: pre-wrap; word-break: break-all; }
  .badge { font-size: 0.72rem; font-weight: 600; border-radius: 999px; padding: 1px 8px; }
  .badge.irreversible { background: var(--block-bg); color: var(--block); }
  .badge.typed { background: var(--ask-bg); color: var(--ask); }
  pre, code { font: 12.5px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  pre { margin: 6px 0; white-space: pre-wrap; word-break: break-word; background: var(--code-bg); padding: 10px; border-radius: 8px; overflow-x: auto; }
  .token { display: grid; gap: 2px; margin: 10px 0; padding: 10px 12px; border-radius: 8px; background: var(--human-bg); }
  .token .label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--human); }
  .token-code { font-size: 1.25rem; letter-spacing: 0.08em; }
  .hint { color: var(--muted); font-size: 0.86rem; }
  .decide { display: grid; gap: 10px; margin-top: 10px; }
  .field { display: grid; gap: 4px; font-size: 0.9rem; }
  .field input { font: 14px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; padding: 7px 9px; border-radius: 8px; border: 1px solid var(--line); background: var(--bg); color: var(--ink); width: 100%; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; }
  .split { border: 0; border-top: 1px solid var(--line); margin: 6px 0; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 4px 6px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; }
  td code { word-break: break-all; }
  .table-wrap { overflow-x: auto; }
  .step { border-left: 3px solid var(--line); padding: 2px 0 2px 12px; margin: 0 0 16px; }
  .step .who { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
  pre.answer.s2 { background: var(--allow-bg); }
  pre.answer.s4, pre.answer.s5 { background: var(--block-bg); }
  pre.audit { font-size: 11.5px; word-break: break-all; }
  footer { color: var(--muted); font-size: 0.85rem; padding: 16px 0 32px; }
  footer a { color: var(--accent); }
`;

/**
 * Control, invisible and direction-changing characters: C0 but tab and line feed, C1, the soft hyphen,
 * fillers, joiners, bidirectional marks and isolates, variation selectors and tag characters. The page
 * shows them as escapes, and so does the server in what it prints to the terminal. PAGE_SCRIPT carries
 * the same pattern, word for word (test/gateway/approvals-ui.test.ts holds them equal).
 */
export const HIDDEN_CHARS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2028\u2029\u2060-\u2064\u2066-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffb]|\ud834[\udd73-\udd7a]|\udb40[\udc00-\udc7f\udd00-\uddef]/g;

export const PAGE_SCRIPT = String.raw`
(function () {
  "use strict";
  var DEMO = document.documentElement.getAttribute("data-mode") === "demo";
  var SNAPSHOT = DEMO ? JSON.parse(document.getElementById("snapshot").textContent) : null;
  var STORE_KEY = "agent-gate-approvals-session";
  var state = { session: null, csrf: null, pending: [], standing: [], selected: null, detail: null, done: null, busy: false, timer: null, controls: [] };

  function $(id) { return document.getElementById(id); }

  // Control, invisible and direction-changing characters (HIDDEN_CHARS in approvals-page.ts), shown as escapes.
  var HIDDEN = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2028\u2029\u2060-\u2064\u2066-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffb]|\ud834[\udd73-\udd7a]|\udb40[\udc00-\udc7f\udd00-\uddef]/g;
  function visible(text) {
    return String(text).replace(HIDDEN, function (found) {
      var out = "";
      for (var i = 0; i < found.length; i++) out += "\\u" + ("000" + found.charCodeAt(i).toString(16)).slice(-4);
      return out;
    });
  }

  function isNode(value) { return value !== null && typeof value === "object" && typeof value.appendChild === "function"; }

  function text(value) {
    if (typeof value === "string") return value;
    if (typeof value === "number" || typeof value === "boolean") return String(value);
    try { return JSON.stringify(value); } catch (e) { return "?"; }
  }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    for (var name in attrs || {}) {
      if (!Object.prototype.hasOwnProperty.call(attrs, name)) continue;
      var value = attrs[name];
      if (value === undefined || value === null || value === false) continue;
      node.setAttribute(name, value === true ? "" : String(value));
    }
    (children || []).forEach(function (child) {
      if (child === undefined || child === null || child === false) return;
      node.appendChild(isNode(child) ? child : document.createTextNode(visible(text(child))));
    });
    return node;
  }

  function say(text, kind) {
    var node = $("status");
    node.textContent = visible(text);
    node.setAttribute("class", "status-line" + (kind ? " " + kind : ""));
  }

  function clock(iso) {
    var d = new Date(iso);
    return isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
  }

  function count(n, word) { return n + " " + word + (n === 1 ? "" : "s"); }

  // The live page's only way out: the agent-gate process that served it. The demo never gets here.
  // A background poll says so (x-agent-gate-poll): it does not keep an idle session from ending.
  function api(method, path, body, poll) {
    if (DEMO) return Promise.reject(new Error("the demo sends nothing"));
    var headers = { accept: "application/json" };
    if (state.session) headers.authorization = "Bearer " + state.session;
    if (poll) headers["x-agent-gate-poll"] = "1";
    if (method === "POST") {
      headers["content-type"] = "application/json";
      if (state.csrf) headers["x-agent-gate-csrf"] = state.csrf;
    }
    var init = { method: method, headers: headers, credentials: "omit", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" };
    if (body !== undefined) init.body = JSON.stringify(body);
    var sent = state.session;
    return fetch(path, init).then(function (res) {
      return res.json().then(function (data) { return { status: res.status, data: data || {}, sent: sent }; }, function () { return { status: res.status, data: {}, sent: sent }; });
    });
  }

  function saveSession() {
    try { sessionStorage.setItem(STORE_KEY, JSON.stringify({ session: state.session, csrf: state.csrf })); } catch (e) { /* private mode: the session lives until a reload */ }
  }
  function loadSession() {
    try {
      var saved = JSON.parse(sessionStorage.getItem(STORE_KEY) || "null");
      if (saved && typeof saved.session === "string" && typeof saved.csrf === "string") {
        state.session = saved.session;
        state.csrf = saved.csrf;
        return true;
      }
    } catch (e) { /* nothing saved */ }
    return false;
  }
  function dropSession() {
    state.session = null;
    state.csrf = null;
    try { sessionStorage.removeItem(STORE_KEY); } catch (e) { /* nothing saved */ }
  }

  function unreachable() { say("The agent-gate process that printed the link is not answering. Is it still running?", "error"); }

  function locked(message) {
    if (state.timer) clearInterval(state.timer);
    state.timer = null;
    state.pending = [];
    state.standing = [];
    state.selected = null;
    state.detail = null;
    $("queue").textContent = "";
    $("queue").appendChild(el("p", { class: "error" }, [message]));
    $("detail").textContent = "";
    $("detail").appendChild(el("p", { class: "empty" }, ["Nothing to read back without a session."]));
    $("grants").textContent = "";
    $("refresh").disabled = true;
    say("No session.", "error");
  }

  function sessionEnded(r) {
    if (r.sent !== state.session) return; // the answer to a session this tab no longer holds
    dropSession();
    locked(r.data.error || "The session ended. Start agent-gate approvals ui again for a new link.");
  }

  // The key leaves the address bar and the history at once; it opens one session, and only once.
  function takeKey() {
    var match = /^#key=([A-Za-z0-9_-]{43})$/.exec(location.hash || "");
    if (location.hash) { try { history.replaceState(null, "", location.pathname); } catch (e) { /* an old browser keeps it in the bar */ } }
    return match ? match[1] : null;
  }

  function start() {
    if (DEMO) return startDemo();
    var key = takeKey();
    // agent-gate registers no service worker. One that controls this page was left for this address by something
    // else, and could read what the page sends: remove it, and use neither the link nor a kept session.
    var workers = typeof navigator !== "undefined" ? navigator.serviceWorker : undefined;
    if (workers && workers.controller) {
      try { workers.getRegistrations().then(function (list) { list.forEach(function (r) { r.unregister(); }); }, function () { /* nothing more to do */ }); } catch (e) { /* nothing more to do */ }
      return locked("A service worker controls this page, and agent-gate registers none: something else left it for this address. It has been removed, and this page used neither the link nor a session. Start agent-gate approvals ui again for a new link, and keep pages that an agent serves out of this browser.");
    }
    $("refresh").addEventListener("click", function () { refresh(false); });
    if (typeof addEventListener === "function") addEventListener("hashchange", function () { var pasted = takeKey(); if (pasted) openWith(pasted); });
    if (key) return openWith(key);
    if (loadSession()) return refresh(true);
    locked("Open the link that agent-gate approvals ui printed in your terminal: this page opens only with it.");
  }

  // Trades the link's key for a session. The tab keeps the session it has until the trade gives it a new one
  // (polls wait meanwhile), and if the key was spent already, a session this tab kept still works.
  function openWith(key) {
    var had = state.session !== null;
    state.busy = true;
    say("Opening a session...");
    api("POST", "/api/session", { key: key }).then(function (r) {
      state.busy = false;
      if (r.status === 200 && typeof r.data.session === "string" && typeof r.data.csrf === "string") {
        state.session = r.data.session;
        state.csrf = r.data.csrf;
        saveSession();
        return refresh(true);
      }
      if (had) return say(r.data.error || "That link opened no session; this tab keeps the one it has.", "error");
      if (loadSession()) return refresh(true);
      locked(r.data.error || "The session could not be opened (" + r.status + ").");
    }, function () {
      state.busy = false;
      unreachable();
    });
  }

  function refresh(first, poll) {
    return api("GET", "/api/approvals", undefined, poll).then(function (r) {
      if (r.status === 401) return sessionEnded(r);
      if (r.status !== 200) return say(r.data.error || "The queue could not be read (" + r.status + ").", "error");
      state.pending = r.data.pending || [];
      state.standing = r.data.standing || [];
      $("refresh").disabled = false;
      renderQueue();
      renderGrants();
      say("Updated " + clock(r.data.now) + ". " + count(state.pending.length, "request") + " waiting.");
      // The request on screen was decided elsewhere (at the CLI, say) or expired: read it back again, once.
      var shown = state.detail && state.detail.approval;
      if (shown && shown.status === "pending" && !shown.expired && !state.busy && !state.pending.some(function (a) { return a.id === shown.id; })) select(shown.id, true);
      if (first && !state.timer) {
        state.timer = setInterval(function () {
          if (document.visibilityState === "hidden" || state.busy) return;
          refresh(false, true);
        }, 5000);
      }
    }, unreachable);
  }

  function renderQueue() {
    var box = $("queue");
    box.textContent = "";
    if (state.pending.length === 0) {
      box.appendChild(el("p", { class: "empty" }, ["Nothing is waiting for a decision."]));
      return;
    }
    state.pending.forEach(function (a) {
      var chosen = state.selected === a.id;
      var item = el("button", { type: "button", class: "item" + (chosen ? " selected" : ""), "aria-pressed": chosen ? "true" : "false", "data-id": a.id }, [
        el("span", { class: "item-head" }, [
          el("code", {}, [a.call]),
          el("span", { class: "badge " + (a.irreversible ? "irreversible" : "typed") }, [a.irreversible ? "irreversible: needs its action token" : "type the end of its id"]),
        ]),
        el("span", { class: "item-why" }, [a.why + " (rule " + a.rule + ")"]),
        el("code", { class: "item-args" }, [a.argsPreview]),
        el("span", { class: "item-meta" }, [a.id + " · expires " + clock(a.expiresAt) + (a.agent ? " · agent " + a.agent : "")]),
      ]);
      item.addEventListener("click", function () { select(a.id); });
      box.appendChild(item);
    });
  }

  function renderGrants() {
    var box = $("grants");
    box.textContent = "";
    if (state.standing.length === 0) {
      box.appendChild(el("p", { class: "empty" }, ["None in force."]));
      return;
    }
    var rows = [el("tr", {}, [el("th", {}, ["id"]), el("th", {}, ["call"]), el("th", {}, ["arguments"]), el("th", {}, ["uses"]), el("th", {}, ["until"])])];
    state.standing.forEach(function (g) {
      var globs = Object.keys(g.args || {}).map(function (k) { return k + "=" + JSON.stringify(g.args[k]); }).join(", ") || "any arguments";
      rows.push(el("tr", {}, [
        el("td", {}, [el("code", {}, [g.id])]),
        el("td", {}, [el("code", {}, [g.call]), g.agent ? " (agent " + g.agent + ")" : ""]),
        el("td", {}, [el("code", {}, [globs])]),
        el("td", {}, [g.used + " of " + g.maxUses]),
        el("td", {}, [clock(g.expiresAt)]),
      ]));
    });
    box.appendChild(el("div", { class: "table-wrap" }, [el("table", {}, rows)]));
  }

  function select(id, automatic) {
    state.selected = id;
    state.detail = null;
    state.done = null;
    renderQueue();
    if (DEMO) {
      state.detail = (SNAPSHOT.readBacks && SNAPSHOT.readBacks[id]) || null;
      return renderDetail();
    }
    renderDetail();
    api("GET", "/api/approvals/" + encodeURIComponent(id), undefined, automatic).then(function (r) {
      if (state.selected !== id) return;
      if (r.status === 401) return sessionEnded(r);
      if (r.status !== 200) return say(r.data.error || "It could not be read back (" + r.status + ").", "error");
      state.detail = r.data;
      renderDetail();
    }, unreachable);
  }

  function field(name, label, max) {
    var id = "field-" + name;
    var input = el("input", { id: id, name: name, type: "text", autocomplete: "off", autocapitalize: "off", autocorrect: "off", spellcheck: "false", maxlength: String(max) });
    return { input: input, wrap: el("label", { class: "field", for: id }, [el("span", {}, [label]), input]) };
  }

  function value(input) { return typeof input.value === "string" ? input.value : ""; }

  function setBusy(on) {
    state.busy = on;
    state.controls.forEach(function (c) { c.disabled = on || DEMO; });
  }

  function renderDetail() {
    var box = $("detail");
    box.textContent = "";
    state.controls = [];
    if (state.done) box.appendChild(el("p", { class: "ok" }, [state.done]));
    if (!state.selected) {
      if (!state.done) box.appendChild(el("p", { class: "empty" }, ["Pick a request to read it back."]));
      return;
    }
    var d = state.detail;
    if (!d) {
      box.appendChild(el("p", { class: "empty" }, [DEMO ? "This request was not read back in the recorded run." : "Reading it back..."]));
      return;
    }
    var a = d.approval;
    box.appendChild(el("pre", { class: "readback" }, [d.readBack]));
    if (a.status !== "pending" || a.expired) {
      box.appendChild(el("p", { class: "note" }, [a.id + " is " + a.status + (a.expired ? ", and expired" : "") + ": there is nothing to decide."]));
      return;
    }
    var form = el("div", { class: "decide" });
    var confirm;
    if (d.confirm === "token") {
      if (d.actionToken) {
        form.appendChild(el("div", { class: "token" }, [
          el("span", { class: "label" }, ["Action token, for you"]),
          el("code", { class: "token-code" }, [d.actionToken]),
          el("span", { class: "hint" }, ["This cannot be undone. Type the token below to approve this one call, with these arguments. The agent is never shown it."]),
        ]));
      } else {
        form.appendChild(el("p", { class: "error" }, ["This request needs its action token, which cannot be made here: " + (d.actionTokenError || "the key cannot be read") + ". Only someone who can read the gateway's key can approve it; it can still be denied."]));
      }
      confirm = field("confirm", "Type the action token to approve", 40);
    } else {
      confirm = field("confirm", "Type the last 4 characters of the id (" + d.code + ") to approve", 40);
    }
    var note = field("note", "Note, kept with the approval (optional)", 500);
    var approve = el("button", { type: "button", class: "primary" }, ["Approve this call"]);
    var reason = field("reason", "Reason, shown to the agent if you deny (optional)", 500);
    var deny = el("button", { type: "button", class: "danger" }, ["Deny"]);
    form.appendChild(confirm.wrap);
    form.appendChild(note.wrap);
    form.appendChild(el("div", { class: "actions" }, [approve]));
    form.appendChild(el("hr", { class: "split" }));
    form.appendChild(reason.wrap);
    form.appendChild(el("div", { class: "actions" }, [deny]));
    if (DEMO) form.appendChild(el("p", { class: "note" }, ["Demo: read-only. These controls send nothing. What the real server answered when these requests were decided is under Recorded run."]));
    box.appendChild(form);
    state.controls = [confirm.input, note.input, approve, reason.input, deny];
    setBusy(false);
    if (DEMO) return;
    function doApprove() {
      var body = { argsHash: a.argsHash, note: value(note.input) };
      if (d.confirm === "token") body.token = value(confirm.input);
      else body.confirm = value(confirm.input);
      send(a, "approve", body);
    }
    approve.addEventListener("click", doApprove);
    confirm.input.addEventListener("keydown", function (e) { if (e && e.key === "Enter") doApprove(); });
    deny.addEventListener("click", function () { send(a, "deny", { argsHash: a.argsHash, reason: value(reason.input) }); });
  }

  function send(a, action, body) {
    if (state.busy || DEMO) return;
    setBusy(true);
    api("POST", "/api/approvals/" + encodeURIComponent(a.id) + "/" + action, body).then(function (r) {
      setBusy(false);
      if (r.status === 401) return sessionEnded(r);
      if (r.status === 200) {
        state.selected = null;
        state.detail = null;
        state.done = r.data.message || action + "d";
        say(state.done, "ok");
        renderDetail();
        return refresh(false);
      }
      say(r.data.error || "Refused (" + r.status + ").", "error");
    }, function () {
      setBusy(false);
      unreachable();
    });
  }

  function startDemo() {
    var banner = $("banner");
    banner.hidden = false;
    banner.textContent = "Demo: a recorded run of agent-gate approvals ui, read-only. Nothing here can approve, deny or send anything: the page has no server behind it, and its security policy lets it connect nowhere.";
    $("refresh").disabled = true;
    state.pending = SNAPSHOT.queue.pending || [];
    state.standing = SNAPSHOT.queue.standing || [];
    renderQueue();
    renderGrants();
    renderRun();
    say("Recorded " + clock(SNAPSHOT.queue.now) + ". " + count(state.pending.length, "request") + " waiting.");
    if (state.pending.length > 0) select(state.pending[0].id);
  }

  function renderRun() {
    $("run-section").hidden = false;
    var box = $("run");
    box.textContent = "";
    SNAPSHOT.steps.forEach(function (s, i) {
      var parts = [el("h3", {}, [i + 1 + ". " + s.title]), el("p", { class: "note" }, [s.note])];
      if (s.request) {
        var head = s.request.method + " " + s.request.path + (s.request.headers && s.request.headers.length ? "\n" + s.request.headers.join("\n") : "");
        parts.push(el("span", { class: "who" }, ["the page sends"]));
        parts.push(el("pre", { class: "http" }, [head + (s.request.body !== undefined ? "\n\n" + JSON.stringify(s.request.body, null, 2) : "")]));
      }
      if (s.response) {
        parts.push(el("span", { class: "who" }, ["the server answers"]));
        parts.push(el("pre", { class: "answer s" + Math.floor(s.response.status / 100) }, [s.response.status + "\n" + JSON.stringify(s.response.body, null, 2)]));
      }
      if (s.call) {
        parts.push(el("span", { class: "who" }, ["the agent calls"]));
        parts.push(el("pre", {}, [s.call.tool + " " + JSON.stringify(s.call.args)]));
        parts.push(el("span", { class: "who" }, ["agent-gate answers"]));
        parts.push(el("pre", { class: "answer " + (s.isError ? "s4" : "s2") }, [s.answer]));
      }
      if (s.command) {
        parts.push(el("span", { class: "who" }, ["the human, at a terminal"]));
        parts.push(el("pre", {}, [s.command + "\n" + s.output]));
      }
      if (s.audit && s.audit.length) {
        parts.push(el("span", { class: "who" }, ["written to the audit log"]));
        s.audit.forEach(function (line) { parts.push(el("pre", { class: "audit" }, [JSON.stringify(line)])); });
      } else if (s.request || s.call) {
        parts.push(el("p", { class: "note" }, ["Nothing was written to the audit log."]));
      }
      box.appendChild(el("article", { class: "step" }, parts));
    });
  }

  start();
})();
`;

const sha256 = (text: string): string => createHash("sha256").update(text, "utf8").digest("base64");

/** The hashes the Content-Security-Policy allows the inline script and style by. */
export const PAGE_HASHES = { script: `sha256-${sha256(PAGE_SCRIPT)}`, style: `sha256-${sha256(PAGE_STYLE)}` };

/**
 * The page's Content-Security-Policy: nothing but its own script and style. The live page may connect
 * to the server that served it; the demo page to nothing at all. (The demo's policy is a meta element,
 * which cannot carry frame-ancestors.)
 */
export function pageCsp(mode: "live" | "demo"): string {
  return [
    "default-src 'none'",
    `script-src '${PAGE_HASHES.script}'`,
    `style-src '${PAGE_HASHES.style}'`,
    mode === "live" ? "connect-src 'self'" : "connect-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    ...(mode === "live" ? ["frame-ancestors 'none'"] : []),
  ].join("; ");
}

export type PageOptions = { mode: "live" } | { mode: "demo"; snapshot: unknown };

/** The whole page. In demo mode the recorded run is a JSON block in it, with every "<" escaped. */
export function approvalsPage(options: PageOptions): string {
  const demo = options.mode === "demo";
  const csp = demo ? `<meta http-equiv="Content-Security-Policy" content="${pageCsp("demo")}">\n` : "";
  const data = demo ? `<script type="application/json" id="snapshot">\n${JSON.stringify(options.snapshot, null, 1).replace(/</g, "\\u003c")}\n</script>\n` : "";
  return `<!doctype html>
<html lang="en" data-mode="${options.mode}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
${csp}<title>agent-gate approvals</title>
<meta name="description" content="The approvals page of agent-gate's MCP gateway: the requests waiting for a human, read back in full, approved or denied with the same checks and audit lines as the CLI.">
<style>${PAGE_STYLE}</style>
</head>
<body>
<div class="page">
<header>
  <h1>agent-gate approvals</h1>
  <p class="live-only">The requests waiting for a human, from the approval queue on this machine. Read each one back before you decide: a decision here is the CLI's decision, with the same record and the same audit line.</p>
  <p class="demo-only">The approvals page of agent-gate's MCP gateway (<code>agent-gate approvals ui</code>), replaying a real local run with the example policy and the fake test server. Pick a request to read it back.</p>
  <p id="banner" class="banner" hidden></p>
  <div class="bar">
    <button id="refresh" type="button">Refresh</button>
    <span id="status" class="status-line" role="status" aria-live="polite"></span>
  </div>
</header>
<main>
  <section aria-labelledby="queue-title">
    <h2 id="queue-title">Waiting for you</h2>
    <div id="queue"><p class="empty">Loading...</p></div>
  </section>
  <section aria-labelledby="detail-title">
    <h2 id="detail-title">Read-back</h2>
    <div id="detail"><p class="empty">Pick a request to read it back.</p></div>
  </section>
</main>
<section class="wide" aria-labelledby="grants-title">
  <h2 id="grants-title">Standing approvals in force</h2>
  <p class="note">Granted and revoked at the CLI (<code>approvals grant</code>, <code>approvals deny sa-...</code>), not here. None of them ever answers an irreversible call.</p>
  <div id="grants"></div>
</section>
<section id="run-section" class="wide" aria-labelledby="run-title" hidden>
  <h2 id="run-title">Recorded run</h2>
  <p class="note">What the page sent and what the server answered, step by step, with what each step wrote to the audit log. Session and CSRF tokens and the link's key are left out; the action token is the run's own, made with a key that was deleted afterwards.</p>
  <div id="run"></div>
</section>
<footer>
  <p class="live-only">This page talks only to the agent-gate process on 127.0.0.1 that printed its link. Stop that process with Ctrl-C in its terminal.</p>
  <p class="demo-only">Written by <code>scripts/demo-approvals.js</code> (<code>npm run demo:approvals</code>). See also <a href="index.html">the MCP gateway, step by step</a> and <a href="llm.html">the LLM gateway</a>.</p>
</footer>
</div>
${data}<script>${PAGE_SCRIPT}</script>
</body>
</html>
`;
}
