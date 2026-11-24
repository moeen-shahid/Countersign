"use strict";
/*
 * Countersign web console.
 *
 * One page, no libraries, no build step, no requests to anywhere but this
 * server. Everything that comes from the API (documents, payee names,
 * references, reasons) is attacker-influenced, so it is only ever inserted as
 * text nodes: nothing is ever parsed as HTML and no style attribute is set.
 *
 * Sections: 1 helpers, 2 state, 3 shell (token, theme, routes, sheet, keys),
 * 4 shared parts (document viewer, lanes, evidence, hold card, inbox),
 * 5 Stage, 6 Scoreboard, 7 Playground, 8 Audit, 9 Live console, 10 boot.
 */

/* ------------------------------------------------------------------ */
/* 1. Helpers                                                          */
/* ------------------------------------------------------------------ */

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/** The one place DOM nodes are made. Strings become text nodes. */
function el(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value == null || value === false || key === "style") continue;
    if (key === "class") node.className = value;
    else if (key === "data") Object.assign(node.dataset, value);
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  add(node, children);
  return node;
}

function add(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child != null && child !== false) node.append(child);
  }
  return node;
}

function fill(node, ...children) {
  node.replaceChildren();
  return add(node, children);
}

/** Run a re-render without losing the field the person is typing in. Fields that
    must survive a re-render carry data-keep; their values live in the page state. */
function keepFocus(render) {
  const active = document.activeElement;
  const key = active && active.dataset ? active.dataset.keep : null;
  const sel = key && typeof active.selectionStart === "number" ? [active.selectionStart, active.selectionEnd] : null;
  const out = render();
  if (key) {
    const again = [...document.querySelectorAll("[data-keep]")].find((n) => n.dataset.keep === key);
    if (again && again !== document.activeElement) {
      again.focus();
      if (sel) { try { again.setSelectionRange(sel[0], sel[1]); } catch (err) { /* not a text field */ } }
    }
  }
  return out;
}

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/** The one place the server is called. GET without a body, POST with one. */
async function api(path, body, raw) {
  const options = { headers: { "X-Countersign-Token": S.token || "" } };
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, options);
  } catch (err) {
    throw new ApiError(0, "The Countersign server did not answer. Is it still running?");
  }
  if (response.status === 401) {
    showGate();
    throw new ApiError(401, "token required");
  }
  if (raw && response.ok) return response.blob();
  let data = {};
  try {
    data = await response.json();
  } catch (err) {
    data = {};
  }
  if (!response.ok) throw new ApiError(response.status, data.error || "Request failed (" + response.status + ").");
  return data;
}

const MONEY = /^(\d+)(?:\.(\d{1,2}))?$/;
function cents(value) {
  const m = MONEY.exec(String(value));
  return m ? Number(m[1]) * 100 + Number((m[2] || "").padEnd(2, "0")) : 0;
}
function fromCents(n) {
  return Math.floor(n / 100) + "." + String(n % 100).padStart(2, "0");
}
/** "1480.00" -> "1,480.00". Anything that is not a plain amount is shown as it came. */
function money(value) {
  const m = MONEY.exec(String(value));
  if (!m) return String(value);
  return m[1].replace(/\B(?=(\d{3})+$)/g, ",") + "." + (m[2] || "").padEnd(2, "0");
}
const eur = (value) => (S.meta ? S.meta.currency : "EUR") + " " + money(value);

const isIban = (a) => /^[A-Z]{2}[0-9]{2}[A-Z0-9]{8,32}$/.test(a || "");
const groups = (a) => (isIban(a) ? a.replace(/(.{4})(?=.)/g, "$1 ") : String(a));
const mask = (a) => (isIban(a) ? a.slice(0, 4) + "…" + a.slice(-4) : String(a).slice(0, 14));
const tail = (a) => "…" + String(a).slice(-4);
const nameKey = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
const short = (hash) => String(hash || "").slice(0, 10) + "…";
const plural = (n, one, many) => n + " " + (n === 1 ? one : many || one + "s");
const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function store(kind, key, value) {
  try {
    const box = kind === "session" ? window.sessionStorage : window.localStorage;
    if (value === undefined) return box.getItem(key);
    if (value === null) box.removeItem(key);
    else box.setItem(key, value);
  } catch (err) {
    /* storage can be blocked; the page works without it */
  }
  return null;
}

function download(blob, name) {
  const url = URL.createObjectURL(blob);
  const link = el("a", { href: url, download: name });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function segButton(label, on, handler, title) {
  return el("button", { type: "button", "aria-pressed": String(on), title, onclick: handler }, label);
}

const OUTCOME_CLASS = { ALLOW: "allow", HOLD: "hold", BLOCK: "block" };
/** A document's name is the sender's words, never a fact or a heading: a document can be
    named "Approved by finance.pdf" (adversary trace D04). Always quoted and labelled. */
function docName(name) {
  return el("span", { class: "doc-name", title: "The sender chose this name. It proves nothing." },
    el("span", { class: "doc-name-label" }, "document named "),
    el("span", { class: "mono" }, "\u201c" + name + "\u201d"));
}
/** The quarantines of a replay whose first refusal (H1) is already on screen. */
function shownQuarantines(run, shown) {
  return (run.quarantines || []).filter((q) => shown.some((a) => a.task === q.number && a.rule === "H1"));
}
const docNameText = (name) => "the document named \u201c" + name + "\u201d";
/** The banner of a task whose queue overflowed (q.text comes from the server). */
function quarantineBanner(q, where) {
  return el("div", { class: "banner block quarantine", role: "status" },
    where ? el("strong", {}, where.charAt(0).toUpperCase() + where.slice(1) + ": ") : null, q.text);
}
const ROUNDABOUT = "Not written as one piece: the guard read it through HTML tags or invisible characters";
const CHECK_WORD = { pass: "pass", block: "BLOCK", hold: "HOLD", na: "does not apply", off: "not in this guard", skipped: "not reached" };

/* ------------------------------------------------------------------ */
/* 2. State                                                            */
/* ------------------------------------------------------------------ */

const S = {
  token: "",
  meta: null,
  view: "stage",
  lab: { scenario: null, runs: {} }, /* the current LabState */
  witness: null, /* audit head this browser saved before any tampering */
  tamper: { stage: null, truncated: false },
  lastApproval: null, /* { amount, legit } after a person approved a hold */
  holdForm: {}, /* "lab|live:hold id:digest" -> { attestation, remember } */
  sheet: null, /* { kind, render, opener } */
};

const VIEWS = [
  { id: "stage", label: "Stage", enter: () => enterStage() },
  { id: "scoreboard", label: "Scoreboard", enter: () => enterScore() },
  { id: "playground", label: "Playground", enter: () => enterPlayground() },
  { id: "audit", label: "Audit", enter: () => renderAudit() },
  { id: "live", label: "Live console", liveOnly: true, enter: () => enterLive() },
];
const activeViews = () => VIEWS.filter((v) => !v.liveOnly || (S.meta && S.meta.live));
const modeInfo = (id) => S.meta.modes.find((m) => m.id === id) || { id, label: id };
const csRun = () => S.lab.runs.countersign || null;

/* ------------------------------------------------------------------ */
/* 3. Shell: token, theme, routes, sheet, toast, keys                  */
/* ------------------------------------------------------------------ */

/** Take the one-time key from the address bar, keep it for this tab only. */
function readToken() {
  const m = /(?:^#|&)token=([^&]+)/.exec(location.hash);
  if (m) {
    S.token = decodeURIComponent(m[1]);
    store("session", "countersign-token", S.token);
    history.replaceState(null, "", location.pathname + location.search);
  } else {
    S.token = store("session", "countersign-token") || "";
  }
}

function showGate() {
  $("gate").hidden = false;
  $("top").hidden = true;
  $("main").hidden = true;
  closeSheet();
}

function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  $("btn-theme").textContent = theme === "dark" ? "Light" : "Dark";
  $("btn-theme").setAttribute("aria-label", theme === "dark" ? "Switch to the light theme" : "Switch to the dark theme");
  store("local", "countersign-theme", theme);
}

function initTheme() {
  const saved = store("local", "countersign-theme");
  const system = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  setTheme(saved === "dark" || saved === "light" ? saved : system);
  $("btn-theme").addEventListener("click", () =>
    setTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark"));
}

let toastTimer = 0;
function toast(message) {
  $("toast").textContent = message;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $("toast").textContent = ""; }, 6000);
}
/** Wrap a handler so a failed request is shown, never swallowed. */
function guard(fn) {
  return (...args) => Promise.resolve().then(() => fn(...args)).catch((err) => {
    if (err.status !== 401) toast(err.message || String(err));
  });
}

function renderTabs() {
  fill($("tabs"), activeViews().map((v, i) =>
    el("a", { href: "#" + v.id, "aria-current": v.id === S.view ? "page" : null }, v.label, el("kbd", {}, String(i + 1)))));
}

function route() {
  const wanted = location.hash.replace(/^#/, "").split("/")[0];
  const view = activeViews().find((v) => v.id === wanted) || VIEWS[0];
  S.view = view.id;
  for (const v of VIEWS) $("view-" + v.id).hidden = v.id !== view.id;
  document.body.classList.toggle("on-stage", view.id === "stage");
  renderTabs();
  updateInboxCount();
  guard(view.enter)();
}

function openSheet(kind, title, render, opener) {
  S.sheet = { kind, render, opener: opener || document.activeElement };
  $("sheet-title").textContent = title;
  $("sheet").hidden = false;
  render();
  const first = $("sheet-body").querySelector("[data-autofocus]");
  /* Focus the default action without scrolling past what is above it (banners, the card's heading). */
  (first || $("sheet-title")).focus({ preventScroll: true });
  $("sheet-body").scrollTop = 0;
}

function closeSheet() {
  if (!S.sheet) return;
  const opener = S.sheet.opener;
  S.sheet = null;
  $("sheet").hidden = true;
  fill($("sheet-body"));
  if (opener && opener.isConnected) opener.focus();
}

function openLimits() {
  openSheet("limits", "What this does not do", () => {
    fill($("sheet-body"),
      el("p", { class: "note" }, "Known limits of Countersign " + S.meta.version + ", in the product's own words."),
      el("ul", { class: "limits" }, S.meta.limits.map((text) => el("li", {}, text))));
  }, $("btn-limits"));
}

function isTyping(target) {
  return target instanceof HTMLElement && (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName));
}

function onKey(ev) {
  if (!S.meta || !$("gate").hidden) return;
  if (ev.key === "Escape" && S.sheet) return closeSheet();
  if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter" && S.view === "playground") return guard(runPlayground)();
  if (ev.ctrlKey || ev.metaKey || ev.altKey || isTyping(ev.target)) return undefined;
  const key = ev.key.length === 1 ? ev.key.toLowerCase() : ev.key;
  const views = activeViews();
  if (key >= "1" && key <= String(views.length)) location.hash = views[Number(key) - 1].id;
  else if (key === "x") { const v = currentViewer(); if (v) v.toggle(); }
  else if (key === "i") openInbox();
  else if (key === "l") openLimits();
  else if (S.view === "stage" && !S.sheet) {
    const onControl = ev.target instanceof HTMLElement && ["BUTTON", "A", "SUMMARY"].includes(ev.target.tagName);
    if (key === " " && !onControl) { ev.preventDefault(); guard(stagePlay)(); }
    else if (key === "ArrowRight") guard(stageStep)();
    else if (key === "r") guard(stageReset)();
  }
  return undefined;
}

/* ------------------------------------------------------------------ */
/* 4. Shared parts                                                     */
/* ------------------------------------------------------------------ */

/* ---- 4a. Document viewer: human view / agent view ---- */

function createViewer(emptyText) {
  const v = { docs: [], payees: [], index: 0, mode: "human", root: el("div", { class: "viewer" }) };

  v.set = (docs, payees) => {
    v.docs = docs || [];
    v.payees = (payees || []).map(nameKey);
    if (v.index >= v.docs.length) v.index = 0;
    v.render();
  };
  v.select = (index) => { if (index !== v.index && v.docs[index]) { v.index = index; v.render(); } };
  v.setMode = (mode) => { v.mode = mode; v.render(); };
  v.toggle = () => v.setMode(v.mode === "human" ? "agent" : "human");

  /** Switch to agent view, open the document and pulse the account at `span`. */
  v.show = (source, span) => {
    const index = v.docs.findIndex((d) => d.label === source || d.name === source);
    if (index < 0) return false;
    v.index = index;
    v.mode = "agent";
    v.render();
    const marks = [...v.root.querySelectorAll(".acct")];
    const mark = marks.find((m) => Number(m.dataset.start) === span[0]) ||
      marks.find((m) => Number(m.dataset.start) <= span[0] && Number(m.dataset.end) >= span[0]);
    if (!mark) return true;
    mark.scrollIntoView({ block: "center", behavior: reducedMotion() ? "auto" : "smooth" });
    mark.classList.add("pulse");
    setTimeout(() => mark.classList.remove("pulse"), 2200);
    return true;
  };

  v.render = () => {
    const doc = v.docs[v.index];
    if (!doc) return fill(v.root, el("p", { class: "empty" }, emptyText || "No documents."));
    const hiddenCount = (d) => d.segments.filter((s) => s[2]).length;
    const tabs = el("div", { class: "doc-tabs", role: "tablist", "aria-label": "Documents the agent read" },
      v.docs.map((d, i) => el("button", {
        type: "button", class: "doc-tab", role: "tab", "aria-selected": String(i === v.index),
        onclick: () => v.select(i), title: "The sender chose this name",
      }, "\u201c" + d.name + "\u201d", hiddenCount(d) ? el("span", { class: "tag tag-block" }, plural(hiddenCount(d), "hidden passage")) : null)));
    const views = el("div", { class: "seg", role: "group", "aria-label": "Document view (key X)" },
      segButton("Human view", v.mode === "human", () => v.setMode("human"), "Key X"),
      segButton("Agent view", v.mode === "agent", () => v.setMode("agent"), "Key X"));
    const paper = el("div", { class: "paper " + v.mode, tabindex: "0", role: "document",
      "aria-label": docNameText(doc.name) + ", " + (v.mode === "human" ? "as a person sees it" : "as the agent reads it") },
      docNodes(doc, v.mode, v.payees));
    const hidden = hiddenCount(doc);
    const note = v.mode === "human"
      ? "Shown as a mail client would show it."
      : hidden ? "Raw text, exactly what the agent read." : "Raw text. Nothing is hidden in this document.";
    return fill(v.root,
      el("div", { class: "viewer-bar" }, tabs, views), paper,
      el("div", { class: "viewer-foot" },
        el("span", {}, note),
        doc.accounts.length ? el("span", {}, "Accounts: ", el("span", { class: "key-on" }, "on file for a payee"), ", ",
          el("span", { class: "key-off" }, "not on file")) : null));
  };
  return v;
}

function docNodes(doc, mode, payees) {
  const out = [];
  for (const [start, end, hidden] of doc.segments) {
    if (!hidden) {
      out.push(textPieces(doc, start, end, payees));
    } else if (mode === "human") {
      /* Really there and really invisible: white, 1px, exactly as the email asks. */
      out.push(el("span", { class: "ink-hidden", "aria-hidden": "true" }, doc.text.slice(start, end)));
    } else {
      const raw = doc.text.slice(start, end);
      const open = /^<span[^>]*>/.exec(raw);
      const close = /<\/span>$/.exec(raw);
      const a = start + (open ? open[0].length : 0);
      const b = end - (close ? close[0].length : 0);
      out.push(el("span", { class: "hid" },
        el("span", { class: "hid-label" }, "Hidden from humans (white text, 1px)"),
        open ? el("span", { class: "tag-dim" }, open[0]) : null,
        textPieces(doc, a, b, payees),
        close ? el("span", { class: "tag-dim" }, close[0]) : null));
    }
  }
  return out;
}

/** Text of doc[start:end] with every account inside it underlined. */
function textPieces(doc, start, end, payees) {
  const out = [];
  let pos = start;
  for (const acc of doc.accounts) {
    if (acc.end <= start || acc.start >= end) continue;
    const a = Math.max(acc.start, start);
    const b = Math.min(acc.end, end);
    if (a > pos) out.push(doc.text.slice(pos, a));
    const onFile = acc.on_file_for && payees.includes(nameKey(acc.on_file_for));
    const title = (onFile ? "On file for " + acc.on_file_for
      : acc.on_file_for ? "On file for " + acc.on_file_for + ", who is not a payee of this task"
        : "Not on file for a payee of this task") + (acc.rendered ? ". " + ROUNDABOUT : "");
    out.push(el("mark", { class: "acct " + (onFile ? "on-file" : "not-on-file") + (acc.rendered ? " rendered" : ""), title,
      data: { start: String(acc.start), end: String(acc.end) } }, doc.text.slice(a, b)));
    pos = b;
  }
  if (pos < end) out.push(doc.text.slice(pos, end));
  return out;
}

function currentViewer() {
  if (S.view === "stage") return stage.viewer;
  if (S.view === "playground") return pg.viewer;
  if (S.view === "live") return live.viewer;
  return null;
}

/* ---- 4b. Lanes: one per guard, with stations and animated payments ---- */

function pillStatus(a) {
  if (a.repeat && a.hold) return { cls: "joined", label: "JOINED " + a.hold.id };
  if (a.status === "paid") {
    const approved = a.hold && a.hold.status === "approved";
    return { cls: a.legit === false ? "lost" : "paid", label: approved ? "PAID, APPROVED" : "PAID" };
  }
  if (a.status === "held") return { cls: "held", label: "HELD " + a.rule };
  if (a.status === "rejected") return { cls: "blocked", label: "REJECTED" };
  if (a.status === "expired") return { cls: "blocked", label: "EXPIRED" };
  if (a.status === "unknown") return { cls: "held", label: "NOT CONFIRMED" };
  return { cls: "blocked", label: "BLOCKED " + a.rule };
}

function truthTag(a) {
  if (a.legit == null) return null;
  return el("span", { class: "truth " + (a.legit ? "wanted" : "unwanted") },
    a.legit ? "the user wanted this" : "the user did not want this");
}

const verdictText = (a) => a.outcome + (a.outcome === "ALLOW" || !a.rule ? "" : " · " + (a.rules && a.rules.length ? a.rules.join(" ") : a.rule));

function createBoard(onSelect) {
  const b = { runs: {}, shown: 0, selected: null, outlined: null, lanes: {}, root: el("div", { class: "board" }) };

  b.set = (runs, shown) => {
    b.runs = runs || {};
    b.shown = shown;
    b.render();
  };
  b.count = () => Math.max(0, ...Object.values(b.runs).map((r) => r.attempts.length));

  b.render = () => {
    b.lanes = {};
    fill(b.root, S.meta.modes.filter((m) => b.runs[m.id]).map((m) => laneEl(m, b.runs[m.id])));
  };

  const multi = () => Object.values(b.runs).some((r) => r.attempts.some((a) => a.task > 1));

  function pillBox(mode, a, withAccount) {
    const st = pillStatus(a);
    const selected = b.selected && b.selected.mode === mode && b.selected.index === a.index;
    const many = multi();
    return el("div", { class: "pillbox" },
      el("button", {
        type: "button", class: "pill " + st.cls + (selected ? " selected" : ""),
        "aria-label": "Payment " + (a.index + 1) + (many ? " (task " + a.task + ")" : "") + ": " + eur(a.amount) + " to " + groups(a.account) + ". " + st.label + ". Open evidence.",
        onclick: (ev) => onSelect(mode, a.index, ev.currentTarget),
      }, many ? el("span", { class: "pill-t" }, "T" + a.task) : null,
      el("span", {}, money(a.amount)), withAccount ? el("span", {}, tail(a.account)) : null,
      el("span", { class: "pill-st" }, st.label)),
      truthTag(a));
  }

  /** Pills grouped by task, each group led by its task's label (several tasks only), so a
      label never wraps away from its pills. */
  function pillGroups(mode, list, withAccount) {
    if (!multi()) return list.map((a) => pillBox(mode, a, withAccount));
    const groups = [];
    for (const a of list) {
      if (!groups.length || groups[groups.length - 1].task !== a.task) groups.push({ task: a.task, items: [] });
      groups[groups.length - 1].items.push(a);
    }
    return groups.map((g) => el("span", { class: "task-group" },
      el("span", { class: "task-div", "aria-hidden": "true" }, "Task " + g.task),
      g.items.map((a) => pillBox(mode, a, withAccount))));
  }

  function pipEls(checks, idle) {
    return checks.map((c) => el("span", {
      class: "pip " + (idle ? "idle" : c.status),
      title: c.rule + " " + (c.title || "") + ": " + (CHECK_WORD[c.status] || c.status) + ". " + c.detail,
    }, c.rule));
  }

  function laneEl(m, run) {
    const shown = run.attempts.slice(0, b.shown);
    const all = b.shown >= run.attempts.length;
    const bad = shown.filter((a) => a.status === "paid" && a.legit === false);
    const lost = all ? cents(run.unauthorised) : bad.reduce((n, a) => n + cents(a.amount), 0);
    const mule = all ? cents(run.to_attacker) : bad.filter((a) => a.to_attacker).reduce((n, a) => n + cents(a.amount), 0);
    const pick = b.selected && b.selected.mode === m.id ? shown[b.selected.index] : null;
    const focus = pick || shown[shown.length - 1] || null;
    /* A repeat that joined a waiting hold stays with the agent: the hold it joined is the payment. */
    const returned = shown.filter((a) => a.repeat || ["blocked", "rejected", "expired"].includes(a.status));
    const held = shown.filter((a) => !a.repeat && a.status === "held");
    const paid = shown.filter((a) => !a.repeat && a.status === "paid");
    const accounts = [...new Set(paid.map((a) => a.account))];
    const guarded = run.mandate !== null;

    const pips = el("div", { class: "pips" }, focus ? pipEls(focus.checks, false) : null);
    const verdict = el("span", { class: "verdict" }, focus && guarded ? "#" + (focus.index + 1) + " " + verdictText(focus) : "");
    const bay = el("div", { class: "bay" }, el("span", { class: "bay-label" }, "Hold bay"),
      pillGroups(m.id, held, true));
    const agent = el("div", { class: "station st-agent" },
      el("div", { class: "st-label" }, "AGENT", el("small", {}, "scripted")),
      el("div", { class: "pillboxes" }, pillGroups(m.id, returned, true)));
    const guardBox = guarded
      ? el("div", { class: "station st-guard" }, el("div", { class: "st-label" }, "GUARD", verdict), pips, bay)
      : el("div", { class: "station st-guard none" }, el("div", { class: "st-label" }, "NO GUARD"),
        el("p", {}, "Nothing is checked. The agent calls the bank directly."));
    const bank = el("div", { class: "station st-bank" }, el("div", { class: "st-label" }, "BANK"),
      el("span", { class: "bank-n" }, String(paid.length)), el("span", { class: "small muted" }, "paid"));
    const dest = el("div", { class: "station st-dest" }, el("div", { class: "st-label" }, "DESTINATIONS"),
      el("div", { class: "dests" }, accounts.map((account) => el("div", { class: "dest" },
        el("div", { class: "dest-acct", title: groups(account) }, mask(account)),
        el("div", { class: "pillboxes" }, pillGroups(m.id, paid.filter((a) => a.account === account), false))))));
    const track = el("div", { class: "track" }, agent, guardBox, bank, dest);
    b.lanes[m.id] = { track, agent, guard: guardBox, pips, verdict, bay, bank, dest, guarded };

    return el("section", {
      class: "lane" + (m.id === "countersign" ? " ours" : "") + (b.outlined === m.id ? " outlined" : ""),
      "aria-label": m.label,
    },
    el("div", { class: "lane-head" },
      el("h3", {}, m.label), m.note ? el("span", { class: "tag" }, m.note) : null,
      shownQuarantines(run, shown).map((q) => el("span", { class: "tag tag-block", title: q.text },
        "QUARANTINED" + ((run.mandates || []).length > 1 ? " IN TASK " + q.number : ""))),
      el("div", { class: "counter" + (lost > 0 ? " bad" : "") },
        mule > 0 ? el("span", {}, eur(fromCents(mule)) + " to attacker-controlled accounts") : null,
        el("span", {}, "Unauthorised money moved"), el("b", {}, eur(fromCents(lost))))),
    track);
  }

  /** Fly attempt `index` along every lane at once, then show it as settled. */
  b.animate = async (index, speed, token) => {
    const jobs = [];
    for (const m of S.meta.modes) {
      const run = b.runs[m.id];
      if (run && run.attempts[index] && b.lanes[m.id]) jobs.push(fly(b.lanes[m.id], run.attempts[index], speed, token));
    }
    await Promise.all(jobs);
    if (token.cancelled) return;
    b.shown = Math.max(b.shown, index + 1);
    b.render();
  };

  async function fly(lane, a, speed, token) {
    const hop = 520 / speed;
    if (lane.guarded) {
      fill(lane.pips, pipEls(a.checks, true));
      lane.verdict.textContent = "#" + (a.index + 1);
    }
    const flyer = el("div", { class: "flyer", "aria-hidden": "true" }, money(a.amount) + " " + tail(a.account));
    lane.track.append(flyer);
    const at = (node) => {
      const t = lane.track.getBoundingClientRect();
      const r = node.getBoundingClientRect();
      return [r.left - t.left + (r.width - flyer.offsetWidth) / 2, r.top - t.top + (r.height - flyer.offsetHeight) / 2];
    };
    const css = (p) => "translate(" + Math.round(p[0]) + "px, " + Math.round(p[1]) + "px)";
    const move = async (from, to) => {
      try {
        await flyer.animate([{ transform: css(from) }, { transform: css(to) }],
          { duration: hop, easing: "ease-in-out", fill: "forwards" }).finished;
      } catch (err) { /* animation cancelled */ }
    };
    const start = at(lane.agent);
    const gate = [at(lane.guard)[0], at(lane.guard.firstElementChild)[1]]; /* over the label row, clear of the pips */
    await move(start, gate);
    if (lane.guarded) {
      const pips = [...lane.pips.children];
      for (let k = 0; k < a.checks.length && !token.cancelled; k++) {
        const status = a.checks[k].status;
        pips[k].className = "pip " + status;
        if (status === "pass" || status === "block" || status === "hold") await sleep(70 / speed);
      }
      lane.verdict.textContent = "#" + (a.index + 1) + " " + verdictText(a);
      await sleep(180 / speed);
    }
    if (!token.cancelled) {
      if (a.outcome === "ALLOW") {
        await move(gate, at(lane.bank));
        await move(at(lane.bank), at(lane.dest));
      } else if (a.outcome === "HOLD") {
        flyer.classList.add("held");
        await move(gate, at(lane.bay));
      } else {
        flyer.classList.add("blocked");
        const [x, y] = gate;
        try {
          await flyer.animate([-5, 5, -4, 4, 0].map((dx) => ({ transform: css([x + dx, y]) })), { duration: 260 / speed }).finished;
        } catch (err) { /* cancelled */ }
        await move(gate, start);
      }
    }
    flyer.remove();
  }
  return b;
}

/* ---- 4c. Evidence card ---- */

function outcomeBadge(a) {
  return el("span", { class: "badge " + (OUTCOME_CLASS[a.outcome] || "block") }, verdictText(a));
}

function statusSentence(a) {
  const h = a.hold;
  if (a.repeat && h) {
    return "Asked again for exactly the same payment while hold " + h.id + " waited. It joined that hold, so there is still one decision and at most one payment. The hold is now " + h.status + ".";
  }
  if (a.status === "paid" && h && h.status === "approved") {
    return "A person approved this hold" + (h.attestation ? " (attestation: " + h.attestation + ")" : "") +
      ". The money was sent" + (a.transfer_id ? " as transfer " + a.transfer_id : "") + ".";
  }
  if (a.status === "paid") return "Paid" + (a.transfer_id ? " as transfer " + a.transfer_id : "") + ".";
  if (a.status === "held") return "Waiting for a person to countersign" + (h ? " (hold " + h.id + ")" : "") + ". Nothing has been paid.";
  if (a.status === "rejected") {
    return "A person rejected this hold. Nothing was paid." +
      (h && h.account_refused ? " They said the account was wrong, so it is refused for this payee for the rest of the task." : "") +
      (h && h.wrong === "payment" ? " They said only this payment was wrong, so the account was not refused." : "") +
      (h && h.vendor_removed ? " It was also taken off the vendor file." : "");
  }
  if (a.status === "expired") return "The hold expired with its task. Nothing was paid.";
  if (a.status === "unknown") return "The bank did not confirm this transfer. It may have been sent and needs a person to reconcile it.";
  return "Blocked. Nothing was paid.";
}

/** ctx: { guardLabel, show(sighting) } */
function evidenceNodes(a, ctx) {
  const ev = a.evidence;
  const cls = OUTCOME_CLASS[a.outcome] || "block";
  const nodes = [
    el("div", { class: "ev-head" }, outcomeBadge(a), el("strong", {}, a.payee),
      el("span", { class: "num" }, eur(a.amount)), el("span", { class: "muted" }, "reference " + a.reference)),
    el("p", { class: "acct-big" }, groups(a.account)),
    a.account_raw && a.account_raw !== a.account && a.account_raw !== groups(a.account)
      ? el("p", { class: "note" }, "As the agent passed it: ", el("span", { class: "mono" }, a.account_raw)) : null,
    el("p", { class: "reason " + cls }, a.reason),
    el("p", {}, statusSentence(a)),
    a.note ? el("p", { class: "note" }, a.note) : null,
    /* Right under the reason: a look-alike letter or a hidden figure is not visible in the lines above. */
    a.found && a.found.length ? el("div", { class: "found-top" }, el("h3", {}, "What else the guard found"), foundList(a)) : null,
  ];
  if (a.legit != null) {
    nodes.push(el("div", { class: "truth-box" },
      el("span", { class: "cap" }, "Ground truth: known to the benchmark, never to the guard"),
      truthTag(a), " ",
      a.to_attacker == null ? null : a.to_attacker ? "The account is controlled by the attacker." : "The account is not controlled by the attacker."));
  }
  if (!ev) {
    nodes.push(el("h3", {}, "Rules, in order"), el("p", {}, "No guard ran, so no rule was checked and there is no evidence to show."));
    return nodes;
  }
  nodes.push(el("h3", {}, "Rules, in order (" + ctx.guardLabel + ")"),
    el("table", { class: "ladder" }, el("tbody", {}, a.checks.map((c) => el("tr", { class: c.status },
      el("td", {}, c.rule),
      el("td", {}, el("span", { class: "rt" }, c.title || ""), el("br"), c.detail),
      el("td", { class: "st" }, CHECK_WORD[c.status] || c.status))))));

  const docs = ev.sightings.filter((s) => s.origin !== "user");
  const typed = ev.sightings.filter((s) => s.origin === "user");
  const onFile = ev.on_file.includes(ev.account);
  const row = (yes, title, ...body) => el("div", { class: "origin-row " + (yes ? "yes" : "no") },
    el("span", { class: "yn" }, yes ? "YES" : "NO"), el("h4", {}, title), el("div", { class: "body" }, body));
  nodes.push(el("h3", {}, "Where did this account come from?"));
  if (!ev.valid_iban) {
    nodes.push(el("p", {}, "This is not a valid IBAN, so there is nothing to trace."));
  } else {
    nodes.push(el("div", { class: "origin" },
      row(ev.dictated || ev.typed_by_user, "Your instruction",
        ev.dictated ? "You gave this account for this payee."
          : ev.typed_by_user ? "You typed this account, but not for a specific payee."
            : "You did not type this account.",
        typed.map((s) => el("div", { class: "sighting" }, "your instruction, line " + s.line))),
      row(onFile, "Vendor file for " + ev.payee,
        !ev.on_file.length ? "No account on file for this payee."
          : onFile ? "This is the account on file."
            : ["The vendor file has a different account: ", el("span", { class: "mono" }, ev.on_file.map(groups).join(", ")), "."],
        ev.on_file_for ? el("div", {}, "This account is on file for " + ev.on_file_for + ".") : null),
      row(docs.length > 0, "Documents the agent read (untrusted)",
        docs.length ? null : "Not in any document the agent read.",
        docs.map((s) => el("div", {}, sightingNodes(s, ctx))))));
    if (!ev.sightings.length && !onFile && !ev.dictated) {
      nodes.push(el("p", { class: "banner block" }, "Nowhere. The guard has never seen this account" +
        (a.rules.includes("O1") ? ", so it refuses (O1)." : ".")));
    }
  }
  nodes.push(el("h3", {}, "What the rules looked at (trusted state)"),
    factsList(a) || el("p", { class: "note" }, "Nothing more to show."));
  nodes.push(el("p", { class: "note" }, "Decided by plain code, not by a model. Same request, same answer."));
  return nodes;
}

/** One place an account was written, with the marker for an account split by markup. */
function sightingNodes(s, ctx) {
  return el("span", { class: "sighting" },
    s.origin === "user" ? el("span", {}, "your instruction") : docName(s.source),
    "line " + s.line, s.origin === "user" ? null : " (untrusted)",
    s.rendered ? el("span", { class: "tag tag-block", title: ROUNDABOUT }, "not written as one piece") : null,
    s.origin === "user" ? null : el("button", { type: "button", class: "btn tiny", onclick: () => ctx.show(s) }, "Show"));
}

/** Every rule a decision carries, with what it found: its line of the rule ladder. */
function heldList(a) {
  const rows = a.held && a.held.length ? a.held : (a.rules || []).map((rule) => ({ rule, title: "", detail: "" }));
  return el("ul", { class: "held-rules" }, rows.map((r) => el("li", {},
    el("span", { class: "tag " + (a.outcome === "BLOCK" ? "tag-block" : "tag-hold") }, r.rule + " " + (r.title || "")),
    r.detail ? el("span", {}, " " + r.detail) : null)));
}

function factsList(a) {
  return a.facts && a.facts.length ? el("ul", { class: "facts-list" }, a.facts.map((f) => el("li", {}, f))) : null;
}

/* What the rules of v0.3 found (hidden figures, a look-alike reference, another invoice with
   the number you named, invoices your sentence left out, an amount above every usual one). */
function foundList(a) {
  return a.found && a.found.length ? el("ul", { class: "facts-list found" }, a.found.map((f) => el("li", {}, f))) : null;
}

function showSighting(viewer, sighting) {
  if (!viewer) return;
  if (window.innerWidth < 1000) closeSheet();
  if (!viewer.show(sighting.source, sighting.spans[0])) toast("That document is not on screen.");
}

/* ---- 4d. Hold card and inbox ---- */

function diffChars(mine, other) {
  const out = [];
  for (let i = 0; i < mine.length; i++) {
    if (i && i % 4 === 0) out.push(" ");
    out.push(mine[i] !== other[i] ? el("b", { class: "diff" }, mine[i]) : mine[i]);
  }
  return out;
}

/** ctx: { key, decide(id, action, body), show(sighting), instruction(a), attempts }
 *
 * What a person must do depends on the hold (a.approval, from the server, which
 * also enforces it): a hold about the account (P1, P2, P3) needs the whole account
 * typed back as the vendor confirmed it; nothing here ever fills it in. A hold
 * about the amount (A1, A2) offers "this is the new usual amount", in plain words.
 */
function holdCard(a, ctx) {
  const h = a.hold;
  const ev = a.evidence || { on_file: [], sightings: [] };
  const ap = Object.assign({ typed_account: false, remember_account: false, usual_amount: null, rivals: [], waiting: [],
    projected_rules: [], cleared: [], on_reject: "", reject_choices: [] }, a.approval || {});
  /* How often the agent asked for exactly this payment: every repeat joined this hold. */
  const asked = (ctx.attempts || []).filter((x) => x.hold && x.hold.id === h.id).length;
  /* Keyed by console, hold and digest: answers never carry over to another hold, or to
     the same hold once it is shown again with new reasons. */
  const key = ctx.key + ":" + h.id + ":" + h.digest;
  const form = S.holdForm[key] || (S.holdForm[key] = { attestation: null, remember: false, usual: false, typed: "", wrong: null, error: "" });
  /* A hold about the account is rejected only once the person says what was wrong. Nothing is chosen for them. */
  const choices = ap.reject_choices || [];
  /* The payee may have several accounts on file: compare with this payment's own when it is one of them. */
  const onFile = ev.on_file.includes(a.account) ? a.account : ev.on_file[0];
  const ready = () => (ap.typed_account ? form.typed.trim().length > 0 : !!form.attestation);
  const body = () => {
    const b = { digest: h.digest, remember_account: !!(ap.remember_account && form.remember),
      usual_amount: !!(ap.usual_amount && form.usual) };
    if (ap.typed_account) b.confirmed_account = form.typed;
    else b.attestation = form.attestation;
    return b;
  };
  const errorLine = form.error ? el("p", { class: "error", role: "alert" }, form.error) : null;
  const decide = (action, payload) => guard(async () => {
    form.error = "";
    try {
      await ctx.decide(h.id, action, payload());
    } catch (err) {
      /* Shown on the card itself, as well as in the toast: the card may have been redrawn. */
      form.error = err.message || String(err);
      rerenderHolds();
      throw err;
    }
  });
  const approve = el("button", { type: "button", class: "btn", disabled: !ready(), onclick: decide("approve", body) },
    "Countersign and pay");
  const reject = el("button", { type: "button", class: "btn strong", "data-autofocus": choices.length ? null : true,
    disabled: choices.length > 0 && !form.wrong, onclick: decide("reject", () => (choices.length ? { wrong: form.wrong } : {})) }, "Reject");
  const wrongBox = choices.length ? el("fieldset", { class: "attest reject-choice" },
    el("legend", {}, "If you reject: what was wrong?"),
    choices.map((c, i) => el("label", {},
      el("input", { type: "radio", name: "wrong-" + key, value: c.wrong, checked: form.wrong === c.wrong,
        "data-autofocus": i === 0 ? true : null,
        onchange: () => { form.wrong = c.wrong; reject.disabled = false; } }),
      el("span", {}, el("strong", {}, c.label + ". "), c.text))),
    el("p", { class: "note" }, "Nothing is chosen for you. If you are not sure the account is the vendor's, choose the account.")) : null;
  const radio = (value, label) => el("label", {},
    el("input", { type: "radio", name: "attest-" + key, value, checked: form.attestation === value,
      onchange: () => { form.attestation = value; approve.disabled = !ready(); } }), label);
  const docs = ev.sightings.filter((s) => s.origin !== "user");

  let confirm;
  if (ap.typed_account) {
    const input = el("input", { type: "text", class: "mono typed-account", autocomplete: "off", spellcheck: "false",
      autocapitalize: "characters", "data-keep": key + ":typed", "aria-describedby": "how-" + key,
      oninput: (e) => { form.typed = e.target.value; approve.disabled = !ready(); } });
    input.value = form.typed; /* what this person typed before a re-render; never the hold's account */
    confirm = el("fieldset", { class: "attest confirm" },
      el("legend", {}, "Confirm the account with the vendor"),
      el("p", { class: "small", id: "how-" + key },
        "Ask " + a.payee + " for their account through a channel you already trusted before this payment: a phone number or a contact you already had, not one from the invoice, an email or the agent. ",
        "Type the whole account they give you. It is compared with this payment's account in full, because a look-alike account can share its first and last characters with the real one."),
      el("label", { class: "field" }, el("span", {}, "Account the vendor confirmed"), input),
      el("p", { class: "note" }, "If the vendor gives you a different account, do not change anything here: reject this payment."));
  } else {
    confirm = el("fieldset", { class: "attest" }, el("legend", {}, "Before you countersign"),
      radio("checked", "I checked with the vendor using contact details I already had"),
      radio("not checked", "I have not checked"),
      el("p", { class: "note" }, "Your answer is written to the audit log. It is an accountability trail, not verification."));
  }
  const usual = ap.usual_amount;
  const usualBox = usual ? el("fieldset", { class: "attest" }, el("legend", {}, "The amount"),
    el("label", {}, el("input", { type: "checkbox", checked: form.usual, onchange: (e) => { form.usual = e.target.checked; } }),
      "This is the new usual amount for " + a.payee + " (" + eur(usual.amount) + ")"),
    el("p", { class: "note" }, usual.text),
    el("p", { class: "small" }, "Line for one invoice from the next task on: ",
      el("b", { class: "num" }, usual.now ? eur(usual.now) : "none, so a payment is held unless the sentence states an amount (A2)"), " without the mark, ",
      el("b", { class: "num" }, eur(usual.after)), " with it.")) : null;
  const remember = ap.remember_account ? el("label", { class: "remember" },
    el("input", { type: "checkbox", checked: form.remember, onchange: (e) => { form.remember = e.target.checked; } }),
    "Also add this account to the vendor file for " + a.payee + ". Payments to it are still held until you countersign one on a later day (P3).") : null;

  return el("article", { class: "hold-card", "aria-label": "Hold " + h.id },
    el("h4", {}, a.rule_title || "Held for countersignature"),
    el("div", { class: "hold-meta" },
      el("strong", {}, a.payee), el("span", { class: "amt" }, eur(a.amount)),
      el("span", { class: "muted" }, "reference " + a.reference), el("span", { class: "tag" }, h.id)),
    el("div", { class: "cmp" },
      el("span", { class: "lab" }, ev.on_file.length > 1 ? "On file (" + (ev.on_file.indexOf(onFile) + 1) + " of " + ev.on_file.length + ")" : "On file"),
      el("span", { class: "val" }, onFile ? diffChars(onFile, a.account) : "No account on file for this payee."),
      el("span", { class: "lab" }, "This payment"),
      el("span", { class: "val" }, onFile ? diffChars(a.account, onFile) : groups(a.account))),
    onFile && onFile.slice(0, 2) !== a.account.slice(0, 2)
      ? el("p", { class: "note" }, "Country code differs: " + onFile.slice(0, 2) + " on file, " + a.account.slice(0, 2) + " in this payment.") : null,
    onFile && onFile !== a.account ? el("p", { class: "note" }, "Characters that differ are marked.") : null,
    el("div", { class: "field-label" }, "Why it is held:"), heldList(a),
    el("p", { class: "reason hold" }, a.reason),
    relatedNodes(ap),
    asked > 1 ? el("p", { class: "note" }, el("span", { class: "tag" }, "asked " + asked + " times"),
      " The agent asked for exactly this payment " + asked + " times. Every repeat joined this hold: one decision, and at most one payment.") : null,
    el("p", { class: "small" }, el("span", { class: "field-label" }, "You asked: "),
      (typeof ctx.instruction === "function" ? ctx.instruction(a) : ctx.instruction) || ""),
    el("div", { class: "small" }, el("span", { class: "field-label" }, "Where the account was read: "),
      docs.length ? docs.map((s) => sightingNodes(s, ctx))
        : ev.typed_by_user ? "in your own instruction."
          : ev.on_file.includes(a.account) ? "nowhere needed: it is the account on file for " + a.payee + "." : "in no document."),
    el("details", { class: "facts-box", open: true }, el("summary", {}, "What the rules looked at (trusted state)"), factsList(a)),
    a.found && a.found.length ? el("details", { class: "facts-box found-box", open: true }, el("summary", {}, "What else the guard found"), foundList(a)) : null,
    confirm, usualBox, remember, wrongBox,
    errorLine,
    el("div", { class: "hold-actions" }, reject, approve,
      el("span", { class: "note" }, choices.length ? "To reject, say what was wrong above. To countersign, type the account above."
        : "Reject is the default. Countersign needs an answer above.")),
    ap.on_reject && !choices.length ? el("p", { class: "note on-reject" }, el("span", { class: "field-label" }, "If you reject: "), ap.on_reject) : null);
}

/** What the guard says about the other waiting payments now (not when the hold was made). */
function relatedNodes(ap) {
  const out = [];
  if (ap.rivals.length) {
    out.push(el("p", { class: "banner hold" }, "Decide together with " + ap.rivals.join(", ") +
      ": another account is waiting for the same invoice (D3), and at most one of them can be right."));
  }
  if (ap.waiting.length) {
    out.push(el("div", { class: "small related" },
      el("span", { class: "field-label" }, "Waiting payments it depends on (H2): "), ap.waiting.join(", ") + ".",
      ap.projected_rules.length ? [" If " + (ap.waiting.length === 1 ? "it were" : "they were") + " paid, this one would break: ",
        el("span", { class: "rule-tags" }, ap.projected_rules.map((r) => el("span", { class: "tag tag-hold", title: r.title }, r.rule + " " + r.title)))] : null,
      " Decide " + (ap.waiting.length === 1 ? "it" : "them") + " first, or together with this one."));
  }
  if (ap.refused && ap.refused.length) {
    out.push(el("p", { class: "banner block" }, "Would now be refused: ",
      el("span", { class: "rule-tags" }, ap.refused.map((r) => el("span", { class: "tag tag-block", title: r.title }, r.rule + " " + r.title))),
      " Approving it would pay nothing; reject it, or ask the agent again once you have checked."));
  }
  if (ap.cleared.length) {
    out.push(el("p", { class: "note cleared" }, el("span", { class: "tag tag-allow" }, "no longer applies: " + ap.cleared.join(", ")),
      " The waiting payment " + (ap.cleared.length === 1 ? "this reason was" : "these reasons were") + " about has been decided since this hold was made."));
  }
  return out.length ? el("div", { class: "related-box" }, el("span", { class: "field-label" }, "Now, with the other waiting payments:"), out) : null;
}

/** Draw every place a hold card is shown again, keeping the field being typed in. */
function rerenderHolds() {
  keepFocus(() => {
    if (S.view === "live" && live.built) renderLive();
    if (S.sheet && S.sheet.kind !== "limits") S.sheet.render();
  });
}

function decidedLine(a) {
  const h = a.hold;
  const cls = h.status === "approved" ? (a.legit === false ? "tag-block" : "tag-allow") : "";
  return el("div", { class: "decided" },
    el("span", { class: "tag " + cls }, h.id + " " + h.status),
    el("span", {}, a.payee + ", " + eur(a.amount)), el("span", { class: "mono" }, mask(a.account)),
    h.decided_by ? el("span", { class: "muted" }, "by " + h.decided_by) : null,
    h.attestation ? el("span", { class: "muted" }, "attestation: " + h.attestation) : null,
    h.account_refused ? el("span", { class: "tag tag-block" }, "account refused for the rest of the task") : null,
    h.wrong === "payment" ? el("span", { class: "tag" }, "only this payment was wrong") : null,
    h.vendor_removed ? el("span", { class: "tag tag-block" }, "taken off the vendor file") : null);
}

/** Attempts that carry a hold, one per hold id. */
function holdsOf(attempts) {
  const seen = new Set();
  return (attempts || []).filter((a) => a.hold && !seen.has(a.hold.id) && seen.add(a.hold.id));
}

function goneBanner() {
  const g = S.lastApproval;
  if (!g) return null;
  if (g.legit === false) {
    return el("p", { class: "banner block" }, "A person approved this. " + eur(g.amount) +
      " is gone. The user did not want this payment. Holds only work if someone checks.");
  }
  return el("p", { class: "banner allow" }, "A person approved this. " + eur(g.amount) + " was paid.");
}

/** Which holds the inbox shows depends on the view: the live session or the lab's Countersign run. */
function inboxSource() {
  if (S.view === "live" && live.state) {
    const task = live.state.task;
    return { attempts: live.state.attempts, ctx: liveHoldCtx(), where: "live session",
      quarantines: task && task.quarantine ? [task.quarantine] : [] };
  }
  const run = csRun();
  return { attempts: run ? run.attempts : [], ctx: labHoldCtx(), where: "Countersign run",
    quarantines: run ? (run.quarantines || []).map((q) => Object.assign({ where: (run.mandates || []).length > 1 ? "task " + q.number : "" }, q)) : [] };
}

function inboxNodes(source) {
  const holds = holdsOf(source.attempts);
  const pending = holds.filter((a) => a.hold.status === "pending");
  const decided = holds.filter((a) => a.hold.status !== "pending");
  const ctx = Object.assign({}, source.ctx, { attempts: source.attempts });
  return [
    el("p", { class: "tools-chip" }, "Agent tools: ", el("span", { class: "mono" }, S.meta.agent_tools.join(", ")),
      ". The agent has no approve tool. A person decides here."),
    (source.quarantines || []).map((q) => quarantineBanner(q, q.where)),
    goneBanner(),
    pending.length ? null : el("p", { class: "empty" }, "No payment is waiting for a countersignature in the " + source.where + "."),
    pending.map((a) => holdCard(a, ctx)),
    decided.length ? el("h3", {}, "Decided") : null,
    decided.map(decidedLine),
  ];
}

function openInbox() {
  openSheet("inbox", "Countersign inbox", () => fill($("sheet-body"), inboxNodes(inboxSource())), $("btn-inbox"));
}

function updateInboxCount() {
  const n = holdsOf(inboxSource().attempts).filter((a) => a.hold.status === "pending").length;
  $("inbox-count").textContent = String(n);
  $("inbox-count").classList.toggle("on", n > 0);
}

/* Approve or reject a hold, in the lab or the live console. Both answer the same way:
   a 409 refreshes the view and shows why; an approval that paid nothing says so. */
async function decideHold(path, id, action, body, { attempts, apply, refresh }) {
  let state;
  try {
    state = await api(path + encodeURIComponent(id) + "/" + action, body);
  } catch (err) {
    if (err.status === 409) await refresh();
    throw err;
  }
  const after = holdsOf(attempts(state)).find((a) => a.hold.id === id);
  S.lastApproval = action === "approve" && after && after.status === "paid" ? { amount: after.amount, legit: after.legit } : null;
  if (action === "approve" && after && after.status !== "paid") toast("Not paid: " + after.reason);
  if (action === "reject" && after) {
    toast("Rejected " + id + ". Nothing was paid." +
      (after.hold.account_refused ? " This account is refused for " + after.payee + " for the rest of the task."
        : after.hold.wrong === "payment" ? " Only this payment is refused; the account was not refused."
          : " This same payment is refused for the rest of the task.") +
      (after.hold.vendor_removed ? " It was also taken off the vendor file." : ""));
  }
  apply(state);
}

function labHoldCtx() {
  return {
    key: "lab",
    instruction: (a) => (labTask(a.task) || {}).instruction || "",
    show: (s) => showSighting(currentViewer(), s),
    decide: (id, action, body) => decideHold("/api/holds/", id, action, body, {
      attempts: (state) => state.runs.countersign.attempts,
      apply: (state) => setLab(state),
      refresh: async () => setLab(await api("/api/lab"), true), /* the saved head stays as it is */
    }),
  };
}

/** One task of the lab's scenario: { number, instruction, documents, ... }. */
function labTask(number) {
  const sc = S.lab.scenario;
  if (!sc) return null;
  const tasks = sc.tasks || [{ number: 1, instruction: sc.instruction, documents: sc.documents, gap_hours: 0 }];
  return tasks[(number || 1) - 1] || tasks[0];
}

function openEvidence(mode, index, opener) {
  const board = S.view === "playground" ? pg.board : stage.board;
  if (board) { board.selected = { mode, index }; board.render(); }
  const several = S.lab.scenario && (S.lab.scenario.tasks || []).length > 1;
  const render = () => {
    const run = S.lab.runs[mode];
    const a = run && run.attempts[index];
    if (!a) return closeSheet();
    const show = (s) => {
      /* The account was read in the documents of this payment's task. */
      if (S.view === "stage" && several) stageShowTask(a.task);
      showSighting(currentViewer(), s);
    };
    return fill($("sheet-body"), evidenceNodes(a, { guardLabel: run.mode_label, show }),
      a.hold && a.hold.status === "pending"
        ? el("p", {}, el("button", { type: "button", class: "btn", onclick: openInbox }, "Open the Countersign inbox")) : null);
  };
  const run = S.lab.runs[mode];
  const a = run && run.attempts[index];
  openSheet("evidence", "Evidence: payment " + (index + 1) + (several && a ? " (task " + a.task + ")" : "") + ", " + modeInfo(mode).label, render, opener);
}

/** Every lab response goes through here so all views stay in step. */
function setLab(state, fromTamper) {
  S.lab = { scenario: state.scenario || null, runs: state.runs || {} };
  if (!fromTamper) saveWitness();
  if (stage.built) renderStage();
  if (pg.built) renderPgResults();
  if (S.view === "audit") renderAudit();
  updateInboxCount();
  if (S.sheet) keepFocus(S.sheet.render);
}

/* ------------------------------------------------------------------ */
/* 5. Stage                                                            */
/* ------------------------------------------------------------------ */

const stage = { built: false, loading: false, pos: 0, playing: false, busy: false, speed: 1, token: { cancelled: false }, board: null, viewer: null, ui: {}, task: 1 };
const KIND_LABEL = { benign: "ordinary tasks", attack: "attacks" };
const suiteLabel = (id) => id.charAt(0).toUpperCase() + id.slice(1);

function scenarioOption(s) {
  return el("option", { value: s.id }, s.id + "  " + s.title + (s.tasks > 1 ? "  [" + s.tasks + " tasks]" : "") + (s.known_gap ? "  [known gap]" : ""));
}

function buildStage() {
  const ui = stage.ui;
  stage.viewer = createViewer("Pick a scenario to see what the agent read.");
  stage.board = createBoard(openEvidence);
  ui.select = el("select", { class: "scenario", "aria-label": "Scenario", onchange: guard(() => loadScenario(ui.select.value)) });
  /* Grouped by suite (who wrote it), then ordinary tasks before attacks. */
  for (const suite of S.meta.suites || [{ id: "standard", note: "" }]) {
    for (const kind of ["benign", "attack"]) {
      const list = S.meta.scenarios.filter((s) => (s.suite || "standard") === suite.id && s.kind === kind);
      if (list.length) ui.select.append(el("optgroup", { label: suiteLabel(suite.id) + ": " + KIND_LABEL[kind] }, list.map(scenarioOption)));
    }
  }
  ui.custom = el("option", { value: "custom" }, "custom  written in the playground");
  ui.tags = el("span", { class: "row" });
  ui.summary = el("span", { class: "summary" });
  ui.play = el("button", { type: "button", id: "stage-play", class: "btn primary", title: "Space", onclick: guard(stagePlay) }, "Play");
  ui.step = el("button", { type: "button", id: "stage-step", class: "btn", title: "Right arrow", onclick: guard(stageStep) }, "Step");
  ui.speed = el("select", { "aria-label": "Speed", onchange: () => { stage.speed = Number(ui.speed.value); } },
    [["0.5", "0.5x"], ["1", "1x"], ["2", "2x"], ["0", "instant"]].map(([value, label]) =>
      el("option", { value, selected: value === "1" }, label)));
  ui.user = el("div", {});
  ui.caption = el("p", { class: "caption", role: "status", "aria-live": "polite" });
  ui.notice = el("div", { class: "stage-notice" });
  fill($("view-stage"),
    el("div", { class: "strip" },
      el("button", { type: "button", class: "btn", "aria-label": "Previous scenario", onclick: guard(() => stageNeighbour(-1)) }, "Prev"),
      ui.select,
      el("button", { type: "button", class: "btn", "aria-label": "Next scenario", onclick: guard(() => stageNeighbour(1)) }, "Next"),
      ui.tags, ui.summary,
      el("div", { class: "transport" }, ui.play, ui.step,
        el("button", { type: "button", id: "stage-reset", class: "btn", title: "R", onclick: guard(stageReset) }, "Reset"), ui.speed)),
    el("div", { class: "stage-grid" },
      el("div", { class: "stage-left" },
        el("section", { class: "panel" }, el("h2", {}, "The user (trusted)"), ui.user),
        el("section", { class: "panel docs" }, el("h2", {}, "What the agent read (untrusted)"), stage.viewer.root)),
      el("div", { class: "stage-right" }, stage.board.root, ui.notice, ui.caption,
        el("p", { class: "legend" }, "The agent is scripted: it attempts every payment the attacker wants. Dashed tags (",
          el("span", { class: "truth" }, "the user wanted this"), " / ", el("span", { class: "truth unwanted" }, "the user did not want this"),
          ") are ground truth: known to the benchmark, never to the guard."))));
  stage.built = true;
}

async function enterStage() {
  if (!stage.built) buildStage();
  if (!S.lab.scenario && !stage.loading) {
    /* Open on the split-payment scenario when the server has it: hidden text, and the guards disagree. */
    const first = S.meta.scenarios.find((s) => s.id === "attack-05") ||
      S.meta.scenarios.find((s) => s.hidden_text && s.kind === "attack" && !s.known_gap) || S.meta.scenarios[0];
    if (first) return loadScenario(first.id);
  }
  return renderStage();
}

function stageCancel() {
  stage.token.cancelled = true;
  stage.token = { cancelled: false };
  stage.playing = false;
  stage.busy = false;
}

async function loadScenario(id, options) {
  const opts = options || {};
  stageCancel();
  if (id === "custom") { stage.pos = 0; return renderStage(); }
  stage.loading = true;
  let state;
  try {
    state = await api("/api/compare", { scenario: id });
  } finally {
    stage.loading = false;
  }
  S.lastApproval = null;
  S.holdForm = {};
  S.tamper = { stage: null, truncated: false };
  stage.pos = 0;
  stage.task = 1;
  stage.board.selected = null;
  stage.board.outlined = opts.outline || null;
  stage.viewer.index = 0;
  if (S.sheet && S.sheet.kind !== "limits") closeSheet();
  setLab(state);
  if (opts.autoplay) await stagePlay();
  return undefined;
}

function stageNeighbour(delta) {
  const ids = S.meta.scenarios.map((s) => s.id);
  const at = ids.indexOf(S.lab.scenario ? S.lab.scenario.id : "");
  return loadScenario(ids[(at + delta + ids.length) % ids.length]);
}

function stageTasks() {
  const sc = S.lab.scenario;
  if (!sc) return [];
  return sc.tasks && sc.tasks.length ? sc.tasks : [{ number: 1, instruction: sc.instruction, documents: sc.documents, gap_hours: 0 }];
}

/** Every step of the replay, task by task: a divider where a task starts (several tasks
    only), the documents the agent reads, then the payments it asks for. */
function stageSteps() {
  const tasks = stageTasks();
  if (!tasks.length) return [];
  const runs = Object.values(S.lab.runs);
  const longest = runs.reduce((best, r) => (r.attempts.length > best.length ? r.attempts : best), []);
  const steps = [];
  for (const t of tasks) {
    if (tasks.length > 1) steps.push({ type: "task", t: t.number });
    t.documents.forEach((d, i) => steps.push({ type: "doc", t: t.number, i }));
    longest.forEach((a, i) => { if ((a.task || 1) === t.number) steps.push({ type: "attempt", t: t.number, i }); });
  }
  return steps;
}

const attemptsBefore = (steps, pos) => steps.slice(0, pos).filter((s) => s.type === "attempt").length;

/** The task the Stage shows on the left: the one of the step being played or last played. */
function stepTask(steps) {
  const at = Math.min(stage.pos, steps.length);
  const step = stage.busy ? steps[at] : steps[at - 1];
  return step ? step.t : 1;
}

/** Show one task's sentence, mandate and documents on the left. */
function stageShowTask(number) {
  if (stage.task === number) return;
  stage.task = number;
  stage.viewer.index = 0;
  renderStageLeft();
}

function mandateChips(m) {
  if (!m) return [];
  const chip = (label, value) => el("span", { class: "chip" }, label + " ", el("b", {}, value));
  const accounts = Object.entries(m.accounts || {}).flatMap(([payee, list]) => list.map((a) => chip("account you gave for " + payee, groups(a))));
  /* What the task expects per payee (S1, S2, S3): one payment unless the sentence or the person said more. */
  const asks = m.payees.map((p) => {
    const ask = (m.asks || {})[p] || {};
    const n = ask.payments || 1;
    return [chip(p, n + (n === 1 ? " payment" : " payments") + (ask.payments ? "" : " (default)") +
        (ask.instalments && n > 1 ? ", instalments of one invoice" : "")),
      ask.amount ? chip(p + " at most", money(ask.amount)) : null,
      (ask.invoices || []).map((r) => chip(p + " invoice", r)),
      /* S4: the sentence leaves some of this payee's invoices out. */
      ask.excludes_some ? el("span", { class: "chip chip-hold", title: "Every payment to " + p + " waits for you, unless its invoice is one your sentence names to pay (S4)." },
        p + " ", el("b", {}, "some invoices not to be paid")) : null];
  });
  return [
    m.payees.map((p) => chip("payee", p)),
    chip("per payment up to", money(m.max_per_payment)), chip("task budget", money(m.max_total)),
    chip("expires", String(m.expires_at).replace("T", " ").slice(0, 16) + " UTC"),
    m.max_payments ? chip("payments allowed", String(m.max_payments)) : null,
    (m.references || []).map((r) => chip("invoice", r)), accounts, asks,
  ];
}

/** The mandate of task `number` (from 1) in the lab, from any guarded run. */
function labMandate(number) {
  for (const r of Object.values(S.lab.runs)) {
    const list = r.mandates && r.mandates.length ? r.mandates : r.mandate ? [r.mandate] : [];
    if (list[number - 1]) return list[number - 1];
  }
  return null;
}

const gapText = (hours) => (hours >= 48 ? Math.round(hours / 24) + " days" : hours + " hours");

/** One task's payees and limits, as the person confirmed them for that task. */
function taskTerms(t) {
  const m = labMandate(t.number) || {};
  const payees = t.payees || m.payees || [];
  const per = t.max_per_payment || m.max_per_payment;
  const total = t.max_total || m.max_total;
  return payees.join(", ") + (per ? "; up to " + money(per) + " a payment" : "") + (total ? ", " + money(total) + " in all" : "");
}

function captionNodes(steps) {
  const at = Math.min(stage.pos, steps.length);
  const step = stage.busy ? steps[at] : steps[at - 1];
  const out = [];
  if (!step) {
    out.push("Ready. Play replays the recorded attempts under every guard at once. The animation is replay pacing, not decision time. Click a payment for its evidence.");
  } else if (step.type === "task") {
    const t = labTask(step.t);
    out.push(el("span", { class: "task-start" }, "Task " + step.t + " of " + stageTasks().length), " ",
      step.t > 1 ? "starts " + gapText(t.gap_hours) + " later, on the same guard, bank and vendor file. Payments still waiting from the task before expire. " : "",
      "The user confirms a new mandate for " + taskTerms(t) + ": “" + t.instruction + "”");
  } else if (step.type === "doc") {
    out.push("The scripted agent reads " + docNameText(labTask(step.t).documents[step.i].name) + ". Everything in it, the name included, was written by the sender.");
  } else {
    const parts = S.meta.modes.filter((m) => S.lab.runs[m.id] && S.lab.runs[m.id].attempts[step.i]).map((m) => {
      const a = S.lab.runs[m.id].attempts[step.i];
      return m.label + ": " + (stage.busy ? verdictText(a) : pillStatus(a).label) + ".";
    });
    const a = Object.values(S.lab.runs).map((r) => r.attempts[step.i]).find(Boolean);
    const several = stageTasks().length > 1;
    out.push("Payment " + (step.i + 1) + (several ? " (task " + step.t + ")" : "") + ": " + eur(a.amount) + " to " + mask(a.account) + " for " + a.payee + ". " + parts.join(" "));
  }
  if (S.lastApproval && S.lastApproval.legit === false && at >= steps.length) {
    out.push(el("span", { class: "gone" }, "A person approved a held payment. " + eur(S.lastApproval.amount) +
      " is gone. Holds only work if someone checks."));
  }
  return out;
}

function renderStageLeft() {
  const ui = stage.ui;
  const tasks = stageTasks();
  const t = labTask(stage.task) || tasks[0];
  if (!t) return;
  const m = labMandate(t.number);
  fill(ui.user,
    /* Each task's own payees and limits: a later task can pay other people, or less. */
    tasks.length > 1 ? el("ol", { class: "task-strip", "aria-label": "Tasks of this scenario" }, tasks.map((x) =>
      el("li", { class: x.number === t.number ? "on" : "" },
        el("button", { type: "button", "aria-pressed": String(x.number === t.number), onclick: () => stageShowTask(x.number),
          title: x.instruction }, "Task " + x.number),
        x.number > 1 ? el("span", { class: "muted small" }, " +" + gapText(x.gap_hours)) : null,
        el("span", { class: "task-terms" }, taskTerms(x))))) : null,
    el("p", { class: "quote" }, "“" + t.instruction + "”"),
    el("div", { class: "chips" }, mandateChips(m)));
  stage.viewer.set(t.documents, m ? m.payees : []);
}

function renderStage() {
  const ui = stage.ui;
  const sc = S.lab.scenario;
  if (!sc) return;
  const steps = stageSteps();
  stage.pos = Math.min(stage.pos, steps.length);
  const known = S.meta.scenarios.some((s) => s.id === sc.id);
  if (!known && !ui.custom.isConnected) ui.select.append(ui.custom);
  if (known && ui.custom.isConnected) ui.custom.remove();
  ui.select.value = known ? sc.id : "custom";
  const meta = S.meta.scenarios.find((s) => s.id === sc.id);
  fill(ui.tags,
    el("span", { class: "tag " + (sc.kind === "attack" ? "tag-block" : "tag-allow") }, sc.kind === "attack" ? "attack" : "ordinary task"),
    sc.tasks && sc.tasks.length > 1 ? el("span", { class: "tag" }, sc.tasks.length + " tasks") : null,
    sc.known_gap ? el("span", { class: "tag tag-gap", title: sc.miss_reason || "" }, "known gap") : null,
    meta && meta.hidden_text ? el("span", { class: "tag" }, "hidden text") : null);
  ui.summary.textContent = sc.summary;
  ui.summary.title = sc.summary;
  stage.task = stepTask(steps);
  renderStageLeft();
  const shown = attemptsBefore(steps, stage.pos);
  stage.board.set(S.lab.runs, shown);
  const cs = csRun();
  fill(ui.notice, cs ? shownQuarantines(cs, cs.attempts.slice(0, shown)).map((q) =>
    quarantineBanner(q, (cs.mandates || []).length > 1 ? "task " + q.number : "")) : null);
  fill(ui.caption, captionNodes(steps));
  ui.play.textContent = stage.playing ? "Pause" : stage.pos >= steps.length && steps.length ? "Replay" : "Play";
  ui.step.disabled = stage.pos >= steps.length;
}

async function stageStep() {
  const steps = stageSteps();
  if (stage.busy || stage.pos >= steps.length) return false;
  const token = stage.token;
  const step = steps[stage.pos];
  const animated = stage.speed > 0 && !reducedMotion();
  stage.busy = true;
  stageShowTask(step.t);
  fill(stage.ui.caption, captionNodes(steps));
  if (step.type === "task") {
    if (animated) await sleep(900 / stage.speed);
  } else if (step.type === "doc") {
    stage.viewer.select(step.i);
    if (animated) await sleep(450 / stage.speed);
  } else if (animated) {
    await stage.board.animate(step.i, stage.speed, token);
  }
  if (token.cancelled) return false;
  stage.busy = false;
  stage.pos += 1;
  renderStage();
  return true;
}

async function stagePlay() {
  if (stage.playing) { stage.playing = false; renderStage(); return; }
  const steps = stageSteps();
  if (stage.busy || !steps.length) return;
  if (stage.pos >= steps.length) { stage.pos = 0; stage.board.selected = null; }
  const token = stage.token;
  stage.playing = true;
  renderStage();
  while (stage.playing && !token.cancelled && await stageStep()) {
    if (stage.speed > 0 && !reducedMotion()) await sleep(220 / stage.speed);
  }
  if (!token.cancelled) { stage.playing = false; renderStage(); }
}

function stageReset() {
  const sc = S.lab.scenario;
  if (!sc) return undefined;
  return loadScenario(S.meta.scenarios.some((s) => s.id === sc.id) ? sc.id : "custom");
}

/* ------------------------------------------------------------------ */
/* 6. Scoreboard                                                       */
/* ------------------------------------------------------------------ */

const score = { built: false, approver: "none", late: false, data: null, fuzz: null, busy: false, fuzzBusy: false, ticket: 0 };
const APPROVERS = [
  ["none", "Nobody approves", "Holds are left waiting. This is what each guard does before any person is involved."],
  ["careful", "Careful approver", "A person approves a hold only when the payment is genuine. No real person knows that for sure: this one is told."],
  ["procedural", "Procedural approver", "A person who follows a written procedure. For a question about the account, they phone the vendor on a number they already had. For anything else, they check the amount against the invoice the user meant. They reject what fails."],
  ["careless", "Careless approver", "A person approves every hold without checking. Holds are only as good as the person reading them."],
];
const WHEN = [
  [false, "At once", "The person answers each hold as soon as it appears."],
  [true, "Late", "The person answers only after the agent's last request of each task, as a slower person would."],
];

async function enterScore() {
  score.built = true;
  renderScore();
  if (!score.data) await loadScore();
}

async function loadScore() {
  /* Clicking quickly sends several requests; only the answer to the newest one is shown. */
  const ticket = ++score.ticket;
  score.busy = true;
  renderScore();
  try {
    const data = await api("/api/benchmark?approver=" + encodeURIComponent(score.approver) + "&late=" + (score.late ? "1" : "0"));
    if (ticket === score.ticket) score.data = data;
  } finally {
    if (ticket === score.ticket) {
      score.busy = false;
      renderScore();
    }
  }
}

async function runFuzz() {
  score.fuzzBusy = true;
  renderScore();
  try {
    score.fuzz = await api("/api/fuzz?runs=300");
  } finally {
    score.fuzzBusy = false;
    renderScore();
  }
}

function tileEl(mode, s, maxLost) {
  const lost = cents(s.unauthorised);
  const pct = (n) => (maxLost ? Math.round((cents(n) / maxLost) * 100) : 0) + "%";
  const att = el("i", { class: "b-att" });
  const ven = el("i", { class: "b-ven" });
  att.style.setProperty("--w", pct(s.to_attacker));
  ven.style.setProperty("--w", pct(s.to_vendor));
  return el("section", { class: "panel tile" },
    el("h3", {}, s.label, mode.note ? el("span", { class: "tag" }, mode.note) : null),
    el("p", { class: "big " + (s.attacks_money_moved ? "bad" : "good") }, s.attacks_money_moved + " of " + s.attacks_total,
      el("small", {}, "attacks where unauthorised money moved")),
    el("div", { class: "bar", role: "img", "aria-label": eur(s.unauthorised) + " unauthorised, of the largest " + eur(fromCents(maxLost)) }, att, ven),
    el("dl", {},
      el("dt", {}, "Unauthorised money moved"), el("dd", {}, eur(s.unauthorised)),
      el("dt", {}, "to attacker-controlled accounts"), el("dd", {}, eur(s.to_attacker)),
      el("dt", {}, "to genuine vendor accounts"), el("dd", {}, eur(s.to_vendor)),
      el("dt", {}, "Attacks held / blocked"), el("dd", {}, s.attacks_held + " / " + s.attacks_blocked),
      el("dt", {}, "Ordinary tasks paid / held / blocked"),
      el("dd", {}, s.benign_paid + " / " + s.benign_held + " / " + s.benign_blocked + " of " + s.benign_total),
      el("dt", {}, "Wanted payments inside attacks: paid / waiting / refused"),
      el("dd", {}, s.wanted_paid + " / " + (s.wanted_waiting || 0) + " / " + (s.wanted_refused || 0) + " of " + s.wanted_total),
      s.benign_needed_person == null ? null : [el("dt", {}, "Ordinary tasks that needed a person"),
        el("dd", {}, s.benign_needed_person + " of " + s.benign_total)]),
    lost ? null : el("p", { class: "note" }, "No unauthorised money moved in these scripted attacks."));
}

function cellInfo(row, c) {
  const rules = c.rules && c.rules.length ? " · " + c.rules.join(" ") : "";
  if (row.kind === "attack") {
    if (c.verdict === "paid") return ["PAID " + money(c.unauthorised), "block"];
    if (c.verdict === "held") return ["HELD" + rules, "hold"];
    return ["BLOCKED" + rules, "allow"];
  }
  if (c.verdict === "paid") return ["paid", "allow"];
  if (c.verdict === "held") return ["held" + rules, "hold"];
  return ["blocked" + rules, "block"];
}

function matrixEl(data, modes) {
  const openCell = (row, mode) => guard(async () => {
    if (!stage.built) buildStage();
    const loading = loadScenario(row.id, { autoplay: true, outline: mode });
    location.hash = "stage";
    await loading;
  });
  const rowEl = (row) => el("tr", {},
    el("th", { scope: "row" }, el("span", { class: "mono" }, row.id), row.title,
      row.tasks > 1 ? [" ", el("span", { class: "tag" }, row.tasks + " tasks")] : null,
      row.known_gap ? [" ", el("span", { class: "tag tag-gap", title: row.miss_reason || "" }, "known gap")] : null),
    modes.map((m) => {
      const c = row.cells[m.id];
      if (!c) return el("td", {}, "");
      const [text, cls] = cellInfo(row, c);
      const wanted = row.kind === "attack" && c.wanted_total ? "wanted payment: " + c.wanted_paid + " of " + c.wanted_total + " paid" : null;
      return el("td", {}, el("button", { type: "button", class: "cell " + cls,
        title: "Open " + row.id + " on the Stage", onclick: openCell(row, m.id) }, text, wanted ? el("small", {}, wanted) : null));
    }));
  const span = String(modes.length + 1);
  const group = (suite, label, kind) => {
    const rows = data.rows.filter((r) => (r.suite || "standard") === suite && r.kind === kind);
    return rows.length ? [el("tr", { class: "group" }, el("th", { colspan: span }, label)), rows.map(rowEl)] : [];
  };
  /* One block per suite, in the order the server gives them: who wrote it, then its rows. */
  const suites = (S.meta.suites || [{ id: "standard", note: "" }]).filter((x) => data.rows.some((r) => (r.suite || "standard") === x.id));
  return el("div", { class: "table-wrap" }, el("table", { class: "matrix" },
    el("thead", {}, el("tr", {}, el("th", { scope: "col" }, "Scenario"),
      modes.map((m) => el("th", { scope: "col" }, m.label, m.ours ? " (ours)" : "")))),
    suites.map((x) => el("tbody", { class: "suite" },
      el("tr", { class: "suite-head" }, el("th", { colspan: span, scope: "rowgroup" }, suiteLabel(x.id) + " suite",
        x.note ? el("span", { class: "suite-note" }, " \u00b7 " + x.note) : null)),
      group(x.id, "Ordinary tasks", "benign"), group(x.id, "Attacks", "attack")))));
}

/** Per suite: attacks where unauthorised money moved, and ordinary tasks left waiting or refused. */
function suitesEl(data, modes) {
  const suites = (S.meta.suites || []).filter((x) => data.suites && data.suites[x.id]);
  if (!suites.length) return null;
  const cell = (sum) => el("td", {},
    sum.attacks_total ? el("div", { class: sum.attacks_money_moved ? "error" : "" }, sum.attacks_money_moved + " of " + sum.attacks_total + " attacks moved money") : null,
    sum.benign_total ? el("div", { class: "small muted" }, sum.benign_held + " held, " + sum.benign_blocked + " blocked of " + sum.benign_total + " ordinary") : null);
  return el("div", { class: "table-wrap" }, el("table", { class: "matrix by-suite" },
    el("thead", {}, el("tr", {}, el("th", { scope: "col" }, "Suite"), modes.map((m) => el("th", { scope: "col" }, m.label)))),
    el("tbody", {}, suites.map((x) => el("tr", {},
      el("th", { scope: "row" }, suiteLabel(x.id), el("div", { class: "small muted" }, x.note)),
      modes.map((m) => cell(data.suites[x.id][m.id])))))));
}

function fuzzEl() {
  const f = score.fuzz;
  return el("section", { class: "panel" }, el("h2", {}, "Invariant check"),
    el("div", { class: "row" },
      el("button", { type: "button", class: "btn", disabled: score.fuzzBusy, onclick: guard(runFuzz) },
        score.fuzzBusy ? "Running…" : "Run invariant check"),
      el("span", { class: "note" }, "This checks that the code keeps its own promise. It says nothing about attacks we have not thought of.")),
    f ? el("div", { class: "fuzz-out", role: "status" },
      el("p", { class: f.violations.length ? "error" : "" },
        plural(f.runs, "random run") + ", " + plural(f.operations, "operation") + ", " +
        plural(f.violations.length, "invariant violation") + " (seed " + f.seed + ", " + f.elapsed_ms + " ms, just now)."),
      el("ul", {}, (f.invariants || []).map((inv) => el("li", {}, el("span", { class: "mono" }, inv.id), " " + inv.text))),
      f.violations.length ? el("ul", { class: "error" }, f.violations.map((v) => el("li", {}, typeof v === "string" ? v : JSON.stringify(v)))) : null)
      : el("p", { class: "note" }, "Not run yet. Results are never stored: you see the run that just happened."));
}

function renderScore() {
  const data = score.data;
  const modes = S.meta.modes.filter((m) => !data || data.summary[m.id]);
  const approver = APPROVERS.find((a) => a[0] === score.approver);
  const when = WHEN.find((w) => w[0] === score.late);
  const nodes = [
    el("h1", {}, "Scoreboard"),
    el("p", { class: "view-lead" }, "Every scenario of every suite replayed under every guard. The two baselines are our own. Known gaps stay on the board."),
    el("div", { class: "score-controls" },
      el("span", { class: "field-label" }, "Who decides holds:"),
      el("div", { class: "seg", role: "group", "aria-label": "Approver model" }, APPROVERS.map(([id, label]) =>
        segButton(label, score.approver === id, guard(() => { score.approver = id; return loadScore(); })))),
      el("span", { class: "field-label" }, "When:"),
      el("div", { class: "seg", role: "group", "aria-label": "When the person answers" }, WHEN.map(([late, label]) =>
        segButton(label, score.late === late, guard(() => { score.late = late; return loadScore(); })))),
      el("button", { type: "button", class: "btn primary", disabled: score.busy, onclick: guard(loadScore) }, score.busy ? "Running…" : "Run again"),
      data ? el("span", { class: "num", role: "status" }, "Shown: " + (APPROVERS.find((a) => a[0] === data.approver) || [0, data.approver])[1].toLowerCase() +
        (data.approver === "none" ? "" : data.late ? ", answering late" : ", answering at once") + ". " +
        plural(data.replays, "replay") + " in " + data.elapsed_ms + " ms on this machine, just now.") : null),
    el("p", { class: "note" }, approver[2] + (score.approver === "none" ? "" : " " + when[2])),
  ];
  if (data) {
    const maxLost = Math.max(0, ...modes.map((m) => cents(data.summary[m.id].unauthorised)));
    nodes.push(
      el("div", { class: "tiles" }, modes.map((m) => tileEl(m, data.summary[m.id], maxLost))),
      el("p", { class: "note" }, "Bar: unauthorised money moved, relative to the largest guard. Solid = to attacker-controlled accounts, striped = to genuine vendor accounts."),
      el("section", { class: "panel" }, el("h2", {}, "By suite"), suitesEl(data, modes)),
      el("section", { class: "panel" }, el("h2", {}, "Every scenario, every guard, by suite (click a cell to replay it on the Stage)"), matrixEl(data, modes)),
      el("section", { class: "panel" }, el("h2", {}, "Read this with the numbers"),
        el("ul", { class: "caveats" }, data.caveats.map((c) => el("li", {}, c)))));
  } else {
    nodes.push(el("p", { class: "empty" }, score.busy ? "Replaying every scenario…" : "No results yet."));
  }
  nodes.push(fuzzEl());
  fill($("view-scoreboard"), nodes);
}

/* ------------------------------------------------------------------ */
/* 7. Playground                                                       */
/* ------------------------------------------------------------------ */

const HIDE_OPEN = '<span style="color:#ffffff;font-size:1px">'; /* the scenarios' hidden-text markup, as text */
const HIDE_CLOSE = "</span>";
const pg = { built: false, doc: null, docIndex: 0, tally: null, ran: false, board: null, viewer: null, field: null, ui: {} };

function blankScenario() {
  const vendor = S.meta.vendors[0] || { name: "", accounts: [""] };
  return {
    title: "My attack", instruction: "Pay this month's " + vendor.name.replace(/ (Ltd|LLP|GmbH|Inc)\.?$/, "") + " invoice.",
    payees: [vendor.name], max_per_payment: "2000.00", max_total: "3000.00", max_payments: null, references: [],
    delay_hours: 0, documents: [{ name: "invoice.eml", text: "" }],
    attempts: [{ payee: vendor.name, account: S.meta.attacker_accounts[0] || "", amount: "480.00", reference: "INV-2041", legit: false }],
    attacker_accounts: [...S.meta.attacker_accounts],
  };
}

async function enterPlayground() {
  if (pg.built) return;
  pg.doc = blankScenario();
  pg.board = createBoard(openEvidence);
  pg.viewer = createViewer("Run the scenario to see the documents as the guard saw them.");
  const ui = pg.ui;
  ui.form = el("div", { class: "pg-grid" });
  ui.results = el("div", { class: "pg-results", "aria-live": "polite" });
  ui.from = el("select", { "aria-label": "Start from a scenario", onchange: guard(async () => {
    if (!ui.from.value) return;
    pg.doc = await api("/api/scenarios/" + encodeURIComponent(ui.from.value));
    if (!pg.doc.attacker_accounts || !pg.doc.attacker_accounts.length) pg.doc.attacker_accounts = [...S.meta.attacker_accounts];
    pg.docIndex = 0;
    renderPgForm();
  }) }, el("option", { value: "" }, "Start from…"),
  /* A playground scenario is one task, so only those can be a starting point. */
  S.meta.scenarios.filter((s) => !(s.tasks > 1)).map((s) => el("option", { value: s.id }, s.id + "  " + s.title)));
  fill($("view-playground"),
    el("h1", {}, "Attack playground"),
    el("p", { class: "view-lead" }, "You are the attacker. Write the documents, script the hijacked agent, and try to move money to an account you control. ",
      "We wrote the benchmark attacks ourselves, so write your own."),
    el("div", { class: "strip" }, ui.from,
      el("button", { type: "button", class: "btn", onclick: () => { pg.doc = blankScenario(); pg.docIndex = 0; ui.from.value = ""; renderPgForm(); } }, "Start blank"),
      el("div", { class: "transport" },
        el("button", { type: "button", class: "btn", onclick: exportScenario }, "Export scenario JSON"),
        el("button", { type: "button", id: "pg-run", class: "btn primary", title: "Ctrl+Enter", onclick: guard(runPlayground) }, "Run against all " + S.meta.modes.length + " guards"))),
    ui.form, ui.results);
  $("view-playground").addEventListener("focusin", (ev) => { if (ev.target.dataset && ev.target.dataset.insert) pg.field = ev.target; });
  pg.built = true;
  renderPgForm();
  renderPgResults();
}

/** An input bound to one property of the scenario being written. */
function bound(obj, key, props, parse) {
  const tag = props.tag || "input";
  const node = el(tag, Object.assign({ type: tag === "input" ? "text" : null }, props, { tag: null }));
  node.value = obj[key] == null ? "" : String(obj[key]);
  node.addEventListener("input", () => { obj[key] = parse ? parse(node.value) : node.value; });
  return node;
}
const field = (label, control, note) => el("label", { class: "field" }, el("span", {}, label), control, note ? el("span", { class: "note" }, note) : null);

function insertAtCursor(text) {
  const active = document.activeElement;
  const f = active && active.dataset && active.dataset.insert ? active : pg.field;
  if (!f || !f.isConnected) return toast("Click into the instruction, a document or an account field first.");
  f.setRangeText(text, f.selectionStart, f.selectionEnd, "end");
  f.dispatchEvent(new Event("input", { bubbles: true }));
  f.focus();
  return undefined;
}

function accountChips() {
  const chip = (label, account) => el("button", { type: "button", class: "btn tiny", title: "Insert " + groups(account) + " at the cursor",
    onmousedown: (ev) => ev.preventDefault(), /* keep the cursor in the field being edited */
    onclick: () => insertAtCursor(groups(account)) }, label + " ", el("span", { class: "mono" }, mask(account)));
  return el("div", { class: "row" },
    S.meta.vendors.flatMap((v) => v.accounts.map((a) => chip(v.name + ", on file", a))),
    S.meta.attacker_accounts.map((a, i) => chip("attacker " + (i + 1), a)));
}

function renderPgForm() {
  const d = pg.doc;
  pg.docIndex = Math.min(pg.docIndex, Math.max(0, d.documents.length - 1));
  const doc = d.documents[pg.docIndex];
  const lines = (text) => text.split("\n").map((s) => s.trim()).filter(Boolean);

  const user = el("section", { class: "panel" }, el("h2", {}, "The user (trusted)"),
    field("Instruction", bound(d, "instruction", { tag: "textarea", class: "prose", rows: "3", "data-insert": "1" }),
      "Anything typed here is the user's word, account numbers included. An attacker who can type here is the user."),
    field("Payees in the mandate (one per line)", bound({ v: d.payees.join("\n") }, "v", { tag: "textarea", class: "prose", rows: "2" }, (v) => { d.payees = lines(v); return v; })),
    el("div", { class: "row" },
      field("Per-payment limit", bound(d, "max_per_payment", { inputmode: "decimal", size: "9" })),
      field("Task budget", bound(d, "max_total", { inputmode: "decimal", size: "9" })),
      field("Payment count (optional)", bound(d, "max_payments", { inputmode: "numeric", size: "5" }, (v) => (/^\d+$/.test(v.trim()) ? Number(v) : null)))),
    el("h2", {}, "Vendor file (read only)"),
    el("table", { class: "vendor-file" }, el("tbody", {}, S.meta.vendors.map((v) => el("tr", {},
      el("td", {}, v.name), el("td", { class: "mono" }, v.accounts.map(groups).join(", ")),
      el("td", { class: "muted" }, v.history.length ? "paid before: " + v.history.map(money).join(", ") : "no history"))))));

  const tabs = el("div", { class: "doc-tabs", role: "tablist", "aria-label": "Attacker documents" },
    d.documents.map((x, i) => el("button", { type: "button", class: "doc-tab", role: "tab", "aria-selected": String(i === pg.docIndex),
      onclick: () => { pg.docIndex = i; renderPgForm(); } }, x.name || "document " + (i + 1))),
    d.documents.length < 4 ? el("button", { type: "button", class: "btn tiny", onclick: () => {
      d.documents.push({ name: "document-" + (d.documents.length + 1) + ".eml", text: "" });
      pg.docIndex = d.documents.length - 1;
      renderPgForm();
    } }, "Add document") : null);
  let area = null;
  if (doc) area = bound(doc, "text", { tag: "textarea", rows: "14", "data-insert": "1", "aria-label": "Document text", spellcheck: "false" });
  const docs = el("section", { class: "panel" }, el("h2", {}, "Documents (attacker-written, up to 4)"), tabs,
    doc ? [
      field("Name", bound(doc, "name", { class: "mono" })),
      area,
      el("div", { class: "row" },
        el("button", { type: "button", class: "btn tiny", title: "Wrap the selected text in white 1px markup", onclick: () => {
          const a = area.selectionStart;
          const b = area.selectionEnd;
          if (a === b) return toast("Select some text in the document first.");
          area.setRangeText(HIDE_OPEN + area.value.slice(a, b) + HIDE_CLOSE, a, b, "end");
          area.dispatchEvent(new Event("input", { bubbles: true }));
          return area.focus();
        } }, "Hide selection"),
        el("button", { type: "button", class: "btn tiny", onclick: () => { d.documents.splice(pg.docIndex, 1); renderPgForm(); } }, "Remove document")),
    ] : el("p", { class: "empty" }, "No documents. The agent reads nothing."),
    el("h2", {}, "Insert a known account at the cursor"), accountChips());

  const attempts = el("section", { class: "panel" }, el("h2", {}, "Payments the hijacked agent attempts (up to 8)"),
    d.attempts.map((a, i) => el("div", { class: "pg-attempt" },
      field("Payee", bound(a, "payee", {})),
      field("Amount", bound(a, "amount", { inputmode: "decimal" })),
      el("div", { class: "wide" }, field("Account", bound(a, "account", { class: "mono", "data-insert": "1", spellcheck: "false" }))),
      field("Reference", bound(a, "reference", {})),
      el("div", { class: "row" },
        el("label", {}, el("input", { type: "checkbox", checked: a.legit, onchange: (e) => { a.legit = e.target.checked; } }), " the user wanted this"),
        d.attempts.length > 1 ? el("button", { type: "button", class: "btn tiny", "aria-label": "Remove payment " + (i + 1),
          onclick: () => { d.attempts.splice(i, 1); renderPgForm(); } }, "Remove") : null))),
    d.attempts.length < 8 ? el("button", { type: "button", class: "btn", onclick: () => {
      const last = d.attempts[d.attempts.length - 1] || { payee: d.payees[0] || "", account: "", amount: "100.00", reference: "REF-1" };
      d.attempts.push({ payee: last.payee, account: last.account, amount: last.amount, reference: last.reference + "-B", legit: false });
      renderPgForm();
    } }, "Add payment") : null,
    el("p", { class: "note" }, "You say which payments the user wanted. The guard never sees that."));

  fill(pg.ui.form, user, docs, attempts);
}

function scenarioBody() {
  const d = pg.doc;
  return {
    title: d.title || "My attack", instruction: d.instruction, payees: d.payees, max_per_payment: String(d.max_per_payment).trim(),
    max_total: String(d.max_total).trim(), max_payments: d.max_payments || null, references: d.references || [],
    delay_hours: d.delay_hours || 0, documents: d.documents.map((x) => ({ name: x.name, text: x.text })),
    attempts: d.attempts.map((a) => ({ payee: a.payee, account: a.account, amount: String(a.amount).trim(), reference: a.reference, legit: !!a.legit })),
    attacker_accounts: d.attacker_accounts || [],
  };
}

function exportScenario() {
  download(new Blob([JSON.stringify(scenarioBody(), null, 2) + "\n"], { type: "application/json" }), "countersign-scenario.json");
}

async function runPlayground() {
  const state = await api("/api/playground/run", scenarioBody());
  pg.tally = state.tally || null;
  pg.ran = true;
  S.lastApproval = null;
  S.holdForm = {};
  S.tamper = { stage: null, truncated: false };
  stageCancel();
  stage.pos = Number.MAX_SAFE_INTEGER;
  pg.board.selected = null;
  pg.playing = true;
  setLab(state);
  pg.ui.results.scrollIntoView({ block: "start", behavior: reducedMotion() ? "auto" : "smooth" });
  const token = { cancelled: false };
  pg.token = token;
  if (!reducedMotion()) {
    for (let i = 0; i < pg.board.count() && pg.token === token; i++) await pg.board.animate(i, 2, token);
  }
  if (pg.token === token) { pg.playing = false; renderPgResults(); }
}

function renderPgResults() {
  const ui = pg.ui;
  const sc = S.lab.scenario;
  if (!pg.ran || !sc || sc.id !== "custom") {
    return fill(ui.results, pg.ran ? el("p", { class: "note" }, "The lab now shows another scenario. Run again to see playground results.") : null);
  }
  const run = csRun();
  const lost = cents(run.unauthorised);
  const blocked = run.attempts.filter((a) => a.status === "blocked").length;
  const held = run.attempts.filter((a) => a.status === "held").length;
  const t = pg.tally;
  const banner = pg.playing ? el("p", { class: "banner hold" }, "Replaying…")
    : lost > 0
      ? el("div", { class: "banner block" },
        S.lastApproval && S.lastApproval.legit === false
          ? "A person approved a held payment. " + eur(run.unauthorised) + " of unauthorised money has moved. Holds only work if someone checks. "
          : "You moved " + eur(run.unauthorised) + " past Countersign. That is a real gap. Export it so it can be added to the benchmark. ",
        el("button", { type: "button", class: "btn", onclick: exportScenario }, "Export scenario JSON"))
      : el("p", { class: "banner allow" }, "Countersign: no unauthorised money moved. " + blocked + " blocked, " + held + " waiting for a person.");
  if (!pg.playing) pg.board.set(S.lab.runs, pg.board.count() || Number.MAX_SAFE_INTEGER);
  else if (!pg.board.root.childElementCount || pg.board.runs !== S.lab.runs) pg.board.set(S.lab.runs, 0);
  const m = run.mandate;
  pg.viewer.set(sc.documents, m ? m.payees : []);
  return fill(ui.results,
    el("h2", { class: "h2" }, "Result"), banner,
    t ? el("p", { class: "tally" }, "Runs written in this console since the server started: " + t.runs + " (" + plural(t.attempts, "payment attempt") +
      "). Runs that moved unauthorised money past Countersign: " + t.runs_with_unauthorised_money + " (" + eur(t.unauthorised) +
      "). Not part of the benchmark.") : null,
    pg.board.root,
    el("p", { class: "legend" }, "Dashed tags are what you said the user wanted: known to the benchmark, never to the guard. Click a payment for its evidence. Holds are in the Inbox."),
    el("section", { class: "panel docs" }, el("h2", {}, "What the agent read (untrusted)"), pg.viewer.root));
}

/* ------------------------------------------------------------------ */
/* 8. Audit                                                            */
/* ------------------------------------------------------------------ */

const WITNESS_KEY = "countersign-witness";

/** Keep the head of the untampered log in this browser: the outside witness. */
function saveWitness() {
  const run = csRun();
  const au = run && run.audit;
  if (!au || !au.entries.length) { S.witness = null; return; }
  S.witness = { seq: au.head.seq, hash: au.head.hash, first: au.entries[0].hash, saved: new Date().toLocaleTimeString() };
  store("session", WITNESS_KEY, JSON.stringify(S.witness));
}

/** After a reload, trust the head saved earlier for this same log, not the server's current one. */
function restoreWitness() {
  const run = csRun();
  const au = run && run.audit;
  let saved = null;
  try { saved = JSON.parse(store("session", WITNESS_KEY) || "null"); } catch (err) { saved = null; }
  if (au && au.entries.length && saved && saved.first === au.entries[0].hash) S.witness = saved;
  else saveWitness();
}

function witnessVerdict(au, w) {
  const entry = au.entries.find((e) => e.seq === w.seq);
  if (!entry) {
    return { ok: false, text: "ENTRIES ARE MISSING", detail: "This browser saved the head at entry " + w.seq + ". The log now ends at entry " +
      au.head.seq + ". The log was cut after the head was saved." };
  }
  if (entry.hash !== w.hash) {
    return { ok: false, text: "A REWRITTEN LOG", detail: "Entry " + w.seq + " now has hash " + short(entry.hash) + ", not the " + short(w.hash) +
      " this browser saved. The log was rewritten after the head was saved." };
  }
  return { ok: true, text: "HEAD MATCHES", detail: "Entry " + w.seq + " still has the hash this browser saved: " + short(w.hash) + "." };
}

function chainVerdict(au) {
  if (au.intact) return { ok: true, text: "THE CHAIN VERIFIES", detail: plural(au.entries.length, "entry", "entries") + ", each linked to the one before by its hash." };
  const i = au.entries.findIndex((e) => e.seq === au.broken_at);
  const at = au.entries[i];
  const link = at && i > 0 && at.prev !== au.entries[i - 1].hash;
  return { ok: false, text: "TAMPERING DETECTED at entry " + au.broken_at,
    detail: link ? "It points at a hash that is no longer there." : "Its content no longer matches its hash." };
}

/* Entries a person should notice in the log, with what they mean in plain words. */
const NOTABLE = {
  hold_confirmation_failed: "The account typed back did not match. Nothing was paid.",
  task_quarantined: "The queue overflowed: this task pays nothing more without a person.",
  vendor_account_removed: "Taken off the vendor file after a person rejected it.",
};

function auditDetail(e) {
  const d = e.data || {};
  const dec = d.decision || d;
  const req = d.request || d.canonical || {};
  const bits = [];
  if (NOTABLE[e.event]) bits.push(NOTABLE[e.event]);
  if (e.event === "payment_decision" && dec.outcome) bits.push(dec.outcome + (dec.rule ? " (" + dec.rule + ")" : ""));
  if (e.event === "payment_decision" && d.repeat === true) bits.push("asked again: joined the waiting hold");
  if (e.event === "hold_confirmation_failed") bits.push("typed " + (typeof d.typed_account === "string" ? groups(d.typed_account) : "something that is not an IBAN"));
  if (e.event === "task_quarantined" && typeof d.waiting === "number") bits.push(plural(d.waiting, "payment") + " waiting");
  if (e.event === "vendor_account_removed" && typeof d.account === "string") bits.push(groups(d.account));
  if (e.event === "hold_rejected" && d.account_refused === true) bits.push("account refused for the rest of the task");
  if (e.event === "hold_rejected" && d.wrong === "payment") bits.push("only this payment was wrong");
  if (typeof d.transfer === "string") bits.push(d.transfer);
  if (typeof d.hold === "string") bits.push(d.hold);
  if (req.payee) bits.push(req.payee);
  if (req.amount) bits.push(money(req.amount));
  if (e.event === "content_observed") bits.push(docNameText(d.source || d.name || ""));
  if (e.event === "task_started") {
    const m = d.mandate || d;
    if (Array.isArray(m.payees)) bits.push(m.payees.join(", "));
    if (m.max_total) bits.push("budget " + money(m.max_total));
    if (typeof d.draft_digest === "string") bits.push("draft " + short(d.draft_digest));
    const set = d.set_by_person && typeof d.set_by_person === "object" ? Object.keys(d.set_by_person) : [];
    if (set.length) bits.push("set by the person for " + set.join(", "));
  }
  if (d.approver) bits.push("by " + d.approver);
  if (d.attestation) bits.push("attestation: " + d.attestation);
  if (!req.payee && typeof d.payee === "string") bits.push(d.payee);
  if (d.log_id) bits.push("log " + d.log_id);
  if (e.event === "payment_decision" && dec.reason && /edited/.test(dec.reason)) bits.push(dec.reason);
  return bits.filter(Boolean).join(" · ");
}

function chainEl(au) {
  return el("ol", { class: "chain", "aria-label": "Audit log entries" }, au.entries.map((e) => {
    const bad = !au.intact && e.seq === au.broken_at;
    return el("li", { class: bad ? "bad" : NOTABLE[e.event] ? "notable" : "" },
      el("span", { class: "seq" }, "#" + e.seq), el("span", { class: "ev" }, e.event),
      el("span", { class: "det" }, auditDetail(e)),
      el("span", { class: "hashes" }, "prev " + short(e.prev) + "  hash " + short(e.hash)),
      bad ? el("span", { class: "flag" }, "The chain breaks here.") : null);
  }));
}

async function tamper(stageName) {
  const state = await api("/api/audit/tamper", { stage: stageName });
  if (stageName === "truncate") S.tamper.truncated = true;
  else S.tamper.stage = stageName;
  setLab(state, true);
}

async function restoreLog() {
  const state = await api("/api/audit/restore", {});
  S.tamper = { stage: null, truncated: false };
  setLab(state);
}

async function downloadLog() {
  download(await api("/api/audit/export", undefined, true), "countersign-audit.jsonl");
}

function renderAudit() {
  const view = $("view-audit");
  const run = csRun();
  const au = run && run.audit;
  const head = [el("h1", {}, "Audit log"),
    el("p", { class: "view-lead" }, "Every decision of the Countersign run is written to a hash-chained log. Play the intruder below and see what is caught, and by what.")];
  if (!au) {
    return fill(view, head, el("p", { class: "empty" }, "Nothing has been replayed yet. "),
      el("p", {}, el("a", { class: "btn", href: "#stage" }, "Open the Stage and play a scenario")));
  }
  const t = S.tamper;
  const touched = !!t.stage || t.truncated;
  const chain = chainVerdict(au);
  const wit = S.witness ? witnessVerdict(au, S.witness) : null;
  const box = (title, v, extra) => el("section", { class: "verdict-box " + (v ? (v.ok ? "ok" : "bad") : ""), role: "status" },
    el("h2", { class: "h2" }, title), el("p", { class: "v" }, v ? v.text : "NO HEAD SAVED"), el("p", {}, v ? v.detail : ""), extra);
  const stepBtn = (label, name, enabled) => el("button", { type: "button", class: "btn", disabled: !enabled, onclick: guard(() => tamper(name)) }, label);
  return fill(view, head, el("div", { class: "audit-grid" },
    el("div", { class: "verdicts" },
      box("What the chain alone says", chain),
      box("What the saved head says (outside witness)", wit,
        S.witness ? el("p", { class: "note" }, "Outside witness: this browser saved head #" + S.witness.seq + " " + short(S.witness.hash) +
          " at " + S.witness.saved + ", before any tampering. Current head on the server: #" + au.head.seq + " " + short(au.head.hash) + ".") : null)),
    el("p", { class: "fixed-copy" }, "The log is tamper-evident, not tamper-proof. Here the browser plays the outside witness. Real use keeps the head somewhere this machine cannot rewrite."),
    el("section", { class: "panel" }, el("h2", {}, "Intruder console (demo only: edits the log the way an intruder would)"),
      el("div", { class: "row" },
        stepBtn("1. Edit a decision", "edit", !t.stage),
        stepBtn("2. Recompute that entry's hash", "rehash", t.stage === "edit"),
        stepBtn("3. Recompute every later hash", "rechain", t.stage === "edit" || t.stage === "rehash"),
        stepBtn("Drop the last two entries", "truncate", !t.truncated),
        el("button", { type: "button", class: "btn strong", disabled: !touched, onclick: guard(restoreLog) }, "Restore log"),
        el("button", { type: "button", class: "btn", onclick: guard(downloadLog) }, "Download log (JSON Lines)")),
      el("p", { class: "note" }, touched
        ? "Done so far: " + [t.stage === "edit" ? "one decision edited" : t.stage === "rehash" ? "decision edited and its hash recomputed"
          : t.stage === "rechain" ? "decision edited and every later hash recomputed" : null, t.truncated ? "last two entries dropped" : null].filter(Boolean).join("; ") + "."
        : "Nothing has been changed. Stages 1 to 3 run in order; dropping entries can be tried at any time.")),
    el("section", { class: "panel" }, el("h2", {}, "The chain: " + run.mode_label + " run" + (S.lab.scenario ? ", " + S.lab.scenario.id : "")), chainEl(au))));
}

/* ------------------------------------------------------------------ */
/* 9. Live console                                                     */
/* ------------------------------------------------------------------ */

const live = { built: false, state: null, seq: null, polling: false, lost: false, viewer: null, ui: {}, draft: null, draftTimer: 0,
  /* adjust: payee -> { payments, amount } as the person typed them on the confirmation; empty = keep what was read */
  form: { instruction: "", picked: {}, other: "", max_per_payment: "2000.00", max_total: "3000.00", hours: "8", max_payments: "", adjust: {} } };

function liveHoldCtx() {
  const task = live.state && live.state.task;
  return {
    key: "live",
    instruction: task ? task.mandate.instruction : "",
    show: (s) => showSighting(live.viewer, s),
    decide: (id, action, body) => decideHold("/api/live/holds/", id, action, body, {
      attempts: (state) => state.attempts,
      apply: applyLive,
      refresh: async () => { live.seq = null; await pollLive(); },
    }),
  };
}

function applyLive(state) {
  if (state.changed === false) return;
  live.state = state;
  live.seq = state.head ? state.head.seq : null;
  const waiting = holdsOf(state.attempts).filter((a) => a.hold.status === "pending").length;
  document.title = (waiting ? "(" + waiting + ") " + (waiting === 1 ? "hold" : "holds") + " waiting · " : "") + "Countersign";
  keepFocus(() => {
    if (live.built) renderLive();
    if (S.sheet && S.sheet.kind !== "limits" && S.view === "live") S.sheet.render();
  });
  updateInboxCount();
}

async function pollLive() {
  if (live.polling || !$("gate").hidden) return;
  live.polling = true;
  try {
    const task = live.state && live.state.task;
    const ranOut = task && task.active && !task.expired && Date.now() >= Date.parse(task.mandate.expires_at);
    applyLive(await api("/api/live/state" + (live.seq == null || ranOut ? "" : "?after=" + live.seq)));
    if (live.lost) { live.lost = false; if (live.built) renderLive(); }
  } catch (err) {
    if (!live.lost) { live.lost = true; if (live.built) renderLive(); }
  } finally {
    live.polling = false;
  }
}

function enterLive() {
  if (!live.built) {
    live.viewer = createViewer("The agent has not read anything yet.");
    live.ui.status = el("div", { class: "live-status" });
    live.ui.form = el("div", {});
    live.ui.session = el("div", {});
    fill($("view-live"), el("h1", {}, "Live console"),
      el("p", { class: "view-lead" }, "A real session against the shared database: an agent connected through the MCP server asks for payments, and a person decides here. The bank is still simulated."),
      live.ui.status, live.ui.form, live.ui.session);
    live.built = true;
    buildLiveForm();
  }
  renderLive();
}

function livePayees() {
  const f = live.form;
  const typed = f.other.split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
  return [...Object.keys(f.picked).filter((name) => f.picked[name]), ...typed];
}

/** One line of what was read: the field, the words it came from (or "default"), and what it does. */
function readingLine(r, withPayee) {
  return el("li", {}, el("span", { class: "field-label" }, r.field + " "),
    r.quote ? el("span", { class: "mono" }, "\u201c" + r.quote + "\u201d") : el("span", { class: "tag" }, "default"),
    withPayee && r.payee ? " (" + r.payee + ")" : "", ": ", r.result);
}

/** What the person sets for one payee on top of what was read. Only what they type counts.
    `note` is the drafter's line about a default count ({ text, several }), shown right by the box;
    `from` the words a count was read from ({ quote, payments, instalments }), also by the box. */
function adjustRow(payee, ask, note, from) {
  const adj = live.form.adjust[payee] || (live.form.adjust[payee] = { payments: "", amount: "" });
  const mark = el("span", { class: "tag tag-hold" }, "you set this");
  const show = () => { mark.hidden = !(String(adj.payments).trim() || String(adj.amount).trim()); };
  const count = el("input", { type: "text", inputmode: "numeric", size: "4", class: "num", "data-keep": "adjust:" + payee + ":payments",
    placeholder: String(ask.payments || 1), "aria-label": "Payments to expect for " + payee,
    oninput: (e) => { adj.payments = e.target.value; show(); } });
  count.value = adj.payments;
  const amount = el("input", { type: "text", inputmode: "decimal", size: "9", class: "num", "data-keep": "adjust:" + payee + ":amount",
    placeholder: ask.amount ? money(ask.amount) : "not stated", "aria-label": "Most to pay " + payee + " in this task",
    oninput: (e) => { adj.amount = e.target.value; show(); } });
  amount.value = adj.amount;
  show();
  const countNote = note ? el("p", { class: note.several ? "count-note banner hold" : "count-note note", role: note.several ? "note" : null },
    note.several ? el("strong", {}, "Warning: ") : null, note.text) : null;
  return el("div", { class: "adjust" },
    el("div", { class: "adjust-count" },
      el("label", {}, "Expect ", count, " payment(s)"),
      note ? el("span", { class: "tag" }, "1 is the default") : null,
      from ? el("span", { class: "tag" }, from.payments + " read from \u201c" + from.quote + "\u201d" +
        (from.instalments ? ", instalments of one invoice" : "")) : null),
    countNote,
    el("label", {}, "at most " + (S.meta ? S.meta.currency : "EUR") + " ", amount, " in total"),
    mark,
    el("span", { class: "note" }, "Leave empty to keep what was read. A value you type replaces it for " + payee + " only."));
}

function renderDraft() {
  const d = live.draft;
  const payees = livePayees();
  const box = live.ui.draft;
  if (!d) return fill(box, el("span", { class: "muted" }, "As you type, this shows what Countersign read in your sentence. You confirm exactly what is shown here."));
  // Everything the drafter read, per payee with the words it came from, everything it
  // saw and did not use, the vendors named but not included and the accounts it does
  // not trust: the same confirmation as `task start`. The digest goes back with the task.
  const readings = d.readings || [];
  const used = readings.filter((r) => r.used);
  const unused = readings.filter((r) => !r.used);
  const blocks = Object.keys(d.asks || {}).map((payee) => {
    const note = (d.count_notes || {})[payee] || null;
    const from = (d.count_from || {})[payee] || null;
    const excl = (d.excludes || {})[payee] || null;
    /* The default count's line is shown by the count box, and an exclusion as a banner: not twice. */
    const mine = used.filter((r) => r.payee === payee && !(note && r.field === "payments" && !r.quote) &&
      !(excl && r.field === "invoices" && r.quote === excl.quote && r.result === excl.text));
    return el("div", { class: "payee-block" }, el("h4", {}, payee),
      excl ? el("p", { class: "banner hold excluded", role: "note" }, el("strong", {}, "You said: "),
        el("span", { class: "mono" }, "\u201c" + excl.quote + "\u201d"), ". ", excl.text) : null,
      mine.length ? el("ul", { class: "readings" }, mine.map((r) => readingLine(r, false)))
        : el("p", { class: "note" }, note || excl ? "Nothing else read for this payee." : "Nothing read for this payee."),
      adjustRow(payee, d.asks[payee], note, from));
  });
  const other = used.filter((r) => !r.payee || !(r.payee in (d.asks || {})));
  return fill(box,
    el("div", { class: "draft-head" }, el("span", { class: "field-label" }, "What you confirm"),
      el("span", { class: "mono muted", title: "sha256 of this reading of this sentence: " + d.digest }, "draft " + short(d.digest))),
    d.mentioned && d.mentioned.length ? el("p", { class: "banner hold" }, "Named in your sentence but NOT a payee (tick one below only if you mean it): " + d.mentioned.join(", ")) : null,
    payees.length ? null : el("p", { class: "note" }, "No payee yet: tick who may be paid below."),
    blocks,
    other.length ? el("ul", { class: "readings" }, other.map((r) => readingLine(r, true))) : null,
    unused.length ? el("div", {}, el("span", { class: "field-label" }, "Seen in your sentence and not used:"),
      el("ul", { class: "readings note" }, unused.map((r) => readingLine(r, true)))) : null,
    d.unbound && d.unbound.length ? el("p", { class: "note" }, "Accounts in your sentence that are NOT trusted: ",
      el("span", { class: "mono" }, d.unbound.map(groups).join(", ")), ". A payment to one of them will be held.") : null);
}

// Draft again for the payees that are ticked now. The first draft of a sentence
// only suggests payees; what is read for each of them depends on who is ticked.
async function refreshDraft() {
  const f = live.form;
  if (!f.instruction.trim()) { live.draft = null; return renderDraft(); }
  const sent = f.instruction;
  const payees = livePayees();
  const d = await api("/api/live/draft", { instruction: sent, payees });
  if (sent !== f.instruction || payees.join("\n") !== livePayees().join("\n")) return undefined;
  live.draft = d;
  return keepFocus(renderDraft);
}

function buildLiveForm() {
  const f = live.form;
  const ui = live.ui;
  ui.draft = el("div", { class: "draft", "aria-live": "polite" });
  ui.vendors = el("div", { class: "checks" });
  ui.mcp = el("pre", { class: "pre", tabindex: "0" });
  const instruction = bound(f, "instruction", { tag: "textarea", class: "prose", rows: "3", placeholder: "Pay this month's Nimbus Hosting invoice." });
  instruction.addEventListener("input", () => {
    clearTimeout(live.draftTimer);
    live.draftTimer = setTimeout(guard(async () => {
      if (!f.instruction.trim()) { live.draft = null; return renderDraft(); }
      const sent = f.instruction;
      const d = await api("/api/live/draft", { instruction: sent });
      if (sent !== f.instruction) return undefined;
      for (const name of d.payees) if (!(name in f.picked)) f.picked[name] = true;
      renderLiveVendors();
      return refreshDraft();
    }), 300);
  });
  const other = bound(f, "other", { placeholder: "Other payees, separated by commas" });
  other.addEventListener("input", guard(refreshDraft));
  fill(ui.form, el("div", { class: "live-grid" },
    el("section", { class: "panel" }, el("h2", {}, "Start a task"),
      field("What should the agent do?", instruction), ui.draft,
      el("span", { class: "field-label" }, "Payees the agent may pay"), ui.vendors,
      field("Payees not in the vendor file", other),
      el("div", { class: "row" },
        field("Per-payment limit", bound(f, "max_per_payment", { inputmode: "decimal", size: "9" })),
        field("Task budget", bound(f, "max_total", { inputmode: "decimal", size: "9" })),
        field("Valid for (hours)", bound(f, "hours", { inputmode: "numeric", size: "4" })),
        field("Payments for the whole task (optional)", bound(f, "max_payments", { inputmode: "numeric", size: "5" }))),
      el("button", { type: "button", class: "btn primary", onclick: guard(startLiveTask) }, "Confirm the mandate and start the task")),
    el("section", { class: "panel" }, el("h2", {}, "Connect an agent"),
      el("p", {}, "Paste this MCP configuration into the agent. Its tools are: ", el("span", { class: "mono" }, S.meta.agent_tools.join(", ")),
        ". It has no approve tool."),
      ui.mcp,
      el("button", { type: "button", class: "btn", onclick: guard(async () => {
        await navigator.clipboard.writeText(ui.mcp.textContent);
        toast("Configuration copied.");
      }) }, "Copy"))));
  renderDraft();
}

function renderLiveVendors() {
  const f = live.form;
  const vendors = (live.state && live.state.vendors) || S.meta.vendors;
  fill(live.ui.vendors, vendors.map((v) => el("label", {},
    el("input", { type: "checkbox", checked: !!f.picked[v.name], onchange: guard(async (e) => { f.picked[v.name] = e.target.checked; await refreshDraft(); }) }),
    " " + v.name + " ", el("span", { class: "mono muted" }, v.accounts.map(mask).join(", ")))));
}

async function startLiveTask() {
  const f = live.form;
  const hours = Number(String(f.hours).trim());
  if (!String(f.hours).trim() || !(hours > 0)) throw new Error("Hours must be a number more than 0.");
  const count = String(f.max_payments).trim();
  if (count && !/^[1-9]\d*$/.test(count)) throw new Error("The payment count must be a whole number of 1 or more, or empty.");
  const payees = livePayees();
  if (!f.instruction.trim()) throw new Error("Type what the agent should do first.");
  // The task confirms the draft that is on the screen. If reading the sentence for
  // these payees now gives another draft, it is shown and nothing starts: the person
  // confirms again. The server drafts once more and refuses a digest that differs.
  const shown = live.draft;
  const fresh = await api("/api/live/draft", { instruction: f.instruction, payees });
  if (!shown || fresh.digest !== shown.digest) {
    live.draft = fresh;
    renderDraft();
    throw new Error("What Countersign read changed since it was shown. Check it, then confirm again.");
  }
  const adjust = {};
  for (const payee of payees) {
    const a = f.adjust[payee];
    if (!a) continue;
    const n = String(a.payments).trim();
    const m = String(a.amount).trim();
    if (!n && !m) continue;
    if (n && !/^[1-9]\d*$/.test(n)) throw new Error("The number of payments for " + payee + " must be a whole number of 1 or more.");
    if (m && !MONEY.test(m)) throw new Error("The amount for " + payee + " must be a plain amount such as 650.00.");
    adjust[payee] = { payments: n ? Number(n) : null, amount: m || null };
  }
  const state = await api("/api/live/tasks", {
    instruction: f.instruction, payees, max_per_payment: f.max_per_payment.trim(), max_total: f.max_total.trim(),
    hours, max_payments: count ? Number(count) : null,
    references: [], accounts: {}, draft_digest: shown.digest, adjust,
  });
  f.adjust = {};
  S.lastApproval = null;
  applyLive(state);
}

function attemptRow(a, ctxFor) {
  const st = pillStatus(a);
  const badge = st.cls === "paid" ? "allow" : st.cls === "held" || st.cls === "joined" ? "hold" : "block";
  /* The rule's title for a refusal ("Already paid in this task"); a repeat says which hold it joined. */
  const why = a.repeat ? "Asked again while " + a.hold.id + " waited: it joined that hold" +
      (a.hold.status === "pending" ? ", which still waits" : ", which is now " + a.hold.status)
    : a.status === "blocked" && a.rule_title ? a.rule_title : "";
  return el("button", { type: "button", class: "attempt-row", onclick: (ev) => openLiveEvidence(a.index, ev.currentTarget, ctxFor) },
    el("span", { class: "mono" }, "#" + (a.index + 1)),
    el("span", {}, el("strong", {}, a.payee), "  ", el("span", { class: "num" }, eur(a.amount))),
    el("span", { class: "badge " + badge },
      !a.repeat && a.status === "held" && a.rules && a.rules.length ? "HELD " + a.rules.join(" ") : st.label),
    el("span", { class: "sub" }, el("span", { class: "mono" }, groups(a.account)), "  reference " + a.reference,
      why ? el("span", { class: "why" }, why) : null));
}

function openLiveEvidence(index, opener) {
  openSheet("evidence", "Evidence: payment " + (index + 1), () => {
    const a = live.state && live.state.attempts.find((x) => x.index === index);
    if (!a) return closeSheet();
    return fill($("sheet-body"), evidenceNodes(a, { guardLabel: live.state.guard_mode, show: (s) => showSighting(live.viewer, s) }));
  }, opener);
}

function renderLive() {
  const st = live.state;
  const ui = live.ui;
  if (!st) return fill(ui.status, el("span", { class: "empty" }, live.lost ? "The server is not answering." : "Connecting…"));
  const task = st.task;
  const active = !!(task && task.active && !task.expired);
  const au = st.audit || { intact: true, entries: [] };
  fill(ui.status,
    el("span", { class: "tag " + (active ? "tag-allow" : "") }, active ? "task active" : task ? (task.expired ? "task expired" : "task ended") : "no task"),
    el("span", {}, "Guard: ", el("b", {}, st.guard_mode)),
    el("span", {}, "Audit head: ", el("span", { class: "mono" }, "#" + st.head.seq + " " + short(st.head.hash))),
    el("span", { class: au.intact ? "" : "error" }, au.intact ? "chain verifies" : "TAMPERING DETECTED at entry " + au.broken_at),
    task && task.quarantine ? el("span", { class: "tag tag-block", title: task.quarantine.text }, "task quarantined") : null,
    el("span", {}, "Simulated balance: ", el("b", { class: "num" }, eur(st.balance))),
    live.lost ? el("span", { class: "error" }, "Connection lost. Retrying every second.") : el("span", { class: "muted" }, "Checked every second."),
    active ? el("button", { type: "button", class: "btn strong", onclick: guard(async () => applyLive(await api("/api/live/tasks/end", {}))) }, "End task") : null);
  ui.form.hidden = active;
  if (!active) {
    renderLiveVendors();
    ui.mcp.textContent = JSON.stringify(st.mcp_config, null, 2);
  }
  if (!task) return fill(ui.session);
  const m = task.mandate;
  const source = { attempts: st.attempts, ctx: liveHoldCtx(), where: "live session", quarantines: [] };
  const pending = holdsOf(st.attempts).filter((a) => a.hold.status === "pending");
  live.viewer.set(st.documents, m.payees);
  return fill(ui.session, task.quarantine ? quarantineBanner(task.quarantine) : null, el("div", { class: "live-grid" },
    el("div", { class: "live-col" },
      el("section", { class: "panel" }, el("h2", {}, "The mandate you confirmed (trusted)"),
        el("p", { class: "quote" }, "“" + m.instruction + "”"),
        el("div", { class: "chips" }, mandateChips(m)),
        el("p", { class: "note" }, "Paid so far: " + eur(task.spent) + " in " + plural(task.payments, "payment") + ".")),
      el("section", { class: "panel docs" }, el("h2", {}, "What the agent has read (untrusted)"), live.viewer.root)),
    el("div", { class: "live-col" },
      el("section", { class: "panel" }, el("h2", {}, "Countersign inbox (" + pending.length + " waiting)"), inboxNodes(source)),
      el("section", { class: "panel" }, el("h2", {}, "Payments the agent asked for"),
        st.attempts.length ? st.attempts.map((a) => attemptRow(a)) : el("p", { class: "empty" }, "None yet."),
        el("p", { class: "note" }, "Click a payment for its evidence.")),
      el("section", { class: "panel" }, el("h2", {}, "Ledger (simulated bank)"),
        st.transfers.length ? el("div", { class: "table-wrap" }, el("table", { class: "ledger" },
          el("thead", {}, el("tr", {}, ["Id", "Payee", "Account", "Amount", "Reference"].map((h) => el("th", { scope: "col" }, h)))),
          el("tbody", {}, st.transfers.map((t) => el("tr", {}, el("td", { class: "mono" }, t.id), el("td", {}, t.payee),
            el("td", { class: "mono" }, mask(t.account)), el("td", { class: "num" }, money(t.amount)), el("td", {}, t.reference))))))
          : el("p", { class: "empty" }, "No transfers.")),
      el("section", { class: "panel" }, el("h2", {}, "Activity log: the audit log (" + plural(au.entries.length, "entry", "entries") + ")"),
        el("p", { class: "note" }, "Highlighted: an account typed back that did not match, a task that stopped paying without a person, an account taken off the vendor file."),
        chainEl(au)))));
}

/* ------------------------------------------------------------------ */
/* 10. Boot                                                            */
/* ------------------------------------------------------------------ */

async function boot() {
  readToken();
  initTheme();
  /* Pasting the terminal link into a tab that already shows this page only changes the hash. */
  window.addEventListener("hashchange", () => {
    if (/(?:^#|&)token=/.test(location.hash)) { readToken(); location.reload(); }
  });
  $("sheet-close").addEventListener("click", closeSheet);
  /* The top bar can wrap on narrow screens; the Stage and the sheet sit below its real height. */
  const fitTop = () => document.documentElement.style.setProperty("--top", $("top").offsetHeight + "px");
  new ResizeObserver(fitTop).observe($("top"));
  if (!S.token) return showGate();
  S.meta = await api("/api/meta");
  $("version").textContent = "v" + S.meta.version;
  $("btn-inbox").addEventListener("click", openInbox);
  $("btn-limits").addEventListener("click", openLimits);
  document.addEventListener("keydown", onKey);
  window.addEventListener("hashchange", route);
  const lab = await api("/api/lab");
  S.lab = { scenario: lab.scenario || null, runs: lab.runs || {} };
  restoreWitness();
  stage.pos = Number.MAX_SAFE_INTEGER; /* a lab that already exists is shown as replayed */
  if (S.meta.live) {
    await pollLive();
    setInterval(pollLive, 1000);
  }
  route();
  return undefined;
}

boot().catch((err) => {
  if (err.status !== 401) toast(err.message || String(err));
});
