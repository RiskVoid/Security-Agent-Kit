// RiskVoid Console front end. Plain JS, no build step. Text that comes from the agent (findings, commands, notes)
// is untrusted: it only ever reaches the page through esc() or textContent.
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const enc = encodeURIComponent;
const SEV = ["critical", "high", "medium", "low", "info"];
const STATUSES = ["candidate", "confirmed", "false-positive", "duplicate", "fixed", "accepted-risk"];
const METHODS = ["runtime-reproduction", "replay", "authorization-matrix", "source-review", "tool-output", "retest", "client-confirmation"];
const PRIORITIES = ["P1", "P2", "P3", "P4"];
const COVERAGE = ["planned", "tested", "failed", "blocked", "excluded", "not-applicable"];
const COV_CLASS = { tested: "ok", failed: "sev-critical", blocked: "warn", planned: "", excluded: "", "not-applicable": "" };
const PLAYBOOKS = ["web-app", "api-security", "laravel", "code-review", "secrets-review", "supply-chain", "ai-llm", "external-network"];
const TABS = { overview: "Overview", live: "Live", scope: "Scope & rules", investigation: "Investigation", findings: "Findings", tasks: "Worker tasks", testing: "Testing", report: "Report", audit: "Audit log", models: "Model log" };

const state = { overview: null, current: null, detail: null, tab: "overview", seenApprovals: null, seenNotices: null, obsFilter: "new", findingFilter: "all", openFinding: null, preview: null, evidence: null, view: "engagements" };

async function api(path, body) {
  const opt = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json", "X-RV-Console": "1" }, body: JSON.stringify(body) };
  const r = await fetch(path, opt);
  let data = {};
  try { data = await r.json(); } catch { /* non-JSON error page */ }
  if (!r.ok || (data && data.error)) {
    const e = new Error(data.error || `${r.status} ${r.statusText}`);
    e.status = r.status;
    throw e;
  }
  if (data && data.warning) toast(data.warning, true);
  return data;
}

function toast(msg, bad = false) {
  const t = $("#toast");
  t.textContent = msg; t.className = "rv-toast" + (bad ? " bad" : ""); t.hidden = false;
  t.setAttribute("role", bad ? "alert" : "status");
  clearTimeout(toast.timer); toast.timer = setTimeout(() => { t.hidden = true; }, bad ? 8000 : 3500);
}

async function act(btn, fn, okMsg) {
  if (btn) btn.disabled = true;
  try { const r = await fn(); if (okMsg) toast(okMsg); return r; }
  catch (e) {
    if (e.status === 409) return conflict(e);
    toast(e.message, true);
  }
  finally { if (btn) btn.disabled = false; }
}

// Someone else (the agent, ./rvkit, another tab) changed the record since this page loaded it. Keep what the user typed
// on screen, take the new revisions so a second save is a deliberate overwrite, and make scope changes preview again.
async function conflict(e) {
  const what = e.message.replace(/[:.]?\s*reload\b.*$/i, "");
  toast(`${what}. Your edit is still on screen; saving again replaces the other change.`, true);
  if (!state.current) return;
  try {
    const fresh = await api(`/api/eng/${enc(state.current)}`);
    const d = state.detail;
    if (!d || d.engagement !== fresh.engagement) return;
    d.info = fresh.info; d.findings = fresh.findings; d.meta_digest = fresh.meta_digest; d.summary_digest = fresh.summary_digest;
    if (state.tab === "findings" && state.openFinding) {  // show the saved version next to the user's edit
      const keep = { status: $("#fe-status")?.value, severity: $("#fe-sev")?.value, notes: $("#fe-notes")?.value, dup: $("#fe-dup")?.value };
      paneFindings();
      if ($("#fe-status")) { $("#fe-status").value = keep.status; $("#fe-sev").value = keep.severity; $("#fe-notes").value = keep.notes; if ($("#fe-dup")) $("#fe-dup").value = keep.dup || ""; }
      const f = d.findings.find((x) => x.id === state.openFinding);
      if (f && $(".rv-editor")) $(".rv-editor").insertAdjacentHTML("afterbegin", `<div class="rv-banner warn"><div class="rv-banner-body">
        <p class="rv-banner-title">Saved meanwhile${f.updated_by ? " by " + esc(f.updated_by) : ""} (revision ${esc(f.revision)})</p>
        <p class="rv-banner-sub">Status ${esc(f.status)}, severity ${esc(f.severity)}${f.notes ? `, notes: ${esc(f.notes)}` : ""}. Your edit is below; Save replaces that version.</p></div></div>`);
    }
    if (state.tab === "scope") {
      state.preview = null;
      const a = $("#apply-btn"), o = $("#preview-out");
      if (a) a.disabled = true;
      if (o) o.innerHTML = `<div class="rv-banner warn"><div class="rv-banner-body"><p class="rv-banner-title">The active scope changed</p><p class="rv-banner-sub">Preview again to see your edit against the current scope, then apply.</p></div></div>`;
    }
  } catch { /* the toast already says what happened */ }
}

const TIER_CLASS = { passive: "passive", active: "active-tier", intrusive: "intrusive" };
const tag = (text, cls = "") => `<span class="rv-tag ${cls}">${esc(text)}</span>`;
const tierTags = (tiers) => (tiers || []).map((t) => tag(t, TIER_CLASS[t] || "")).join(" ");
const sevTag = (s) => tag(s, "sev-" + s);
const codeChips = (list) => list.length ? `<div class="rv-chips">${list.map((t) => `<span class="rv-code-chip">${esc(t)}</span>`).join("")}</div>` : `<span class="rv-dim">none</span>`;
const fmtTime = (v) => { if (!v) return ""; const d = typeof v === "number" ? new Date(v * 1000) : new Date(v); return isNaN(d) ? esc(v) : d.toLocaleString(); };
const ICON_COPY = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;

function engState(e) {
  if (!e) return ["active", "c-ok", "live"];
  if (e.closed) return ["closed", "c-info", ""];
  if (e.halted) return ["halted", "c-critical", "halted"];
  return ["active", "c-ok", "live"];
}

// ---------------------------------------------------------------- routing
function crumbs(parts) {
  $("#crumbs").innerHTML = parts.map((p, i) => (i ? `<span class="sep">/</span>` : "") +
    (i === parts.length - 1 ? `<strong>${esc(p[0])}</strong>` : p[1] ? `<a href="${p[1]}">${esc(p[0])}</a>` : `<span>${esc(p[0])}</span>`)).join("");
}
function show(view) {
  state.view = view;
  for (const v of ["engagements", "approvals", "status", "models"]) $(`#view-${v}`).hidden = v !== view;
  $$(".rv-sidebar-item[data-view]").forEach((a) => a.classList.toggle("active", a.dataset.view === view));
  document.body.classList.remove("nav-open");
  if (stream.es) connectStream();  // the live topic only while an engagement's Live tab shows
  if (view === "status") { crumbs([["Console", "#engagements"], ["Stack status"]]); loadStatus(); }
  else if (view === "models") { crumbs([["Console", "#engagements"], ["Model log"]]); loadModels(); }
  else if (view === "approvals") crumbs([["Console", "#engagements"], ["Approvals"]]);
  else crumbs(state.current ? [["Console", "#engagements"], ["Engagements", "#engagements"], [state.current]] : [["Console", "#engagements"], ["Engagements"]]);
}
function route() {
  const h = location.hash.replace("#", "");
  if (h === "approvals" || h === "status" || h === "models") return show(h);
  if (h.startsWith("eng-")) { const name = h.slice(4); if (name !== state.current) { state.current = name; openEngagement(name); } }
  show("engagements");
}
window.addEventListener("hashchange", route);
$("#menu-btn").addEventListener("click", () => document.body.classList.toggle("nav-open"));

// ---------------------------------------------------------------- live updates
// The console pushes changes over server-sent events (/api/stream): the overview always, and the open engagement's
// live view while its Live tab is showing. If the stream drops, the page polls until it comes back.
const stream = { es: null, key: null, last: 0 };
const streamFresh = () => stream.es && stream.es.readyState === 1 && Date.now() - stream.last < 20000;
function connectStream() {
  const key = state.view === "engagements" && state.tab === "live" && state.current ? state.current : "";
  if (stream.es && stream.key === key && stream.es.readyState !== 2) return;
  if (stream.es) stream.es.close();
  stream.key = key; stream.last = 0;
  const es = (stream.es = new EventSource("/api/stream" + (key ? "?eng=" + enc(key) : "")));
  const seen = () => { stream.last = Date.now(); };
  es.addEventListener("open", seen);
  es.addEventListener("overview", (e) => { seen(); applyOverview(JSON.parse(e.data)); });
  es.addEventListener("live", (e) => { seen(); const d = JSON.parse(e.data); state.live = d; if (state.onLive) state.onLive(d); });
  es.addEventListener("problem", (e) => { seen(); const d = JSON.parse(e.data); if (d.topic === "overview") showOverviewError(d.error); else if (state.onLive) state.onLive(d); });
}

// ---------------------------------------------------------------- overview + approvals
async function refresh() {
  try { applyOverview(await api("/api/overview")); } catch (e) { showOverviewError(e.message); }
}
function showOverviewError(msg) { $("#eng-list").innerHTML = `<div class="rv-empty err">${esc(msg)}</div>`; }
function applyOverview(o) {
  {
    state.overview = o;
    $("#agent-ui").href = o.ui_url;
    if (o.version) $("#side-version").textContent = "kit " + o.version;
    $("#eng-count").textContent = o.engagements.length || "";
    renderList(); renderApprovals();
    const mb = $("#model-badge"); mb.textContent = o.model_problems || 0; mb.hidden = !o.model_problems;
    mb.title = "failed model calls in the last 24 hours";
    const ids = new Set(o.approvals.map((a) => a.id));
    if (state.seenApprovals) {
      const fresh = o.approvals.filter((a) => !state.seenApprovals.has(a.id));
      if (fresh.length) notify(fresh);
    }
    state.seenApprovals = ids;
    const notices = new Set(o.engagements.flatMap((e) => (e.notices || []).map((n) => e.engagement + "|" + n)));
    if (state.seenNotices) {
      const fresh = [...notices].filter((n) => !state.seenNotices.has(n));
      if (fresh.length) notifyNotices(fresh);
    }
    state.seenNotices = notices;
    const b = $("#appr-badge"); b.textContent = o.approvals.length; b.hidden = !o.approvals.length;
    document.title = (o.approvals.length ? `(${o.approvals.length}) ` : "") + "RiskVoid Console";
  }
}

function notify(fresh) {
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  for (const a of fresh.slice(0, 3)) new Notification("RiskVoid: approval needed", { body: `${a.engagement}: ${a.command.slice(0, 100)}` });
}

const TASK_WORDS = { done: "worker task finished", error: "worker task failed", interrupted: "worker task interrupted", blocked: "worker task blocked", awaiting_approval: "worker task waits for an approval" };
function notifyNotices(fresh) {
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  for (const n of fresh.slice(0, 3)) {
    const [eng, kind, id, st, sev] = n.split(/[|:]/);
    const body = kind === "finding" ? `${eng}: ${id} is ${st} (${sev})` : `${eng}: ${TASK_WORDS[st] || st} (${id})`;
    new Notification(kind === "finding" ? "RiskVoid: material finding" : "RiskVoid: worker task", { body });
  }
}

function renderList() {
  const q = $("#eng-filter").value.trim().toLowerCase();
  const rows = (state.overview?.engagements || []).filter((e) => !q || e.engagement.toLowerCase().includes(q) || (e.client || "").toLowerCase().includes(q));
  $("#eng-list").innerHTML = rows.map((e) => {
    const f = e.findings || {};
    const [label, color] = engState(e);
    const meta = [e.client || label, `${f.confirmed || 0} confirmed`, f.candidate ? `${f.candidate} to triage` : ""].filter(Boolean)
      .map(esc).join(`<span class="slash">/</span>`);
    return `<button role="listitem" class="rv-row ${e.engagement === state.current ? "selected" : ""}" data-eng="${esc(e.engagement)}">
      <span class="ind ${color}" title="${label}"></span>
      <span style="min-width:0"><div class="title">${esc(e.engagement)}</div><div class="meta">${meta}</div></span>
      ${e.pending ? `<span class="rv-count danger" title="pending approvals">${e.pending}</span>` : e.closed ? tag("closed") : e.halted ? tag("halted", "halted") : ""}
    </button>`;
  }).join("") || `<div class="rv-empty">${q ? "No match." : "No engagements yet."}</div>`;
}
$("#eng-list").addEventListener("click", (ev) => { const b = ev.target.closest("[data-eng]"); if (b) location.hash = "eng-" + b.dataset.eng; });
$("#eng-filter").addEventListener("input", renderList);

function approvalCard(a, withEng) {
  return `<div class="rv-card rv-approval"><div class="rv-card-body">
    <div class="rv-meta">${withEng ? `<a href="#eng-${esc(a.engagement)}">${esc(a.engagement)}</a>` : ""}${tag(a.tier, TIER_CLASS[a.tier] || "intrusive")}
      <span>id ${esc(a.id)}</span><span>${fmtTime(a.created)}</span></div>
    <pre class="rv-pre">${esc(a.command)}</pre>
    ${approvalBinding(a)}
    <div class="rv-actions">
      <button class="rv-btn ghost" data-deny="${esc(a.engagement)}/${esc(a.id)}">Deny</button>
      <button class="rv-btn accent" data-approve="${esc(a.engagement)}/${esc(a.id)}">Approve ${a.kind === "http" ? "this request" : "this command"}</button>
    </div></div></div>`;
}
function approvalBinding(a) {
  // What the approval covers: a later change to any of these needs a new approval.
  const act = a.action || {}, bits = [];
  if (a.policy_version) bits.push(`scope and rules revision ${esc(a.policy_version)}`);
  const exes = Object.keys(act.executables || {});
  if (exes.length) bits.push(`programs ${exes.map((x) => `<code>${esc(x)}</code>`).join(", ")}`);
  const inputs = Object.keys(act.inputs || {});
  if (inputs.length) bits.push(`files ${inputs.slice(0, 6).map((x) => `<code>${esc(x)}</code>`).join(", ")}${inputs.length > 6 ? ` +${inputs.length - 6}` : ""}`);
  if (act.kind === "http" && Object.keys(act.headers || {}).length) bits.push(`headers ${Object.keys(act.headers).map((x) => `<code>${esc(x)}</code>`).join(", ")}`);
  if (a.task) bits.push(`worker task ${esc(a.task)}`);
  return bits.length ? `<p class="hint">Bound to ${bits.join("; ")}.</p>` : "";
}
function renderApprovals() {
  const list = state.overview?.approvals || [];
  $("#appr-all").innerHTML = list.length ? list.map((a) => approvalCard(a, true)).join("")
    : `<div class="rv-card"><div class="rv-empty">Nothing is waiting for approval.</div></div>`;
}
document.addEventListener("click", async (ev) => {
  const b = ev.target.closest("[data-approve],[data-deny]");
  if (!b) return;
  const approve = b.hasAttribute("data-approve");
  const [eng, id] = (b.dataset.approve || b.dataset.deny).split("/");
  await act(b, () => api(`/api/approvals/${enc(eng)}/${id}/${approve ? "approve" : "deny"}`, {}),
    approve ? "Approved. Tell the agent to run the command again." : "Denied.");
  await refresh();
  if (state.current === eng) await openEngagement(eng, true);
});
$("#notify-btn").addEventListener("click", async () => {
  if (!("Notification" in window)) return toast("This browser has no desktop notifications.", true);
  const p = await Notification.requestPermission();
  toast(p === "granted" ? "Desktop notifications on for new approvals (while this page is open)." : "Notifications not allowed.", p !== "granted");
});

// ---------------------------------------------------------------- engagement detail
async function openEngagement(name, keepTab) {
  state.current = name; if (!keepTab) { state.tab = "overview"; state.openFinding = null; state.preview = null; state.evidence = null; }
  renderList(); if (state.view === "engagements") show("engagements");
  if (!keepTab) $("#detail").innerHTML = `<div class="rv-empty">Loading ${esc(name)}…</div>`;
  try { state.detail = await api(`/api/eng/${enc(name)}`); renderDetail(); }
  catch (e) { $("#detail").innerHTML = `<div class="rv-empty err">${esc(e.message)}</div>`; }
}

function renderDetail() {
  const d = state.detail, i = d.info, r = i.rules;
  const ov = (state.overview?.engagements || []).find((e) => e.engagement === d.engagement) || {};
  const [label, , cls] = engState({ ...ov, halted: i.halted });
  const counts = { findings: d.findings.length };
  if (ov.model_problems) counts.models = ov.model_problems;
  $("#detail").innerHTML = `
    <div class="rv-detail-head">
      <div class="rv-detail-title"><h1 class="rv-h-display">${esc(d.engagement)}</h1>${tag(label, cls)} ${tierTags(r.tiers)}</div>
      <div class="rv-meta"><span>${esc(d.meta.client || "No client name yet")}</span><span>${esc(r.network)}</span><span>max ${esc(r.max_rate)}/s</span>${r.worker === "private" ? "<span>private worker</span>" : ""}</div>
      <div class="rv-detail-actions">
        ${i.halted ? `<button id="resume-btn" class="rv-btn">Resume</button>` : `<button id="halt-btn" class="rv-btn danger">Halt now</button>`}
        <button id="close-btn" class="rv-btn">Close out…</button>
        <button id="delete-btn" class="rv-btn ghost danger-quiet">Delete…</button>
      </div>
      <div id="confirm-slot"></div>
    </div>
    <div class="rv-tabs" role="tablist" aria-label="Engagement sections">
      ${Object.entries(TABS).map(([t, name]) => `<button role="tab" id="tab-${t}" aria-controls="pane" aria-selected="${state.tab === t}" tabindex="${state.tab === t ? 0 : -1}" data-tab="${t}" class="rv-tab ${state.tab === t ? "active" : ""}">${name}${counts[t] !== undefined ? ` <span class="n">${counts[t]}</span>` : ""}</button>`).join("")}
    </div>
    <div id="pane" class="rv-pane" role="tabpanel" aria-labelledby="tab-${state.tab}" tabindex="-1"></div>`;
  $$(".rv-tab").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.tab; renderDetail(); }));
  // keyboard: arrow keys, Home and End move between tabs (WAI-ARIA tabs pattern)
  $(".rv-tabs").addEventListener("keydown", (ev) => {
    const keys = Object.keys(TABS), i = keys.indexOf(state.tab);
    const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: keys.length - 1 }[ev.key];
    if (next === undefined) return;
    ev.preventDefault();
    state.tab = keys[(next + keys.length) % keys.length]; renderDetail();
    $(`#tab-${state.tab}`).focus();
  });
  connectStream();
  $("#halt-btn")?.addEventListener("click", (ev) => lifecycle(ev.currentTarget, "halt", "Halted: running commands were killed."));
  $("#resume-btn")?.addEventListener("click", (ev) => lifecycle(ev.currentTarget, "resume", "Resumed."));
  $("#close-btn").addEventListener("click", () => confirmBox("Close out " + d.engagement + "?",
    "Writes the audit extract and a SHA-256 manifest, archives the folder to _archive/, and halts the engagement. You can resume it later for a retest.",
    "Close out", (btn) => lifecycle(btn, "close", "Closed and archived.")));
  $("#delete-btn").addEventListener("click", () => confirmBox("Delete " + d.engagement + "?",
    ov.closed ? "Removes its scope, rules, approvals and firewall rules and frees its slot. The folder is kept, renamed to _deleted-…; archives and the audit history stay."
      : "This engagement isn't closed, so there's no archive or manifest. Close it first unless it's a practice engagement. The folder is kept, renamed to _deleted-….",
    ov.closed ? "Delete" : "Delete without closing", async (btn) => {
      await act(btn, () => api(`/api/eng/${enc(d.engagement)}/delete`, { force: !ov.closed }), "Deleted.");
      state.current = null; location.hash = "engagements"; $("#detail").innerHTML = `<div class="rv-empty">Pick an engagement, or create one.</div>`; refresh(); show("engagements");
    }));
  ({ overview: paneOverview, live: paneLive, scope: paneScope, investigation: paneInvestigation, findings: paneFindings, tasks: paneTasks, testing: paneTesting, report: paneReport, audit: paneAudit, models: paneModels })[state.tab]();
}

function confirmBox(title, text, label, fn) {
  $("#confirm-slot").innerHTML = `<div class="rv-banner danger"><div class="rv-banner-body">
    <p class="rv-banner-title">${esc(title)}</p><p class="rv-banner-sub">${esc(text)}</p>
    <div class="rv-actions start" style="margin-top:8px"><button id="cf-yes" class="rv-btn danger">${esc(label)}</button><button id="cf-no" class="rv-btn ghost">Cancel</button></div></div></div>`;
  const close = () => { $("#confirm-slot").innerHTML = ""; $("#delete-btn")?.focus(); };
  $("#cf-no").addEventListener("click", close);
  $("#cf-yes").addEventListener("click", (ev) => fn(ev.currentTarget));
  $("#confirm-slot").addEventListener("keydown", (ev) => { if (ev.key === "Escape") close(); });
  $("#cf-no").focus();  // the safe choice has focus; Escape cancels
}

async function lifecycle(btn, action, msg) {
  const name = state.current;
  const r = await act(btn, () => api(`/api/eng/${enc(name)}/${action}`, {}), msg);
  if (r) { await refresh(); await openEngagement(name, true); }
}

function paneOverview() {
  const d = state.detail, i = d.info, sc = i.scope, c = {};
  d.findings.forEach((f) => { c[f.status] = (c[f.status] || 0) + 1; });
  const conf = d.findings.filter((f) => f.status === "confirmed");
  const n = Object.fromEntries(SEV.map((s) => [s, conf.filter((f) => f.severity === s).length]));
  const total = conf.length;
  const prompt = `Engagement \`${d.engagement}\`: <what to test>. Follow the matching playbooks, then write the executive summary and generate the report.`;
  const kpi = (label, value, color, delta) => `<div class="rv-kpi"><span class="rv-label">${color ? `<span class="rv-dot ${color}"></span>` : ""}${label}</span><span class="rv-value">${value}</span><span class="rv-delta">${delta}</span></div>`;
  $("#pane").innerHTML = `
    ${d.approvals.length ? `<div class="rv-stack"><span class="rv-label">Waiting for your approval</span>${d.approvals.map((a) => approvalCard(a, false)).join("")}</div>` : ""}
    <div class="rv-stack">
      <div class="rv-kpi-grid">
        ${kpi("Critical", n.critical, "c-critical", "open, confirmed")}
        ${kpi("High", n.high, "c-high", "open, confirmed")}
        ${kpi("Medium", n.medium, "c-medium", "open, confirmed")}
        ${kpi("Low / info", n.low + n.info, "c-low", "open, confirmed")}
        ${kpi("To triage", c.candidate || 0, "", `${c["false-positive"] || 0} false positive · ${c.duplicate || 0} duplicate`)}
      </div>
      ${total ? `<div class="rv-sev-bar" aria-label="Confirmed findings by severity">${SEV.map((s) => n[s] ? `<span style="width:${(100 * n[s] / total).toFixed(1)}%;background:var(--rv-sev-${s})"></span>` : "").join("")}</div>` : ""}
    </div>
    <div class="rv-two">
      <div class="rv-card"><div class="rv-card-head"><h3>Scope and rules</h3><button class="rv-btn ghost sm" data-goto="scope">Edit</button></div>
        <div class="rv-card-body"><dl class="rv-kv">
          <dt>Targets</dt><dd>${codeChips([...sc.nets, ...sc.domains, ...sc.paths])}</dd>
          <dt>Tiers</dt><dd>${tierTags(i.rules.tiers)}${i.rules.strict ? " " + tag("strict", "warn") : ""}</dd>
          <dt>Rate</dt><dd>${esc(i.rules.max_rate)} per second</dd>
          <dt>Network</dt><dd>${esc(i.rules.network)}</dd>
          <dt>Window</dt><dd>${i.rules.window ? esc(i.rules.window.join(":")) + " UTC" : "any time"}</dd>
          <dt>Worker</dt><dd>${i.rules.worker === "private" ? "private: never the fallback model" : "fallback allowed when switched on"}</dd>
          <dt>Client data</dt><dd>${i.rules.client_data ? esc(i.rules.client_data.join(", ")) : "any configured model"}</dd>
        </dl></div></div>
      ${modelsCard(d)}
    </div>
    <div class="rv-two">
      ${conversationsCard(d)}
      ${credentialsCard(d)}
    </div>`;
  bindConversations(d, prompt);
  bindCredentials(d);
  $$("[data-goto]").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.goto; renderDetail(); }));
}

// ---------------------------------------------------------------- models, conversations, credentials (RW-006/7)
const DEST = { local: "this machine or network", colab: "Colab notebook", api: "self-hosted endpoint", openrouter: "OpenRouter", anthropic: "Anthropic", openai: "OpenAI" };
function destTag(dest, allowed) {
  const ok = !allowed || allowed.includes(dest);
  return tag(DEST[dest] || dest, ok ? "" : "warn") + (ok ? "" : ` <span class="err">not allowed for this engagement's client data</span>`);
}
function modelsCard(d) {
  const m = d.models || {}, allowed = d.info.rules.client_data, w = m.worker || {}, p = m.planner || {}, fb = m.worker_fallback || {};
  return `<div class="rv-card"><div class="rv-card-head"><h3>Models</h3></div><div class="rv-card-body"><dl class="rv-kv">
    <dt>Worker</dt><dd>${destTag(w.destination, allowed)}<div class="rv-dim">${esc(w.model || "")}${w.host ? " at " + esc(w.host) : ""}</div></dd>
    <dt>Fallback</dt><dd>${fb.on ? destTag(fb.destination, allowed) + `<div class="rv-dim">${esc(fb.model)} while the worker is down${allowed && !allowed.includes(fb.destination) ? " (not used for this engagement)" : ""}</div>` : "off"}</dd>
    <dt>Planner</dt><dd>${destTag(p.destination, allowed)}<div class="rv-dim">${esc(p.model || "")}</div></dd>
  </dl><p class="hint">Model calls that would send this engagement's data somewhere its rules don't allow are refused at the model gateway.</p></div></div>`;
}
function conversationsCard(d) {
  const cs = d.conversations, err = cs && !Array.isArray(cs) ? cs.error : null, rows = Array.isArray(cs) ? cs : [];
  return `<div class="rv-card"><div class="rv-card-head"><h3>Conversations</h3><a class="rv-btn ghost sm" href="${esc(state.overview?.ui_url || "#")}" target="_blank" rel="noopener">Open agent UI ↗</a></div>
    <div class="rv-card-body">
      ${err ? `<p class="err">${esc(err)}</p>` : ""}
      ${rows.length ? `<ul class="rv-rows">${rows.map((c) => `<li><a href="${esc(c.url)}" target="_blank" rel="noopener">${esc(c.title || c.id)}</a> ${c.status ? tag(c.status, c.status === "running" ? "running" : "") : ""}
        <span class="rv-dim">${esc(c.id.slice(0, 8))} · ${fmtTime(c.bound)}</span> <button class="rv-btn ghost sm" data-unbind="${esc(c.id)}">Unbind</button></li>`).join("")}</ul>`
        : `<p class="hint">No conversation is bound to this engagement yet. A bound conversation follows the engagement: its client-data rule applies to every model it uses, and halting stops it.</p>`}
      <label class="rv-label" for="conv-msg">First message (optional)</label>
      <textarea id="conv-msg" class="rv-input" rows="3" placeholder="What to test, e.g. a web assessment of the in-scope app; follow the playbooks and write the report."></textarea>
      <div class="rv-actions start"><button id="conv-new" class="rv-btn sm">New conversation</button><button id="copy-prompt" class="rv-btn ghost sm">${ICON_COPY} Copy prompt</button></div>
    </div></div>`;
}
function bindConversations(d, prompt) {
  $("#copy-prompt").addEventListener("click", () => navigator.clipboard.writeText(prompt).then(() => toast("Copied.")).catch(() => toast("Copy failed: select the text instead.", true)));
  $("#conv-new").addEventListener("click", async (ev) => {
    const r = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/conversation`, { message: $("#conv-msg").value }), "Conversation created and bound.");
    if (r) { window.open(r.url, "_blank", "noopener"); openEngagement(d.engagement, true); }
  });
  $$("[data-unbind]").forEach((b) => b.addEventListener("click", async (ev) => {
    const r = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/unbind`, { id: b.dataset.unbind }), "Unbound.");
    if (r) openEngagement(d.engagement, true);
  }));
}
function credentialsCard(d) {
  const cs = d.credentials || [];
  return `<div class="rv-card"><div class="rv-card-head"><h3>Credentials</h3></div><div class="rv-card-body">
    ${cs.length ? `<ul class="rv-rows">${cs.map((c) => `<li><b>${esc(c.name)}</b> <span class="rv-code-chip">$${esc(c.env)}</span> <span class="rv-code-chip">${esc(c.ref)}</span>
      <span class="rv-dim">${fmtTime(c.set_at)} · ${esc(c.set_by || "")}</span> <button class="rv-btn ghost sm" data-credrm="${esc(c.name)}">Remove</button></li>`).join("")}</ul>`
      : `<p class="hint">None stored. The agent uses a credential by reference ($RV_CRED_NAME in commands, {{cred:NAME}} in requests); the value never reaches the model and is replaced by the reference in output and evidence.</p>`}
    <div class="rv-form-row"><input id="cred-name" class="rv-input" placeholder="NAME" autocomplete="off" spellcheck="false" maxlength="32" aria-label="Credential name">
      <input id="cred-value" class="rv-input" type="password" placeholder="value" autocomplete="new-password" aria-label="Credential value">
      <button id="cred-save" class="rv-btn sm">Store</button></div>
  </div></div>`;
}
function bindCredentials(d) {
  $("#cred-save").addEventListener("click", async (ev) => {
    const name = $("#cred-name").value.trim().toUpperCase(), value = $("#cred-value").value;
    const r = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/cred`, { name, value }), `${name} stored.`);
    $("#cred-value").value = "";
    if (r) openEngagement(d.engagement, true);
  });
  $$("[data-credrm]").forEach((b) => b.addEventListener("click", async (ev) => {
    const r = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/cred`, { name: b.dataset.credrm, remove: true }), "Removed.");
    if (r) openEngagement(d.engagement, true);
  }));
}

function paneScope() {
  const d = state.detail, p = state.preview;
  $("#pane").innerHTML = `
    <p class="hint">Edit the scope and rules, preview what changes, then apply. Applying rebuilds the engagement's firewall at once.</p>
    <div class="rv-two">
      <label class="rv-field"><span class="rv-field-label">SCOPE.md</span><textarea id="scope-text" class="rv-input" rows="14" spellcheck="false">${esc(d.scope_text)}</textarea></label>
      <label class="rv-field"><span class="rv-field-label">RULES.md</span><textarea id="rules-text" class="rv-input" rows="14" spellcheck="false">${esc(d.rules_text)}</textarea></label>
    </div>
    <div class="rv-actions"><button id="preview-btn" class="rv-btn">Preview changes</button><button id="apply-btn" class="rv-btn accent" ${p && p.diff && !(p.errors || []).length ? "" : "disabled"}>Apply</button></div>
    <div id="preview-out" class="rv-stack">${p ? previewHtml(p) : ""}</div>`;
  const reset = () => { state.preview = null; $("#apply-btn").disabled = true; $("#preview-out").innerHTML = ""; };
  $("#scope-text").addEventListener("input", reset); $("#rules-text").addEventListener("input", reset);
  $("#preview-btn").addEventListener("click", async (ev) => {
    const r = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/preview`, { scope: $("#scope-text").value, rules: $("#rules-text").value }));
    if (!r) return;
    state.preview = r; d.scope_text = $("#scope-text").value; d.rules_text = $("#rules-text").value;
    $("#preview-out").innerHTML = previewHtml(r); $("#apply-btn").disabled = !r.diff || (r.errors || []).length > 0;
  });
  $("#apply-btn").addEventListener("click", async (ev) => {
    const r = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/apply`, { scope: $("#scope-text").value, rules: $("#rules-text").value, revision: d.info.revision }), "Applied. The firewall now uses the new scope.");
    if (r) { state.preview = null; await refresh(); await openEngagement(d.engagement, true); }
  });
}
function previewHtml(p) {
  const lines = (p.diff || "").split("\n").map((l) => `<span class="${l.startsWith("+++") || l.startsWith("---") || l.startsWith("@@") ? "hdr" : l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : ""}">${esc(l)}</span>`).join("\n");
  const errs = p.errors || [], ex = p.exclude || { hosts: [], nets: [], urls: [] }, r = p.rules;
  const excluded = [...ex.hosts.map((x) => (x.wildcard ? "*." : "") + x.name), ...ex.nets, ...ex.urls.map((u) => `${u.scheme}://${u.host}:${u.port}${u.prefix}`)];
  const when = [r.dates ? `${r.dates[0]} to ${r.dates[1]}` : "", r.days ? r.days.join(", ") : "", r.window ? r.window.map((x, i) => String(x).padStart(2, "0") + (i === 0 || i === 2 ? ":" : i === 1 ? "-" : "")).join("") : ""].filter(Boolean);
  const list = (items) => `<ul>${items.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>`;
  return `${errs.length ? `<div class="rv-banner danger"><div class="rv-banner-body"><p class="rv-banner-title">Can't apply: fix these lines first</p>${list(errs)}</div></div>` : ""}
    ${p.warnings.length ? `<div class="rv-banner warn"><div class="rv-banner-body"><p class="rv-banner-title">Check these</p>${list(p.warnings)}</div></div>` : ""}
    <div class="rv-card"><div class="rv-card-head"><h3>Preview</h3>${p.diff ? tag("changes", "warn") : tag("no changes")}</div><div class="rv-card-body">
      ${p.diff ? `<pre class="rv-pre">${lines}</pre>` : ""}
      <dl class="rv-kv"><dt>Will allow</dt><dd>${(p.allows || []).length ? codeChips(p.allows) : "nothing"}</dd>
      ${excluded.length ? `<dt>Excluded</dt><dd>${codeChips(excluded)}</dd>` : ""}
      <dt>Tiers</dt><dd>${tierTags(r.tiers)}${r.strict ? " " + tag("strict", "warn") : ""}${r.execution === "controlled" ? " " + tag("controlled execution", "warn") : ""}</dd>
      <dt>Rate / network</dt><dd>${esc(r.max_rate)}/s · ${esc(r.network)}${r.max_requests ? ` · ${esc(r.max_requests)} requests` : ""}${r.max_commands ? ` · ${esc(r.max_commands)} commands` : ""}</dd>
      <dt>When</dt><dd>${when.length ? esc(when.join(" · ")) + ` <span class="rv-muted">(${esc(r.timezone)})</span>` : "any time"}</dd>
      ${r.stop_conditions.length ? `<dt>Stop conditions</dt><dd>${list(r.stop_conditions)}</dd>` : ""}</dl>
      ${(p.limits || []).length ? `<p class="rv-field-label" style="margin-top:12px">Not enforced by the kit</p>${list(p.limits)}` : ""}
    </div></div>`;
}

function paneFindings() {
  const d = state.detail, filt = state.findingFilter;
  const n = (s) => d.findings.filter((f) => s === "all" || f.status === s).length;
  const rows = d.findings.filter((f) => filt === "all" || f.status === filt).sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || a.id.localeCompare(b.id));
  const ev = state.evidence;
  $("#pane").innerHTML = `
    <div class="rv-actions" style="justify-content:space-between">
      <div class="rv-sev-filters">${["all", ...STATUSES].map((s) => `<button class="rv-sev-filter ${s === filt ? "active" : ""}" data-filter="${s}">${s} <span class="count">${n(s)}</span></button>`).join("")}</div>
      <button id="ev-btn" class="rv-btn sm">Check evidence integrity</button>
    </div>
    ${ev ? ev.issues.length ? `<div class="rv-banner danger"><div class="rv-banner-body"><p class="rv-banner-title">Evidence problems</p><ul>${ev.issues.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div></div>`
      : `<div class="rv-banner"><div class="rv-banner-body"><p class="rv-banner-title">All evidence checks out</p><p class="rv-banner-sub">Every file matches the hash recorded when the sandbox produced it.</p></div></div>` : ""}
    <div class="rv-finding-list">${rows.map((f) => `<button class="rv-row ${state.openFinding === f.id ? "selected" : ""}" data-fid="${esc(f.id)}">
        <span class="ind c-${esc(f.severity)}"></span>
        <span style="min-width:0"><div class="title">${esc(f.title)}</div>
          <div class="meta">${esc(f.id)}<span class="slash">/</span>${esc(f.asset || "no asset")}${f.cwe ? `<span class="slash">/</span>${esc(f.cwe)}` : ""}</div></span>
        ${f.priority ? tag(f.priority) : ""}${f.verification === "verified" ? tag("verified", "ok") : f.verification === "not-reproducible" ? tag("not reproducible", "warn") : ""}
        ${sevTag(f.severity)}
        ${tag(f.status + (f.duplicate_of ? " of " + f.duplicate_of : ""), { confirmed: "sev-critical", fixed: "ok", candidate: "warn" }[f.status] || "")}
      </button>${state.openFinding === f.id ? editor(f, ev) : ""}`).join("") || `<div class="rv-empty">No findings${filt === "all" ? " yet" : " with this status"}.</div>`}</div>`;
  $$("[data-filter]").forEach((b) => b.addEventListener("click", () => { state.findingFilter = b.dataset.filter; paneFindings(); }));
  $("#ev-btn").addEventListener("click", async (e) => {
    const r = await act(e.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/evidence`));
    if (r) { state.evidence = r; paneFindings(); }
  });
  $$("[data-fid]").forEach((b) => b.addEventListener("click", () => { state.openFinding = state.openFinding === b.dataset.fid ? null : b.dataset.fid; paneFindings(); }));
  const save = $("#fe-save");
  if (save) {
    const cur = d.findings.find((x) => x.id === state.openFinding) || {};
    const sync = () => {
      const st = $("#fe-status").value;
      $("#fe-dup-wrap").hidden = st !== "duplicate";
      $("#fe-method-wrap").hidden = st !== "confirmed" || cur.status === "confirmed";
      const needs = ["false-positive", "accepted-risk"].includes(st) && st !== cur.status || $("#fe-sev").value !== cur.severity
        || cur.priority && $("#fe-prio").value !== cur.priority;
      $("#fe-reason-label").textContent = needs ? "Reason (required for this change)" : "Reason (optional)";
    };
    ["#fe-status", "#fe-sev", "#fe-prio"].forEach((s) => $(s).addEventListener("change", sync));
    sync();
    save.addEventListener("click", async () => {
      const body = { id: state.openFinding, status: $("#fe-status").value, severity: $("#fe-sev").value, notes: $("#fe-notes").value };
      if (Number.isInteger(cur.revision)) body.revision = cur.revision;
      if (body.status === "duplicate") body.duplicate_of = $("#fe-dup").value.trim();
      if ($("#fe-prio").value && $("#fe-prio").value !== (cur.priority || "")) body.priority = $("#fe-prio").value;
      const vec = $("#fe-cvss").value.trim();
      if (vec && vec !== (cur.cvss_vector || "")) body.cvss_vector = vec;
      const pre = $("#fe-prereq").value.trim();
      if (pre !== (cur.prerequisites || "")) body.prerequisites = pre;
      if (body.status === "confirmed" && cur.status !== "confirmed" && $("#fe-method").value) body.method = $("#fe-method").value;
      if ($("#fe-reason").value.trim()) body.reason = $("#fe-reason").value.trim();
      const r = await act(save, () => api(`/api/eng/${enc(d.engagement)}/finding`, body), "Saved.");
      if (r) { await openEngagement(d.engagement, true); refresh(); }
    });
    $("#fe-nr")?.addEventListener("click", async (ev) => {
      const reason = $("#fe-reason").value.trim();
      if (!reason) { toast("Give the reason first: what you tried and what happened.", true); $("#fe-reason").focus(); return; }
      const r = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/finding`, { id: state.openFinding, not_reproducible: true, reason }), "Recorded as not reproducible.");
      if (r) { await openEngagement(d.engagement, true); refresh(); }
    });
    $("#fe-hist").addEventListener("click", async (ev) => {
      const h = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/history?id=${enc(state.openFinding)}`));
      if (h) $("#fe-history").innerHTML = historyHtml(h);
    });
    $$("[data-preview]").forEach((b) => b.addEventListener("click", async (ev) => {
      const pv = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/preview?path=${enc(b.dataset.preview)}`));
      if (pv) $("#fe-preview").innerHTML = previewBox(pv);
    }));
  }
}
function evidenceBadge(st) {
  if (!st) return "";
  if (st === "verified") return tag("verified", "ok");
  if (st === "code reference") return tag("code ref", "code");
  if (st.startsWith("not produced")) return tag("not audited", "warn");
  return tag(st, "fail");
}
function historyHtml(h) {
  const dec = h.decisions.map((x) => `<li>${fmtTime(x.at)} <b>${esc(x.kind)}</b> ${x.from_value || x.to_value ? `${esc(x.from_value || "-")} &rarr; ${esc(x.to_value || "-")}` : ""}
    ${x.method ? tag(x.method) : ""} <span class="rv-dim">${esc(x.actor || "")}</span>${x.reason ? `<div class="rv-dim">${esc(x.reason)}</div>` : ""}</li>`).join("");
  const revs = h.revisions.map((r) => `<li>rev ${r.revision} · ${fmtTime(r.at)} <span class="rv-dim">${esc(r.actor || "")}</span> ${tag(r.snapshot.status)} ${sevTag(r.snapshot.severity)}</li>`).join("");
  return `<div class="rv-history"><p class="rv-field-label">Decisions</p><ul class="rv-rows">${dec || "<li class='rv-dim'>none</li>"}</ul>
    <p class="rv-field-label">Revisions</p><ul class="rv-rows">${revs}</ul></div>`;
}
function previewBox(pv) {
  return `<div class="rv-preview-box"><div class="rv-meta"><span class="mono">${esc(pv.path)}</span><span>${pv.size} bytes</span><span class="mono">sha256 ${esc(pv.sha256.slice(0, 16))}...</span>${pv.truncated ? "<span>first 256 KB</span>" : ""}<span>secrets redacted in this view</span></div>
    ${pv.binary ? `<p class="rv-dim">Binary file: not shown.</p>` : `<pre class="rv-pre">${esc(pv.text)}</pre>`}</div>`;
}
function editor(f, ev) {
  const items = ev?.items?.[f.id] || (f.evidence || []).map((p) => ({ path: p }));
  const opt = (list, cur) => list.map((s) => `<option ${s === cur ? "selected" : ""}>${s}</option>`).join("");
  return `<div class="rv-editor">
    <div class="rv-form-grid">
      <label class="rv-field"><span class="rv-field-label">Status</span><select id="fe-status" class="rv-select">${opt(STATUSES, f.status)}</select></label>
      <label class="rv-field"><span class="rv-field-label">Severity</span><select id="fe-sev" class="rv-select">${opt(SEV, f.severity)}</select></label>
      <label class="rv-field"><span class="rv-field-label">Priority</span><select id="fe-prio" class="rv-select"><option value="">not set</option>${opt(PRIORITIES, f.priority)}</select></label>
      <label id="fe-method-wrap" class="rv-field" hidden><span class="rv-field-label">Verified by</span><select id="fe-method" class="rv-select"><option value="">not stated</option>${opt(METHODS, "")}</select></label>
      <label id="fe-dup-wrap" class="rv-field" ${f.status === "duplicate" ? "" : "hidden"}><span class="rv-field-label">Duplicate of</span><input id="fe-dup" class="rv-input" value="${esc(f.duplicate_of || "")}" placeholder="F-001"></label>
    </div>
    <label class="rv-field"><span id="fe-reason-label" class="rv-field-label">Reason (optional)</span><input id="fe-reason" class="rv-input" maxlength="2000" placeholder="why: kept with the decision in the finding's history"></label>
    <label class="rv-field"><span class="rv-field-label">Notes</span><textarea id="fe-notes" class="rv-input" rows="3">${esc(f.notes)}</textarea></label>
    <div class="rv-form-grid">
      <label class="rv-field"><span class="rv-field-label">CVSS 3.1 vector (the score is computed)</span><input id="fe-cvss" class="rv-input mono" value="${esc(f.cvss_vector || "")}" placeholder="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" spellcheck="false"></label>
      <label class="rv-field"><span class="rv-field-label">Prerequisites</span><input id="fe-prereq" class="rv-input" value="${esc(f.prerequisites || "")}" placeholder="an account in another tenant"></label>
    </div>
    <dl class="rv-kv">
      <dt>Verification</dt><dd>${tag(f.verification || "unverified", { verified: "ok", "not-reproducible": "warn" }[f.verification] || "")}
        ${f.verified_by ? `<span class="rv-dim">by ${esc(f.verified_by)}${f.verified_method ? ", " + esc(f.verified_method) : ""}, ${fmtTime(f.verified_at)}</span>` : ""}</dd>
      <dt>CWE / CVSS</dt><dd>${esc(f.cwe || "n/a")} · ${esc(f.cvss_score ?? "n/a")}${f.cvss_rating ? ` (${esc(f.cvss_rating)})` : ""} <span class="mono rv-dim">${esc(f.cvss_vector || "")}</span></dd>
      ${(f.instances || []).length ? `<dt>Instances</dt><dd><ul class="rv-evidence">${f.instances.map((i) => `<li><span class="rv-code-chip">${esc(i.location || i)}</span>${i.observation ? `<span class="rv-dim">${esc(i.observation)}</span>` : ""}</li>`).join("")}</ul></dd>` : ""}
      <dt>Description</dt><dd><p class="rv-prose">${esc(f.description)}</p></dd>
      ${f.reproduction ? `<dt>Reproduction</dt><dd><pre class="rv-pre">${esc(f.reproduction)}</pre></dd>` : ""}
      ${f.remediation ? `<dt>Remediation</dt><dd><p class="rv-prose">${esc(f.remediation)}</p></dd>` : ""}
      <dt>Evidence</dt><dd>${items.length ? `<ul class="rv-evidence">${items.map((i) => `<li><span class="rv-code-chip">${esc(i.path)}</span>${i.note ? `<span class="rv-dim">${esc(i.note)}</span>` : ""}${evidenceBadge(i.status)}${!String(i.path).startsWith("/src/") ? ` <button class="rv-btn ghost sm" data-preview="${esc(i.path)}">View</button>` : ""}</li>`).join("")}</ul>` : `<span class="rv-dim">none</span>`}
        <div id="fe-preview"></div></dd>
      <dt>Source</dt><dd>${esc(f.source)} · updated ${fmtTime(f.updated)} · revision ${esc(f.revision)}</dd>
    </dl>
    <div id="fe-history"></div>
    <div class="rv-actions"><button id="fe-hist" class="rv-btn ghost sm">History</button>${f.status === "confirmed" || f.status === "candidate" ? `<button id="fe-nr" class="rv-btn ghost sm danger-quiet" title="Record that a retest couldn't reproduce it (needs the reason)">Not reproducible</button>` : ""}<button id="fe-save" class="rv-btn accent">Save</button></div></div>`;
}

function paneReport() {
  const d = state.detail, m = d.meta;
  const files = d.report_files || [];
  const html = files.filter((f) => f.endsWith(".html"));
  $("#pane").innerHTML = `
    <div class="rv-card"><div class="rv-card-head"><h3>Cover details</h3><button id="m-save" class="rv-btn sm">Save details</button></div>
      <div class="rv-card-body"><div class="rv-form-grid">
        <label class="rv-field"><span class="rv-field-label">Client</span><input id="m-client" class="rv-input" value="${esc(m.client || "")}"></label>
        <label class="rv-field"><span class="rv-field-label">Prepared by</span><input id="m-by" class="rv-input" value="${esc(m["prepared by"] || "")}"></label>
        <label class="rv-field"><span class="rv-field-label">Version</span><input id="m-ver" class="rv-input" value="${esc(m.version || "1.0")}"></label>
        <label class="rv-field"><span class="rv-field-label">Classification</span><input id="m-cls" class="rv-input" value="${esc(m.classification || "Confidential")}"></label>
      </div></div></div>
    <div class="rv-card"><div class="rv-card-head"><h3>Executive summary</h3><span class="rv-label">markdown</span></div>
      <div class="rv-card-body">
        <textarea id="exec" class="rv-input" rows="10" placeholder="3–5 paragraphs: what was assessed, overall posture, the most important findings in business terms, and the top priorities.">${esc(d.executive_summary)}</textarea>
        <div class="rv-actions"><button id="exec-save" class="rv-btn">Save summary</button><button id="gen-btn" class="rv-btn accent">Generate report</button></div>
      </div></div>
    <div id="gen-out"></div>
    <div id="delivery-out" class="rv-stack"><div class="rv-empty">Loading revisions…</div></div>
    <div class="rv-card"><div class="rv-card-head"><h3>Files</h3>${html.length ? `<a class="rv-btn sm" href="/report/${enc(d.engagement)}/${enc(html[0])}" target="_blank" rel="noopener">View HTML report ↗</a>` : ""}</div>
      ${files.length ? `<div class="rv-card-body flush"><table class="rv-table"><tbody>${files.map((f) => `<tr><td><span class="mono">${esc(f)}</span></td>
        <td style="text-align:right">${f.endsWith(".html") ? `<a href="/report/${enc(d.engagement)}/${enc(f)}" target="_blank" rel="noopener">View</a> · ` : ""}<a href="/files/${enc(d.engagement)}/${enc(f)}">Download</a></td></tr>`).join("")}</tbody></table></div>`
      : `<div class="rv-empty">No report yet.</div>`}</div>`;
  $("#m-save").addEventListener("click", async (e) => {
    const r = await act(e.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/meta`,
      { client: $("#m-client").value, "prepared by": $("#m-by").value, version: $("#m-ver").value, classification: $("#m-cls").value, digest: d.meta_digest }), "Saved.");
    if (r) { d.meta = r.meta; d.meta_digest = r.digest; refresh(); }
  });
  $("#exec-save").addEventListener("click", async (e) => {
    const r = await act(e.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/summary`, { text: $("#exec").value, digest: d.summary_digest }), "Saved.");
    if (r) { d.executive_summary = $("#exec").value; d.summary_digest = r.digest; }
  });
  $("#gen-btn").addEventListener("click", async (e) => {
    $("#gen-out").innerHTML = `<div class="rv-banner"><div class="rv-banner-body"><p class="rv-banner-title">Building the report</p><p class="rv-banner-sub">Checking evidence and writing the HTML, Word, PDF and Excel files. Up to a minute.</p></div></div>`;
    const r = await act(e.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/report`, {}));
    if (!r) { $("#gen-out").innerHTML = ""; return; }
    const ready = r.state === "ready";
    const keep = `<div class="rv-banner ${ready ? "" : "warn"}"><div class="rv-banner-body">
      <p class="rv-banner-title">${esc(r.id)} ${ready ? tag("ready", "ok") : tag("draft", "draft")} ${esc(r.report.findings)} finding(s) in the report</p>
      <p class="rv-banner-sub">${ready ? "Nothing blocks delivery. Review it, then approve it below." : "Not ready for the client: see the readiness checks below."}</p></div></div>`;
    await openEngagement(d.engagement, true); $("#gen-out").innerHTML = keep;
  });
  loadDelivery();
}

const REV_CLASS = { approved: "ok", ready: "ok", generated: "warn", superseded: "" };
const fileLink = (eng, p) => `<a href="/files/${enc(eng)}/${p.split("/").map(enc).join("/")}">${esc(p.split("/").pop())}</a>`;
async function loadDelivery() {
  const d = state.detail, e = enc(d.engagement);
  let r;
  try { r = await api(`/api/eng/${e}/delivery`); } catch (err) { $("#delivery-out").innerHTML = `<div class="rv-empty err">${esc(err.message)}</div>`; return; }
  if (state.tab !== "report" || state.current !== d.engagement) return;
  const rd = r.readiness, latest = r.revisions[0];
  const reported = d.findings.filter((f) => ["confirmed", "fixed"].includes(f.status));
  const material = d.findings.filter((f) => f.status === "confirmed" && ["critical", "high"].includes(f.severity));
  $("#delivery-out").innerHTML = `
    <div class="rv-card"><div class="rv-card-head"><h3>Readiness for delivery</h3>${rd.ready ? tag("nothing blocks", "ok") : tag(`${rd.blocking.length} blocking`, "warn")}</div><div class="rv-card-body">
      ${rd.blocking.length ? `<ul class="rv-rows">${rd.blocking.map((b) => `<li>${tag(b.check.split(":")[0])} ${esc(b.issue)}${r.exceptable.includes(b.check.split(":")[0]) ? ` <button class="rv-btn ghost sm" data-except="${esc(b.check)}">Except…</button>` : ""}</li>`).join("")}</ul>` : `<p class="hint">Every check passes or has an exception.</p>`}
      ${rd.excepted.length ? `<p class="rv-field-label">Excepted</p><ul class="rv-rows">${rd.excepted.map((x) => `<li>${tag(x.check)} ${esc(x.issue)}<div class="rv-dim">${esc(x.rationale)} (${esc(x.by)}, ${fmtTime(x.at)})</div></li>`).join("")}</ul>` : ""}
      ${rd.warnings.length ? `<p class="rv-field-label">Warnings</p><ul class="rv-rows">${rd.warnings.map((w) => `<li class="rv-dim">${esc(w)}</li>`).join("")}</ul>` : ""}
      <div id="except-form"></div>
      ${r.exceptions.filter((x) => !x.revoked_at).length ? `<details><summary>Active exceptions</summary><ul class="rv-rows">${r.exceptions.filter((x) => !x.revoked_at).map((x) => `<li>${tag(x.check_key)} ${esc(x.rationale)} <span class="rv-dim">${esc(x.actor)}</span> <button class="rv-btn ghost sm danger-quiet" data-revoke="${x.id}">Revoke</button></li>`).join("")}</ul></details>` : ""}
    </div></div>
    <div class="rv-card"><div class="rv-card-head"><h3>Report revisions</h3></div>
      ${r.revisions.length ? `<div class="rv-card-body flush"><table class="rv-table"><thead><tr><th>Revision</th><th>State</th><th>Files</th><th></th></tr></thead><tbody>${r.revisions.map((v) => `<tr>
        <td><b>${esc(v.id)}</b><div class="rv-dim">${fmtTime(v.created)} · ${esc(v.actor || "")}</div>${v.approved_by ? `<div class="rv-dim">approved by ${esc(v.approved_by)}, ${fmtTime(v.approved_at)}${v.approval_note ? ": " + esc(v.approval_note) : ""}</div>` : ""}${v.superseded_by ? `<div class="rv-dim">superseded by ${esc(v.superseded_by)}</div>` : ""}${v.transmissions.map((t) => `<div class="rv-dim">sent to ${esc(t.to)} via ${esc(t.channel)} (${esc(t.by)}, ${fmtTime(t.at)})</div>`).join("")}</td>
        <td>${tag(v.state, REV_CLASS[v.state])}</td>
        <td>${Object.keys(v.artifacts).map((n) => fileLink(d.engagement, `revisions/${v.id}/${n}`)).join("<br>")}</td>
        <td style="text-align:right;white-space:nowrap">
          ${v.state === "ready" && v.id === latest.id ? `<button class="rv-btn sm accent" data-approve="${esc(v.id)}">Approve for delivery…</button>` : ""}
          ${v.state === "approved" ? `<button class="rv-btn ghost sm" data-sent="${esc(v.id)}">Record sending…</button>` : ""}
          <button class="rv-btn ghost sm" data-verify="${esc(v.id)}">Verify</button><button class="rv-btn ghost sm" data-rebuild="${esc(v.id)}">Rebuild</button></td></tr>`).join("")}</tbody></table></div>
        <div class="rv-card-body"><div id="rev-form"></div>
          <div class="rv-actions start"><button id="exp-btn" class="rv-btn sm">Export findings (JSON, SARIF, issues)</button><label class="rv-check"><input type="checkbox" id="exp-draft"> latest revision, as DRAFT</label></div><div id="exp-out"></div></div>`
      : `<div class="rv-empty">No revision yet: Generate report creates R-001.</div>`}</div>
    <div class="rv-card"><div class="rv-card-head"><h3>Retests</h3></div><div class="rv-card-body">
      ${r.retests.length ? `<ul class="rv-rows">${r.retests.map((t) => `<li><b>${esc(t.id)}</b> ${esc(t.finding_id)} ${tag(t.outcome, { resolved: "ok", partial: "warn", unresolved: "sev-critical" }[t.outcome])} build ${esc(t.retest_build)}${t.original_build ? ` (found on ${esc(t.original_build)})` : ""} <span class="rv-dim">${t.cases.map((c) => `${esc(c.name)}: ${esc(c.result)}`).join("; ")} · ${esc(t.actor)}, ${fmtTime(t.at)}</span>${t.reauthorization ? `<div class="rv-dim">re-authorized: ${esc(t.reauthorization)}</div>` : ""}</li>`).join("")}</ul>` : `<p class="hint">No retests yet.</p>`}
      ${reported.length ? `<details><summary>Record a retest</summary><div class="rv-form-grid">
        <label class="rv-field"><span class="rv-field-label">Finding</span><select id="rt-f" class="rv-select">${reported.map((f) => `<option>${esc(f.id)}</option>`).join("")}</select></label>
        <label class="rv-field"><span class="rv-field-label">Retested on build</span><input id="rt-build" class="rv-input mono" spellcheck="false"></label>
        <label class="rv-field"><span class="rv-field-label">Outcome</span><select id="rt-out" class="rv-select"><option>resolved</option><option>partial</option><option>unresolved</option></select></label></div>
        <label class="rv-field"><span class="rv-field-label">Cases (one per line: name | pass, fail or partial | evidence path of the retest)</span><textarea id="rt-cases" class="rv-input mono" rows="3" spellcheck="false" placeholder="other tenant reads invoice | pass | evidence/authz/run-2.json"></textarea></label>
        <label class="rv-field"><span class="rv-field-label">Scope or access re-authorized (who, when), if it was needed</span><input id="rt-reauth" class="rv-input"></label>
        <div class="rv-actions start"><button id="rt-save" class="rv-btn sm">Record retest</button></div></details>` : ""}
    </div></div>
    <div class="rv-card"><div class="rv-card-head"><h3>Cleanup and retention</h3></div><div class="rv-card-body">
      ${r.obligations.length ? `<ul class="rv-rows">${r.obligations.map((o) => `<li><b>${esc(o.id)}</b> ${tag(o.kind)} ${tag(o.state, { done: "ok", open: "warn" }[o.state])} ${esc(o.what)}${o.note ? `<div class="rv-dim">${esc(o.note)} (${esc(o.updated_by)})</div>` : ""}
        ${o.state === "open" ? `<button class="rv-btn ghost sm" data-ob="${esc(o.id)}" data-st="done">Done…</button><button class="rv-btn ghost sm" data-ob="${esc(o.id)}" data-st="waived">Waive…</button>` : ""}</li>`).join("")}</ul>` : `<p class="hint">Nothing recorded: test data, fixture changes, credentials to revoke and what to keep or delete at close-out.</p>`}
      <div class="rv-form-row"><select id="ob-kind" class="rv-select" aria-label="Kind">${["fixture", "credential", "data", "access", "retention", "other"].map((k) => `<option>${k}</option>`).join("")}</select><input id="ob-what" class="rv-input" placeholder="delete the test invoices created in tenant B" aria-label="Obligation"><button id="ob-add" class="rv-btn sm">Add</button></div>
    </div></div>
    <div class="rv-card"><div class="rv-card-head"><h3>Material finding notices</h3></div><div class="rv-card-body">
      ${r.notices.length ? `<ul class="rv-rows">${r.notices.map((n) => `<li><b>${esc(n.id)}</b> ${esc(n.finding_id)} rev ${esc(n.finding_revision)} ${tag(n.state, n.state === "reviewed" ? "ok" : "warn")} ${fileLink(d.engagement, n.path.replace(/^report\//, ""))}${n.reviewed_by ? ` <span class="rv-dim">reviewed by ${esc(n.reviewed_by)}</span>` : ` <button class="rv-btn ghost sm" data-review="${esc(n.id)}">Mark reviewed</button>`}</li>`).join("")}</ul>` : `<p class="hint">A notice is a draft for the client about one confirmed critical or high finding, reviewed by you before it's shared. Nothing is sent from here.</p>`}
      ${material.length ? `<div class="rv-form-row"><select id="nt-f" class="rv-select" aria-label="Finding">${material.map((f) => `<option>${esc(f.id)}</option>`).join("")}</select><button id="nt-add" class="rv-btn sm">Prepare notice</button></div>` : ""}
    </div></div>`;
  const post = (body) => api(`/api/eng/${e}/delivery`, body);
  const again = () => loadDelivery();
  $$("[data-except]").forEach((b) => b.addEventListener("click", () => {
    $("#except-form").innerHTML = `<div class="rv-editor"><p>Exception for <b>${esc(b.dataset.except)}</b>: recorded with your name and shown in the revision.</p>
      <input id="ex-why" class="rv-input" placeholder="why the methodology allows this, e.g. the client excluded load testing in the kickoff on 3 Nov"><div class="rv-actions start"><button id="ex-save" class="rv-btn sm">Record exception</button></div></div>`;
    $("#ex-save").addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post({ op: "exception", check: b.dataset.except, rationale: $("#ex-why").value }), "Exception recorded. Generate the report again.")) again(); });
  }));
  $$("[data-revoke]").forEach((b) => b.addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post({ op: "revoke", id: Number(b.dataset.revoke) }), "Revoked.")) again(); }));
  $$("[data-approve]").forEach((b) => b.addEventListener("click", () => {
    $("#rev-form").innerHTML = `<div class="rv-editor"><p>Approve <b>${esc(b.dataset.approve)}</b> for client delivery. Approval checks that nothing changed since it was generated and that its files match their hashes; it doesn't send anything.</p>
      <input id="ap-note" class="rv-input" placeholder="note (optional): what you reviewed"><div class="rv-actions start"><button id="ap-save" class="rv-btn sm accent">Approve</button></div></div>`;
    $("#ap-save").addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post({ op: "approve", revision: b.dataset.approve, note: $("#ap-note").value }), "Approved for delivery.")) again(); });
  }));
  $$("[data-sent]").forEach((b) => b.addEventListener("click", () => {
    $("#rev-form").innerHTML = `<div class="rv-editor"><p>Record that <b>${esc(b.dataset.sent)}</b> was sent. This is a record only.</p><div class="rv-form-grid">
      <label class="rv-field"><span class="rv-field-label">To</span><input id="tx-to" class="rv-input" placeholder="client security lead"></label>
      <label class="rv-field"><span class="rv-field-label">How</span><input id="tx-ch" class="rv-input" placeholder="client portal upload"></label></div>
      <div class="rv-actions start"><button id="tx-save" class="rv-btn sm">Record</button></div></div>`;
    $("#tx-save").addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post({ op: "transmitted", revision: b.dataset.sent, to: $("#tx-to").value, channel: $("#tx-ch").value }), "Recorded.")) again(); });
  }));
  $$("[data-verify]").forEach((b) => b.addEventListener("click", async (ev) => {
    const x = await act(ev.currentTarget, () => post({ op: "verify", revision: b.dataset.verify }));
    if (x) toast(x.problems.length ? `${x.revision}: ${x.problems.join("; ")}` : `${x.revision}: all ${x.files} files match their hashes.`, !!x.problems.length);
  }));
  $$("[data-rebuild]").forEach((b) => b.addEventListener("click", async (ev) => {
    const x = await act(ev.currentTarget, () => post({ op: "rebuild", revision: b.dataset.rebuild }));
    if (x) toast(`${x.revision} rebuilt from its frozen inputs in ${x.folder}: the HTML is ${x.html_identical ? "identical" : "different"}.`, !x.html_identical);
  }));
  $("#exp-btn")?.addEventListener("click", async (ev) => {
    const x = await act(ev.currentTarget, () => post({ op: "export", draft: $("#exp-draft").checked }));
    if (x) $("#exp-out").innerHTML = `<p>${esc(x.revision)} (${esc(x.state)}): ${Object.keys(x.files).map((n) => fileLink(d.engagement, `${x.folder.replace(/^report\//, "")}/${n}`)).join(" · ")}</p>`;
  });
  $("#rt-save")?.addEventListener("click", async (ev) => {
    const cases = $("#rt-cases").value.split("\n").map((l) => l.split("|").map((s) => s.trim())).filter((c) => c[0]).map(([name, result, after]) => ({ name, result, after: after ? [after] : [] }));
    if (await act(ev.currentTarget, () => post({ op: "retest", finding_id: $("#rt-f").value, build: $("#rt-build").value.trim(), outcome: $("#rt-out").value, cases, reauthorization: $("#rt-reauth").value }), "Retest recorded.")) { await openEngagement(d.engagement, true); }
  });
  $("#ob-add").addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post({ op: "cleanup_add", kind: $("#ob-kind").value, what: $("#ob-what").value }), "Added.")) again(); });
  $$("[data-ob]").forEach((b) => b.addEventListener("click", async (ev) => {
    const note = prompt(b.dataset.st === "done" ? "What was done?" : "Why is it waived?");
    if (note === null) return;
    if (await act(ev.currentTarget, () => post({ op: "cleanup_update", id: b.dataset.ob, state: b.dataset.st, note }), "Updated.")) again();
  }));
  $("#nt-add")?.addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post({ op: "notice_prepare", finding_id: $("#nt-f").value }), "Notice drafted.")) again(); });
  $$("[data-review]").forEach((b) => b.addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post({ op: "notice_review", id: b.dataset.review }), "Marked reviewed.")) again(); }));
}

// ---------------------------------------------------------------- authenticated testing (RW-008 to RW-011)
const STATE_CLASS = { valid: "c-low", expired: "c-high", challenge: "c-medium", denied: "c-medium", error: "c-high", revoked: "", unchecked: "" };
const VERDICT_CLASS = { pass: "c-low", FAIL: "c-critical", "unexpected-deny": "c-medium", blocked: "c-medium" };
const IDENTITY_TEMPLATE = `{
  "kind": "form",
  "role": "member",
  "tenant": "acme",
  "login_url": "https://app.example.com/login",
  "username": "tester@acme.test",
  "secret": "ACME_TESTER_PASS",
  "check": {"url": "https://app.example.com/dashboard", "marker": "text only this account sees"},
  "fixtures": [{"kind": "invoice", "id": 1, "marker": "text only that record contains"}],
  "tiers": ["active"],
  "effects": ["read"]
}`;

async function paneTesting() {
  const d = state.detail, e = enc(d.engagement);
  $("#pane").innerHTML = `<p class="hint">Test identities, request captures and authorization matrices. Secrets stay on this machine: the agent
    sees identity names, roles, tenants and sanitized captures, never a password, token or cookie.</p><div id="testing-out" class="rv-empty">Loading…</div>`;
  let r;
  try { r = await api(`/api/eng/${e}/testing`); } catch (err) { $("#testing-out").textContent = err.message; return; }
  const ids = r.identities || [], caps = r.captures || [], mats = r.matrices || [];
  const idOpts = `<option value="">no identity</option>` + ids.map((i) => `<option>${esc(i.name)}</option>`).join("");
  $("#testing-out").outerHTML = `<div id="testing-out" class="rv-stack">
    <div class="rv-card"><div class="rv-card-head"><h3>Identities</h3></div><div class="rv-card-body">
      ${ids.length ? `<ul class="rv-rows">${ids.map((i) => `<li><b>${esc(i.name)}</b> ${tag(i.status.state || "unchecked", STATE_CLASS[i.status.state || "unchecked"])}
        <span class="rv-dim">${esc(i.kind)} · role ${esc(i.role || "-")} · tenant ${esc(i.tenant || "-")} · ${esc(i.effects.join("/"))} · ${esc(i.hosts.join(", "))}</span>
        ${i.fixtures.length ? `<span class="rv-dim">owns ${i.fixtures.map((f) => esc(`${f.kind} ${f.id}`)).join(", ")}</span>` : ""}
        ${i.status.reason ? `<span class="rv-dim">${esc(i.status.reason)}</span>` : ""}
        <button class="rv-btn ghost sm" data-idop="check" data-name="${esc(i.name)}">Check session</button>
        ${i.status.state !== "revoked" ? `<button class="rv-btn ghost sm danger-quiet" data-idop="revoke" data-name="${esc(i.name)}">Revoke</button>` : ""}
        <button class="rv-btn ghost sm danger-quiet" data-idop="rm" data-name="${esc(i.name)}">Remove</button></li>`).join("")}</ul>`
        : `<p class="hint">None yet. An identity is a test account: how it logs in (it names a stored credential), the hosts its session may go to, what it may be used for, and the fixture records it owns.</p>`}
      <details><summary>Add or replace an identity</summary>
        <div class="rv-form-row"><input id="id-name" class="rv-input" placeholder="name (e.g. acme-member)" maxlength="32" spellcheck="false" aria-label="Identity name"></div>
        <textarea id="id-spec" class="rv-input" rows="12" spellcheck="false" aria-label="Identity spec (JSON)">${esc(IDENTITY_TEMPLATE)}</textarea>
        <div class="rv-actions start"><button id="id-save" class="rv-btn sm">Save identity</button></div>
      </details>
    </div></div>
    <div class="rv-card"><div class="rv-card-head"><h3>Captures</h3></div><div class="rv-card-body">
      ${caps.length ? `<ul class="rv-rows">${caps.map((c) => `<li><b>${esc(c.name || c.id)}</b> <span class="rv-dim">${esc(c.source)} · ${c.entries} request(s) · ${c.out_of_scope} out of scope · ${Object.values(c.redactions || {}).reduce((a, b) => a + b, 0)} value(s) redacted · ${fmtTime(c.imported_at)}</span>
        <button class="rv-btn ghost sm" data-capopen="${esc(c.id)}">Open</button> <button class="rv-btn ghost sm danger-quiet" data-caprm="${esc(c.id)}">Delete</button></li>`).join("")}</ul>`
        : `<p class="hint">Import a HAR file (browser developer tools, ZAP, mitmproxy) or a Burp Suite XML export. The original is kept encrypted for you; the agent sees a sanitized copy.</p>`}
      <div class="rv-form-row"><input id="cap-file" type="file" accept=".har,.json,.xml" aria-label="Capture file"><button id="cap-import" class="rv-btn sm">Import</button></div>
      <div id="cap-view"></div>
    </div></div>
    <div class="rv-card"><div class="rv-card-head"><h3>Authorization matrices</h3></div><div class="rv-card-body">
      ${mats.length ? mats.map((m) => { const res = (r.results || {})[m.name]; return `<div class="rv-matrix">
        <p><b>${esc(m.name)}</b> ${tag(m.state, m.state === "approved" ? "c-low" : "c-medium")} <span class="rv-dim">${m.operations} operation(s) x ${m.identities.length} identit${m.identities.length === 1 ? "y" : "ies"}${m.purpose ? " · " + esc(m.purpose) : ""}</span>
        <button class="rv-btn ghost sm" data-mxshow="${esc(m.name)}">Review</button>
        ${m.state === "approved" ? `<button class="rv-btn sm" data-mxrun="${esc(m.name)}">Run</button>` : ""}</p>
        <div id="mx-${esc(m.name)}"></div>
        ${res ? `<p class="rv-dim">Last run ${fmtTime(res.at)}: ${Object.entries(res.summary).map(([k, v]) => `${esc(k)} ${v}`).join(", ")} · <code>${esc(res.file)}</code></p>
          <table class="rv-table"><thead><tr><th>Operation</th><th>Identity</th><th>Expected</th><th>Outcome</th><th>Verdict</th><th>Why</th></tr></thead><tbody>
          ${res.cells.map((c) => `<tr><td>${esc(c.operation)}</td><td>${esc(c.identity)}</td><td>${esc(c.expected)}</td><td>${esc(c.outcome)}</td><td>${tag(c.verdict, VERDICT_CLASS[c.verdict] || "")}</td><td class="rv-dim">${esc(c.reason)}</td></tr>`).join("")}</tbody></table>` : ""}
      </div>`; }).join("") : `<p class="hint">The agent proposes a matrix (operations, identities, expected allow or deny). Review it here and approve exactly that version; it can't run before.</p>`}
    </div></div></div>`;

  $$("[data-idop]").forEach((b) => b.addEventListener("click", async (ev) => {
    const op = b.dataset.idop;
    if (op === "rm" && !confirm(`Remove identity ${b.dataset.name}?`)) return;
    const x = await act(ev.currentTarget, () => api(`/api/eng/${e}/identity`, { name: b.dataset.name, op }), op === "check" ? null : "Done.");
    if (x && op === "check") toast(`${b.dataset.name}: ${x.state}${x.reason ? " (" + x.reason + ")" : ""}`, x.state !== "valid");
    if (x) paneTesting();
  }));
  $("#id-save").addEventListener("click", async (ev) => {
    let spec;
    try { spec = JSON.parse($("#id-spec").value); } catch { return toast("The spec isn't valid JSON.", true); }
    const x = await act(ev.currentTarget, () => api(`/api/eng/${e}/identity`, { name: $("#id-name").value.trim(), op: "set", spec }), "Identity saved. Check its session next.");
    if (x) paneTesting();
  });
  $("#cap-import").addEventListener("click", async (ev) => {
    const f = $("#cap-file").files[0];
    if (!f) return toast("Choose a file first.", true);
    const buf = new Uint8Array(await f.arrayBuffer());
    let bin = ""; for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
    const x = await act(ev.currentTarget, () => api(`/api/eng/${e}/capture`, { op: "import", name: f.name, data: btoa(bin) }), "Imported and sanitized.");
    if (x) paneTesting();
  });
  $$("[data-caprm]").forEach((b) => b.addEventListener("click", async (ev) => {
    if (!confirm("Delete this capture (the sanitized copy and the encrypted original)?")) return;
    if (await act(ev.currentTarget, () => api(`/api/eng/${e}/capture`, { op: "rm", id: b.dataset.caprm }), "Deleted.")) paneTesting();
  }));
  $$("[data-capopen]").forEach((b) => b.addEventListener("click", async () => {
    const c = await api(`/api/eng/${e}/capture?id=${enc(b.dataset.capopen)}`);
    $("#cap-view").innerHTML = `<table class="rv-table"><thead><tr><th>#</th><th>Request</th><th>Status</th><th></th></tr></thead><tbody>
      ${c.entries.map((q) => `<tr><td>${q.n}</td><td><code>${esc(q.method)} ${esc(q.url)}</code>${q.in_scope ? "" : ` <span class="rv-dim">(${esc(q.scope_note || "out of scope")})</span>`}</td><td>${esc(q.response.status ?? "")}</td>
        <td>${q.in_scope ? `<select class="rv-input sm" data-replayas="${q.n}" aria-label="Identity for the replay">${idOpts}</select> <button class="rv-btn ghost sm" data-replay="${q.n}">Replay</button>` : ""}</td></tr>`).join("")}</tbody></table><div id="replay-out"></div>`;
    $$("[data-replay]").forEach((rb) => rb.addEventListener("click", async (ev) => {
      const n = Number(rb.dataset.replay), identity = $(`[data-replayas="${n}"]`).value;
      const send = (approval_id) => api(`/api/eng/${e}/capture`, { op: "replay", id: c.id, entry: n, identity, approval_id });
      let x = await act(ev.currentTarget, () => send(""));
      if (x && x.approval && confirm(`This request can change state (approval ${x.approval}). Approve it and send it now as ${identity || "no identity"}?`)) {
        await act(null, () => api(`/api/approvals/${enc(d.engagement)}/${enc(x.approval)}/approve`, {}));
        x = await act(ev.currentTarget, () => send(x.approval));
      }
      if (x) $("#replay-out").innerHTML = `<pre class="rv-pre">${esc(x.text)}${x.comparison && x.comparison.diff ? "\n\n" + esc(x.comparison.diff) : ""}</pre>`;
    }));
  }));
  $$("[data-mxshow]").forEach((b) => b.addEventListener("click", async () => {
    const m = await api(`/api/eng/${e}/matrix?name=${enc(b.dataset.mxshow)}`);
    // everything the approved digest covers, as escaped text: headers and bodies are agent-written
    const one = (v) => typeof v === "string" ? v : JSON.stringify(v);
    const reqText = (r) => [...Object.entries(r.headers || {}).map(([k, v]) => `${k}: ${v}`),
      ...(r.body == null || r.body === "" ? [] : ["", one(r.body)])].join("\n");
    const writes = m.operations.some((o) => o.effect === "write") || m.cleanup.length > 0;
    $(`#mx-${b.dataset.mxshow}`).innerHTML = `<p class="rv-dim">digest ${esc(m.digest)} · proposed by ${esc(m.proposed_by)} ${fmtTime(m.proposed_at)}${m.allow_writes || writes ? ` · <b>changes state</b>: at most ${esc(m.max_writes)} write(s), cleanup included` : " · read-only"}</p>
      <table class="rv-table"><thead><tr><th>Operation</th><th>Request</th>${m.identities.map((i) => `<th>${esc(i)}</th>`).join("")}</tr></thead><tbody>
      ${m.operations.map((o) => `<tr><td>${esc(o.id)}${o.effect === "write" ? " <b>(write)</b>" : ""}</td><td><code>${esc(o.method || "GET")} ${esc(o.url)}</code>${o.marker ? `<br><span class="rv-dim">marker ${esc(o.marker)}</span>` : ""}${reqText(o) ? `<pre class="rv-pre">${esc(reqText(o))}</pre>` : ""}</td>${m.identities.map((i) => `<td>${esc(m.expect[o.id][i])}</td>`).join("")}</tr>`).join("")}</tbody></table>
      ${m.cleanup.length ? `<p class="rv-dim">Cleanup, run after the writes (counted in max writes):</p>
      <table class="rv-table"><thead><tr><th>Request</th><th>Identity</th></tr></thead><tbody>
      ${m.cleanup.map((c) => `<tr><td><code>${esc(c.method || "POST")} ${esc(c.url)}</code>${reqText(c) ? `<pre class="rv-pre">${esc(reqText(c))}</pre>` : ""}</td><td>${esc(c.identity || "no identity")}</td></tr>`).join("")}</tbody></table>`
      : m.no_cleanup_reason ? `<p class="rv-dim">No cleanup: ${esc(m.no_cleanup_reason)}</p>` : ""}
      <p class="rv-dim">Header values are as proposed: {{cred:NAME}} references are filled in only when sent.</p>
      <div class="rv-actions start"><button class="rv-btn sm" data-mxapprove="${esc(m.name)}" data-digest="${esc(m.digest)}">Approve this version</button></div>`;
    $(`[data-mxapprove="${m.name}"]`).addEventListener("click", async (ev) => {
      const x = await act(ev.currentTarget, () => api(`/api/eng/${e}/authz`, { name: m.name, op: "approve", digest: ev.currentTarget.dataset.digest }), "Approved.");
      if (x) paneTesting();
    });
  }));
  $$("[data-mxrun]").forEach((b) => b.addEventListener("click", async (ev) => {
    const x = await act(ev.currentTarget, () => api(`/api/eng/${e}/authz`, { name: b.dataset.mxrun, op: "run" }), "Matrix run finished.");
    if (x) paneTesting();
  }));
}

async function paneInvestigation() {
  const d = state.detail, e = enc(d.engagement);
  $("#pane").innerHTML = `<p class="hint">What the engagement must answer, how far testing got and what still needs a decision. Built from the findings, observations and planned tests; the note at the end is yours.</p><div id="inv-out" class="rv-empty">Loading…</div>`;
  let r;
  try { r = await api(`/api/eng/${e}/investigation`); } catch (err) { $("#inv-out").textContent = err.message; return; }
  if (state.tab !== "investigation" || state.current !== d.engagement) return;
  const h = r.handover, cov = r.coverage, f = state.obsFilter;
  const obs = r.observations.filter((o) => f === "all" || o.status === f);
  const nObs = (s) => r.observations.filter((o) => s === "all" || o.status === s).length;
  const reload = () => paneInvestigation();
  $("#inv-out").outerHTML = `<div id="inv-out" class="rv-stack">
    <div class="rv-card"><div class="rv-card-head"><h3>Objective</h3></div><div class="rv-card-body">
      <textarea id="inv-obj" class="rv-input" rows="2" maxlength="4000" placeholder="What this engagement must answer, e.g. can a member of one tenant read or change another tenant's invoices?">${esc(r.objective)}</textarea>
      <div class="rv-actions start"><button id="inv-obj-save" class="rv-btn sm">Save objective</button></div>
    </div></div>
    <div class="rv-card"><div class="rv-card-head"><h3>Where it stands</h3></div><div class="rv-card-body">
      <div class="rv-meta"><span>findings: ${Object.entries(h.findings).filter(([, v]) => v).map(([k, v]) => `${v} ${esc(k)}`).join(", ") || "none"}</span>
        <span>observations: ${Object.entries(h.observations).filter(([, v]) => v).map(([k, v]) => `${v} ${esc(k)}`).join(", ") || "none"}</span>
        <span>${h.imports} import(s)</span></div>
      ${h.material.length ? `<p class="rv-field-label">Material findings</p><ul class="rv-rows">${h.material.map((m) => `<li>${sevTag(m.severity)} ${tag(m.status)} <b>${esc(m.id)}</b> ${esc(m.title)}</li>`).join("")}</ul>` : ""}
      ${h.pending.length ? `<p class="rv-field-label">Pending decisions</p><ul class="rv-rows">${h.pending.slice(0, 30).map((p) => `<li>${tag(p.kind)} ${esc(p.what)}</li>`).join("")}</ul>` : ""}
      ${h.parse_problems.length ? `<p class="rv-field-label">Import problems</p><ul class="rv-rows">${h.parse_problems.map((p) => `<li class="err">${esc(p)}</li>`).join("")}</ul>` : ""}
      <p class="rv-field-label">Next</p><ul class="rv-rows">${h.next.map((n) => `<li>${esc(n)}</li>`).join("") || "<li class='rv-dim'>nothing pending</li>"}</ul>
    </div></div>
    <div class="rv-card"><div class="rv-card-head"><h3>Coverage</h3></div><div class="rv-card-body">
      <div class="rv-meta">${cov.total ? COVERAGE.map((s) => `<span>${cov.counts[s]} ${esc(s)}</span>`).join("") : "<span>No plan yet.</span>"}${cov.stale.length ? `<span class="err">${cov.stale.length} stale</span>` : ""}</div>
      <p class="hint">${esc(cov.note)}</p>
      <div class="rv-form-row"><select id="inv-pb" class="rv-select" aria-label="Playbook">${PLAYBOOKS.map((p) => `<option>${p}</option>`).join("")}</select><button id="inv-pb-add" class="rv-btn sm">Add its checklist to the plan</button>
        <input id="inv-build" class="rv-input" placeholder="build or source digest now deployed" aria-label="Current build" spellcheck="false"><button id="inv-reassess" class="rv-btn ghost sm" title="Mark tests that ran on another build or policy revision as stale">Reassess</button></div>
      ${r.plan.length ? `<table class="rv-table rv-plan"><thead><tr><th>Test</th><th>References</th><th>Outcome</th><th></th></tr></thead><tbody>${r.plan.map((i) => `<tr>
        <td><b>${esc(i.id)}</b> ${esc(i.title)}${i.area ? `<div class="rv-dim">${esc(i.area)}</div>` : ""}</td>
        <td>${(i.refs || []).map((x) => `<span class="rv-code-chip">${esc(x)}</span>`).join(" ")}</td>
        <td>${tag(i.state, COV_CLASS[i.state])}${i.stale ? " " + tag("stale", "warn") : ""}${i.finding_id ? ` <b>${esc(i.finding_id)}</b>` : ""}${i.rationale ? `<div class="rv-dim">${esc(i.rationale)}</div>` : ""}${i.stale_reason ? `<div class="rv-dim">${esc(i.stale_reason)}</div>` : ""}</td>
        <td><button class="rv-btn ghost sm" data-plan="${esc(i.id)}">Record</button></td></tr>`).join("")}</tbody></table>
        <div id="plan-form"></div>` : ""}
    </div></div>
    <div class="rv-card"><div class="rv-card-head"><h3>Observations</h3></div><div class="rv-card-body">
      <p class="hint">What tools reported, before anyone decided it's a finding. Link the ones that share a root cause to one finding, dismiss the rest with the reason.</p>
      <div class="rv-form-row"><input id="obs-path" class="rv-input mono" placeholder="semgrep.json or evidence/authz/....json" aria-label="Tool output to import" spellcheck="false"><button id="obs-import" class="rv-btn sm">Import tool output</button></div>
      ${r.imports.length ? `<details><summary>${r.imports.length} import(s)</summary><ul class="rv-rows">${r.imports.map((i) => `<li><b>${esc(i.id)}</b> <span class="mono">${esc(i.path)}</span> <span class="rv-dim">${esc(i.parser || "no parser")} v${esc(i.parser_version)} · ${i.observations} observation(s), ${i.new} new · ${fmtTime(i.at)}</span>
        ${i.errors.map((x) => `<div class="err">${esc(x.type)}: ${esc(x.message)}${x.path ? ` (${esc(x.path)})` : ""}</div>`).join("")}${i.limitations.map((x) => `<div class="rv-dim">${esc(x)}</div>`).join("")}</li>`).join("")}</ul></details>` : ""}
      ${r.groups.length ? `<p class="rv-field-label">May share a root cause</p><ul class="rv-rows">${r.groups.map((g) => `<li><span class="mono">${esc(g.group_key)}</span> <span class="rv-dim">${esc(g.suggestion)}</span> <button class="rv-btn ghost sm" data-group="${esc(g.observations.join(","))}">Select</button></li>`).join("")}</ul>` : ""}
      <div class="rv-sev-filters">${["new", "linked", "duplicate", "dismissed", "all"].map((s) => `<button class="rv-sev-filter ${s === f ? "active" : ""}" data-obsf="${s}">${s} <span class="count">${nObs(s)}</span></button>`).join("")}</div>
      ${obs.length ? `<table class="rv-table rv-obs"><thead><tr><th><input type="checkbox" id="obs-all" aria-label="Select all"></th><th>Observation</th><th>Where</th><th>Status</th></tr></thead><tbody>${obs.map((o) => `<tr>
        <td><input type="checkbox" class="obs-cb" value="${esc(o.id)}" aria-label="Select ${esc(o.id)}"></td>
        <td><b>${esc(o.id)}</b> ${sevTag(o.severity || "info")} ${esc(o.title)}<div class="rv-dim">${esc(o.tool)}${o.rule_id ? " · " + esc(o.rule_id) : ""}${o.seen > 1 ? ` · seen ${o.seen} times` : ""}</div></td>
        <td class="mono">${esc(o.location)}</td>
        <td>${tag(o.status)}${o.finding_id ? ` <b>${esc(o.finding_id)}</b>` : ""}${o.duplicate_of ? ` of ${esc(o.duplicate_of)}` : ""}${o.reason ? `<div class="rv-dim">${esc(o.reason)}</div>` : ""}</td></tr>`).join("")}</tbody></table>
        <div class="rv-form-row"><input id="obs-fid" class="rv-input" placeholder="F-001" aria-label="Finding to link to" style="max-width:110px"><button id="obs-link" class="rv-btn sm">Link to finding</button>
          <input id="obs-reason" class="rv-input" placeholder="reason it's not an issue" aria-label="Dismiss reason"><button id="obs-dismiss" class="rv-btn ghost sm">Dismiss</button><button id="obs-reopen" class="rv-btn ghost sm">Reopen</button></div>`
        : `<div class="rv-empty">No observations${f === "all" ? " yet" : " with this status"}.</div>`}
    </div></div>
    <div class="rv-card"><div class="rv-card-head"><h3>Handover note</h3></div><div class="rv-card-body">
      <textarea id="inv-note" class="rv-input" rows="5" placeholder="What the next person (or the agent, when it resumes) should know that the records don't say.">${esc(h.note)}</textarea>
      ${h.note_updated ? `<p class="rv-dim">saved ${fmtTime(h.note_updated.at)} by ${esc(h.note_updated.by)}</p>` : ""}
      <div class="rv-actions start"><button id="inv-note-save" class="rv-btn sm">Save note</button></div>
      <details><summary>Handover as text (what the agent reads)</summary><pre class="rv-pre">${esc(h.markdown)}</pre></details>
    </div></div></div>`;
  const post = (what, body) => api(`/api/eng/${e}/${what}`, body);
  const sel = () => $$(".obs-cb").filter((c) => c.checked).map((c) => c.value);
  $("#inv-obj-save").addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post("objective", { text: $("#inv-obj").value, digest: r.objective_digest }), "Objective saved.")) reload(); });
  $("#inv-note-save").addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post("handover", { text: $("#inv-note").value, digest: h.note_digest }), "Note saved.")) reload(); });
  $("#inv-pb-add").addEventListener("click", async (ev) => {
    const x = await act(ev.currentTarget, () => post("plan", { op: "playbook", playbook: $("#inv-pb").value }));
    if (x) { toast(`${x.ids.length} test(s) added from ${x.playbook} (version ${x.version}).`); reload(); }
  });
  $("#inv-reassess").addEventListener("click", async (ev) => {
    const x = await act(ev.currentTarget, () => post("plan", { op: "reassess", build: $("#inv-build").value.trim() }));
    if (x) { toast(`${x.stale} test(s) now stale.`); reload(); }
  });
  $$("[data-obsf]").forEach((b) => b.addEventListener("click", () => { state.obsFilter = b.dataset.obsf; reload(); }));
  $$("[data-group]").forEach((b) => b.addEventListener("click", () => { const ids = b.dataset.group.split(","); $$(".obs-cb").forEach((c) => { c.checked = ids.includes(c.value); }); }));
  $("#obs-all")?.addEventListener("change", (ev) => $$(".obs-cb").forEach((c) => { c.checked = ev.target.checked; }));
  $("#obs-import").addEventListener("click", async (ev) => {
    const x = await act(ev.currentTarget, () => post("observation", { op: "import", path: $("#obs-path").value.trim() }));
    if (x) { toast(`${x.observations} observation(s), ${x.new} new${x.errors.length ? `, ${x.errors.length} parser error(s)` : ""}.`, !!x.errors.length); reload(); }
  });
  const triage = async (btn, body, msg) => {
    const ids = sel();
    if (!ids.length) { toast("Select observations first.", true); return; }
    if (await act(btn, () => post("observation", { ...body, ids }), msg)) reload();
  };
  $("#obs-link")?.addEventListener("click", (ev) => triage(ev.currentTarget, { op: "link", finding_id: $("#obs-fid").value.trim() }, "Linked."));
  $("#obs-dismiss")?.addEventListener("click", (ev) => triage(ev.currentTarget, { op: "dismiss", reason: $("#obs-reason").value.trim() }, "Dismissed."));
  $("#obs-reopen")?.addEventListener("click", (ev) => triage(ev.currentTarget, { op: "reopen" }, "Reopened."));
  $$("[data-plan]").forEach((b) => b.addEventListener("click", () => {
    const i = r.plan.find((x) => x.id === b.dataset.plan);
    $("#plan-form").innerHTML = `<div class="rv-editor"><p><b>${esc(i.id)}</b> ${esc(i.title)}</p>${i.hypothesis ? `<p class="rv-dim">${esc(i.hypothesis)}</p>` : ""}
      <div class="rv-form-grid">
        <label class="rv-field"><span class="rv-field-label">Outcome</span><select id="pf-state" class="rv-select">${COVERAGE.map((s) => `<option ${s === i.state ? "selected" : ""}>${s}</option>`).join("")}</select></label>
        <label class="rv-field"><span class="rv-field-label">Finding (when failed)</span><input id="pf-fid" class="rv-input" value="${esc(i.finding_id || "")}" placeholder="F-001"></label>
        <label class="rv-field"><span class="rv-field-label">Build it ran on</span><input id="pf-build" class="rv-input mono" value="${esc(i.build || "")}" spellcheck="false"></label>
      </div>
      <label class="rv-field"><span class="rv-field-label">Evidence (when tested; one path per line)</span><textarea id="pf-ev" class="rv-input mono" rows="2" spellcheck="false">${esc((i.evidence || []).join("\n"))}</textarea></label>
      <label class="rv-field"><span class="rv-field-label">Rationale (blocked, excluded, not applicable: why, and what would unblock it)</span><input id="pf-why" class="rv-input" value="${esc(i.rationale || "")}"></label>
      <div class="rv-actions start"><button id="pf-save" class="rv-btn sm accent">Save outcome</button></div></div>`;
    $("#pf-save").addEventListener("click", async (ev) => {
      const fields = { state: $("#pf-state").value, rationale: $("#pf-why").value.trim() || null, finding_id: $("#pf-fid").value.trim() || null,
        evidence: $("#pf-ev").value.split("\n").map((s) => s.trim()).filter(Boolean), build: $("#pf-build").value.trim() || null };
      Object.keys(fields).forEach((k) => fields[k] === null && delete fields[k]);
      if (await act(ev.currentTarget, () => post("plan", { op: "update", id: i.id, fields, revision: i.revision }), "Outcome recorded.")) reload();
    });
  }));
}

async function paneTasks() {
  const d = state.detail;
  const m = d.models || {}, allowed = d.info.rules.client_data;
  $("#pane").innerHTML = `<div id="tasks-sum" class="rv-card"><div class="rv-card-body"><span class="rv-dim">Loading the investigation…</span></div></div>
    <p class="hint">Tasks the planner handed to the worker model, newest first. Full output of every step is in
    <code>evidence/tasks/&lt;task&gt;/</code>.</p><div id="tasks-out" class="rv-empty">Loading…</div>`;
  (async () => {  // where the investigation stands (RW-018), above the tasks
    try {
      const [inv, lv] = await Promise.all([api(`/api/eng/${enc(d.engagement)}/investigation`), api(`/api/eng/${enc(d.engagement)}/live`).catch(() => ({}))]);
      if (state.tab !== "tasks" || state.current !== d.engagement) return;
      const h = inv.handover, sp = lv.spend, w = m.worker || {}, fb = m.worker_fallback || {};
      $("#tasks-sum").innerHTML = `<div class="rv-card-body"><dl class="rv-kv">
        <dt>Objective</dt><dd>${h.objective ? esc(h.objective) : `<span class="rv-dim">not set (Investigation tab)</span>`}</dd>
        <dt>Next</dt><dd>${esc(h.next[0] || "nothing pending")}</dd>
        <dt>Decisions</dt><dd>${h.pending.length ? `${h.pending.length} pending: ${h.pending.slice(0, 3).map((x) => esc(x.what)).join("; ")}${h.pending.length > 3 ? " …" : ""}` : "none pending"}</dd>
        <dt>Coverage</dt><dd>${h.coverage.total ? `${h.coverage.counts.planned} of ${h.coverage.total} planned test(s) not run${h.coverage.blocked.length ? `, ${h.coverage.blocked.length} blocked` : ""}${h.coverage.stale.length ? `, ${h.coverage.stale.length} stale` : ""}` : "no plan yet"}</dd>
        <dt>Worker model</dt><dd>${destTag(w.destination, allowed)} <span class="rv-dim">${esc(w.model || "")}</span>${fb.on ? ` <span class="rv-dim">fallback: ${esc(DEST[fb.destination] || fb.destination)}</span>` : ""}</dd>
        <dt>Spend today</dt><dd>${sp ? `$${sp.spend.toFixed(2)}${sp.budget ? ` of $${sp.budget.toFixed(2)} daily budget` : ""}` : `<span class="rv-dim">unknown</span>`}</dd>
      </dl></div>`;
    } catch (err) { $("#tasks-sum").innerHTML = `<div class="rv-card-body err">${esc(err.message)}</div>`; }
  })();
  const load = async () => {
    if (state.tab !== "tasks" || state.current !== d.engagement) return;
    try {
      const r = await api(`/api/eng/${enc(d.engagement)}/tasks`);
      $("#tasks-out").outerHTML = `<div id="tasks-out" class="rv-stack">${r.tasks.map((t) => `<details class="rv-card rv-task" ${["running", "awaiting_approval", "interrupted"].includes(t.status) ? "open" : ""}>
        <summary>${tag(t.status, t.status)} ${tag(t.tier, TIER_CLASS[t.tier] || "")}<span class="goal">${esc((t.goal || "").slice(0, 160))}</span></summary>
        <div class="rv-card-body">
          <div class="rv-meta"><span>${esc(t.id)}</span><span>started ${fmtTime(t.started)}</span>${t.finished ? `<span>${Math.max(0, Math.round((t.finished - t.started) / 60))} min</span>` : ""}
            <span>${t.steps.length} step(s)</span><span>${t.candidates} candidate(s)</span>${t.models.length ? `<span>model: ${t.models.map(esc).join(", ")}</span>` : ""}</div>
          ${t.approval ? `<p>Paused for approval <b>${esc(t.approval.id)}</b>: <code>${esc(t.approval.action)}</code>. Decide it on the Overview tab; the task then continues by itself.</p>` : ""}
          ${(t.depends_on || []).length ? `<p class="rv-dim">waits for ${t.depends_on.map(esc).join(", ")}</p>` : ""}
          ${t.error ? `<p class="err">${esc(t.error)}</p>` : ""}${t.summary ? `<p class="rv-prose">${esc(t.summary)}</p>` : ""}
          ${t.recovery ? `<p class="${t.recovery.decision === "needs_review" ? "err" : "rv-dim"}">After a restart: ${esc(t.recovery.note || t.recovery.decision)}${(t.recovery.uncertain || []).length ? ` (in flight: ${t.recovery.uncertain.map((u) => esc(u.action || u.tool)).join("; ")})` : ""}</p>` : ""}
          ${["queued", "waiting", "running", "awaiting_approval", "interrupted"].includes(t.status) ? `<div class="rv-actions start">
            ${t.status === "interrupted" ? `<button class="rv-btn sm" data-task="resume" data-id="${esc(t.id)}">Resume from checkpoint</button>` : `<button class="rv-btn ghost sm danger-quiet" data-task="cancel" data-id="${esc(t.id)}">Cancel task</button>`}</div>` : ""}
          ${t.steps.length ? `<pre class="rv-pre">${t.steps.map((s, i) => `<span class="ln">${String(i + 1).padStart(2, " ")}</span>  ${esc(s)}`).join("\n")}</pre>` : ""}
        </div></details>`).join("") || `<div class="rv-card"><div class="rv-empty">No worker tasks yet.</div></div>`}</div>`;
      $$("[data-task]").forEach((b) => b.addEventListener("click", async (ev) => {
        const ok = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/task`, { id: b.dataset.id, action: b.dataset.task }),
          b.dataset.task === "cancel" ? "Cancel requested." : "Resumed from its last checkpoint.");
        if (ok) setTimeout(load, 1500);
      }));
      if (r.tasks.some((t) => ["running", "queued", "waiting", "awaiting_approval"].includes(t.status))) setTimeout(load, 5000);
    } catch (e) { $("#tasks-out").textContent = e.message; }
  };
  load();
}

// ---------------------------------------------------------------- live run view
const dur = (s) => {
  s = Math.max(0, Math.round(s)); const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = s % 60;
  return h ? `${h}h ${String(m).padStart(2, "0")}m` : m ? `${m}m ${String(x).padStart(2, "0")}s` : `${x}s`;
};

function liveEvent(e) {
  const t = e.ts ? new Date(e.ts) : null;
  const time = t && !isNaN(t) ? t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
  const tier = e.tier ? tag(e.tier, TIER_CLASS[e.tier] || "") : "";
  let dot, body;
  if (e.refused) {
    dot = "c-critical";
    body = `<span>Refused: ${esc(e.refused)}</span>${e.command ? `<code>${esc(e.command)}</code>` : ""}`;
  } else if (e.action === "http") {
    const last = (e.hops || []).slice(-1)[0] || {};
    dot = last.status && last.status < 400 ? "c-ok" : "c-high";
    body = `<code>${esc(e.method)} ${esc(e.url)}</code><span class="rv-meta">${tier}<span>${esc(last.status || last.error || "no response")}</span>${(e.hops || []).length > 1 ? `<span>${e.hops.length - 1} redirect(s)</span>` : ""}${e.approval ? `<span>approval ${esc(e.approval)}</span>` : ""}</span>${(e.notes || []).map((n) => `<span class="rv-meta">${esc(n)}</span>`).join("")}`;
  } else if (e.command && e.exit !== undefined) {
    dot = e.exit === 0 ? "c-ok" : "c-high";
    body = `<code>${esc(e.command)}</code><span class="rv-meta">${tier}<span>exit ${esc(e.exit)}</span><span>${esc(e.seconds)} s</span>${e.approval ? `<span>approval ${esc(e.approval)}</span>` : ""}</span>`;
  } else {
    const ev = String(e.event || "event");
    dot = ev === "approval-requested" ? "c-medium" : ev === "halted" ? "c-critical" : "c-info";
    body = `<span>${esc(ev.replace(/-/g, " "))}</span>${e.command ? `<code>${esc(e.command)}</code>` : ""}`;
  }
  return `<li><time>${esc(time)}</time><span class="rv-dot ${dot}"></span><div class="what">${body}</div></li>`;
}

async function paneLive() {
  const d = state.detail, eng = d.engagement, gen = (state.liveGen = (state.liveGen || 0) + 1);
  const active = () => state.tab === "live" && state.current === eng && state.liveGen === gen;
  let skew = 0;
  const now = () => Date.now() / 1000 - skew;
  $("#pane").innerHTML = `<p class="hint">What this engagement is doing now. Refreshes every few seconds while this tab is open.</p><div id="live-out" class="rv-empty">Loading…</div>`;
  const tick = () => {
    $$("#live-out [data-since]").forEach((el) => { el.textContent = dur(now() - Number(el.dataset.since)); });
    $$("#live-out [data-meter]").forEach((el) => {
      const [s, t] = el.dataset.meter.split(",").map(Number);
      el.style.width = `${Math.min(100, (100 * (now() - s)) / t).toFixed(1)}%`;
    });
  };
  const kpi = (label, value, color, delta) => `<div class="rv-kpi"><span class="rv-label">${color ? `<span class="rv-dot ${color}"></span>` : ""}${label}</span><span class="rv-value">${value}</span><span class="rv-delta">${delta}</span></div>`;
  const render = (r) => {
    const busy = r.tasks.filter((t) => t.status === "running" || t.status === "queued");
    const first = r.running[0], last = r.events[0];
    let status;
    if (r.halted) {
      status = `<div class="rv-banner danger"><div class="rv-banner-body"><p class="rv-banner-title">Halted</p><p class="rv-banner-sub">Running commands were stopped and new ones are refused until you resume the engagement.</p></div></div>`;
    } else if (first || busy.length) {
      const title = first ? first.command : busy[0].steps.slice(-1)[0] || busy[0].goal;
      status = `<div class="rv-progress-status"><div style="min-width:0"><span class="rv-progress-status-label"><span class="rv-progress-dot"></span>Running</span>
        <p class="rv-progress-status-title"><code>${esc(String(title || "").slice(0, 240))}</code></p>
        <p class="rv-progress-elapsed">${r.running.length} command(s) running${busy.length ? ` · ${busy.length} worker task(s)` : ""}${first ? ` · for <span data-since="${Number(first.started)}"></span>` : ""}</p></div></div>`;
    } else {
      status = `<div class="rv-progress-status idle"><div><span class="rv-progress-status-label"><span class="rv-progress-dot"></span>Idle</span>
        <p class="rv-progress-status-title">Nothing running</p>
        <p class="rv-progress-elapsed">${last ? `Last activity ${fmtTime(last.ts)}` : "No activity yet. Start the agent in the OpenHands UI with the prompt on the Overview tab."}</p></div></div>`;
    }
    const sp = r.spend;
    // the budget is per provider, so the bar shows the provider closest to its cap
    const pct = sp && sp.budget ? Math.min(100, (100 * (sp.top ?? sp.spend)) / sp.budget) : 0;
    const provs = sp && sp.providers && sp.providers.length > 1 ? ` (${sp.providers.join(", ")})` : "";
    const spendKpi = sp ? kpi("Model spend today", `$${sp.spend.toFixed(2)}`, "", sp.budget ? `$${sp.budget.toFixed(2)} daily budget per provider${esc(provs)} · ${pct.toFixed(0)}%` : "no daily budget set")
      : kpi("Model spend today", "–", "", "LiteLLM isn't answering");
    const runs = r.running.map((c) => `<div class="rv-run">${tag(c.tier, TIER_CLASS[c.tier] || "")}<code>${esc(c.command)}</code>
        <span class="rv-elapsed"><span data-since="${Number(c.started)}"></span> / ${dur(c.timeout_s)}</span>
        <div class="rv-meter" title="Time used of the command's timeout"><span data-meter="${Number(c.started)},${Number(c.timeout_s) || 600}"></span></div></div>`).join("");
    const tasks = r.tasks.map((t) => `<div class="rv-run">${tag(t.status, t.status)}<span>${esc((t.goal || "").slice(0, 140))}</span>
        <span class="rv-elapsed">${t.status === "running" ? `<span data-since="${Number(t.started)}"></span>` : t.finished && t.started ? dur(t.finished - t.started) : ""}</span>
        <div class="rv-meta" style="grid-column:1/-1">${t.steps.length ? `<span>step ${t.steps.length}: ${esc(String(t.steps.slice(-1)[0]).slice(0, 120))}</span>` : "<span>no steps yet</span>"}${t.models.length ? `<span>model: ${t.models.map(esc).join(", ")}</span>` : ""}${t.candidates ? `<span>${esc(t.candidates)} candidate(s)</span>` : ""}</div></div>`).join("");
    $("#live-out").outerHTML = `<div id="live-out" class="rv-stack">
      ${status}
      ${r.approvals.length ? `<div class="rv-stack"><span class="rv-label">Waiting for your approval</span>${r.approvals.map((a) => approvalCard(a, false)).join("")}</div>` : ""}
      <div class="rv-stack"><div class="rv-kpi-grid">
        ${kpi("Running commands", r.running.length, r.running.length ? "c-low" : "", "in the Kali sandbox")}
        ${kpi("Worker tasks", busy.length, busy.length ? "c-low" : "", "running or queued")}
        ${kpi("Approvals", r.approvals.length, r.approvals.length ? "c-medium" : "", "waiting for you")}
        ${spendKpi}
      </div>${sp && sp.budget ? `<div class="rv-budget ${pct >= 90 ? "over" : ""}"><div class="rv-sev-bar" role="img" aria-label="Spend against the daily budget: ${pct.toFixed(0)}%"><span style="width:${pct.toFixed(1)}%"></span></div></div>` : ""}</div>
      <div class="rv-two">
        <div class="rv-stack">
          <div class="rv-card"><div class="rv-card-head"><h3>Running now</h3>${tag(String(r.running.length), r.running.length ? "running" : "")}</div>
            <div class="rv-card-body flush">${runs || `<div class="rv-empty">No command running.</div>`}</div></div>
          <div class="rv-card"><div class="rv-card-head"><h3>Worker</h3><button class="rv-btn ghost sm" data-goto="tasks">All tasks</button></div>
            <div class="rv-card-body flush">${tasks || `<div class="rv-empty">No worker tasks yet.</div>`}</div></div>
        </div>
        <div class="rv-card"><div class="rv-card-head"><h3>Latest events</h3><button class="rv-btn ghost sm" data-goto="audit">Audit log</button></div>
          <div class="rv-card-body flush">${r.events.length ? `<ol class="rv-timeline">${r.events.map(liveEvent).join("")}</ol>` : `<div class="rv-empty">No activity yet.</div>`}</div></div>
      </div></div>`;
    $$("#live-out [data-goto]").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.goto; renderDetail(); }));
    tick();
  };
  const show = (r) => {
    if (!active() || (r.topic && r.topic !== "live:" + eng)) return;
    if (r.error) { const o = $("#live-out"); if (o) o.textContent = r.error; return; }
    skew = Date.now() / 1000 - r.now;
    render(r);
  };
  state.onLive = show;
  if (state.live && state.live.topic === "live:" + eng) show(state.live);
  const load = async () => {  // only while the stream is down; otherwise "live" events call show()
    if (!active()) return;
    if (!document.hidden && !streamFresh()) {
      try { show(await api(`/api/eng/${enc(eng)}/live`)); }
      catch (e) { const o = $("#live-out"); if (o) o.textContent = e.message; }
    }
    setTimeout(load, 3000);
  };
  const timer = setInterval(() => { if (!active()) clearInterval(timer); else tick(); }, 1000);
  load();
}

// who did it: a person through the console or ./rvkit, or the agent (entries from before actors were recorded: none)
function actorTag(a) {
  if (!a) return `<span class="rv-dim">unknown</span>`;
  const [kind, name] = String(a).split(":", 2);
  return `<span class="rv-actor ${esc(kind)}" title="${esc(a)}">${esc(kind === "agent" ? "agent" : name || kind)}<span class="rv-dim"> ${esc(kind === "agent" ? name || "" : "via " + kind)}</span></span>`;
}

async function paneAudit() {
  const d = state.detail;
  $("#pane").innerHTML = `<p class="hint">Newest first. The authoritative log is in the kit's control volume.</p><div id="audit-out" class="rv-empty">Loading…</div>`;
  try {
    const r = await api(`/api/eng/${enc(d.engagement)}/audit?n=300`);
    $("#audit-out").outerHTML = `<div class="rv-table-wrap"><table class="rv-table"><thead><tr><th>Time</th><th>Who</th><th>What</th><th>Tier</th><th>Result</th></tr></thead><tbody>
      ${r.entries.map((e) => {
        const what = e.command ? `<code>${esc(e.command)}</code>` : `${esc(String(e.event || "").replace(/-/g, " "))}${e.target ? ` <span class="mono">${esc(e.target)}</span>` : ""}${e.fields ? ` <span class="rv-dim">${esc([].concat(e.fields).join(", "))}</span>` : ""}`;
        const rev = e.before !== undefined || e.after !== undefined ? `<span class="mono rv-dim">${esc(e.before ?? "new")} → ${esc(e.after ?? "")}</span>` : "";
        const res = e.refused ? `${tag("refused", "fail")} <span class="rv-dim">${esc(e.refused)}</span>` : e.exit !== undefined ? `<span class="mono">exit ${esc(e.exit)} · ${esc(e.seconds)}s</span>` : rev || esc(e.archive || e.status || "");
        return `<tr><td class="nowrap">${fmtTime(e.ts)}</td><td class="nowrap">${actorTag(e.actor)}</td><td>${what}</td><td>${e.tier ? tag(e.tier, TIER_CLASS[e.tier] || "") : ""}</td><td>${res}</td></tr>`;
      }).join("") || `<tr><td colspan="5"><div class="rv-empty">No activity yet.</div></td></tr>`}</tbody></table></div>`;
  } catch (e) { $("#audit-out").textContent = e.message; }
}

// ---------------------------------------------------------------- model log (litellm/rv_events.py)
// Failed model calls (no credits, budget used up, worker down, refusals nobody recovered from) and calls another model
// answered instead. Per engagement in its "Model log" tab; all of them on the Model log page.
function modelTable(events, withEng) {
  const head = `<th>Time</th>${withEng ? "<th>Engagement</th>" : ""}<th>Model</th><th>What happened</th><th>Result</th>`;
  const rows = events.map((e) => `<tr>
      <td class="nowrap">${fmtTime(e.ts)}</td>
      ${withEng ? `<td class="nowrap">${e.engagement ? `<a href="#eng-${esc(e.engagement)}">${esc(e.engagement)}</a>` : `<span class="rv-dim">none</span>`}</td>` : ""}
      <td class="nowrap"><span class="mono">${esc(e.model)}</span>${e.model_id ? `<div class="rv-dim mono sm">${esc(e.model_id.replace(/^openrouter\//, ""))}</div>` : ""}</td>
      <td class="rv-model-text">${esc(e.text || e.message)}${e.count > 1 ? ` <span class="rv-dim mono">x${e.count}</span>` : ""}</td>
      <td class="nowrap">${e.problem ? tag("failed", "fail") : tag("recovered", "ok")}</td></tr>`).join("");
  const cols = withEng ? 5 : 4;
  return `<div class="rv-table-wrap"><table class="rv-table"><thead><tr>${head}</tr></thead><tbody>${rows ||
    `<tr><td colspan="${cols}"><div class="rv-empty">No model problems in this period.</div></td></tr>`}</tbody></table></div>`;
}
async function loadModels() {
  const out = $("#models-out");
  try { const r = await api(`/api/models?since=${enc($("#models-since").value)}`); out.outerHTML = `<div id="models-out">${modelTable(r.events, true)}</div>`; }
  catch (e) { out.textContent = e.message; }
}
$("#models-refresh").addEventListener("click", loadModels);
$("#models-since").addEventListener("change", loadModels);
async function paneModels() {
  const d = state.detail;
  $("#pane").innerHTML = `<p class="hint">Model calls for this engagement that failed, or that another model answered instead (last 7 days, newest first). Calls not matched to an engagement are on the <a href="#models">Model log</a> page.</p><div id="models-eng" class="rv-empty">Loading…</div>`;
  try { const r = await api(`/api/models?eng=${enc(d.engagement)}`); $("#models-eng").outerHTML = modelTable(r.events, false); }
  catch (e) { $("#models-eng").textContent = e.message; }
}

// ---------------------------------------------------------------- new engagement
$("#new-btn").addEventListener("click", () => { $("#new-err").hidden = true; $("#new-dlg").showModal(); });
$("#new-cancel").addEventListener("click", () => $("#new-dlg").close());
$("#new-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target, btn = f.querySelector("button[type=submit]");
  const body = { name: f.name.value.trim(), client: f.client.value.trim(), targets: f.targets.value, rate: f.rate.value,
    network: f.network.value, private: f.private.checked, tiers: $$("input[name=tiers]:checked", f).map((i) => i.value) };
  btn.disabled = true;
  try {
    await api("/api/engagements", body);
    $("#new-dlg").close(); f.reset(); toast(`Engagement ${body.name} is active.`);
    await refresh(); location.hash = "eng-" + body.name;
  } catch (e) { $("#new-err").textContent = e.message; $("#new-err").hidden = false; }
  finally { btn.disabled = false; }
});

// ---------------------------------------------------------------- status
async function loadStatus() {
  $("#status-text").textContent = "Loading…";
  try { $("#status-text").textContent = (await api("/api/status")).text; } catch (e) { $("#status-text").textContent = e.message; }
}
$("#status-refresh").addEventListener("click", loadStatus);

refresh().then(route).then(connectStream);
setInterval(() => { if (!streamFresh()) { refresh(); connectStream(); } }, 5000);
