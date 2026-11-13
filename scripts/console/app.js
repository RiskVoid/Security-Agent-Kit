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
const TABS = { overview: "Overview", agent: "Agent", live: "Live", scope: "Scope & rules", investigation: "Investigation", findings: "Findings", tasks: "Worker tasks", testing: "Testing", report: "Report", audit: "Audit log", models: "Model calls" };

const state = { overview: null, current: null, detail: null, tab: "overview", seenApprovals: null, seenNotices: null, obsFilter: "new", findingFilter: "all", findingQuery: "", findingSev: "", findingPage: 0, findingTab: "details", openFinding: null, preview: null, evidence: null, view: "engagements" };

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
      if (f && $(".rv-fpanel-body")) $(".rv-fpanel-body").insertAdjacentHTML("afterbegin", `<div class="rv-banner warn"><div class="rv-banner-body">
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
  for (const v of ["engagements", "approvals", "status", "models", "kit"]) $(`#view-${v}`).hidden = v !== view;
  $$(".rv-sidebar-item[data-view]").forEach((a) => a.classList.toggle("active", a.dataset.view === view));
  document.body.classList.remove("nav-open");
  if (stream.es) connectStream();  // the live topic only while an engagement's Live tab shows
  // the engagements view is either the list to pick from or the open engagement, never both
  const open = view === "engagements" && !!state.current && !state.picking;
  $("#eng-picker").hidden = view === "engagements" && open; $("#detail").hidden = !open;
  $$(".rv-sidebar-item[data-view='engagements']").forEach((a) => a.classList.toggle("active", view === "engagements" && !open));
  renderEngNav();
  if (view === "status") { crumbs([["Console", "#engagements"], ["Stack status"]]); loadStatus(); }
  else if (view === "kit") { crumbs([["Console", "#engagements"], ["UI kit"]]); renderKit(); }
  else if (view === "models") { crumbs([["Console", "#engagements"], ["Model log"]]); loadModels(); }
  else if (view === "approvals") crumbs([["Console", "#engagements"], ["Approvals"]]);
  else crumbs(open ? [["Console", "#engagements"], ["Home", "#engagements"], [state.current, `#eng-${state.current}/overview`], [TABS[state.tab]]] : [["Console", "#engagements"], ["Home"]]);
}
// #engagements is the list; #eng-NAME/section is one section of one engagement, so sections can be linked and Back works
function route() {
  const h = location.hash.replace("#", "");
  if (h === "approvals" || h === "status" || h === "models" || h === "kit") return show(h);
  if (h.startsWith("eng-")) {
    const [name, sec, sub] = h.slice(4).split("/"), tab = TABS[sec] ? sec : "overview";
    // #eng-NAME/agent/<conversation id> opens that conversation in the Agent section
    const conv = tab === "agent" && /^[0-9a-f-]{8,64}$/i.test(sub || "") ? sub : null;
    state.picking = false;
    if (name !== state.current) { if (conv) state.agentConv = conv; openEngagement(name); state.tab = tab; }
    else if (tab !== state.tab || (conv && conv !== state.agentConv)) { state.tab = tab; if (conv) state.agentConv = conv; if (state.detail) { renderDetail(); window.scrollTo(0, 0); } }
  } else state.picking = true;
  show("engagements");
}

// The selected engagement's menu: its sections grouped by what you do there. Which engagement it is, and its state,
// are in the bar at the top of the page (renderDetail).
const NAV_GROUPS = [["Run", ["overview", "agent", "live", "tasks"]], ["Test", ["scope", "investigation", "testing"]], ["Results", ["findings", "report"]], ["Records", ["audit", "models"]]];
function renderEngNav() {
  const box = $("#eng-nav"), name = state.current;
  // The workspace menu above stays as it is. The selected engagement's menu sits under it from the moment an engagement
  // is opened until the user goes back to Home; it stays while they look at Approvals, Stack status or the Model log.
  const selected = !!name && !state.picking, here = selected && state.view === "engagements";
  box.hidden = !selected;
  if (!selected) { box.innerHTML = ""; return; }
  const d = state.detail && state.detail.engagement === name ? state.detail : null;
  const ov = (state.overview?.engagements || []).find((e) => e.engagement === name) || {};
  const count = (t) => !d ? "" : t === "overview" && d.approvals.length ? `<span class="rv-count danger" title="waiting for your approval">${d.approvals.length}</span>`
    : t === "findings" && d.findings.length ? `<span class="rv-count">${d.findings.length}</span>`
    : t === "models" && ov.model_problems ? `<span class="rv-count danger" title="failed model calls">${ov.model_problems}</span>` : "";
  box.innerHTML = `${NAV_GROUPS.map(([group, tabs]) => `<div class="rv-side-label">${group}</div><nav class="rv-side-nav" aria-label="${group}">${tabs.map((t) => `<a class="rv-sidebar-item sub ${here && state.tab === t ? "active" : ""}" href="#eng-${esc(name)}/${t}" ${here && state.tab === t ? `aria-current="page"` : ""}><span>${TABS[t]}</span>${count(t)}</a>`).join("")}</nav>`).join("")}`;
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
    renderList(); renderApprovals(); renderEngNav();
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

// Home: every engagement as a row, with search, a filter by state and a pager.
const ENG_FILTERS = [["all", "All"], ["needs", "Needs you"], ["active", "Active"], ["halted", "Halted"], ["closed", "Closed"]];
const ENG_PILL = { active: "ok", halted: "bad", closed: "closed" };
const engNeeds = (e) => (e.pending || 0) + ((e.findings || {}).candidate || 0) > 0;
const engIs = (e, f) => f === "all" || (f === "needs" ? engNeeds(e) : engState(e)[0] === f);
function renderList() {
  const all = state.overview?.engagements || [], q = $("#eng-filter").value.trim().toLowerCase(), f = state.engFilter || "all";
  const sum = (k) => all.reduce((a, e) => a + ((e.findings || {})[k] || 0), 0);
  $("#eng-sum").innerHTML = `<span>${all.length} engagement${all.length === 1 ? "" : "s"}</span><span>${all.reduce((a, e) => a + (e.pending || 0), 0)} approval(s) waiting</span><span>${sum("confirmed")} confirmed finding(s) open</span><span>${sum("candidate")} to triage</span>`;
  $("#eng-chips").innerHTML = ENG_FILTERS.map(([k, label]) => { const n = all.filter((e) => engIs(e, k)).length; return `<button class="rv-chip ${k === f ? "active" : ""} ${n ? "" : "empty"}" aria-pressed="${k === f}" data-engf="${k}">${label} <span class="count">${n}</span></button>`; }).join("");
  const rows = all.filter((e) => engIs(e, f) && has(q, [e.engagement, e.client, ...(e.targets || [])]));
  const [page, from, pages, p] = pageOf(rows, state.engPage || 0);
  state.engPage = p;
  $("#eng-list").innerHTML = rows.length ? `<div class="rv-dl" style="--cols:minmax(200px, 1.5fr) 104px minmax(150px, 1.2fr) 120px minmax(140px, 1fr) 180px;--minw:940px"><div class="rv-dl-in">
      <div class="rv-dl-head"><span>Engagement</span><span>State</span><span>Targets</span><span>Tiers</span><span>Findings</span><span>Needs you</span></div>
      ${page.map((e) => {
        const c = e.findings || {}, [label] = engState(e), t = e.targets || [], tiers = e.tiers || [];
        const top = ["intrusive", "active", "passive"].find((x) => tiers.includes(x));
        return `<a class="rv-dl-row tall link" href="#eng-${esc(e.engagement)}/overview">
          <span class="two"><b title="${esc(e.engagement)}">${esc(e.engagement)}</b><small title="${esc(e.client || "")}">${esc(e.client || "no client name")}</small></span>
          <span>${pill(label, ENG_PILL[label])}</span>
          <span class="two"><span class="mono" title="${esc(t.join(", "))}">${esc(t[0] || "no targets")}</span><small>${t.length > 1 ? `+${t.length - 1} more · ` : ""}${esc(e.network || "")}${e.worker === "private" ? " · private worker" : ""}</small></span>
          <span>${top ? (tiers.length > 1 ? `Up to ${top}` : `${cap(top)} only`) : "none"}</span>
          <span class="two"><span>${c.confirmed || 0} confirmed</span><small>${c.candidate || 0} to triage · ${c.fixed || 0} fixed</small></span>
          <span class="cell">${e.pending ? pill(`${e.pending} approval${e.pending === 1 ? "" : "s"} waiting`, "bad") : c.candidate ? pill(`${c.candidate} to triage`, "warn") : `<span class="rv-dim">nothing</span>`}</span></a>`;
      }).join("")}
    </div></div>${pagerHtml(from, page.length, rows.length, p, pages)}` : `<div class="rv-empty">${all.length ? "No engagement matches these filters." : "No engagements yet. Create one with New engagement."}</div>`;
}
$("#eng-chips").addEventListener("click", (ev) => { const b = ev.target.closest("[data-engf]"); if (b) { state.engFilter = b.dataset.engf; state.engPage = 0; renderList(); } });
$("#eng-list").addEventListener("click", (ev) => { const b = ev.target.closest("[data-page]"); if (b) { state.engPage = (state.engPage || 0) + Number(b.dataset.page); renderList(); } });
$("#eng-filter").addEventListener("input", () => { state.engPage = 0; renderList(); });

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
  const [label] = engState({ ...ov, halted: i.halted });
  $("#detail").innerHTML = `
    <div class="rv-eng-bar">
      <div class="who">
        <div class="name"><b>${esc(d.engagement)}</b>${pill(label, ENG_PILL[label])}</div>
        <div class="rv-meta"><span>${esc(d.meta.client || "No client name yet")}</span><span>${esc(r.network)}</span><span>max ${esc(r.max_rate)}/s</span>${r.worker === "private" ? "<span>private worker</span>" : ""}<span>tiers: ${esc((r.tiers || []).join(", ") || "none")}</span></div>
      </div>
      <div class="rv-detail-actions">
        ${i.halted ? `<button id="resume-btn" class="rv-btn">Resume</button>` : `<button id="halt-btn" class="rv-btn danger">Halt now</button>`}
        <button id="close-btn" class="rv-btn">Close out</button>
        <button id="delete-btn" class="rv-btn danger-quiet">Delete</button>
      </div>
    </div>
    <div id="confirm-slot"></div>
    <h1 class="rv-h-display rv-sec-title">${TABS[state.tab]}</h1>
    <div id="pane" class="rv-pane" role="region" aria-label="${TABS[state.tab]}"></div>`;
  // the sections are links in the sidebar; keep the address in step when a section is opened from inside a page
  if (state.view === "engagements" && !state.picking) {
    const want = `#eng-${d.engagement}/${state.tab}`;
    if (location.hash !== want && !(state.tab === "agent" && location.hash.startsWith(want + "/"))) history.replaceState(null, "", want);
    crumbs([["Console", "#engagements"], ["Home", "#engagements"], [d.engagement, `#eng-${d.engagement}/overview`], [TABS[state.tab]]]);
  }
  renderEngNav();
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
  ({ overview: paneOverview, agent: paneAgent, live: paneLive, scope: paneScope, investigation: paneInvestigation, findings: paneFindings, tasks: paneTasks, testing: paneTesting, report: paneReport, audit: paneAudit, models: paneModels })[state.tab]();
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
  const total = conf.length, convs = Array.isArray(d.conversations) ? d.conversations : [];
  const prompt = `Engagement \`${d.engagement}\`: <what to test>. Follow the matching playbooks, then write the executive summary and generate the report.`;
  // each tile opens the findings it counts
  const kpi = (label, value, mark, note, status, sev = "") => `<button class="rv-kpi ${value ? "" : "zero"}" data-kstatus="${status}" data-ksev="${sev}">
    <span class="rv-label">${mark}${label}</span><span class="rv-value">${value}</span><span class="rv-delta">${note}</span></button>`;
  const sq = (s) => `<span class="rv-sev c-${s}"><span class="mark"></span></span>`;
  const next = (title, sub, action = "", cls = "") => `<div class="rv-next ${cls}"><div class="body"><span class="rv-label">${cls === "idle" ? "Status" : "Next step"}</span><b>${title}</b><span class="sub">${sub}</span></div>${action}</div>`;
  const go = (tab, label, filter = "") => `<button class="rv-btn accent" data-goto="${tab}" data-ffilter="${filter}">${label}</button>`;
  // the one thing that needs the operator, from what this page already knows; otherwise the report's state decides (below)
  const first = i.halted ? next("This engagement is halted", "Running commands were stopped and new ones are refused until you resume it.", "", "danger")
    : d.approvals.length ? next(`${d.approvals.length} command${d.approvals.length === 1 ? " waits" : "s wait"} for your approval`, "Each approval works once, for that exact command. After you approve, tell the agent to run it again.")
    : c.candidate ? next(`${c.candidate} finding${c.candidate === 1 ? "" : "s"} to triage`, "Confirm each one, or close it as a false positive or a duplicate.", go("findings", "Open findings", "candidate"))
    : !convs.length && !d.findings.length ? next("Start the agent on this engagement", "No conversation is bound yet. Start one below; it follows this engagement's rules, and halting stops it.")
    : "";
  $("#pane").innerHTML = `
    <div id="ov-next">${first}</div>
    ${d.approvals.length ? `<div class="rv-stack">${d.approvals.map((a) => approvalCard(a, false)).join("")}</div>` : ""}
    <div class="rv-stack">
      <div class="rv-kpi-grid">
        ${kpi("Critical", n.critical, sq("critical"), "open, confirmed", "confirmed", "critical")}
        ${kpi("High", n.high, sq("high"), "open, confirmed", "confirmed", "high")}
        ${kpi("Medium", n.medium, sq("medium"), "open, confirmed", "confirmed", "medium")}
        ${kpi("Low / info", n.low + n.info, sq("low"), "open, confirmed", "confirmed")}
        ${kpi("To triage", c.candidate || 0, "", `${c["false-positive"] || 0} false positive · ${c.duplicate || 0} duplicate`, "candidate")}
        ${kpi("Fixed", c.fixed || 0, "", `${c["accepted-risk"] || 0} accepted risk`, "fixed")}
      </div>
      ${total ? `<div class="rv-sev-bar" aria-label="Confirmed findings by severity">${SEV.map((s) => n[s] ? `<span style="width:${(100 * n[s] / total).toFixed(1)}%;background:var(--rv-sev-${s})"></span>` : "").join("")}</div>` : ""}
    </div>
    <div class="rv-two">
      <div class="rv-card"><div class="rv-card-head"><h3>Scope and rules</h3><button class="rv-btn ghost" data-goto="scope">Edit</button></div>
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
    ${conversationsCard(d)}
    ${credentialsCard(d)}`;
  bindConversations(d, prompt);
  bindCredentials(d);
  const bindGoto = () => $$("#pane [data-goto]").forEach((b) => { b.onclick = () => { if (b.dataset.ffilter) { state.findingFilter = b.dataset.ffilter; state.findingPage = 0; } state.tab = b.dataset.goto; renderDetail(); }; });
  bindGoto();
  $$("[data-kstatus]").forEach((b) => b.addEventListener("click", () => {
    Object.assign(state, { findingFilter: b.dataset.kstatus, findingSev: b.dataset.ksev, findingPage: 0, findingQuery: "", tab: "findings" }); renderDetail();
  }));
  if (first) return;
  (async () => {  // nothing urgent on this page: say where the report stands
    let r;
    try { r = await api(`/api/eng/${enc(d.engagement)}/delivery`); } catch { return; }
    if (state.tab !== "overview" || state.current !== d.engagement || !$("#ov-next")) return;
    const v = r.revisions[0], open = go("report", "Open report");
    $("#ov-next").innerHTML = !v ? (d.findings.some((f) => ["confirmed", "fixed"].includes(f.status)) ? next("Generate the report", "There are reported findings and no report revision yet.", open)
        : next("Nothing needs you right now", "No approvals are waiting and there is nothing to triage.", "", "idle"))
      : v.state === "ready" ? next(`Report ${esc(v.id)} is ready`, "Review it, then approve it for delivery.", open)
      : v.state === "approved" && !v.transmissions.length ? next(`Report ${esc(v.id)} is approved`, "Record the sending once it is with the client.", open)
      : v.state === "generated" ? next(`${r.readiness.blocking.length} check${r.readiness.blocking.length === 1 ? " blocks" : "s block"} delivery of ${esc(v.id)}`, "Fix them or record an exception, then generate the report again.", open)
      : next("Nothing needs you right now", `Report ${esc(v.id)} is ${esc(v.state)}${v.transmissions.length ? " and its sending is recorded" : ""}.`, "", "idle");
    bindGoto();
  })();
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
  return `<div class="rv-card"><div class="rv-card-head"><h3>Conversations <span class="rv-dim">${rows.length}</span></h3><a class="rv-btn ghost" href="${esc(state.overview?.ui_url || "#")}" target="_blank" rel="noopener">Open agent UI ↗</a></div>
    ${rows.length ? `<div class="rv-dl" style="--cols:minmax(0, 1fr) 130px 90px;--minw:440px"><div class="rv-dl-in">${rows.map((c) => `<div class="rv-dl-row tall">
      <span class="two"><a href="#eng-${esc(d.engagement)}/agent/${esc(c.id)}" title="${esc(c.title || c.id)}">${esc(c.title || c.id)}</a><small>${esc(c.id.slice(0, 8))} · bound ${fmtTime(c.bound)} · <a href="${esc(c.url)}" target="_blank" rel="noopener">OpenHands ↗</a></small></span>
      <span>${c.status ? pill(c.status, c.status === "running" ? "ok" : "closed") : ""}</span>
      <span class="acts"><button class="rv-btn ghost" data-unbind="${esc(c.id)}">Unbind</button></span></div>`).join("")}</div></div>` : ""}
    <div class="rv-card-body">
      ${err ? `<p class="err">${esc(err)}</p>` : ""}
      ${rows.length ? "" : `<p class="hint">No conversation is bound to this engagement yet. A bound conversation follows the engagement: its client-data rule applies to every model it uses, and halting stops it.</p>`}
      <label class="rv-field"><span class="rv-field-label">First message for a new conversation (optional)</span>
        <textarea id="conv-msg" class="rv-input" rows="2" placeholder="What to test, e.g. a web assessment of the in-scope app; follow the playbooks and write the report."></textarea></label>
      <div class="rv-actions start"><button id="conv-new" class="rv-btn">New conversation</button><button id="copy-prompt" class="rv-btn ghost">${ICON_COPY} Copy starter prompt</button></div>
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
  return `<div class="rv-card"><div class="rv-card-head"><h3>Credentials <span class="rv-dim">${cs.length}</span></h3></div>
    ${cs.length ? `<div class="rv-dl" style="--cols:minmax(120px, 1fr) minmax(200px, 1.4fr) 270px;--minw:660px"><div class="rv-dl-in">
      <div class="rv-dl-head"><span>Name</span><span>Stored</span><span></span></div>
      ${cs.map((c) => `<div class="rv-dl-row"><b class="mono" title="${esc(c.name)}">${esc(c.name)}</b>
        <span title="${esc(c.set_by || "")}">${fmtTime(c.set_at)}${c.set_by ? ` · ${esc(c.set_by)}` : ""}</span>
        <span class="acts"><button class="rv-btn ghost" data-copy="$${esc(c.env)}" title="Copy $${esc(c.env)}, the reference for commands">${ICON_COPY} Command</button>
          <button class="rv-btn ghost" data-copy="${esc(c.ref)}" title="Copy ${esc(c.ref)}, the reference for requests">${ICON_COPY} Request</button>
          <button class="rv-btn ghost danger-quiet" data-credrm="${esc(c.name)}">Remove</button></span></div>`).join("")}</div></div>` : ""}
    <div class="rv-card-body">
      <p class="hint">The agent uses a credential by reference: $RV_CRED_NAME in commands, {{cred:NAME}} in requests. The value never reaches the model and is replaced by the reference in output and evidence.</p>
      <div class="rv-form-row"><input id="cred-name" class="rv-input" placeholder="NAME" autocomplete="off" spellcheck="false" maxlength="32" aria-label="Credential name">
        <input id="cred-value" class="rv-input" type="password" placeholder="value" autocomplete="new-password" aria-label="Credential value">
        <button id="cred-save" class="rv-btn">Store</button></div>
    </div></div>`;
}
function bindCredentials(d) {
  $("#cred-save").addEventListener("click", async (ev) => {
    const name = $("#cred-name").value.trim().toUpperCase(), value = $("#cred-value").value;
    const r = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/cred`, { name, value }), `${name} stored.`);
    $("#cred-value").value = "";
    if (r) openEngagement(d.engagement, true);
  });
  $$("[data-copy]").forEach((b) => b.addEventListener("click", () => navigator.clipboard.writeText(b.dataset.copy).then(() => toast(`Copied ${b.dataset.copy}`)).catch(() => toast("Copy failed.", true))));
  $$("[data-credrm]").forEach((b) => b.addEventListener("click", async (ev) => {
    const r = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/cred`, { name: b.dataset.credrm, remove: true }), "Removed.");
    if (r) openEngagement(d.engagement, true);
  }));
}

function paneScope() {
  const d = state.detail, p = state.preview;
  $("#pane").innerHTML = `
    <div class="rv-card"><div class="rv-card-head"><h3>Scope and rules <span class="rv-dim">revision ${esc(d.info.revision ?? "")} in force</span></h3>
        <span class="rv-actions"><button id="preview-btn" class="rv-btn">Preview changes</button><button id="apply-btn" class="rv-btn accent" ${p && p.diff && !(p.errors || []).length ? "" : "disabled"}>Apply</button></span></div>
      <div class="rv-card-body"><p class="hint">Edit either file, preview what changes, then apply. Applying rebuilds the engagement's firewall at once; Apply stays off until a preview shows a change without errors.</p>
    <div class="rv-two">
      <label class="rv-field"><span class="rv-field-label">SCOPE.md</span><textarea id="scope-text" class="rv-input" rows="14" spellcheck="false">${esc(d.scope_text)}</textarea></label>
      <label class="rv-field"><span class="rv-field-label">RULES.md</span><textarea id="rules-text" class="rv-input" rows="14" spellcheck="false">${esc(d.rules_text)}</textarea></label>
    </div></div></div>
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

// ---------------------------------------------------------------- findings
// A list with search, status and severity filters and a pager; the selected finding opens in a panel beside the list.
const STATUS_LABEL = { all: "All", candidate: "To triage", confirmed: "Confirmed", "false-positive": "False positive", duplicate: "Duplicate", fixed: "Fixed", "accepted-risk": "Accepted risk" };
const STATUS_DOT = { candidate: "warn", confirmed: "open", fixed: "ok" };
const FINDING_PAGE = 25;
const ICON_SEARCH = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>`;
const ICON_CLOSE = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg>`;
const cap = (s) => String(s || "").replace(/^./, (c) => c.toUpperCase());
const statusPill = (f) => `<span class="rv-pill ${STATUS_DOT[f.status] || "closed"}"><span class="rv-dot"></span>${esc(STATUS_LABEL[f.status] || f.status)}${f.duplicate_of ? " of " + esc(f.duplicate_of) : ""}</span>`;
const sevMark = (s) => `<span class="rv-sev c-${esc(s)}"><span class="mark"></span><span class="word">${esc(cap(s))}</span></span>`;

function findingRows() {
  const filt = state.findingFilter, q = state.findingQuery.trim().toLowerCase(), sev = state.findingSev;
  const closed = (f) => (f.status === "candidate" || f.status === "confirmed" ? 0 : 1);
  return state.detail.findings
    .filter((f) => (filt === "all" || f.status === filt) && (!sev || f.severity === sev)
      && (!q || [f.id, f.title, f.asset, f.cwe].some((v) => String(v || "").toLowerCase().includes(q))))
    .sort((a, b) => closed(a) - closed(b) || SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || a.id.localeCompare(b.id));
}

function paneFindings() {
  const d = state.detail, filt = state.findingFilter, ev = state.evidence;
  const n = (s) => d.findings.filter((f) => s === "all" || f.status === s).length;
  const cur = d.findings.find((f) => f.id === state.openFinding);
  if (!cur) state.openFinding = null;
  $("#pane").innerHTML = `
    <div class="rv-toolbar">
      <div class="rv-search">${ICON_SEARCH}<input id="f-q" class="rv-input" type="search" placeholder="Search title, id, asset, CWE" aria-label="Search findings" value="${esc(state.findingQuery)}"></div>
      <div class="rv-chipset" role="group" aria-label="Status">${["all", ...STATUSES].map((s) => `<button class="rv-chip ${s === filt ? "active" : ""} ${n(s) ? "" : "empty"}" aria-pressed="${s === filt}" data-filter="${s}">${STATUS_LABEL[s]} <span class="count">${n(s)}</span></button>`).join("")}</div>
      <select id="f-sev" class="rv-select fit" aria-label="Severity"><option value="">Any severity</option>${SEV.map((s) => `<option value="${s}" ${s === state.findingSev ? "selected" : ""}>${cap(s)}</option>`).join("")}</select>
    </div>
    ${ev && ev.issues.length ? `<div class="rv-banner danger"><div class="rv-banner-body"><p class="rv-banner-title">Evidence problems</p><ul>${ev.issues.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div></div>` : ""}
    <div class="rv-findings ${cur ? "has-open" : ""}">
      <section class="rv-flist" aria-label="Findings"><div id="f-rows"></div>
        <div class="rv-evrow"><span class="rv-ok-note">${!ev ? "Evidence files are checked against the hashes recorded when the sandbox produced them."
          : ev.issues.length ? `<span class="rv-dot c-critical"></span>${ev.issues.length} evidence problem${ev.issues.length === 1 ? "" : "s"}, listed above`
          : `<span class="rv-dot c-ok"></span>Every evidence file matches its recorded hash`}</span>
          <button id="ev-btn" class="rv-btn">${ev ? "Check again" : "Check evidence integrity"}</button></div></section>
      ${cur ? findingPanel(cur, ev) : ""}
    </div>`;

  const row = (f) => `<button class="rv-frow ${state.openFinding === f.id ? "selected" : ""}" aria-pressed="${state.openFinding === f.id}" data-fid="${esc(f.id)}">
      ${sevMark(f.severity)}
      <span class="body"><span class="title">${esc(f.title)}</span>
        <span class="meta">${[f.id, f.asset || "no asset", f.cwe, f.verification === "verified" ? "verified" : f.verification === "not-reproducible" ? "not reproducible" : ""].filter(Boolean).map(esc).join(" · ")}</span></span>
      <span class="pri">${esc(f.priority || "")}</span>
      ${statusPill(f)}
    </button>`;
  const fill = () => {
    const rows = findingRows(), pages = Math.max(1, Math.ceil(rows.length / FINDING_PAGE));
    state.findingPage = Math.max(0, Math.min(state.findingPage, pages - 1));
    const from = state.findingPage * FINDING_PAGE, page = rows.slice(from, from + FINDING_PAGE);
    $("#f-rows").innerHTML = rows.length ? `<div class="rv-fhead" aria-hidden="true"><span>Severity</span><span>Finding</span><span class="pri">Pri</span><span>Status</span></div>
      ${page.map(row).join("")}
      <div class="rv-pager"><span>${from + 1}–${from + page.length} of ${rows.length}</span>
        ${pages > 1 ? `<span class="rv-pager-nav"><button class="rv-btn ghost" data-page="-1" ${state.findingPage ? "" : "disabled"}>Previous</button><span>Page ${state.findingPage + 1} of ${pages}</span><button class="rv-btn ghost" data-page="1" ${state.findingPage < pages - 1 ? "" : "disabled"}>Next</button></span>` : ""}
        <span>Open first, then by severity</span></div>`
      : `<div class="rv-empty">${d.findings.length ? "No findings match these filters." : "No findings yet."}</div>`;
    $$("#f-rows [data-fid]").forEach((b) => b.addEventListener("click", () => {
      state.openFinding = state.openFinding === b.dataset.fid ? null : b.dataset.fid; state.findingTab = "details"; paneFindings();
    }));
    $$("#f-rows [data-page]").forEach((b) => b.addEventListener("click", () => { state.findingPage += Number(b.dataset.page); fill(); }));
  };
  fill();

  $$("[data-filter]").forEach((b) => b.addEventListener("click", () => { state.findingFilter = b.dataset.filter; state.findingPage = 0; paneFindings(); }));
  $("#f-q").addEventListener("input", (e) => { state.findingQuery = e.target.value; state.findingPage = 0; fill(); });
  $("#f-sev").addEventListener("change", (e) => { state.findingSev = e.target.value; state.findingPage = 0; fill(); });
  $("#ev-btn").addEventListener("click", async (e) => {
    const r = await act(e.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/evidence`));
    if (r) { state.evidence = r; paneFindings(); }
  });
  if (!cur) return;

  $("#fe-close").addEventListener("click", () => { state.openFinding = null; paneFindings(); });
  // the panel's sections are shown and hidden, not rendered again, so an unsaved edit survives a look at the evidence
  const showTab = async (t) => {
    if (!$(`[data-fsec="${t}"]`)) t = "details";
    state.findingTab = t;
    $$("[data-ftab]").forEach((b) => { const on = b.dataset.ftab === t; b.classList.toggle("active", on); b.setAttribute("aria-selected", on); });
    $$("[data-fsec]").forEach((s) => { s.hidden = s.dataset.fsec !== t; });
    const box = $("#fe-history");
    if (t === "history" && !box.dataset.loaded) {
      box.dataset.loaded = "1";
      const id = state.openFinding, h = await act(null, () => api(`/api/eng/${enc(d.engagement)}/history?id=${enc(id)}`));
      if (state.openFinding !== id || !$("#fe-history")) return;
      if (h) $("#fe-history").innerHTML = historyHtml(h); else delete $("#fe-history").dataset.loaded;
    }
  };
  $$("[data-ftab]").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.ftab)));
  showTab(state.findingTab);

  const save = $("#fe-save");
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
  $$("[data-preview]").forEach((b) => b.addEventListener("click", async (ev) => {
    const pv = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/preview?path=${enc(b.dataset.preview)}`));
    if (pv) $("#fe-preview").innerHTML = previewBox(pv);
  }));
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
function findingPanel(f, ev) {
  const items = ev?.items?.[f.id] || (f.evidence || []).map((p) => ({ path: p }));
  const inst = f.instances || [];
  const opt = (list, cur, label = (s) => s) => list.map((s) => `<option value="${s}" ${s === cur ? "selected" : ""}>${label(s)}</option>`).join("");
  const tabs = [["details", "Details"], ["evidence", `Evidence <span class="n">${items.length}</span>`], ...(inst.length ? [["instances", `Instances <span class="n">${inst.length}</span>`]] : []), ["history", "History"]];
  const block = (label, html) => `<div class="rv-fblock"><span class="rv-field-label">${label}</span>${html}</div>`;
  return `<aside class="rv-fpanel" aria-label="Finding ${esc(f.id)}">
    <div class="rv-fpanel-head">
      <div class="top"><span class="mono rv-muted">${esc(f.id)}</span>
        ${tag(f.verification || "unverified", { verified: "ok", "not-reproducible": "warn" }[f.verification] || "")}
        <button id="fe-close" class="rv-btn ghost icon" aria-label="Close finding">${ICON_CLOSE}</button></div>
      <h2>${esc(f.title)}</h2>
      <div class="rv-meta"><span>${esc(f.asset || "no asset")}</span>${f.cwe ? `<span>${esc(f.cwe)}</span>` : ""}${f.cvss_score != null ? `<span>CVSS ${esc(f.cvss_score)}${f.cvss_rating ? ` (${esc(f.cvss_rating)})` : ""}</span>` : ""}</div>
    </div>
    <div class="rv-fpanel-body">
      <div class="rv-fprops">
        <label class="rv-field"><span class="rv-field-label">Status</span><select id="fe-status" class="rv-select">${opt(STATUSES, f.status, (s) => STATUS_LABEL[s])}</select></label>
        <label class="rv-field"><span class="rv-field-label">Severity</span><select id="fe-sev" class="rv-select">${opt(SEV, f.severity, cap)}</select></label>
        <label class="rv-field"><span class="rv-field-label">Priority</span><select id="fe-prio" class="rv-select"><option value="">Not set</option>${opt(PRIORITIES, f.priority)}</select></label>
        <label id="fe-method-wrap" class="rv-field" hidden><span class="rv-field-label">Verified by</span><select id="fe-method" class="rv-select"><option value="">not stated</option>${opt(METHODS, "")}</select></label>
        <label id="fe-dup-wrap" class="rv-field" ${f.status === "duplicate" ? "" : "hidden"}><span class="rv-field-label">Duplicate of</span><input id="fe-dup" class="rv-input" value="${esc(f.duplicate_of || "")}" placeholder="F-001"></label>
      </div>
      <div class="rv-subtabs" role="tablist" aria-label="Finding sections">${tabs.map(([t, label]) => `<button role="tab" class="rv-subtab" data-ftab="${t}" aria-selected="false">${label}</button>`).join("")}</div>
      <div class="rv-fsec" data-fsec="details">
        ${block("Description", `<p class="rv-prose">${esc(f.description)}</p>`)}
        ${f.reproduction ? block("Reproduction", `<pre class="rv-pre">${esc(f.reproduction)}</pre>`) : ""}
        ${f.remediation ? block("Remediation", `<p class="rv-prose">${esc(f.remediation)}</p>`) : ""}
        <label class="rv-field"><span class="rv-field-label">CVSS 3.1 vector (the score is computed)</span><input id="fe-cvss" class="rv-input mono" value="${esc(f.cvss_vector || "")}" placeholder="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" spellcheck="false"></label>
        <label class="rv-field"><span class="rv-field-label">Prerequisites</span><input id="fe-prereq" class="rv-input" value="${esc(f.prerequisites || "")}" placeholder="an account in another tenant"></label>
        <label class="rv-field"><span class="rv-field-label">Notes</span><textarea id="fe-notes" class="rv-input" rows="3">${esc(f.notes)}</textarea></label>
        <div class="rv-meta">${f.verified_by ? `<span>verified by ${esc(f.verified_by)}${f.verified_method ? ", " + esc(f.verified_method) : ""}, ${fmtTime(f.verified_at)}</span>` : ""}
          <span>${esc(f.source)}</span><span>updated ${fmtTime(f.updated)}</span><span>revision ${esc(f.revision)}</span></div>
      </div>
      <div class="rv-fsec" data-fsec="evidence" hidden>
        ${items.length ? `<ul class="rv-evidence">${items.map((i) => `<li><span class="rv-code-chip">${esc(i.path)}</span>${evidenceBadge(i.status)}${!String(i.path).startsWith("/src/") ? `<button class="rv-btn ghost" data-preview="${esc(i.path)}">View</button>` : ""}${i.note ? `<span class="rv-dim note">${esc(i.note)}</span>` : ""}</li>`).join("")}</ul>` : `<p class="hint">No evidence is attached to this finding.</p>`}
        <div id="fe-preview"></div>
      </div>
      ${inst.length ? `<div class="rv-fsec" data-fsec="instances" hidden><ul class="rv-evidence">${inst.map((i) => `<li><span class="rv-code-chip">${esc(i.location || i)}</span>${i.observation ? `<span class="rv-dim note">${esc(i.observation)}</span>` : ""}</li>`).join("")}</ul></div>` : ""}
      <div class="rv-fsec" data-fsec="history" hidden><div id="fe-history"><p class="hint">Loading the history…</p></div></div>
    </div>
    <div class="rv-fpanel-foot">
      <label class="rv-field"><span id="fe-reason-label" class="rv-field-label">Reason (optional)</span><input id="fe-reason" class="rv-input" maxlength="2000" placeholder="why: kept with the decision in the finding's history"></label>
      <div class="rv-actions">${f.status === "confirmed" || f.status === "candidate" ? `<button id="fe-nr" class="rv-btn ghost danger-quiet" title="Record that a retest couldn't reproduce it (needs the reason)">Not reproducible</button>` : ""}<button id="fe-save" class="rv-btn accent">Save changes</button></div>
    </div>
  </aside>`;
}

function paneReport() {
  const d = state.detail, m = d.meta;
  $("#pane").innerHTML = `
    <ol id="rep-steps" class="rv-stepper" aria-label="Delivery steps"></ol>
    <div id="gen-out"></div>
    <div id="rep-latest"><div class="rv-card"><div class="rv-empty">Loading revisions…</div></div></div>
    <div id="rep-ready"></div>
    <div class="rv-card"><div class="rv-card-head"><h3>Report content</h3><button id="gen-btn" class="rv-btn">Generate report</button></div>
      <div class="rv-card-body">
        <div class="rv-form-grid">
          <label class="rv-field"><span class="rv-field-label">Client</span><input id="m-client" class="rv-input" value="${esc(m.client || "")}"></label>
          <label class="rv-field"><span class="rv-field-label">Prepared by</span><input id="m-by" class="rv-input" value="${esc(m["prepared by"] || "")}"></label>
          <label class="rv-field"><span class="rv-field-label">Version</span><input id="m-ver" class="rv-input" value="${esc(m.version || "1.0")}"></label>
          <label class="rv-field"><span class="rv-field-label">Classification</span><input id="m-cls" class="rv-input" value="${esc(m.classification || "Confidential")}"></label>
        </div>
        <div class="rv-actions"><button id="m-save" class="rv-btn">Save cover details</button></div>
        <label class="rv-field"><span class="rv-field-label">Executive summary (markdown)</span>
          <textarea id="exec" class="rv-input" rows="10" placeholder="3–5 paragraphs: what was assessed, overall posture, the most important findings in business terms, and the top priorities.">${esc(d.executive_summary)}</textarea></label>
        <div class="rv-actions"><button id="exec-save" class="rv-btn">Save summary</button></div>
      </div></div>
    <div id="delivery-out" class="rv-stack"></div>`;
  $("#m-save").addEventListener("click", async (e) => {
    const r = await act(e.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/meta`,
      { client: $("#m-client").value, "prepared by": $("#m-by").value, version: $("#m-ver").value, classification: $("#m-cls").value, digest: d.meta_digest }), "Saved.");
    if (r) { d.meta = r.meta; d.meta_digest = r.digest; refresh(); reportSteps(); }
  });
  $("#exec-save").addEventListener("click", async (e) => {
    const r = await act(e.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/summary`, { text: $("#exec").value, digest: d.summary_digest }), "Saved.");
    if (r) { d.executive_summary = $("#exec").value; d.summary_digest = r.digest; reportSteps(); }
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

const REV_PILL = { approved: "ok", ready: "ok", generated: "warn", superseded: "closed" };
const EXT_ORDER = ["pdf", "docx", "html", "xlsx", "json"];
const EXT_LABEL = { pdf: "Report", docx: "Report", html: "Report", xlsx: "Findings", json: "Frozen inputs" };
const fileExt = (n) => String(n).split(".").pop().toLowerCase();
const byExt = (names) => [...names].sort((a, b) => (EXT_ORDER.indexOf(fileExt(a)) + 1 || 9) - (EXT_ORDER.indexOf(fileExt(b)) + 1 || 9) || a.localeCompare(b));
const fileHref = (eng, p) => `/files/${enc(eng)}/${p.split("/").map(enc).join("/")}`;
const fileLink = (eng, p) => `<a href="${fileHref(eng, p)}">${esc(p.split("/").pop())}</a>`;
// a report file as a tile: the format is what you pick by, the long name is the tooltip
const fileTile = (eng, p) => { const name = p.split("/").pop(), x = fileExt(name); return `<a class="rv-file" href="${fileHref(eng, p)}" title="${esc(name)}"><span class="ext">${esc(x)}</span><span class="body"><b>${EXT_LABEL[x] || esc(name)}</b><small>Download</small></span></a>`; };

// the six steps from cover details to a recorded sending; the first one not done is the next thing to do
function reportSteps() {
  const d = state.detail, r = state.delivery, box = $("#rep-steps");
  if (!box || !r || r.engagement !== d.engagement) return;
  const m = d.meta, latest = r.revisions[0], rd = r.readiness, approved = !!latest && latest.state === "approved";
  const steps = [
    ["Cover details", !!(m.client && m["prepared by"]), m.client ? (m["prepared by"] ? "" : "prepared by is empty") : "client is empty"],
    ["Executive summary", !!String(d.executive_summary || "").trim(), ""],
    ["Readiness checks", !!rd.ready, rd.ready ? "" : `${rd.blocking.length} blocking`],
    ["Generate", !!latest, latest ? latest.id : ""],
    ["Approve", approved, ""],
    ["Record sending", approved && latest.transmissions.length > 0, ""],
  ];
  const cur = steps.findIndex((s) => !s[1]);
  box.innerHTML = steps.map(([name, ok, note], i) => `<li class="${ok ? "done" : i === cur ? "now" : ""}"><span class="st">${ok ? "Done" : i === cur ? "Next" : "Later"}${note ? " · " + esc(note) : ""}</span><b>${name}</b></li>`).join("");
}

async function loadDelivery() {
  const d = state.detail, e = enc(d.engagement);
  let r;
  try { r = await api(`/api/eng/${e}/delivery`); } catch (err) { $("#rep-latest").innerHTML = `<div class="rv-card"><div class="rv-empty err">${esc(err.message)}</div></div>`; return; }
  if (state.tab !== "report" || state.current !== d.engagement || !$("#rep-latest")) return;
  state.delivery = { ...r, engagement: d.engagement };
  const rd = r.readiness, latest = r.revisions[0], earlier = r.revisions.slice(1);
  const reported = d.findings.filter((f) => ["confirmed", "fixed"].includes(f.status));
  const material = d.findings.filter((f) => f.status === "confirmed" && ["critical", "high"].includes(f.severity));
  const html = (d.report_files || []).filter((f) => f.endsWith(".html"));
  const post = (body) => api(`/api/eng/${e}/delivery`, body);
  const again = () => { state.revForm = null; loadDelivery(); };
  const files = (v) => byExt(Object.keys(v.artifacts)).map((n) => `revisions/${v.id}/${n}`);
  const story = (v) => [v.approved_by ? `Approved by ${esc(v.approved_by)}, ${fmtTime(v.approved_at)}${v.approval_note ? ": " + esc(v.approval_note) : ""}` : "",
    v.superseded_by ? `Superseded by ${esc(v.superseded_by)}` : "", ...v.transmissions.map((t) => `Sent to ${esc(t.to)} via ${esc(t.channel)} (${esc(t.by)}, ${fmtTime(t.at)})`)].filter(Boolean);
  const form = (v) => {
    const f = state.revForm;
    if (!f || f.id !== v.id) return "";
    return f.kind === "approve" ? `<div class="rv-dl-detail"><p>Approve <b>${esc(v.id)}</b> for client delivery. Approval checks that nothing changed since it was generated and that its files match their hashes; it doesn't send anything.</p>
        <input id="ap-note" class="rv-input" placeholder="note (optional): what you reviewed" aria-label="Approval note">
        <div class="rv-actions start"><button id="ap-save" class="rv-btn accent">Approve ${esc(v.id)}</button><button class="rv-btn ghost" data-revcancel="1">Cancel</button></div></div>`
      : `<div class="rv-dl-detail"><p>Record that <b>${esc(v.id)}</b> was sent. This is a record only; nothing is sent from here.</p><div class="rv-form-grid">
        <label class="rv-field"><span class="rv-field-label">To</span><input id="tx-to" class="rv-input" placeholder="client security lead"></label>
        <label class="rv-field"><span class="rv-field-label">How</span><input id="tx-ch" class="rv-input" placeholder="client portal upload"></label></div>
        <div class="rv-actions start"><button id="tx-save" class="rv-btn accent">Record sending</button><button class="rv-btn ghost" data-revcancel="1">Cancel</button></div></div>`;
  };

  const render = () => {
    // one primary action on the page: approve a ready revision, else record the sending of an approved one, else generate
    const canApprove = latest && latest.state === "ready", canSend = latest && latest.state === "approved";
    $("#gen-btn").classList.toggle("accent", !canApprove && !(canSend && latest.transmissions.length));
    reportSteps();
    $("#rep-latest").innerHTML = latest ? `<div class="rv-card rv-rev-latest ${canApprove ? "focus" : ""}">
        <div class="rv-rev-head"><div class="body">
            <div class="top"><h3>${esc(latest.id)}</h3>${pill(latest.state, REV_PILL[latest.state])}<span class="rv-dim">Latest revision</span></div>
            <p>Generated ${fmtTime(latest.created)}${latest.actor ? " by " + esc(latest.actor) : ""}. ${canApprove ? "Nothing blocks delivery: review it, then approve it." : latest.state === "generated" ? "Not ready for the client: see the readiness checks." : ""}</p>
            ${story(latest).map((s) => `<p class="rv-dim">${s}</p>`).join("")}</div>
          <span class="rv-actions">
            ${html.length ? `<a class="rv-btn" href="/report/${e}/${enc(html[0])}" target="_blank" rel="noopener">View HTML report ↗</a>` : ""}
            <button class="rv-btn ghost" data-verify="${esc(latest.id)}">Verify hashes</button><button class="rv-btn ghost" data-rebuild="${esc(latest.id)}">Rebuild</button>
            ${canApprove ? `<button class="rv-btn accent" data-revform="approve" data-rev="${esc(latest.id)}">Approve for delivery</button>` : ""}
            ${canSend ? `<button class="rv-btn ${latest.transmissions.length ? "" : "accent"}" data-revform="sent" data-rev="${esc(latest.id)}">Record sending</button>` : ""}</span></div>
        <div class="rv-files">${files(latest).map((p) => fileTile(d.engagement, p)).join("")}</div>
        ${form(latest)}
        <div class="rv-rev-foot"><button id="exp-btn" class="rv-btn ghost">Export findings (JSON, SARIF, issues)</button><label class="rv-check"><input type="checkbox" id="exp-draft"> as DRAFT</label><span id="exp-out"></span></div>
      </div>` : `<div class="rv-card"><div class="rv-card-head"><h3>No revision yet</h3></div>
        <div class="rv-card-body"><p class="hint">Fill in the report content below, then Generate report creates R-001 with the HTML, Word, PDF and Excel files.</p></div>
        ${(d.report_files || []).length ? `<div class="rv-files">${byExt(d.report_files).map((p) => fileTile(d.engagement, p)).join("")}</div>` : ""}</div>`;

    const exc = r.exceptions.filter((x) => !x.revoked_at);
    $("#rep-ready").innerHTML = `<div class="rv-card"><div class="rv-card-head"><h3>Readiness for delivery</h3>${rd.ready ? pill("nothing blocks", "ok") : pill(`${rd.blocking.length} blocking`, "bad")}</div>
      ${rd.blocking.length || rd.excepted.length || rd.warnings.length || exc.length ? `<div class="rv-dl" style="--cols:150px minmax(0, 1fr) 100px;--minw:520px"><div class="rv-dl-in">
        ${rd.blocking.map((b) => `<div class="rv-dl-row wrap"><span>${tag(b.check.split(":")[0], "fail")}</span><span>${esc(b.issue)}</span>
          <span class="acts">${r.exceptable.includes(b.check.split(":")[0]) ? `<button class="rv-btn" data-except="${esc(b.check)}">Except</button>` : ""}</span></div>`).join("")}
        ${rd.excepted.map((x) => `<div class="rv-dl-row wrap"><span>${tag(x.check)}</span><span>${esc(x.issue)}<small>Excepted: ${esc(x.rationale)} (${esc(x.by)}, ${fmtTime(x.at)})</small></span><span></span></div>`).join("")}
        ${rd.warnings.map((w) => `<div class="rv-dl-row wrap"><span>${tag("warning", "warn")}</span><span>${esc(w)}</span><span></span></div>`).join("")}
        ${exc.map((x) => `<div class="rv-dl-row wrap"><span>${tag(x.check_key)}</span><span>Exception in force: ${esc(x.rationale)}<small>${esc(x.actor)}</small></span>
          <span class="acts"><button class="rv-btn ghost danger-quiet" data-revoke="${x.id}">Revoke</button></span></div>`).join("")}
      </div></div>` : `<div class="rv-card-body"><p class="hint">Every check passes.</p></div>`}
      <div id="except-form"></div></div>`;

    $("#delivery-out").innerHTML = `
      ${earlier.length ? `<div class="rv-card"><div class="rv-card-head"><h3>Earlier revisions <span class="rv-dim">${earlier.length}</span></h3></div>
        <div class="rv-dl" style="--cols:56px 112px minmax(160px, 1fr) 250px;--minw:620px"><div class="rv-dl-in">
        <div class="rv-dl-head"><span>Rev</span><span>State</span><span>What happened</span><span></span></div>
        ${earlier.map((v) => { const s = story(v), open = state.revOpen === v.id; return `<div class="rv-dl-row tall"><b>${esc(v.id)}</b><span>${pill(v.state, REV_PILL[v.state])}</span>
          <span class="two"><b title="${s[0] || ""}">${s[0] || `Generated ${fmtTime(v.created)}`}</b><small>${s.length > 1 ? `${s.length - 1} more event${s.length > 2 ? "s" : ""} · ` : ""}generated ${fmtTime(v.created)}</small></span>
          <span class="acts">${v.state === "approved" ? `<button class="rv-btn" data-revform="sent" data-rev="${esc(v.id)}">Record sending</button>` : ""}
            <button class="rv-btn ${open ? "" : "ghost"}" data-revopen="${esc(v.id)}" aria-expanded="${open}">${open ? "Hide" : "Files and details"}</button></span></div>${form(v)}
          ${open ? `<div class="rv-dl-detail">${s.map((x) => `<p>${x}</p>`).join("")}<p class="rv-dim">Generated ${fmtTime(v.created)}${v.actor ? " by " + esc(v.actor) : ""}</p>
            <div class="rv-files flat">${files(v).map((p) => fileTile(d.engagement, p)).join("")}</div>
            <div class="rv-actions start"><button class="rv-btn" data-verify="${esc(v.id)}">Verify hashes</button><button class="rv-btn" data-rebuild="${esc(v.id)}">Rebuild from frozen inputs</button></div></div>` : ""}`; }).join("")}
        </div></div></div>` : ""}

      <div class="rv-card"><div class="rv-card-head"><h3>Retests <span class="rv-dim">${r.retests.length}</span></h3></div>
        ${r.retests.length ? `<div class="rv-dl" style="--cols:64px 64px 120px minmax(0, 1fr);--minw:560px"><div class="rv-dl-in">${r.retests.map((t) => `<div class="rv-dl-row wrap"><b>${esc(t.id)}</b><span class="mono">${esc(t.finding_id)}</span>
          <span>${pill(t.outcome, { resolved: "ok", partial: "warn", unresolved: "bad" }[t.outcome])}</span>
          <span>Build ${esc(t.retest_build)}${t.original_build ? ` (found on ${esc(t.original_build)})` : ""}<small>${t.cases.map((c) => `${esc(c.name)}: ${esc(c.result)}`).join("; ")} · ${esc(t.actor)}, ${fmtTime(t.at)}${t.reauthorization ? ` · re-authorized: ${esc(t.reauthorization)}` : ""}</small></span></div>`).join("")}</div></div>` : ""}
        <div class="rv-card-body">${r.retests.length ? "" : `<p class="hint">No retests yet.</p>`}
        ${reported.length ? `<details><summary>Record a retest</summary><div class="rv-stack" style="margin-top:12px"><div class="rv-form-grid">
          <label class="rv-field"><span class="rv-field-label">Finding</span><select id="rt-f" class="rv-select">${reported.map((f) => `<option>${esc(f.id)}</option>`).join("")}</select></label>
          <label class="rv-field"><span class="rv-field-label">Retested on build</span><input id="rt-build" class="rv-input mono" spellcheck="false"></label>
          <label class="rv-field"><span class="rv-field-label">Outcome</span><select id="rt-out" class="rv-select"><option>resolved</option><option>partial</option><option>unresolved</option></select></label></div>
          <label class="rv-field"><span class="rv-field-label">Cases (one per line: name | pass, fail or partial | evidence path of the retest)</span><textarea id="rt-cases" class="rv-input mono" rows="3" spellcheck="false" placeholder="other tenant reads invoice | pass | evidence/authz/run-2.json"></textarea></label>
          <label class="rv-field"><span class="rv-field-label">Scope or access re-authorized (who, when), if it was needed</span><input id="rt-reauth" class="rv-input"></label>
          <div class="rv-actions start"><button id="rt-save" class="rv-btn">Record retest</button></div></div></details>` : ""}</div></div>

      <div class="rv-card"><div class="rv-card-head"><h3>Cleanup and retention <span class="rv-dim">${r.obligations.length}</span></h3></div>
        ${r.obligations.length ? `<div class="rv-dl" style="--cols:64px 104px 96px minmax(0, 1fr) 150px;--minw:640px"><div class="rv-dl-in">${r.obligations.map((o) => `<div class="rv-dl-row wrap"><b>${esc(o.id)}</b><span>${tag(o.kind)}</span>
          <span>${pill(o.state, { done: "ok", open: "warn" }[o.state])}</span><span>${esc(o.what)}${o.note ? `<small>${esc(o.note)} (${esc(o.updated_by)})</small>` : ""}</span>
          <span class="acts">${o.state === "open" ? `<button class="rv-btn" data-ob="${esc(o.id)}" data-st="done">Done</button><button class="rv-btn ghost" data-ob="${esc(o.id)}" data-st="waived">Waive</button>` : ""}</span></div>`).join("")}</div></div>` : ""}
        <div class="rv-card-body">${r.obligations.length ? "" : `<p class="hint">Nothing recorded: test data, fixture changes, credentials to revoke and what to keep or delete at close-out.</p>`}
          <div class="rv-form-row"><select id="ob-kind" class="rv-select" aria-label="Kind" style="flex:0 0 150px">${["fixture", "credential", "data", "access", "retention", "other"].map((k) => `<option>${k}</option>`).join("")}</select><input id="ob-what" class="rv-input" placeholder="delete the test invoices created in tenant B" aria-label="Obligation"><button id="ob-add" class="rv-btn">Add</button></div></div></div>

      <div class="rv-card"><div class="rv-card-head"><h3>Material finding notices <span class="rv-dim">${r.notices.length}</span></h3></div>
        ${r.notices.length ? `<div class="rv-dl" style="--cols:64px minmax(0, 1fr) 110px 190px;--minw:560px"><div class="rv-dl-in">${r.notices.map((n) => `<div class="rv-dl-row wrap"><b>${esc(n.id)}</b>
          <span>${esc(n.finding_id)} revision ${esc(n.finding_revision)}<small>${fileLink(d.engagement, n.path.replace(/^report\//, ""))}</small></span><span>${pill(n.state, n.state === "reviewed" ? "ok" : "warn")}</span>
          <span class="acts">${n.reviewed_by ? `<span class="rv-dim">reviewed by ${esc(n.reviewed_by)}</span>` : `<button class="rv-btn" data-review="${esc(n.id)}">Mark reviewed</button>`}</span></div>`).join("")}</div></div>` : ""}
        <div class="rv-card-body">${r.notices.length ? "" : `<p class="hint">A notice is a draft for the client about one confirmed critical or high finding, reviewed by you before it's shared. Nothing is sent from here.</p>`}
          ${material.length ? `<div class="rv-form-row"><select id="nt-f" class="rv-select" aria-label="Finding" style="flex:0 0 150px">${material.map((f) => `<option>${esc(f.id)}</option>`).join("")}</select><button id="nt-add" class="rv-btn">Prepare notice</button></div>` : ""}</div></div>`;
    bind();
  };

  const bind = () => {
    $$("[data-revform]").forEach((b) => b.addEventListener("click", () => {
      const same = state.revForm && state.revForm.id === b.dataset.rev && state.revForm.kind === b.dataset.revform;
      state.revForm = same ? null : { id: b.dataset.rev, kind: b.dataset.revform }; render();
      ($("#ap-note") || $("#tx-to"))?.focus();
    }));
    $$("[data-revopen]").forEach((b) => b.addEventListener("click", () => { state.revOpen = state.revOpen === b.dataset.revopen ? null : b.dataset.revopen; render(); }));
    $$("[data-revcancel]").forEach((b) => b.addEventListener("click", () => { state.revForm = null; render(); }));
    $("#ap-save")?.addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post({ op: "approve", revision: state.revForm.id, note: $("#ap-note").value }), "Approved for delivery.")) again(); });
    $("#tx-save")?.addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post({ op: "transmitted", revision: state.revForm.id, to: $("#tx-to").value, channel: $("#tx-ch").value }), "Recorded.")) again(); });
    $$("[data-except]").forEach((b) => b.addEventListener("click", () => {
      $("#except-form").innerHTML = `<div class="rv-dl-detail"><p>Exception for <b>${esc(b.dataset.except)}</b>: recorded with your name and shown in the revision.</p>
        <input id="ex-why" class="rv-input" placeholder="why the methodology allows this, e.g. the client excluded load testing in the kickoff on 3 Nov" aria-label="Rationale"><div class="rv-actions start"><button id="ex-save" class="rv-btn">Record exception</button></div></div>`;
      $("#ex-save").addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post({ op: "exception", check: b.dataset.except, rationale: $("#ex-why").value }), "Exception recorded. Generate the report again.")) again(); });
      $("#ex-why").focus();
    }));
    $$("[data-revoke]").forEach((b) => b.addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post({ op: "revoke", id: Number(b.dataset.revoke) }), "Revoked.")) again(); }));
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
      if (x) $("#exp-out").innerHTML = `${esc(x.revision)} (${esc(x.state)}): ${Object.keys(x.files).map((n) => fileLink(d.engagement, `${x.folder.replace(/^report\//, "")}/${n}`)).join(" · ")}`;
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
  };
  render();
}

// ---------------------------------------------------------------- authenticated testing (RW-008 to RW-011)
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

const SESSION_PILL = { valid: "ok", expired: "bad", error: "bad", challenge: "warn", denied: "warn", revoked: "closed", unchecked: "closed" };
const VERDICT_KIND = { FAIL: "fail", blocked: "blocked", "unexpected-deny": "unexpected" };
const VERDICT_WORD = { fail: "Fail", blocked: "Blocked: not tested", unexpected: "Unexpected deny", pass: "Pass" };
const cellKind = (c) => VERDICT_KIND[c.verdict] || "pass";

// One run of a matrix as a grid: operations down, identities across. Only a failure is filled, so it is what you see first.
function matrixGrid(m, res, ids, view) {
  const cells = res.cells, key = (c) => c.operation + "\n" + c.identity;
  const ops = [...new Set(cells.map((c) => c.operation))];
  const cols = [...new Set([...m.identities, ...cells.map((c) => c.identity)])].filter((i) => cells.some((c) => c.identity === i));
  const at = new Map(cells.map((c) => [key(c), c]));
  // the request behind an operation: every cell of a run carries its method and URL
  const route = (o) => { const c = cells.find((x) => x.operation === o && x.url); return c ? `${c.method || "GET"} ${c.url}` : ""; };
  const who = (name) => { const i = ids.find((x) => x.name === name); return i ? [i.role, i.tenant].filter(Boolean).join(" · ") : name === "anonymous" ? "no session" : ""; };
  const count = (k) => cells.filter((c) => cellKind(c) === k).length;
  const f = view.filter || "all", match = (c) => f === "all" || cellKind(c) === f;
  const rows = ops.filter((o) => cols.some((i) => at.has(o + "\n" + i) && match(at.get(o + "\n" + i))));
  const sel = (view.cell && at.get(view.cell)) || cells.find((c) => cellKind(c) === "fail") || null;
  const why = {};
  cells.filter((c) => cellKind(c) === "blocked").forEach((c) => {
    const k = cols.reduce((s, i) => s.split(i).join("…"), String(c.reason || "no reason given"));
    why[k] = (why[k] || 0) + 1;
  });
  const chips = [["all", "All cells", cells.length], ["fail", "Fail", count("fail")], ["unexpected", "Unexpected deny", count("unexpected")], ["blocked", "Blocked", count("blocked")], ["pass", "Pass", count("pass")]]
    .filter(([k, , n]) => k !== "unexpected" || n);
  const cell = (o, i) => {
    const c = at.get(o + "\n" + i);
    if (!c) return `<span class="rv-mx-none" title="Not part of this run">–</span>`;
    const k = cellKind(c);
    return `<button class="rv-mx-cell ${k} ${esc(c.outcome)} ${c === sel ? "selected" : ""} ${match(c) ? "" : "dim"}" data-cell="${cells.indexOf(c)}" aria-pressed="${c === sel}"
      aria-label="${esc(`${o} as ${i}: ${VERDICT_WORD[k]}, expected ${c.expected}, got ${c.outcome}`)}">${esc(cap(c.outcome))}</button>`;
  };
  return `<div class="rv-toolbar rv-mx-bar"><div class="rv-chipset" role="group" aria-label="Verdict">${chips.map(([k, label, n]) => `<button class="rv-chip ${k === f ? "active" : ""} ${n ? "" : "empty"}" aria-pressed="${k === f}" data-mxf="${k}">${label} <span class="count">${n}</span></button>`).join("")}</div>
      <span class="rv-toolbar-end rv-ok-note">Last run ${fmtTime(res.at)}</span></div>
    ${Object.keys(why).length ? `<div class="rv-mx-note"><b>${count("blocked")} cell(s) could not be tested.</b> ${Object.entries(why).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span><b>${n}</b> ${esc(k)}</span>`).join("")}</div>` : ""}
    <div class="rv-mx" style="--n:${cols.length}">
      <div class="rv-mx-grid">
        ${rows.length ? `<div class="rv-mx-table">
          <span class="rv-label">Operation</span>${cols.map((i) => `<span class="rv-mx-col" title="${esc(i)}"><b>${esc(i)}</b><small>${esc(who(i))}</small></span>`).join("")}
          ${rows.map((o) => `<span class="rv-mx-op" title="${esc(route(o) || o)}"><b>${esc(o)}</b>${route(o) ? `<small>${esc(route(o).replace(/^(\S+ )https?:\/\//, "$1"))}</small>` : ""}</span>${cols.map((i) => cell(o, i)).join("")}`).join("")}
        </div>` : `<div class="rv-empty">No cell has this verdict.</div>`}
        <div class="rv-mx-legend"><span><i class="fail"></i>Fail: allowed, should be denied</span><span><i class="blocked"></i>Blocked: not tested</span><span><i></i>Pass: as expected</span></div>
      </div>
      <aside class="rv-mx-side" aria-label="Selected cell">${sel ? `<span class="rv-label">Selected cell</span>
        <b class="rv-mx-title">${esc(sel.operation)} as ${esc(sel.identity)}</b>
        <span class="rv-mx-verdict ${cellKind(sel)}">${VERDICT_WORD[cellKind(sel)]}</span>
        <dl class="rv-kv">${route(sel.operation) ? `<dt>Request</dt><dd class="mono">${esc(route(sel.operation))}</dd>` : ""}<dt>Expected</dt><dd>${esc(cap(sel.expected))}</dd><dt>Got</dt><dd>${esc(cap(sel.outcome))}</dd>
          <dt>Why</dt><dd>${esc(sel.reason || "no reason recorded")}</dd>${who(sel.identity) ? `<dt>Identity</dt><dd>${esc(who(sel.identity))}</dd>` : ""}</dl>
        <span class="rv-meta">${esc(res.file)}</span>` : `<p class="hint">Select a cell to see what was expected and what came back.</p>`}</aside>
    </div>`;
}

async function paneTesting() {
  const d = state.detail, e = enc(d.engagement);
  if (!$("#testing-out")) $("#pane").innerHTML = `<p class="hint">Test identities, request captures and authorization matrices. Secrets stay on this machine: the agent
    sees identity names, roles, tenants and sanitized captures, never a password, token or cookie.</p><div id="testing-out" class="rv-empty">Loading…</div>`;
  let r;
  try { r = await api(`/api/eng/${e}/testing`); } catch (err) { $("#testing-out").textContent = err.message; return; }
  if (state.tab !== "testing" || state.current !== d.engagement || !$("#testing-out")) return;
  const ids = r.identities || [], caps = r.captures || [], mats = r.matrices || [];
  const idOpts = `<option value="">no identity</option>` + ids.map((i) => `<option>${esc(i.name)}</option>`).join("");
  const idCols = "minmax(100px, 1.2fr) 100px 76px 76px 92px minmax(90px, 2fr) 128px";
  const idRow = (i) => {
    const st = i.status.state || "unchecked", open = state.openIdentity === i.name;
    return `<div class="rv-dl-row"><b>${esc(i.name)}</b>
        <span><span class="rv-pill ${SESSION_PILL[st] || "closed"}"><span class="rv-dot"></span>${esc(cap(st))}</span></span>
        <span>${esc(i.role || "–")}</span><span>${esc(i.tenant || "–")}</span><span>${esc(i.effects.join(", "))}</span>
        <span class="mono" title="${esc(i.hosts.join(", "))}">${esc(i.hosts.join(", "))}</span>
        <span class="acts"><button class="rv-btn" data-idop="check" data-name="${esc(i.name)}">Check</button>
          <button class="rv-btn ghost" data-idopen="${esc(i.name)}" aria-expanded="${open}">${open ? "Hide" : "Details"}</button></span></div>
      ${open ? `<div class="rv-dl-detail"><dl class="rv-kv">
          <dt>Session</dt><dd>${esc(i.status.reason || "not checked yet")}</dd>
          <dt>Sign-in</dt><dd>${esc(i.kind)}</dd>
          <dt>Owns</dt><dd>${i.fixtures.length ? i.fixtures.map((f) => esc(`${f.kind} ${f.id}`)).join(", ") : `<span class="rv-dim">no fixture records</span>`}</dd>
          <dt>Hosts</dt><dd>${codeChips(i.hosts)}</dd></dl>
        <div class="rv-actions start">${st !== "revoked" ? `<button class="rv-btn danger-quiet" data-idop="revoke" data-name="${esc(i.name)}">Revoke session</button>` : ""}
          <button class="rv-btn danger-quiet" data-idop="rm" data-name="${esc(i.name)}">Remove identity</button></div></div>` : ""}`;
  };
  const capCols = "minmax(140px, 2fr) minmax(90px, 1fr) 90px 100px 90px 150px 130px";
  $("#testing-out").outerHTML = `<div id="testing-out" class="rv-stack">
    <div class="rv-card"><div class="rv-card-head"><h3>Identities <span class="rv-dim">${ids.length}</span></h3>
        <span class="rv-actions">${ids.length ? `<button id="id-checkall" class="rv-btn">Check all sessions</button>` : ""}<button id="id-add" class="rv-btn" aria-expanded="${!!state.idForm}">${state.idForm ? "Close form" : "Add identity"}</button></span></div>
      ${state.idForm ? `<div class="rv-dl-detail">
        <label class="rv-field"><span class="rv-field-label">Name (saving under an existing name replaces that identity)</span><input id="id-name" class="rv-input" placeholder="acme-member" maxlength="32" spellcheck="false" style="max-width:280px"></label>
        <label class="rv-field"><span class="rv-field-label">Spec (JSON). "secret" names a stored credential, never the value.</span><textarea id="id-spec" class="rv-input" rows="12" spellcheck="false">${esc(IDENTITY_TEMPLATE)}</textarea></label>
        <div class="rv-actions start"><button id="id-save" class="rv-btn accent">Save identity</button></div></div>` : ""}
      ${ids.length ? `<div class="rv-dl" style="--cols:${idCols};--minw:760px"><div class="rv-dl-in">
        <div class="rv-dl-head"><span>Identity</span><span>Session</span><span>Role</span><span>Tenant</span><span>May</span><span>Hosts</span><span></span></div>
        ${ids.map(idRow).join("")}</div></div>`
        : `<div class="rv-card-body"><p class="hint">None yet. An identity is a test account: how it logs in (it names a stored credential), the hosts its session may go to, what it may be used for, and the fixture records it owns.</p></div>`}
    </div>

    ${mats.length ? mats.map((m, n) => { const res = (r.results || {})[m.name], ok = m.state === "approved"; return `<div class="rv-card">
      <div class="rv-card-head"><div class="rv-mx-head"><h3>${esc(m.name)}</h3><span class="rv-pill ${ok ? "ok" : "warn"}"><span class="rv-dot"></span>${esc(cap(m.state))}</span>
          <span class="rv-dim">${m.operations} operation(s) × ${m.identities.length} identit${m.identities.length === 1 ? "y" : "ies"}</span></div>
        <span class="rv-actions"><button class="rv-btn" data-mxshow="${esc(m.name)}" data-n="${n}">${ok ? "Review definition" : "Review and approve"}</button>
          ${ok ? `<button class="rv-btn accent" data-mxrun="${esc(m.name)}">${res ? "Run again" : "Run"}</button>` : ""}</span></div>
      ${m.purpose ? `<p class="rv-mx-purpose" title="${esc(m.purpose)}">${esc(m.purpose)}</p>` : ""}
      <div id="mxdef-${n}" class="rv-matrix"></div>
      ${res ? `<div id="mxg-${n}" data-mxg="${n}"></div>` : `<div class="rv-card-body"><p class="hint">${ok ? "Approved, not run yet." : "Proposed by the agent. Review it and approve exactly this version; it can't run before."}</p></div>`}
    </div>`; }).join("") : `<div class="rv-card"><div class="rv-card-head"><h3>Authorization matrices</h3></div><div class="rv-card-body"><p class="hint">The agent proposes a matrix (operations, identities, expected allow or deny). Review it here and approve exactly that version; it can't run before.</p></div></div>`}

    <div class="rv-card"><div class="rv-card-head"><h3>Captures <span class="rv-dim">${caps.length}</span></h3>
        <span class="rv-actions"><input id="cap-file" type="file" accept=".har,.json,.xml" aria-label="Capture file"><button id="cap-import" class="rv-btn">Import</button></span></div>
      ${caps.length ? `<div class="rv-dl" style="--cols:${capCols};--minw:820px"><div class="rv-dl-in">
        <div class="rv-dl-head"><span>Capture</span><span>Source</span><span>Requests</span><span>Out of scope</span><span>Redacted</span><span>Imported</span><span></span></div>
        ${caps.map((c) => `<div class="rv-dl-row"><b title="${esc(c.name || c.id)}">${esc(c.name || c.id)}</b><span>${esc(c.source)}</span><span>${c.entries}</span><span>${c.out_of_scope}</span>
          <span>${Object.values(c.redactions || {}).reduce((a, b) => a + b, 0)}</span><span>${fmtTime(c.imported_at)}</span>
          <span class="acts"><button class="rv-btn" data-capopen="${esc(c.id)}">Open</button><button class="rv-btn ghost danger-quiet" data-caprm="${esc(c.id)}">Delete</button></span></div>`).join("")}</div></div>`
        : `<div class="rv-card-body"><p class="hint">Import a HAR file (browser developer tools, ZAP, mitmproxy) or a Burp Suite XML export. The original is kept encrypted for you; the agent sees a sanitized copy.</p></div>`}
      <div id="cap-view"></div>
    </div></div>`;

  // matrix grids: the filter and the selected cell are view state, drawn again without asking the server
  state.mxView = state.mxView || {};
  $$("[data-mxg]").forEach((box) => {
    const m = mats[Number(box.dataset.mxg)], res = r.results[m.name];
    const view = (state.mxView[d.engagement + "/" + m.name] = state.mxView[d.engagement + "/" + m.name] || {});
    const draw = () => { box.innerHTML = matrixGrid(m, res, ids, view); };
    box.addEventListener("click", (ev) => {
      const fb = ev.target.closest("[data-mxf]"), cb = ev.target.closest("[data-cell]");
      if (fb) { view.filter = fb.dataset.mxf; draw(); }
      else if (cb) { const c = res.cells[Number(cb.dataset.cell)]; view.cell = c.operation + "\n" + c.identity; draw(); box.querySelector(".rv-mx-cell.selected")?.focus(); }
    });
    draw();
  });

  $$("[data-idopen]").forEach((b) => b.addEventListener("click", () => { state.openIdentity = state.openIdentity === b.dataset.idopen ? null : b.dataset.idopen; paneTesting(); }));
  $("#id-add").addEventListener("click", () => { state.idForm = !state.idForm; paneTesting(); });
  $("#id-checkall")?.addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, live = ids.filter((i) => i.status.state !== "revoked");
    btn.disabled = true; let bad = 0;
    for (const i of live) {
      btn.textContent = `Checking ${i.name}…`;
      try { if ((await api(`/api/eng/${e}/identity`, { name: i.name, op: "check" })).state !== "valid") bad++; } catch { bad++; }
    }
    toast(bad ? `${bad} of ${live.length} session(s) are not valid.` : `All ${live.length} session(s) are valid.`, !!bad);
    paneTesting();
  });
  $$("[data-idop]").forEach((b) => b.addEventListener("click", async (ev) => {
    const op = b.dataset.idop;
    if (op === "rm" && !confirm(`Remove identity ${b.dataset.name}?`)) return;
    const x = await act(ev.currentTarget, () => api(`/api/eng/${e}/identity`, { name: b.dataset.name, op }), op === "check" ? null : "Done.");
    if (x && op === "check") toast(`${b.dataset.name}: ${x.state}${x.reason ? " (" + x.reason + ")" : ""}`, x.state !== "valid");
    if (x) paneTesting();
  }));
  $("#id-save")?.addEventListener("click", async (ev) => {
    let spec;
    try { spec = JSON.parse($("#id-spec").value); } catch { return toast("The spec isn't valid JSON.", true); }
    const x = await act(ev.currentTarget, () => api(`/api/eng/${e}/identity`, { name: $("#id-name").value.trim(), op: "set", spec }), "Identity saved. Check its session next.");
    if (x) { state.idForm = false; paneTesting(); }
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
        <td>${q.in_scope ? `<select class="rv-input fit" data-replayas="${q.n}" aria-label="Identity for the replay">${idOpts}</select> <button class="rv-btn ghost" data-replay="${q.n}">Replay</button>` : ""}</td></tr>`).join("")}</tbody></table><div id="replay-out"></div>`;
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
    const box = $(`#mxdef-${b.dataset.n}`);
    if (box.innerHTML) { box.innerHTML = ""; return; }  // a second click closes the definition
    const m = await api(`/api/eng/${e}/matrix?name=${enc(b.dataset.mxshow)}`);
    // everything the approved digest covers, as escaped text: headers and bodies are agent-written
    const one = (v) => typeof v === "string" ? v : JSON.stringify(v);
    const reqText = (r) => [...Object.entries(r.headers || {}).map(([k, v]) => `${k}: ${v}`),
      ...(r.body == null || r.body === "" ? [] : ["", one(r.body)])].join("\n");
    const writes = m.operations.some((o) => o.effect === "write") || m.cleanup.length > 0;
    box.innerHTML = `<div class="rv-dl-detail"><p class="rv-dim">digest ${esc(m.digest)} · proposed by ${esc(m.proposed_by)} ${fmtTime(m.proposed_at)}${m.allow_writes || writes ? ` · <b>changes state</b>: at most ${esc(m.max_writes)} write(s), cleanup included` : " · read-only"}</p>
      <table class="rv-table"><thead><tr><th>Operation</th><th>Request</th>${m.identities.map((i) => `<th>${esc(i)}</th>`).join("")}</tr></thead><tbody>
      ${m.operations.map((o) => `<tr><td>${esc(o.id)}${o.effect === "write" ? " <b>(write)</b>" : ""}</td><td><code>${esc(o.method || "GET")} ${esc(o.url)}</code>${o.marker ? `<br><span class="rv-dim">marker ${esc(o.marker)}</span>` : ""}${reqText(o) ? `<pre class="rv-pre">${esc(reqText(o))}</pre>` : ""}</td>${m.identities.map((i) => `<td>${esc(m.expect[o.id][i])}</td>`).join("")}</tr>`).join("")}</tbody></table>
      ${m.cleanup.length ? `<p class="rv-dim">Cleanup, run after the writes (counted in max writes):</p>
      <table class="rv-table"><thead><tr><th>Request</th><th>Identity</th></tr></thead><tbody>
      ${m.cleanup.map((c) => `<tr><td><code>${esc(c.method || "POST")} ${esc(c.url)}</code>${reqText(c) ? `<pre class="rv-pre">${esc(reqText(c))}</pre>` : ""}</td><td>${esc(c.identity || "no identity")}</td></tr>`).join("")}</tbody></table>`
      : m.no_cleanup_reason ? `<p class="rv-dim">No cleanup: ${esc(m.no_cleanup_reason)}</p>` : ""}
      <p class="rv-dim">Header values are as proposed: {{cred:NAME}} references are filled in only when sent.</p>
      <div class="rv-actions start"><button class="rv-btn accent" data-mxapprove="1" data-digest="${esc(m.digest)}">Approve this version</button></div></div>`;
    box.querySelector("[data-mxapprove]").addEventListener("click", async (ev) => {
      const x = await act(ev.currentTarget, () => api(`/api/eng/${e}/authz`, { name: m.name, op: "approve", digest: ev.currentTarget.dataset.digest }), "Approved.");
      if (x) paneTesting();
    });
  }));
  $$("[data-mxrun]").forEach((b) => b.addEventListener("click", async (ev) => {
    const x = await act(ev.currentTarget, () => api(`/api/eng/${e}/authz`, { name: b.dataset.mxrun, op: "run" }), "Matrix run finished.");
    if (x) paneTesting();
  }));
}

const COV_PILL = { tested: "ok", failed: "bad", blocked: "warn", planned: "open", excluded: "closed", "not-applicable": "closed" };
const OBS_PILL = { new: "warn", linked: "ok", duplicate: "closed", dismissed: "closed" };
const INV_TABS = [["summary", "Summary"], ["coverage", "Coverage"], ["observations", "Observations"], ["imports", "Imports"], ["handover", "Handover note"]];
const LIST_PAGE = 25;
const human = (s) => cap(String(s || "").replace(/-/g, " "));
const pill = (text, cls) => `<span class="rv-pill ${cls || "closed"}"><span class="rv-dot"></span>${esc(human(text))}</span>`;
const has = (q, vals) => !q || vals.some((v) => String(v || "").toLowerCase().includes(q));
// one page of a list: [rows on this page, index of the first, number of pages, the page it ended up on]
function pageOf(rows, page) {
  const pages = Math.max(1, Math.ceil(rows.length / LIST_PAGE)), p = Math.max(0, Math.min(page, pages - 1));
  return [rows.slice(p * LIST_PAGE, (p + 1) * LIST_PAGE), p * LIST_PAGE, pages, p];
}
const pagerHtml = (from, shown, total, page, pages) => `<div class="rv-pager"><span>${from + 1}–${from + shown} of ${total}</span>
  ${pages > 1 ? `<span class="rv-pager-nav"><button class="rv-btn ghost" data-page="-1" ${page ? "" : "disabled"}>Previous</button><span>Page ${page + 1} of ${pages}</span><button class="rv-btn ghost" data-page="1" ${page < pages - 1 ? "" : "disabled"}>Next</button></span>` : ""}
  <span>${LIST_PAGE} per page</span></div>`;

async function paneInvestigation() {
  const d = state.detail, e = enc(d.engagement);
  if (state.invEng !== d.engagement) Object.assign(state, { invEng: d.engagement, invTab: "summary", covFilter: "all", covQuery: "", covPage: 0, planOpen: null,
    obsFilter: "new", obsQuery: "", obsTool: "", obsPage: 0, obsSel: new Set(), impOpen: null, invAllPending: false });
  if (!$("#inv-out")) $("#pane").innerHTML = `<div id="inv-out" class="rv-empty">Loading…</div>`;
  let r;
  try { r = await api(`/api/eng/${e}/investigation`); } catch (err) { $("#inv-out").textContent = err.message; return; }
  if (state.tab !== "investigation" || state.current !== d.engagement || !$("#inv-out")) return;
  const h = r.handover, cov = r.coverage, c = cov.counts || {};
  const post = (what, body) => api(`/api/eng/${e}/${what}`, body);
  const reload = () => paneInvestigation();
  const nNew = r.observations.filter((o) => o.status === "new").length;
  const counts = { coverage: cov.total || "", observations: nNew ? `${nNew} new` : "", imports: r.imports.length || "" };
  const done = (c.tested || 0) + (c.failed || 0);
  const covLine = [c.planned && `${c.planned} not run yet`, c.blocked && `${c.blocked} blocked`, cov.stale.length && `${cov.stale.length} stale`].filter(Boolean).join(" · ");
  const body = (html) => { $("#inv-body").innerHTML = html; };

  const summary = () => {
    const pend = state.invAllPending ? h.pending : h.pending.slice(0, 8);
    const line = (obj) => Object.entries(obj).filter(([, v]) => v).map(([k, v]) => `${v} ${esc(k)}`).join(", ") || "none";
    body(`
      <div class="rv-card"><div class="rv-card-head"><h3>Objective</h3><button id="inv-obj-save" class="rv-btn">Save objective</button></div><div class="rv-card-body">
        <textarea id="inv-obj" class="rv-input" rows="2" maxlength="4000" aria-label="Objective" placeholder="What this engagement must answer, e.g. can a member of one tenant read or change another tenant's invoices?">${esc(r.objective)}</textarea></div></div>
      ${h.parse_problems.length ? `<div class="rv-banner danger"><div class="rv-banner-body"><p class="rv-banner-title">Import problems</p><ul>${h.parse_problems.map((p) => `<li>${esc(p)}</li>`).join("")}</ul></div></div>` : ""}
      <div class="rv-two">
        <div class="rv-card"><div class="rv-card-head"><h3>Next</h3></div><div class="rv-card-body">
          ${h.next.length ? `<ol class="rv-steps">${h.next.map((n) => `<li>${esc(n)}</li>`).join("")}</ol>` : `<p class="hint">Nothing pending.</p>`}</div></div>
        <div class="rv-card"><div class="rv-card-head"><h3>Where it stands</h3></div><div class="rv-card-body"><dl class="rv-kv">
          <dt>Findings</dt><dd>${line(h.findings)}</dd>
          <dt>Observations</dt><dd>${line(h.observations)}</dd>
          <dt>Coverage</dt><dd>${cov.total ? `${done} of ${cov.total} tests have an outcome${covLine ? `<div class="rv-dim">${covLine}</div>` : ""}` : "no plan yet"}</dd>
          <dt>Imports</dt><dd>${h.imports}</dd></dl></div></div>
      </div>
      ${h.material.length ? `<div class="rv-card"><div class="rv-card-head"><h3>Material findings <span class="rv-dim">${h.material.length}</span></h3></div>
        <div class="rv-dl" style="--cols:92px 64px minmax(0, 1fr) 132px;--minw:520px"><div class="rv-dl-in">${h.material.map((m) => `<div class="rv-dl-row">${sevMark(m.severity)}<span class="mono">${esc(m.id)}</span><b>${esc(m.title)}</b><span>${statusPill(m)}</span></div>`).join("")}</div></div></div>` : ""}
      ${h.pending.length ? `<div class="rv-card"><div class="rv-card-head"><h3>Pending decisions <span class="rv-dim">${h.pending.length}</span></h3>
          ${h.pending.length > 8 ? `<button id="inv-pend" class="rv-btn ghost">${state.invAllPending ? "Show the first 8" : `Show all ${h.pending.length}`}</button>` : ""}</div>
        <div class="rv-dl" style="--cols:130px minmax(0, 1fr);--minw:420px"><div class="rv-dl-in">${pend.map((p) => `<div class="rv-dl-row"><span>${tag(p.kind)}</span><span title="${esc(p.what)}">${esc(p.what)}</span></div>`).join("")}</div></div></div>` : ""}`);
    $("#inv-obj-save").addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post("objective", { text: $("#inv-obj").value, digest: r.objective_digest }), "Objective saved.")) reload(); });
    $("#inv-pend")?.addEventListener("click", () => { state.invAllPending = !state.invAllPending; summary(); });
  };

  const planForm = (i) => `<div class="rv-dl-detail">${i.hypothesis ? `<p class="rv-dim">${esc(i.hypothesis)}</p>` : ""}
      <div class="rv-form-grid">
        <label class="rv-field"><span class="rv-field-label">Outcome</span><select id="pf-state" class="rv-select">${COVERAGE.map((s) => `<option ${s === i.state ? "selected" : ""}>${s}</option>`).join("")}</select></label>
        <label class="rv-field"><span class="rv-field-label">Finding (when failed)</span><input id="pf-fid" class="rv-input" value="${esc(i.finding_id || "")}" placeholder="F-001"></label>
        <label class="rv-field"><span class="rv-field-label">Build it ran on</span><input id="pf-build" class="rv-input mono" value="${esc(i.build || "")}" spellcheck="false"></label>
      </div>
      <label class="rv-field"><span class="rv-field-label">Evidence (when tested; one path per line)</span><textarea id="pf-ev" class="rv-input mono" rows="2" spellcheck="false">${esc((i.evidence || []).join("\n"))}</textarea></label>
      <label class="rv-field"><span class="rv-field-label">Rationale (blocked, excluded, not applicable: why, and what would unblock it)</span><input id="pf-why" class="rv-input" value="${esc(i.rationale || "")}"></label>
      <div class="rv-actions start"><button id="pf-save" class="rv-btn accent">Save outcome</button></div></div>`;

  const coverage = () => {
    const nState = (s) => r.plan.filter((i) => s === "all" || (s === "stale" ? i.stale : i.state === s)).length;
    const chips = ["all", ...COVERAGE, ...(nState("stale") ? ["stale"] : [])];
    body(`
      <div class="rv-card"><div class="rv-card-body">
        ${cov.total ? `<div class="rv-cov-head"><b>${done} of ${cov.total} tests have an outcome</b><span class="rv-dim">${covLine}</span></div>
          <div class="rv-cov-bar" role="img" aria-label="${esc(COVERAGE.map((s) => `${c[s] || 0} ${s}`).join(", "))}">${COVERAGE.map((s) => c[s] ? `<span class="${s}" style="flex:${Number(c[s])} 0 0" title="${Number(c[s])} ${s}"></span>` : "").join("")}</div>`
          : `<p class="hint">No plan yet. Add a playbook's checklist to start one.</p>`}
        ${cov.note ? `<p class="hint">${esc(cov.note)}</p>` : ""}
        <div class="rv-toolbar"><select id="inv-pb" class="rv-select fit" aria-label="Playbook">${PLAYBOOKS.map((p) => `<option>${p}</option>`).join("")}</select><button id="inv-pb-add" class="rv-btn">Add its checklist to the plan</button>
          <span class="rv-toolbar-end"><input id="inv-build" class="rv-input fit mono" placeholder="build or source digest now deployed" aria-label="Current build" spellcheck="false" style="width:260px">
            <button id="inv-reassess" class="rv-btn" title="Mark tests that ran on another build or policy revision as stale">Reassess</button></span></div>
      </div></div>
      ${r.plan.length ? `<div class="rv-card"><div class="rv-toolbar pad">
          <div class="rv-search">${ICON_SEARCH}<input id="cov-q" class="rv-input" type="search" placeholder="Search tests, references" aria-label="Search tests" value="${esc(state.covQuery)}"></div>
          <div class="rv-chipset" role="group" aria-label="Outcome">${chips.map((s) => `<button class="rv-chip ${s === state.covFilter ? "active" : ""} ${nState(s) ? "" : "empty"}" aria-pressed="${s === state.covFilter}" data-covf="${s}">${human(s)} <span class="count">${nState(s)}</span></button>`).join("")}</div>
        </div><div id="cov-rows"></div></div>` : ""}`);
    const row = (i) => { const open = state.planOpen === i.id, note = i.stale_reason || i.rationale || ""; return `<div class="rv-dl-row tall">
        <span class="mono" title="${esc(i.id)}">${esc(i.id)}</span>
        <span class="two"><b title="${esc(i.title)}">${esc(i.title)}</b>${note ? `<small title="${esc(note)}">${esc(note)}</small>` : ""}</span>
        <span class="mono" title="${esc((i.refs || []).join(", "))}">${esc((i.refs || []).join(" · "))}</span>
        <span class="cell">${pill(i.state, COV_PILL[i.state])}${i.stale ? tag("stale", "warn") : ""}${i.finding_id ? `<b>${esc(i.finding_id)}</b>` : ""}</span>
        <span class="acts"><button class="rv-btn ${open ? "" : "ghost"}" data-plan="${esc(i.id)}" aria-expanded="${open}">${open ? "Close" : "Record"}</button></span></div>${open ? planForm(i) : ""}`; };
    const fill = () => {
      if (!$("#cov-rows")) return;
      const q = state.covQuery.trim().toLowerCase(), f = state.covFilter;
      const rows = r.plan.filter((i) => (f === "all" || (f === "stale" ? i.stale : i.state === f)) && has(q, [i.id, i.title, i.area, i.finding_id, ...(i.refs || [])]));
      const areas = [...new Set(rows.map((i) => i.area || ""))], grouped = areas.length > 1 || !!areas[0];
      const [page, from, pages, p] = pageOf(areas.flatMap((a) => rows.filter((i) => (i.area || "") === a)), state.covPage);
      state.covPage = p;
      let last = null;
      $("#cov-rows").innerHTML = rows.length ? `<div class="rv-dl" style="--cols:minmax(64px, 90px) minmax(160px, 2fr) minmax(80px, 1fr) 170px 72px;--minw:700px"><div class="rv-dl-in">
          <div class="rv-dl-head"><span>Id</span><span>Test</span><span>References</span><span>Outcome</span><span></span></div>
          ${page.map((i) => { const a = i.area || "", head = grouped && a !== last ? `<div class="rv-dl-group">${esc(a || "No area")} <span class="rv-dim">${rows.filter((x) => (x.area || "") === a).length}</span></div>` : ""; last = a; return head + row(i); }).join("")}
        </div></div>${pagerHtml(from, page.length, rows.length, p, pages)}` : `<div class="rv-empty">No test matches these filters.</div>`;
      $$("#cov-rows [data-plan]").forEach((b) => b.addEventListener("click", () => { state.planOpen = state.planOpen === b.dataset.plan ? null : b.dataset.plan; fill(); }));
      $$("#cov-rows [data-page]").forEach((b) => b.addEventListener("click", () => { state.covPage += Number(b.dataset.page); fill(); }));
      $("#pf-save")?.addEventListener("click", async (ev) => {
        const i = r.plan.find((x) => x.id === state.planOpen);
        const fields = { state: $("#pf-state").value, rationale: $("#pf-why").value.trim() || null, finding_id: $("#pf-fid").value.trim() || null,
          evidence: $("#pf-ev").value.split("\n").map((s) => s.trim()).filter(Boolean), build: $("#pf-build").value.trim() || null };
        Object.keys(fields).forEach((k) => fields[k] === null && delete fields[k]);
        if (await act(ev.currentTarget, () => post("plan", { op: "update", id: i.id, fields, revision: i.revision }), "Outcome recorded.")) { state.planOpen = null; reload(); }
      });
    };
    fill();
    $("#cov-q")?.addEventListener("input", (ev) => { state.covQuery = ev.target.value; state.covPage = 0; fill(); });
    $$("[data-covf]").forEach((b) => b.addEventListener("click", () => { state.covFilter = b.dataset.covf; state.covPage = 0; coverage(); }));
    $("#inv-pb-add").addEventListener("click", async (ev) => {
      const x = await act(ev.currentTarget, () => post("plan", { op: "playbook", playbook: $("#inv-pb").value }));
      if (x) { toast(`${x.ids.length} test(s) added from ${x.playbook} (version ${x.version}).`); reload(); }
    });
    $("#inv-reassess").addEventListener("click", async (ev) => {
      const x = await act(ev.currentTarget, () => post("plan", { op: "reassess", build: $("#inv-build").value.trim() }));
      if (x) { toast(`${x.stale} test(s) now stale.`); reload(); }
    });
  };

  const observations = () => {
    const nObs = (s) => r.observations.filter((o) => s === "all" || o.status === s).length;
    const tools = [...new Set(r.observations.map((o) => o.tool).filter(Boolean))].sort();
    body(`
      ${r.groups.length ? `<div class="rv-card"><div class="rv-card-head"><h3>May share a root cause <span class="rv-dim">${r.groups.length}</span></h3></div>
        <div class="rv-scroll">${r.groups.map((g) => `<div class="rv-group-row"><span class="body"><b class="mono">${esc(g.group_key)}</b><small>${esc(g.suggestion)}</small></span>
          <button class="rv-btn" data-group="${esc(g.observations.join(","))}">Select ${g.observations.length}</button></div>`).join("")}</div></div>` : ""}
      <div class="rv-card">
        <div class="rv-toolbar pad">
          <div class="rv-search">${ICON_SEARCH}<input id="obs-q" class="rv-input" type="search" placeholder="Search title, rule, location" aria-label="Search observations" value="${esc(state.obsQuery)}"></div>
          <div class="rv-chipset" role="group" aria-label="Status">${["new", "linked", "duplicate", "dismissed", "all"].map((s) => `<button class="rv-chip ${s === state.obsFilter ? "active" : ""} ${nObs(s) ? "" : "empty"}" aria-pressed="${s === state.obsFilter}" data-obsf="${s}">${cap(s)} <span class="count">${nObs(s)}</span></button>`).join("")}</div>
          ${tools.length > 1 ? `<select id="obs-tool" class="rv-select fit" aria-label="Tool"><option value="">All tools</option>${tools.map((t) => `<option ${t === state.obsTool ? "selected" : ""}>${esc(t)}</option>`).join("")}</select>` : ""}
        </div>
        <div id="obs-bulk" class="rv-bulk" hidden><b id="obs-n"></b>
          <input id="obs-fid" class="rv-input fit" placeholder="F-001" aria-label="Finding to link to" style="width:90px"><button id="obs-link" class="rv-btn">Link to finding</button>
          <input id="obs-reason" class="rv-input fit" placeholder="reason it's not an issue" aria-label="Dismiss reason"><button id="obs-dismiss" class="rv-btn">Dismiss</button>
          <button id="obs-reopen" class="rv-btn">Reopen</button><button id="obs-clear" class="rv-btn ghost">Clear</button></div>
        <div id="obs-rows"></div>
      </div>`);
    const sync = () => { const n = state.obsSel.size; $("#obs-bulk").hidden = !n; $("#obs-n").textContent = `${n} selected`; };
    const fill = () => {
      const q = state.obsQuery.trim().toLowerCase(), f = state.obsFilter;
      const rows = r.observations.filter((o) => (f === "all" || o.status === f) && (!state.obsTool || o.tool === state.obsTool) && has(q, [o.id, o.title, o.tool, o.rule_id, o.location, o.finding_id]));
      const [page, from, pages, p] = pageOf(rows, state.obsPage);
      state.obsPage = p;
      $("#obs-rows").innerHTML = rows.length ? `<div class="rv-dl" style="--cols:18px 84px minmax(160px, 2fr) minmax(90px, 1fr) 150px;--minw:700px"><div class="rv-dl-in">
          <div class="rv-dl-head"><input type="checkbox" id="obs-all" aria-label="Select all on this page" ${page.every((o) => state.obsSel.has(o.id)) ? "checked" : ""}><span>Severity</span><span>Observation</span><span>Where</span><span>Status</span></div>
          ${page.map((o) => `<label class="rv-dl-row tall ${state.obsSel.has(o.id) ? "on" : ""}">
            <input type="checkbox" class="obs-cb" value="${esc(o.id)}" aria-label="Select ${esc(o.id)}" ${state.obsSel.has(o.id) ? "checked" : ""}>
            ${sevMark(o.severity || "info")}
            <span class="two"><b title="${esc(o.title)}">${esc(o.title)}</b><small>${esc([o.id, o.tool, o.rule_id, o.seen > 1 ? `seen ${o.seen} times` : "", o.reason].filter(Boolean).join(" · "))}</small></span>
            <span class="mono" title="${esc(o.location)}">${esc(o.location)}</span>
            <span class="cell">${pill(o.status, OBS_PILL[o.status])}${o.finding_id ? `<b>${esc(o.finding_id)}</b>` : ""}${o.duplicate_of ? `<span class="rv-dim">of ${esc(o.duplicate_of)}</span>` : ""}</span></label>`).join("")}
        </div></div>${pagerHtml(from, page.length, rows.length, p, pages)}` : `<div class="rv-empty">No observations${f === "all" && !q && !state.obsTool ? " yet" : " match these filters"}.</div>`;
      $$("#obs-rows .obs-cb").forEach((cb) => cb.addEventListener("change", () => {
        state.obsSel[cb.checked ? "add" : "delete"](cb.value); cb.closest(".rv-dl-row").classList.toggle("on", cb.checked);
        $("#obs-all").checked = $$("#obs-rows .obs-cb").every((x) => x.checked); sync();
      }));
      $("#obs-all")?.addEventListener("change", (ev) => { page.forEach((o) => state.obsSel[ev.target.checked ? "add" : "delete"](o.id)); fill(); sync(); });
      $$("#obs-rows [data-page]").forEach((b) => b.addEventListener("click", () => { state.obsPage += Number(b.dataset.page); fill(); }));
    };
    fill(); sync();
    $("#obs-q").addEventListener("input", (ev) => { state.obsQuery = ev.target.value; state.obsPage = 0; fill(); });
    $("#obs-tool")?.addEventListener("change", (ev) => { state.obsTool = ev.target.value; state.obsPage = 0; fill(); });
    $$("[data-obsf]").forEach((b) => b.addEventListener("click", () => { state.obsFilter = b.dataset.obsf; state.obsPage = 0; observations(); }));
    $$("[data-group]").forEach((b) => b.addEventListener("click", () => { state.obsSel = new Set(b.dataset.group.split(",")); fill(); sync(); $("#obs-bulk").scrollIntoView({ block: "nearest" }); }));
    $("#obs-clear").addEventListener("click", () => { state.obsSel.clear(); fill(); sync(); });
    const triage = async (btn, fields, msg) => {
      if (await act(btn, () => post("observation", { ...fields, ids: [...state.obsSel] }), msg)) { state.obsSel.clear(); reload(); }
    };
    $("#obs-link").addEventListener("click", (ev) => triage(ev.currentTarget, { op: "link", finding_id: $("#obs-fid").value.trim() }, "Linked."));
    $("#obs-dismiss").addEventListener("click", (ev) => triage(ev.currentTarget, { op: "dismiss", reason: $("#obs-reason").value.trim() }, "Dismissed."));
    $("#obs-reopen").addEventListener("click", (ev) => triage(ev.currentTarget, { op: "reopen" }, "Reopened."));
  };

  const imports = () => {
    body(`<div class="rv-card"><div class="rv-card-head"><h3>Imports <span class="rv-dim">${r.imports.length}</span></h3>
        <span class="rv-actions"><input id="obs-path" class="rv-input fit mono" placeholder="semgrep.json or evidence/authz/....json" aria-label="Tool output to import" spellcheck="false" style="width:300px"><button id="obs-import" class="rv-btn">Import tool output</button></span></div>
      ${r.imports.length ? `<div class="rv-dl" style="--cols:52px minmax(70px, 100px) minmax(160px, 1fr) 90px 150px 96px;--minw:700px"><div class="rv-dl-in">
        <div class="rv-dl-head"><span>Id</span><span>Tool</span><span>File</span><span>Found</span><span>Imported</span><span></span></div>
        ${r.imports.map((i) => { const n = i.errors.length + i.limitations.length, open = state.impOpen === i.id; return `<div class="rv-dl-row">
          <b>${esc(i.id)}</b><span title="${esc(`${i.parser || "no parser"} v${i.parser_version}`)}">${esc(i.parser || "no parser")}</span>
          <span class="mono" title="${esc(i.path)}">${esc(String(i.path).split("/").pop())}</span>
          <span>${i.observations ? `${i.observations} · ${i.new} new` : `<span class="rv-dim">0</span>`}</span><span>${fmtTime(i.at)}</span>
          <span class="acts">${n ? `<button class="rv-btn ${open ? "" : "ghost"} ${i.errors.length ? "danger-quiet" : ""}" data-imp="${esc(i.id)}" aria-expanded="${open}">${i.errors.length ? `${i.errors.length} error${i.errors.length === 1 ? "" : "s"}` : `${n} note${n === 1 ? "" : "s"}`}</button>` : ""}</span></div>
          ${open ? `<div class="rv-dl-detail"><div class="rv-notes rv-scroll">${i.errors.map((x) => `<div class="err">${esc(x.type)}: ${esc(x.message)}${x.path ? ` (${esc(x.path)})` : ""}</div>`).join("")}${i.limitations.map((x) => `<div>${esc(x)}</div>`).join("")}</div></div>` : ""}`; }).join("")}
      </div></div>` : `<div class="rv-card-body"><p class="hint">Nothing imported yet. An import turns a tool's output file into observations: what the tool reported, before anyone decided it's a finding.</p></div>`}</div>`);
    $$("[data-imp]").forEach((b) => b.addEventListener("click", () => { state.impOpen = state.impOpen === b.dataset.imp ? null : b.dataset.imp; imports(); }));
    $("#obs-import").addEventListener("click", async (ev) => {
      const x = await act(ev.currentTarget, () => post("observation", { op: "import", path: $("#obs-path").value.trim() }));
      if (x) { toast(`${x.observations} observation(s), ${x.new} new${x.errors.length ? `, ${x.errors.length} parser error(s)` : ""}.`, !!x.errors.length); reload(); }
    });
  };

  const handover = () => {
    body(`<div class="rv-card"><div class="rv-card-head"><h3>Handover note</h3><button id="inv-note-save" class="rv-btn">Save note</button></div><div class="rv-card-body">
        <textarea id="inv-note" class="rv-input" rows="6" aria-label="Handover note" placeholder="What the next person (or the agent, when it resumes) should know that the records don't say.">${esc(h.note)}</textarea>
        ${h.note_updated ? `<p class="rv-dim">saved ${fmtTime(h.note_updated.at)} by ${esc(h.note_updated.by)}</p>` : ""}</div></div>
      <div class="rv-card"><div class="rv-card-head"><h3>Handover as text</h3><span class="rv-dim">what the agent reads when it resumes</span></div>
        <div class="rv-card-body"><pre class="rv-pre">${esc(h.markdown)}</pre></div></div>`);
    $("#inv-note-save").addEventListener("click", async (ev) => { if (await act(ev.currentTarget, () => post("handover", { text: $("#inv-note").value, digest: h.note_digest }), "Note saved.")) reload(); });
  };

  const panes = { summary, coverage, observations, imports, handover };
  const draw = () => {
    $("#inv-out").outerHTML = `<div id="inv-out" class="rv-stack">
      <div class="rv-subtabs page" role="tablist" aria-label="Investigation sections">${INV_TABS.map(([t, label]) => `<button role="tab" class="rv-subtab ${t === state.invTab ? "active" : ""}" aria-selected="${t === state.invTab}" data-invtab="${t}">${label}${counts[t] ? ` <span class="n">${counts[t]}</span>` : ""}</button>`).join("")}</div>
      <div id="inv-body" class="rv-stack"></div></div>`;
    $$("[data-invtab]").forEach((b) => b.addEventListener("click", () => { state.invTab = b.dataset.invtab; draw(); }));
    (panes[state.invTab] || summary)();
  };
  draw();
}

const TASK_PILL = { running: "open", queued: "closed", waiting: "closed", awaiting_approval: "warn", interrupted: "warn", done: "ok", error: "bad", blocked: "bad" };
const TASK_ACTIVE = ["queued", "waiting", "running", "awaiting_approval", "interrupted"];
const taskGroup = (t) => TASK_ACTIVE.includes(t.status) ? "active" : t.status === "done" ? "done" : "stopped";

async function paneTasks() {
  const d = state.detail, eng = d.engagement, gen = (state.taskGen = (state.taskGen || 0) + 1);
  const m = d.models || {}, allowed = d.info.rules.client_data;
  const active = () => state.tab === "tasks" && state.current === eng && state.taskGen === gen;
  if (state.taskEng !== eng) Object.assign(state, { taskEng: eng, taskFilter: "all", taskPage: 0, taskOpen: undefined });
  $("#pane").innerHTML = `<div id="tasks-sum" class="rv-card"><div class="rv-card-body"><span class="rv-dim">Loading the investigation…</span></div></div>
    <div id="tasks-out" class="rv-card"><div class="rv-empty">Loading…</div></div>`;
  (async () => {  // where the investigation stands (RW-018), above the tasks
    try {
      const [inv, lv] = await Promise.all([api(`/api/eng/${enc(eng)}/investigation`), api(`/api/eng/${enc(eng)}/live`).catch(() => ({}))]);
      if (!active()) return;
      const h = inv.handover, sp = lv.spend, w = m.worker || {}, fb = m.worker_fallback || {};
      $("#tasks-sum").innerHTML = `<div class="rv-card-head"><h3>Where the investigation stands</h3><a class="rv-btn ghost" href="#eng-${esc(eng)}/investigation">Open investigation</a></div><div class="rv-card-body"><dl class="rv-kv">
        <dt>Objective</dt><dd>${h.objective ? esc(h.objective) : `<span class="rv-dim">not set</span>`}</dd>
        <dt>Next</dt><dd>${esc(h.next[0] || "nothing pending")}</dd>
        <dt>Decisions</dt><dd>${h.pending.length ? `${h.pending.length} pending: ${h.pending.slice(0, 3).map((x) => esc(x.what)).join("; ")}${h.pending.length > 3 ? " …" : ""}` : "none pending"}</dd>
        <dt>Coverage</dt><dd>${h.coverage.total ? `${h.coverage.counts.planned} of ${h.coverage.total} planned test(s) not run${h.coverage.blocked.length ? `, ${h.coverage.blocked.length} blocked` : ""}${h.coverage.stale.length ? `, ${h.coverage.stale.length} stale` : ""}` : "no plan yet"}</dd>
        <dt>Worker model</dt><dd>${destTag(w.destination, allowed)} <span class="rv-dim">${esc(w.model || "")}</span>${fb.on ? ` <span class="rv-dim">fallback: ${esc(DEST[fb.destination] || fb.destination)}</span>` : ""}</dd>
        <dt>Spend today</dt><dd>${sp ? `$${sp.spend.toFixed(2)}${sp.budget ? ` of $${sp.budget.toFixed(2)} daily budget` : ""}` : `<span class="rv-dim">unknown</span>`}</dd>
      </dl></div>`;
    } catch (err) { if (active()) $("#tasks-sum").innerHTML = `<div class="rv-card-body err">${esc(err.message)}</div>`; }
  })();

  const detail = (t) => `<div class="rv-dl-detail">
      <div class="rv-meta"><span>${esc(t.id)}</span><span>started ${fmtTime(t.started)}</span><span>${t.steps.length} step(s)</span><span>${t.candidates} candidate(s)</span>${t.models.length ? `<span>model: ${t.models.map(esc).join(", ")}</span>` : ""}</div>
      <p class="rv-prose">${esc(t.goal || "")}</p>
      ${t.approval ? `<p>Paused for approval <b>${esc(t.approval.id)}</b>: <code>${esc(t.approval.action)}</code>. Decide it on the <a href="#eng-${esc(eng)}/overview">Overview</a>; the task then continues by itself.</p>` : ""}
      ${(t.depends_on || []).length ? `<p class="rv-dim">waits for ${t.depends_on.map(esc).join(", ")}</p>` : ""}
      ${t.error ? `<p class="err">${esc(t.error)}</p>` : ""}${t.summary ? `<p class="rv-prose">${esc(t.summary)}</p>` : ""}
      ${t.recovery ? `<p class="${t.recovery.decision === "needs_review" ? "err" : "rv-dim"}">After a restart: ${esc(t.recovery.note || t.recovery.decision)}${(t.recovery.uncertain || []).length ? ` (in flight: ${t.recovery.uncertain.map((u) => esc(u.action || u.tool)).join("; ")})` : ""}</p>` : ""}
      ${TASK_ACTIVE.includes(t.status) ? `<div class="rv-actions start">${t.status === "interrupted" ? `<button class="rv-btn" data-task="resume" data-id="${esc(t.id)}">Resume from checkpoint</button>` : `<button class="rv-btn danger-quiet" data-task="cancel" data-id="${esc(t.id)}">Cancel task</button>`}</div>` : ""}
      ${t.steps.length ? `<pre class="rv-pre rv-scroll">${t.steps.map((s, i) => `<span class="ln">${String(i + 1).padStart(2, " ")}</span>  ${esc(s)}`).join("\n")}</pre>` : ""}
      <p class="rv-dim">Full output of every step: <code>evidence/tasks/${esc(t.id)}/</code></p></div>`;

  const load = async () => {
    if (!active()) return;
    let r;
    try { r = await api(`/api/eng/${enc(eng)}/tasks`); } catch (e) { if (active()) $("#tasks-out").innerHTML = `<div class="rv-empty err">${esc(e.message)}</div>`; return; }
    if (!active()) return;
    const tasks = r.tasks, n = (g) => tasks.filter((t) => g === "all" || taskGroup(t) === g).length;
    if (state.taskOpen === undefined) state.taskOpen = (tasks.find((t) => ["running", "awaiting_approval", "interrupted"].includes(t.status)) || {}).id || null;
    const draw = () => {
      const f = state.taskFilter, rows = tasks.filter((t) => f === "all" || taskGroup(t) === f);
      const [page, from, pages, p] = pageOf(rows, state.taskPage);
      state.taskPage = p;
      $("#tasks-out").innerHTML = `<div class="rv-toolbar pad"><div class="rv-chipset" role="group" aria-label="Status">${[["all", "All"], ["active", "Active"], ["done", "Done"], ["stopped", "Failed or stopped"]].map(([g, label]) => `<button class="rv-chip ${g === f ? "active" : ""} ${n(g) ? "" : "empty"}" aria-pressed="${g === f}" data-taskf="${g}">${label} <span class="count">${n(g)}</span></button>`).join("")}</div>
          <span class="rv-toolbar-end rv-ok-note">Tasks the planner handed to the worker model, newest first</span></div>
        ${rows.length ? `<div class="rv-dl" style="--cols:150px 104px minmax(160px, 1fr) 76px 84px;--minw:680px"><div class="rv-dl-in">
          <div class="rv-dl-head"><span>Status</span><span>Tier</span><span>Task</span><span>Took</span><span></span></div>
          ${page.map((t) => { const open = state.taskOpen === t.id; return `<div class="rv-dl-row tall"><span>${pill(t.status.replace(/_/g, " "), TASK_PILL[t.status])}</span><span>${tag(t.tier, TIER_CLASS[t.tier] || "")}</span>
            <span class="two"><b title="${esc(t.goal || "")}">${esc(t.goal || "")}</b><small>${esc([t.id, `${t.steps.length} step${t.steps.length === 1 ? "" : "s"}`, t.candidates ? `${t.candidates} candidate${t.candidates === 1 ? "" : "s"}` : "", t.models.join(", ")].filter(Boolean).join(" · "))}</small></span>
            <span>${t.finished && t.started ? dur(t.finished - t.started) : t.status === "running" ? "running" : ""}</span>
            <span class="acts"><button class="rv-btn ${open ? "" : "ghost"}" data-taskopen="${esc(t.id)}" aria-expanded="${open}">${open ? "Hide" : "Details"}</button></span></div>${open ? detail(t) : ""}`; }).join("")}
        </div></div>${pagerHtml(from, page.length, rows.length, p, pages)}` : `<div class="rv-empty">${tasks.length ? "No task has this status." : "No worker tasks yet."}</div>`}`;
      $$("[data-taskf]").forEach((b) => b.addEventListener("click", () => { state.taskFilter = b.dataset.taskf; state.taskPage = 0; draw(); }));
      $$("[data-taskopen]").forEach((b) => b.addEventListener("click", () => { state.taskOpen = state.taskOpen === b.dataset.taskopen ? null : b.dataset.taskopen; draw(); }));
      $$("#tasks-out [data-page]").forEach((b) => b.addEventListener("click", () => { state.taskPage += Number(b.dataset.page); draw(); }));
      $$("[data-task]").forEach((b) => b.addEventListener("click", async (ev) => {
        const ok = await act(ev.currentTarget, () => api(`/api/eng/${enc(eng)}/task`, { id: b.dataset.id, action: b.dataset.task }),
          b.dataset.task === "cancel" ? "Cancel requested." : "Resumed from its last checkpoint.");
        if (ok) setTimeout(load, 1500);
      }));
    };
    draw();
    if (tasks.some((t) => ["running", "queued", "waiting", "awaiting_approval"].includes(t.status))) setTimeout(load, 5000);
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
    const tasks = r.tasks.map((t) => `<div class="rv-run">${pill(t.status.replace(/_/g, " "), TASK_PILL[t.status])}<span class="goal" title="${esc(t.goal || "")}">${esc(t.goal || "")}</span>
        <span class="rv-elapsed">${t.status === "running" ? `<span data-since="${Number(t.started)}"></span>` : t.finished && t.started ? dur(t.finished - t.started) : ""}</span>
        <div class="rv-meta one" style="grid-column:1/-1">${t.steps.length ? `<span>step ${t.steps.length}: ${esc(String(t.steps.slice(-1)[0]).slice(0, 200))}</span>` : "<span>no steps yet</span>"}${t.models.length ? `<span>model: ${t.models.map(esc).join(", ")}</span>` : ""}${t.candidates ? `<span>${esc(t.candidates)} candidate(s)</span>` : ""}</div></div>`).join("");
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
          <div class="rv-card"><div class="rv-card-head"><h3>Worker</h3><button class="rv-btn ghost" data-goto="tasks">All tasks</button></div>
            <div class="rv-card-body flush">${tasks || `<div class="rv-empty">No worker tasks yet.</div>`}</div></div>
        </div>
        <div class="rv-card"><div class="rv-card-head"><h3>Latest events</h3><button class="rv-btn ghost" data-goto="audit">Audit log</button></div>
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

// what an audit entry is: a command or request that ran, one that was refused, or a change to a record
const auditKind = (e) => e.refused ? "refused" : e.command || e.action === "http" ? "commands" : "changes";
const auditWhat = (e) => e.command ? e.command : e.action === "http" ? `${e.method || "GET"} ${e.url || ""}` : String(e.event || "event").replace(/-/g, " ");

async function paneAudit() {
  const d = state.detail;
  if (state.auditEng !== d.engagement) Object.assign(state, { auditEng: d.engagement, auditQuery: "", auditKind: "all", auditWho: "", auditPage: 0, auditOpen: null });
  $("#pane").innerHTML = `<div id="audit-out" class="rv-card"><div class="rv-empty">Loading…</div></div>`;
  let r;
  try { r = await api(`/api/eng/${enc(d.engagement)}/audit?n=300`); } catch (e) { $("#audit-out").innerHTML = `<div class="rv-empty err">${esc(e.message)}</div>`; return; }
  if (state.tab !== "audit" || state.current !== d.engagement || !$("#audit-out")) return;
  const all = r.entries, n = (k) => all.filter((e) => k === "all" || auditKind(e) === k).length;
  const isAgent = (e) => String(e.actor || "").startsWith("agent");
  $("#audit-out").innerHTML = `<div class="rv-toolbar pad">
      <div class="rv-search">${ICON_SEARCH}<input id="au-q" class="rv-input" type="search" placeholder="Search commands, events, people" aria-label="Search the audit log" value="${esc(state.auditQuery)}"></div>
      <div class="rv-chipset" role="group" aria-label="Kind">${[["all", "All"], ["commands", "Commands and requests"], ["changes", "Changes"], ["refused", "Refused"]].map(([k, label]) => `<button class="rv-chip ${k === state.auditKind ? "active" : ""} ${n(k) ? "" : "empty"}" aria-pressed="${k === state.auditKind}" data-auk="${k}">${label} <span class="count">${n(k)}</span></button>`).join("")}</div>
      <select id="au-who" class="rv-select fit" aria-label="Who"><option value="">Anyone</option><option value="people" ${state.auditWho === "people" ? "selected" : ""}>People</option><option value="agent" ${state.auditWho === "agent" ? "selected" : ""}>The agent</option></select>
    </div><div id="au-rows"></div>
    <p class="rv-list-note">Newest first, the latest ${all.length} entries. The authoritative log is in the kit's control volume.</p>`;
  const result = (e) => {
    const last = (e.hops || []).slice(-1)[0] || {};
    return e.refused ? pill("refused", "bad") : e.exit !== undefined ? `<span class="mono">exit ${esc(e.exit)} · ${esc(e.seconds)}s</span>`
      : e.action === "http" ? `<span class="mono">${esc(last.status || last.error || "no response")}</span>`
      : e.before !== undefined || e.after !== undefined ? `<span class="mono">${esc(e.before ?? "new")} → ${esc(e.after ?? "")}</span>` : esc(e.archive || e.status || "");
  };
  const sub = (e) => [e.refused, e.target, e.fields ? [].concat(e.fields).join(", ") : "", e.approval ? `approval ${e.approval}` : ""].filter(Boolean).join(" · ");
  const detail = (e) => `<div class="rv-dl-detail"><pre class="rv-pre">${esc(auditWhat(e))}</pre>
      ${e.refused ? `<p class="err">Refused: ${esc(e.refused)}</p>` : ""}
      <div class="rv-meta"><span>${fmtTime(e.ts)}</span><span>${esc(e.actor || "unknown actor")}</span>${e.approval ? `<span>approval ${esc(e.approval)}</span>` : ""}${e.target ? `<span>${esc(e.target)}</span>` : ""}
        ${e.fields ? `<span>fields: ${esc([].concat(e.fields).join(", "))}</span>` : ""}${(e.hops || []).length > 1 ? `<span>${e.hops.length - 1} redirect(s)</span>` : ""}</div>
      ${(e.notes || []).map((x) => `<p class="rv-dim">${esc(x)}</p>`).join("")}</div>`;
  const fill = () => {
    const q = state.auditQuery.trim().toLowerCase(), k = state.auditKind, who = state.auditWho;
    const rows = all.filter((e) => (k === "all" || auditKind(e) === k) && (!who || (who === "agent") === isAgent(e)) && has(q, [auditWhat(e), e.actor, e.target, e.refused, e.tier]));
    const [page, from, pages, p] = pageOf(rows, state.auditPage);
    state.auditPage = p;
    $("#au-rows").innerHTML = rows.length ? `<div class="rv-dl" style="--cols:156px minmax(90px, 150px) minmax(180px, 1fr) 104px minmax(90px, 150px) 76px;--minw:820px"><div class="rv-dl-in">
        <div class="rv-dl-head"><span>Time</span><span>Who</span><span>What</span><span>Tier</span><span>Result</span><span></span></div>
        ${page.map((e) => { const i = all.indexOf(e), open = state.auditOpen === i, code = auditKind(e) !== "changes" || e.command; return `<div class="rv-dl-row tall"><span>${fmtTime(e.ts)}</span><span>${actorTag(e.actor)}</span>
          <span class="two"><b class="${code ? "mono" : ""}" title="${esc(auditWhat(e))}">${esc(auditWhat(e))}</b>${sub(e) ? `<small title="${esc(sub(e))}">${esc(sub(e))}</small>` : ""}</span>
          <span>${e.tier ? tag(e.tier, TIER_CLASS[e.tier] || "") : ""}</span><span>${result(e)}</span>
          <span class="acts"><button class="rv-btn ${open ? "" : "ghost"}" data-auopen="${i}" aria-expanded="${open}">${open ? "Hide" : "Details"}</button></span></div>${open ? detail(e) : ""}`; }).join("")}
      </div></div>${pagerHtml(from, page.length, rows.length, p, pages)}` : `<div class="rv-empty">${all.length ? "No entry matches these filters." : "No activity yet."}</div>`;
    $$("[data-auopen]").forEach((b) => b.addEventListener("click", () => { const i = Number(b.dataset.auopen); state.auditOpen = state.auditOpen === i ? null : i; fill(); }));
    $$("#au-rows [data-page]").forEach((b) => b.addEventListener("click", () => { state.auditPage += Number(b.dataset.page); fill(); }));
  };
  fill();
  $("#au-q").addEventListener("input", (ev) => { state.auditQuery = ev.target.value; state.auditPage = 0; fill(); });
  $("#au-who").addEventListener("change", (ev) => { state.auditWho = ev.target.value; state.auditPage = 0; fill(); });
  $$("[data-auk]").forEach((b) => b.addEventListener("click", () => {
    state.auditKind = b.dataset.auk; state.auditPage = 0;
    $$("[data-auk]").forEach((x) => { const on = x === b; x.classList.toggle("active", on); x.setAttribute("aria-pressed", on); });
    fill();
  }));
}

// ---------------------------------------------------------------- model log (litellm/rv_events.py)
// Failed model calls (no credits, budget used up, worker down, refusals nobody recovered from) and calls another model
// answered instead. Per engagement in its "Model calls" section; all of them on the Model log page.
// One list for both places: failed calls first in the eye (filled red dot), a filter by result and a pager. `view` keeps
// the filter and the page between refreshes.
function modelList(box, events, withEng, view) {
  const n = (f) => events.filter((e) => f === "all" || (f === "failed") === !!e.problem).length;
  const cols = `156px ${withEng ? "minmax(100px, 180px) " : ""}minmax(120px, 210px) minmax(200px, 1fr) 116px`;
  const fill = () => {
    const f = view.filter || "all", rows = events.filter((e) => f === "all" || (f === "failed") === !!e.problem);
    const [page, from, pages, p] = pageOf(rows, view.page || 0);
    view.page = p;
    box.innerHTML = `<div class="rv-toolbar pad"><div class="rv-chipset" role="group" aria-label="Result">${[["all", "All"], ["failed", "Failed"], ["recovered", "Recovered"]].map(([k, label]) => `<button class="rv-chip ${k === f ? "active" : ""} ${n(k) ? "" : "empty"}" aria-pressed="${k === f}" data-mlf="${k}">${label} <span class="count">${n(k)}</span></button>`).join("")}</div></div>
      ${rows.length ? `<div class="rv-dl" style="--cols:${cols};--minw:${withEng ? 860 : 720}px"><div class="rv-dl-in">
        <div class="rv-dl-head"><span>Time</span>${withEng ? "<span>Engagement</span>" : ""}<span>Model</span><span>What happened</span><span>Result</span></div>
        ${page.map((e) => `<div class="rv-dl-row wrap"><span>${fmtTime(e.ts)}</span>
          ${withEng ? `<span>${e.engagement ? `<a href="#eng-${esc(e.engagement)}/models">${esc(e.engagement)}</a>` : `<span class="rv-dim">none</span>`}</span>` : ""}
          <span><span class="mono">${esc(e.model)}</span>${e.model_id ? `<small class="mono">${esc(e.model_id.replace(/^openrouter\//, ""))}</small>` : ""}</span>
          <span>${esc(e.text || e.message)}${e.count > 1 ? ` <span class="rv-dim mono">x${e.count}</span>` : ""}</span>
          <span>${e.problem ? pill("failed", "bad") : pill("recovered", "ok")}</span></div>`).join("")}
      </div></div>${pagerHtml(from, page.length, rows.length, p, pages)}` : `<div class="rv-empty">${events.length ? "No call has this result." : "No model problems in this period."}</div>`}`;
    box.querySelectorAll("[data-mlf]").forEach((b) => b.addEventListener("click", () => { view.filter = b.dataset.mlf; view.page = 0; fill(); }));
    box.querySelectorAll("[data-page]").forEach((b) => b.addEventListener("click", () => { view.page += Number(b.dataset.page); fill(); }));
  };
  fill();
}
async function loadModels() {
  const out = $("#models-out");
  try { const r = await api(`/api/models?since=${enc($("#models-since").value)}`); modelList(out, r.events, true, (state.modelView = state.modelView || {})); }
  catch (e) { out.innerHTML = `<div class="rv-empty err">${esc(e.message)}</div>`; }
}
$("#models-refresh").addEventListener("click", loadModels);
$("#models-since").addEventListener("change", loadModels);
async function paneModels() {
  const d = state.detail;
  $("#pane").innerHTML = `<div class="rv-card"><div class="rv-card-body"><p class="hint">Model calls for this engagement that failed, or that another model answered instead (last 7 days, newest first). Calls not matched to an engagement are on the <a href="#models">Model log</a> page.</p></div>
    <div id="models-eng"><div class="rv-empty">Loading…</div></div></div>`;
  try {
    const r = await api(`/api/models?eng=${enc(d.engagement)}`);
    if (state.tab !== "models" || state.current !== d.engagement || !$("#models-eng")) return;
    if (state.modelEng !== d.engagement) { state.modelEng = d.engagement; state.modelEngView = {}; }
    modelList($("#models-eng"), r.events, false, state.modelEngView);
  } catch (e) { $("#models-eng").innerHTML = `<div class="rv-empty err">${esc(e.message)}</div>`; }
}

// ---------------------------------------------------------------- agent (the planner's conversation)
// A conversation bound to the engagement, from /api/eng/<eng>/agent as typed items (scripts/agent_view.py): messages
// and one step per tool call, with a composer to answer the planner and Pause / Resume. All of it was written by the
// agent or a tool, so it reaches the page through esc() only;
// mdLite escapes first and then adds a fixed set of tags.
const STEP_KIND = { kali: "Kali", http: "HTTP", browser: "Browser", record: "Record", worker: "Worker", web: "Web", intel: "Intel", shell: "Shell", file: "File", tool: "Tool" };
const COMMAND_KINDS = ["kali", "http", "browser", "shell", "file", "web", "worker"];
const AGENT_STATUS = { running: ["Running", "ok"], finished: ["Finished", "closed"], paused: ["Paused", "warn"], idle: ["Idle", "closed"], error: ["Error", "bad"], stuck: ["Stuck", "bad"], waiting_for_confirmation: ["Waiting for you", "warn"], missing: ["Not in OpenHands", "bad"] };
const AGENT_FILTERS = [["all", "Everything", () => true], ["messages", "Messages", (i) => i.t === "user" || i.t === "agent"],
  ["commands", "Commands", (i) => i.t === "step" && COMMAND_KINDS.includes(i.kind)], ["findings", "Findings", (i) => i.t === "step" && !!i.finding],
  ["refused", "Refused", (i) => i.t === "step" && (i.state === "refused" || i.state === "approval")]];
// starters fill the composer; nothing is sent until the operator sends it
const AGENT_STARTERS = [["Continue", "Continue."], ["Approved, run it again", "The approval is granted. Run that command again."],
  ["Where do we stand?", "Summarise where the engagement stands: what is tested, what is left, and the findings so far."],
  ["Draft executive summary", "Draft the executive summary from the confirmed findings and save it for the report."]];
const utc = (ts) => new Date(/Z$|[+-]\d\d:?\d\d$/.test(ts || "") ? ts : ts + "Z");
const clock = (ts) => { const d = utc(ts); return isNaN(d) ? "" : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); };
function mdLite(text) {
  const inline = (s) => esc(s).replace(/`([^`\n]+)`/g, "<code>$1</code>").replace(/\*\*([^*\n]+)\*\*/g, "<b>$1</b>");
  const line = (l) => { const h = l.match(/^#{1,6}\s+(.*)$/); return h ? `<b>${inline(h[1])}</b>` : inline(l); };
  return String(text || "").split(/```[^\n]*\n?/).map((part, i) => i % 2 ? `<pre class="rv-pre">${esc(part.replace(/\n$/, ""))}</pre>`
    : part.split(/\n{2,}/).filter((p) => p.trim()).map((p) => `<p>${p.split("\n").map(line).join("<br>")}</p>`).join("")).join("");
}
function agentStep(s, open) {
  // an approval this call asked for is still waiting only while the overview lists it
  const waiting = s.state === "approval" && (state.overview?.approvals || []).some((a) => a.id === s.approval);
  const mark = s.state === "refused" ? tag("refused", "fail") : s.state === "approval" ? tag("approval", "warn")
    : s.local ? tag("agent box", "warn") : s.tier ? tag(s.tier, TIER_CLASS[s.tier] || "") : "<span></span>";
  const res = s.state === "running" ? `<span class="res"><span class="rv-progress-dot"></span>running</span>`
    : s.state === "approval" ? `<span class="res warn">${waiting ? "waiting for you" : "asked for approval"}</span>`
    : s.state === "refused" ? `<span class="res bad">not run</span>`
    : s.res ? `<span class="res ${s.state === "bad" ? "bad" : ""}"><span class="rv-dot ${s.state === "bad" ? "" : "c-ok"}"></span>${esc(s.res)}</span>`
    : s.state === "bad" ? `<span class="res bad">error</span>` : "<span></span>";
  return `<details class="rv-step ${s.state === "refused" || s.state === "bad" ? "refused" : s.state === "approval" || s.local ? "local" : ""}" data-step="${esc(s.id)}" ${open.has(s.id) ? "open" : ""}>
    <summary><span class="kind">${esc(STEP_KIND[s.kind] || s.kind)}</span>${mark}<code>${esc(s.title)}</code>${res}</summary>
    <div class="rv-step-body">
      ${s.reason ? `<p class="err">Refused: ${esc(s.reason)}</p>` : ""}
      ${s.state === "approval" ? `<p class="hint">${waiting ? `Waiting for your decision in <a href="#approvals">Approvals</a>` : "This call asked for an approval"}${s.approval ? ` (<code>${esc(s.approval)}</code>)` : ""}. ${waiting ? "After you approve, tell the agent to run it again." : "It is no longer waiting: it was decided or it expired."}</p>` : ""}
      ${s.local ? `<p class="hint">Ran in the planner's own container with an OpenHands built-in tool, not in the Kali sandbox.</p>` : ""}
      <div class="rv-meta">${s.task ? `<span>${esc(s.task)}</span>` : ""}<span>${esc(s.tool)}</span><span>${esc(clock(s.ts))}</span></div>
      ${s.why ? `<p class="rv-why">${esc(s.why)}</p>` : ""}
      <pre class="rv-pre">${esc(s.args || "")}</pre>
      ${s.out ? `<pre class="rv-pre">${esc(s.out)}</pre>` : ""}
      ${s.cut ? `<p class="hint">The output is longer than what is shown here.${s.evidence ? " The evidence file has all of it." : ""}</p>` : ""}
      ${s.evidence ? codeChips(s.evidence) : ""}
    </div></details>`;
}
// consecutive record-keeping calls of one tool (44 coverage updates) fold into one row
function agentSteps(steps, open) {
  const rows = [];
  for (let i = 0; i < steps.length;) {
    let j = i; while (j < steps.length && steps[j].tool === steps[i].tool) j++;
    const run = steps.slice(i, j), f = run[0];
    if (run.length >= 3 && f.kind === "record" && !run.some((s) => s.finding)) {
      const bad = run.filter((s) => s.state === "refused" || s.state === "bad").length, id = "g-" + f.id;
      rows.push(`<details class="rv-step" data-step="${esc(id)}" ${open.has(id) ? "open" : ""}><summary><span class="kind">${esc(STEP_KIND[f.kind])}</span><span></span>
        <code>${esc(f.tool.replace(/^[a-z]+_/, "").replace(/_/g, " "))} × ${run.length}</code><span class="res ${bad ? "warn" : ""}">${bad ? `${bad} refused` : ""}</span></summary>
        <div class="rv-step-sub">${run.map((s) => agentStep(s, open)).join("")}</div></details>`);
    } else rows.push(...run.map((s) => agentStep(s, open)));
    i = j;
  }
  return `<div class="rv-steps-box">${rows.join("")}</div>`;
}
function agentFinding(f, current) {
  const now = current.find((x) => x.id === f.id), sev = (now || f).severity, status = (now || f).status;
  return `<div class="rv-obj"><span class="id"><span class="rv-sev c-${esc(sev)}"><span class="mark"></span></span>${esc(f.id)}</span><span class="t" title="${esc(f.title)}">${esc(f.title)}</span>
    <span class="rv-meta"><span>${esc(sev)}</span>${f.cwe ? `<span>${esc(f.cwe)}</span>` : ""}${status ? `<span>${esc(human(status))}</span>` : ""}${now ? "" : "<span>no longer in the findings list</span>"}</span>
    ${now ? `<button class="rv-btn" data-finding="${esc(f.id)}">Open finding</button>` : ""}</div>`;
}
function agentStream(items, open, findings) {
  const turns = [];
  for (const it of items) {
    const last = turns[turns.length - 1];
    if (it.t === "step") { if (last && last.t === "agent") last.steps.push(it); else turns.push({ t: "agent", ts: it.ts, steps: [it] }); }
    else turns.push({ ...it, steps: [] });
  }
  if (!turns.length) return `<div class="rv-empty">Nothing here yet.</div>`;
  return turns.map((t) => {
    if (t.t === "note") return `<div class="rv-turn"><p class="${t.bad ? "err" : "hint"}">${esc(t.text)}</p></div>`;
    const found = t.steps.filter((s) => s.finding);
    return `<div class="rv-turn ${t.t === "user" ? "operator" : ""}">
      <div class="rv-turn-head"><span class="rv-label">${t.t === "user" ? "You" : "Planner"}</span><time>${esc(clock(t.ts))}</time></div>
      ${t.text ? `<div class="rv-prose">${mdLite(t.text)}</div>${t.cut ? `<p class="hint">This message is longer than what is shown here.</p>` : ""}` : ""}
      ${t.steps.length ? agentSteps(t.steps, open) : ""}
      ${found.length ? `<div class="rv-obj-list">${found.map((s) => agentFinding(s.finding, findings)).join("")}</div>` : ""}</div>`;
  }).join("");
}
async function paneAgent() {
  const d = state.detail, eng = d.engagement, gen = (state.agentGen = (state.agentGen || 0) + 1);
  const active = () => state.tab === "agent" && state.current === eng && state.agentGen === gen;
  const cs = d.conversations, convs = Array.isArray(cs) ? [...cs].sort((a, b) => String(b.updated || "").localeCompare(String(a.updated || ""))) : [];
  if (!convs.length) {
    $("#pane").innerHTML = `<div class="rv-card"><div class="rv-empty">${cs && cs.error ? `<p class="err">${esc(cs.error)}</p>` : ""}
      No conversation is bound to this engagement yet. Start one under Conversations on the <a href="#eng-${esc(eng)}/overview">Overview</a>.</div></div>`;
    return;
  }
  if (state.agentEng !== eng) Object.assign(state, { agentEng: eng, agentFilter: "all", agentOpen: new Set() });
  const cid = (state.agentConv = convs.some((c) => c.id === state.agentConv) ? state.agentConv : convs[0].id);
  const conv = convs.find((c) => c.id === cid), open = state.agentOpen, halted = !!d.info.halted;
  history.replaceState(null, "", `#eng-${eng}/agent/${cid}`);
  $("#pane").innerHTML = `<div class="rv-agent">
    <div class="rv-card">
      <div class="rv-conv-head">
        <select id="agent-conv" class="rv-select fit" aria-label="Conversation">${convs.map((c) => `<option value="${esc(c.id)}" ${c.id === cid ? "selected" : ""}>${esc(c.title || c.id)}</option>`).join("")}</select>
        <span id="agent-pill"></span>
        <div class="end"><span id="agent-ctl"></span><a class="rv-btn ghost" href="${esc(conv.url)}" target="_blank" rel="noopener" title="The same conversation in the OpenHands UI">OpenHands ↗</a></div>
      </div>
      <div class="rv-toolbar pad"><div id="agent-chips" class="rv-chipset" role="group" aria-label="Show"></div></div>
      <div class="rv-stream-wrap"><div id="agent-stream" class="rv-stream"><div class="rv-empty">Loading…</div></div>
        <button id="agent-jump" class="rv-btn rv-jump" hidden>Latest ↓</button></div>
      <form id="agent-form" class="rv-composer">
        ${halted ? `<p class="err">${esc(eng)} is halted: resume the engagement to talk to the planner.</p>` : ""}
        <textarea id="agent-msg" class="rv-input" rows="2" maxlength="20000" aria-label="Message to the planner" placeholder="Message the planner. Enter sends, Shift+Enter adds a line." ${halted ? "disabled" : ""}></textarea>
        <div class="row"><div class="rv-chipset" role="group" aria-label="Starters">${AGENT_STARTERS.map(([name], i) => `<button type="button" class="rv-chip" data-starter="${i}" ${halted ? "disabled" : ""}>${esc(name)}</button>`).join("")}</div>
          <div class="send"><button id="agent-send" type="submit" class="rv-btn accent" ${halted ? "disabled" : ""}>Send</button></div></div>
      </form>
    </div>
    <div id="agent-rail" class="rv-agent-rail"></div>
  </div>`;
  // A chat log, not a long page: the section fills the window below the engagement bar, the conversation scrolls
  // inside its own panel and the page stays where it is. The crumbs already say "Agent", so the page title goes.
  $(".rv-sec-title").hidden = true;
  const box = $("#agent-stream"), jump = $("#agent-jump"), msg = $("#agent-msg");
  state.agentDraft = state.agentDraft || {};   // what the operator was typing survives the page drawing itself again
  msg.value = state.agentDraft[cid] || "";
  const fit = () => { const el = $(".rv-agent"); if (el) el.style.setProperty("--agent-h", Math.max(420, innerHeight - (el.getBoundingClientRect().top + scrollY) - 32) + "px"); };
  state.agentFit = fit; fit(); window.scrollTo(0, 0);
  const atEnd = () => box.scrollHeight - box.scrollTop - box.clientHeight < 120;
  const toEnd = () => { box.scrollTop = box.scrollHeight; jump.hidden = true; };
  let view = null, rev = "", problem = "", timer = 0, busy = false, again = false, follow = false;
  const drawRail = () => {
    if (!view) return;
    const [label, cls] = AGENT_STATUS[view.status] || [human(view.status || "unknown"), "closed"];
    $("#agent-ctl").innerHTML = view.status === "running" ? `<button class="rv-btn" data-do="pause">Pause</button>`
      : ["paused", "error", "stuck"].includes(view.status) && !halted ? `<button class="rv-btn" data-do="resume">Resume</button>` : "";
    $("#agent-pill").innerHTML = `<span class="rv-pill ${cls}">${view.status === "running" ? `<span class="rv-progress-dot"></span>` : `<span class="rv-dot"></span>`}${esc(label)}</span>`;
    const waiting = (state.overview?.approvals || []).filter((a) => a.engagement === eng);
    const found = view.items.filter((i) => i.finding).map((i) => i.finding), started = utc(view.created), upd = utc(view.updated);
    $("#agent-rail").innerHTML = `
      ${problem ? `<div class="rv-banner warn"><div class="rv-banner-body"><p class="rv-banner-title">Can't refresh</p><p class="rv-banner-sub">${esc(problem)}</p></div></div>` : ""}
      ${waiting.length ? `<div class="rv-next danger"><div class="body"><span class="rv-label">Waiting for you</span><b>${waiting.length} approval${waiting.length > 1 ? "s" : ""}</b><span class="sub">The planner can't run ${waiting.length > 1 ? "these" : "this"} until you decide.</span></div><a class="rv-btn" href="#approvals">Review</a></div>` : ""}
      <div class="rv-card"><div class="rv-card-body">
        <div class="rv-rail-status"><span class="rv-label">${esc(label)}</span><b>${esc(view.title || "Conversation")}</b>
          <span class="sub">${isNaN(started) ? "" : "Started " + esc(started.toLocaleString())}${isNaN(upd) ? "" : " · last activity " + esc(upd.toLocaleTimeString())}</span></div>
        <div class="rv-rail-row"><span>Tool calls</span><span class="mono">${view.steps}${view.max_steps ? " of " + esc(view.max_steps) : ""}</span></div>
        ${view.truncated ? `<p class="hint">This conversation is very long: only its first part is shown.</p>` : ""}
      </div></div>
      <div class="rv-card"><div class="rv-card-head"><h3>Findings <span class="rv-dim">recorded here</span></h3></div><div class="rv-card-body" style="gap:2px">
        ${found.length ? found.map((f) => `<a class="rv-rail-find c-${esc((d.findings.find((x) => x.id === f.id) || f).severity)}" href="#eng-${esc(eng)}/findings" data-finding="${esc(f.id)}"><span class="mark"></span><span class="mono">${esc(f.id)}</span><span title="${esc(f.title)}">${esc(f.title)}</span></a>`).join("") : `<span class="rv-dim" style="font-size:12.5px">None yet.</span>`}
      </div></div>
      ${modelsCard(d)}`;
  };
  const draw = () => {
    const f = AGENT_FILTERS.find((x) => x[0] === state.agentFilter) || AGENT_FILTERS[0];
    $("#agent-chips").innerHTML = AGENT_FILTERS.map(([k, name, fn]) => { const n = k === "all" ? "" : view.items.filter(fn).length;
      return `<button class="rv-chip ${k === f[0] ? "active" : ""} ${n === 0 ? "empty" : ""}" data-filter="${k}" aria-pressed="${k === f[0]}">${name}${n === "" ? "" : ` <span class="count">${n}</span>`}</button>`; }).join("");
    $("#agent-stream").innerHTML = agentStream(view.items.filter(f[2]), open, d.findings);
    drawRail();
  };
  // one load at a time; a load asked for meanwhile (after sending) runs right after it
  const load = async () => {
    if (busy) { again = true; return; }
    busy = true; clearTimeout(timer);
    try {
      const r = await api(`/api/eng/${enc(eng)}/agent?id=${enc(cid)}${rev ? "&rev=" + rev : ""}`);
      if (!active()) return;
      problem = "";
      if (!r.unchanged) {
        const stay = follow || !view || atEnd();   // open at the latest message; keep following only while the reader is there
        view = r; rev = r.rev; follow = false; draw();
        if (stay) toEnd(); else jump.hidden = false;
      } else drawRail();
    } catch (e) {
      if (!active()) return;
      if (view) { problem = e.message; drawRail(); } else $("#agent-stream").innerHTML = `<div class="rv-empty err">${esc(e.message)}</div>`;
    } finally { busy = false; }
    if (!active()) return;
    if (again) { again = false; return load(); }
    timer = setTimeout(load, view && view.status === "running" ? 3000 : 10000);
  };
  const tell = async (btn, do_, text) => {
    const r = await act(btn, () => api(`/api/eng/${enc(eng)}/agent`, { id: cid, do: do_, text }));
    if (r && active()) { follow = do_ === "message"; load(); }
    return r;
  };
  const send = async () => {
    const text = msg.value.trim();
    if (!text || halted) return;
    msg.disabled = true;   // one message at a time: Enter twice doesn't send it twice
    const r = await tell($("#agent-send"), "message", text);
    if (!active()) return;
    msg.disabled = false;
    if (r) { msg.value = ""; delete state.agentDraft[cid]; }
    msg.focus();
  };
  $("#agent-form").addEventListener("submit", (ev) => { ev.preventDefault(); send(); });
  msg.addEventListener("keydown", (ev) => { if (ev.key === "Enter" && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); send(); } });
  msg.addEventListener("input", () => { state.agentDraft[cid] = msg.value; });
  $("#agent-form").addEventListener("click", (ev) => {
    const b = ev.target.closest("[data-starter]"); if (!b) return;
    msg.value = AGENT_STARTERS[Number(b.dataset.starter)][1]; state.agentDraft[cid] = msg.value; msg.focus();
  });
  $("#agent-ctl").addEventListener("click", (ev) => { const b = ev.target.closest("[data-do]"); if (b) tell(b, b.dataset.do, ""); });
  $("#agent-conv").addEventListener("change", (ev) => { state.agentConv = ev.target.value; state.agentOpen = new Set(); paneAgent(); });
  $("#agent-chips").addEventListener("click", (ev) => { const b = ev.target.closest("[data-filter]"); if (b && view) { state.agentFilter = b.dataset.filter; draw(); toEnd(); } });
  box.addEventListener("scroll", () => { jump.hidden = atEnd(); }, { passive: true });
  jump.addEventListener("click", toEnd);
  // toggle doesn't bubble: capture it, so an open step stays open when the stream is drawn again
  $("#agent-stream").addEventListener("toggle", (ev) => { const id = ev.target.dataset?.step; if (id) open[ev.target.open ? "add" : "delete"](id); }, true);
  $("#agent-stream").addEventListener("click", (ev) => { const b = ev.target.closest("[data-finding]"); if (b) { state.openFinding = b.dataset.finding; location.hash = `eng-${eng}/findings`; } });
  $("#agent-rail").addEventListener("click", (ev) => { const b = ev.target.closest("[data-finding]"); if (b) state.openFinding = b.dataset.finding; });
  load();
}

// ---------------------------------------------------------------- UI kit (#kit)
// A reference page, reached by its address only (/#kit): nothing in the console links to it.
// Every component the console is built from, drawn with the same classes and helpers the pages use, so this page
// cannot drift from them. Add a component here when you add one to app.css; reuse one before writing a new one.
function renderKit() {
  const item = (name, cls, html, note = "") => `<div class="rv-kit-item"><div class="rv-kit-demo">${html}</div>
    <div class="rv-kit-doc"><b>${name}</b><code>${esc(cls)}</code>${note ? `<span>${note}</span>` : ""}</div></div>`;
  const sec = (title, rule, items) => `<div class="rv-card"><div class="rv-card-head"><h3>${title}</h3></div>
    <div class="rv-card-body">${rule ? `<p class="hint">${rule}</p>` : ""}<div class="rv-kit-grid">${items.join("")}</div></div></div>`;
  const btns = (size) => `<button class="rv-btn accent ${size}">Primary</button><button class="rv-btn ${size}">Default</button><button class="rv-btn ghost ${size}">Quiet</button><button class="rv-btn danger ${size}">Danger</button><button class="rv-btn danger-quiet ${size}">Delete</button><button class="rv-btn ${size}" disabled>Disabled</button>`;
  $("#kit-out").innerHTML = [
    sec("Buttons", "Two heights only. 32px for the actions of a page, a card, a bar or a form; 28px for actions inside a list row, a pager or a side panel header. The place sets the size, so the markup never does: write .rv-btn and a kind, nothing else. One primary (accent) button per view.", [
      item("Standard, 32px", ".rv-btn  + .accent | .ghost | .danger | .danger-quiet", `<div class="rv-actions start">${btns("")}</div>`, "Card heads, the engagement bar, toolbars, forms, banners."),
      item("Compact, 28px", ".rv-btn inside a row, pager, bulk bar or panel header", `<div class="rv-kit-row">${btns("sm")}</div>`, "Automatic in those places. .rv-btn.sm forces it somewhere the rules do not cover; avoid it."),
      item("With an icon", ".rv-btn > svg", `<div class="rv-actions start"><button class="rv-btn">${ICON_COPY} Copy</button><button class="rv-btn ghost icon" aria-label="Close">${ICON_CLOSE}</button></div>`, "Icon-only buttons are square: add .icon and an aria-label."),
    ]),
    sec("Fields", "Inputs, selects and chips are 32px, the same as standard buttons, so a toolbar is one even row; 28px inside a bulk bar or a list row, automatically. A field fills its container unless it has .fit. Every field has a visible label or an aria-label.", [
      item("Text input", ".rv-input", `<label class="rv-field"><span class="rv-field-label">Label</span><input class="rv-input" placeholder="placeholder"></label>`),
      item("Select", ".rv-select", `<label class="rv-field"><span class="rv-field-label">Label</span><select class="rv-select"><option>Option</option></select></label>`),
      item("Search", ".rv-search > svg + .rv-input", `<div class="rv-search">${ICON_SEARCH}<input class="rv-input" type="search" placeholder="Search" aria-label="Search"></div>`),
      item("Text area", "textarea.rv-input", `<textarea class="rv-input" rows="2" aria-label="Example">mono, for files and JSON</textarea>`),
      item("Filter chips", ".rv-chipset > .rv-chip  + .active | .empty", `<div class="rv-chipset"><button class="rv-chip active">All <span class="count">12</span></button><button class="rv-chip">Open <span class="count">3</span></button><button class="rv-chip empty">None <span class="count">0</span></button></div>`, "Always with a count. One is active."),
      item("Toolbar", ".rv-toolbar  (.pad inside a card)", `<div class="rv-toolbar"><div class="rv-search">${ICON_SEARCH}<input class="rv-input" type="search" placeholder="Search" aria-label="Search"></div><div class="rv-chipset"><button class="rv-chip active">All <span class="count">12</span></button><button class="rv-chip">Open <span class="count">3</span></button></div><select class="rv-select fit" aria-label="Example"><option>Any</option></select><span class="rv-toolbar-end"><button class="rv-btn">Action</button></span></div>`, "Search, chips, selects, then actions at the end."),
    ]),
    sec("Status and labels", "Four vocabularies, never mixed. Severity is a square marker and a word and is the only use of the warm scale. Workflow status is a round pill. Tags are square and neutral. All are 22px high.", [
      item("Severity", "sevMark(severity)", `<div class="rv-kit-row">${SEV.map(sevMark).join("")}</div>`),
      item("Status pill", "pill(text, kind)   kinds: ok | open | warn | bad | closed", `<div class="rv-kit-row">${[["ok", "ok"], ["open", "open"], ["warn", "warn"], ["bad", "bad"], ["closed", "closed"]].map(([t, k]) => pill(t, k)).join("")}</div>`, "ok done or valid, open active, warn needs a decision, bad failed, closed over."),
      item("Tag", "tag(text, kind)", `<div class="rv-kit-row">${tag("neutral")}${tag("passive", "passive")}${tag("ok", "ok")}${tag("warn", "warn")}${tag("fail", "fail")}</div>`, "Categories and kinds: tier, parser, check name."),
      item("Count badge", ".rv-count  + .danger", `<div class="rv-kit-row"><span class="rv-count">12</span><span class="rv-count danger">3</span></div>`, "Red only when it needs the operator."),
      item("Code chip", ".rv-code-chip", `<span class="rv-code-chip">10.250.0.16/32</span>`, "Things you can copy: paths, targets, ids."),
    ]),
    sec("Surfaces", "", [
      item("Card", ".rv-card > .rv-card-head + .rv-card-body", `<div class="rv-card"><div class="rv-card-head"><h3>Title <span class="rv-dim">4</span></h3><button class="rv-btn">Action</button></div><div class="rv-card-body"><p class="hint">Body text.</p></div></div>`, "The count sits in the title; actions on the right."),
      item("Next step", ".rv-next  + .idle | .danger", `<div class="rv-next"><div class="body"><span class="rv-label">Next step</span><b>One thing that needs you</b><span class="sub">What to do about it.</span></div><button class="rv-btn accent">Do it</button></div>`),
      item("Banner", ".rv-banner  + .warn | .danger", `<div class="rv-banner warn"><div class="rv-banner-body"><p class="rv-banner-title">Check this</p><p class="rv-banner-sub">Something the operator should read.</p></div></div>`),
      item("Key and value", "dl.rv-kv", `<dl class="rv-kv"><dt>Rate</dt><dd>10 per second</dd><dt>Network</dt><dd>online</dd></dl>`),
      item("File tile", "fileTile(engagement, path)", `<div class="rv-files flat">${fileTile("example", "report.pdf")}${fileTile("example", "findings.xlsx")}</div>`),
      item("Steps", "ol.rv-stepper > li  + .done | .now", `<ol class="rv-stepper"><li class="done"><span class="st">Done</span><b>First</b></li><li class="now"><span class="st">Next</span><b>Second</b></li><li><span class="st">Later</span><b>Third</b></li></ol>`),
    ]),
    sec("Lists", "Every list is the same: a toolbar, a header, rows of one height (52px, or 56px with two lines), an optional detail row under a row, and a pager. Columns are set per list with --cols.", [
      item("Data list", ".rv-dl > .rv-dl-in > .rv-dl-head + .rv-dl-row (+ .tall | .wrap) + .rv-dl-detail", `<div class="rv-card"><div class="rv-dl" style="--cols:84px minmax(0, 1fr) 110px 84px;--minw:420px"><div class="rv-dl-in">
        <div class="rv-dl-head"><span>Severity</span><span>Item</span><span>Status</span><span></span></div>
        <div class="rv-dl-row tall">${sevMark("high")}<span class="two"><b>Title on one line, cut with an ellipsis</b><small>id · one line of detail</small></span><span>${pill("open", "open")}</span><span class="acts"><button class="rv-btn">Hide</button></span></div>
        <div class="rv-dl-detail"><p>The detail row: the full text, the form or the secondary actions for the row above.</p></div>
        <div class="rv-dl-row tall">${sevMark("low")}<span class="two"><b>Second row</b><small>id · detail</small></span><span>${pill("done", "ok")}</span><span class="acts"><button class="rv-btn ghost">Details</button></span></div>
      </div></div>${pagerHtml(0, 2, 60, 0, 3)}</div>`, "One visible action per row; the rest go in the detail row."),
    ]),
  ].join("");
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

window.addEventListener("resize", () => { if (state.tab === "agent" && state.agentFit) state.agentFit(); });
refresh().then(route).then(connectStream);
setInterval(() => { if (!streamFresh()) { refresh(); connectStream(); } }, 5000);
