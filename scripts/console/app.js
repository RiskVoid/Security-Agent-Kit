// RiskVoid Console front end. Plain JS, no build step. Text that comes from the agent (findings, commands, notes)
// is untrusted: it only ever reaches the page through esc() or textContent.
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const enc = encodeURIComponent;
const SEV = ["critical", "high", "medium", "low", "info"];
const STATUSES = ["candidate", "confirmed", "false-positive", "duplicate", "fixed", "accepted-risk"];
const TABS = { overview: "Overview", live: "Live", scope: "Scope & rules", findings: "Findings", tasks: "Worker tasks", report: "Report", audit: "Audit log" };

const state = { overview: null, current: null, detail: null, tab: "overview", seenApprovals: null, findingFilter: "all", openFinding: null, preview: null, evidence: null, view: "engagements" };

async function api(path, body) {
  const opt = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json", "X-RV-Console": "1" }, body: JSON.stringify(body) };
  const r = await fetch(path, opt);
  let data = {};
  try { data = await r.json(); } catch { /* non-JSON error page */ }
  if (!r.ok) throw new Error(data.error || `${r.status} ${r.statusText}`);
  if (data && data.error) throw new Error(data.error);
  return data;
}

function toast(msg, bad = false) {
  const t = $("#toast");
  t.textContent = msg; t.className = "rv-toast" + (bad ? " bad" : ""); t.hidden = false;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => { t.hidden = true; }, bad ? 8000 : 3500);
}

async function act(btn, fn, okMsg) {
  if (btn) btn.disabled = true;
  try { const r = await fn(); if (okMsg) toast(okMsg); return r; }
  catch (e) { toast(e.message, true); }
  finally { if (btn) btn.disabled = false; }
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
  for (const v of ["engagements", "approvals", "status"]) $(`#view-${v}`).hidden = v !== view;
  $$(".rv-sidebar-item[data-view]").forEach((a) => a.classList.toggle("active", a.dataset.view === view));
  document.body.classList.remove("nav-open");
  if (view === "status") { crumbs([["Console", "#engagements"], ["Stack status"]]); loadStatus(); }
  else if (view === "approvals") crumbs([["Console", "#engagements"], ["Approvals"]]);
  else crumbs(state.current ? [["Console", "#engagements"], ["Engagements", "#engagements"], [state.current]] : [["Console", "#engagements"], ["Engagements"]]);
}
function route() {
  const h = location.hash.replace("#", "");
  if (h === "approvals" || h === "status") return show(h);
  if (h.startsWith("eng-")) { const name = h.slice(4); if (name !== state.current) { state.current = name; openEngagement(name); } }
  show("engagements");
}
window.addEventListener("hashchange", route);
$("#menu-btn").addEventListener("click", () => document.body.classList.toggle("nav-open"));

// ---------------------------------------------------------------- overview + approvals polling
async function refresh() {
  try {
    const o = await api("/api/overview");
    state.overview = o;
    $("#agent-ui").href = o.ui_url;
    if (o.version) $("#side-version").textContent = "kit " + o.version;
    $("#eng-count").textContent = o.engagements.length || "";
    renderList(); renderApprovals();
    const ids = new Set(o.approvals.map((a) => a.id));
    if (state.seenApprovals) {
      const fresh = o.approvals.filter((a) => !state.seenApprovals.has(a.id));
      if (fresh.length) notify(fresh);
    }
    state.seenApprovals = ids;
    const b = $("#appr-badge"); b.textContent = o.approvals.length; b.hidden = !o.approvals.length;
    document.title = (o.approvals.length ? `(${o.approvals.length}) ` : "") + "RiskVoid Console";
  } catch (e) {
    $("#eng-list").innerHTML = `<div class="rv-empty err">${esc(e.message)}</div>`;
  }
}

function notify(fresh) {
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  for (const a of fresh.slice(0, 3)) new Notification("RiskVoid: approval needed", { body: `${a.engagement}: ${a.command.slice(0, 100)}` });
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
    <div class="rv-actions">
      <button class="rv-btn ghost" data-deny="${esc(a.engagement)}/${esc(a.id)}">Deny</button>
      <button class="rv-btn accent" data-approve="${esc(a.engagement)}/${esc(a.id)}">Approve this command</button>
    </div></div></div>`;
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
    <div class="rv-tabs" role="tablist">
      ${Object.entries(TABS).map(([t, name]) => `<button role="tab" aria-selected="${state.tab === t}" data-tab="${t}" class="rv-tab ${state.tab === t ? "active" : ""}">${name}${counts[t] !== undefined ? ` <span class="n">${counts[t]}</span>` : ""}</button>`).join("")}
    </div>
    <div id="pane" class="rv-pane"></div>`;
  $$(".rv-tab").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.tab; renderDetail(); }));
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
  ({ overview: paneOverview, live: paneLive, scope: paneScope, findings: paneFindings, tasks: paneTasks, report: paneReport, audit: paneAudit })[state.tab]();
}

function confirmBox(title, text, label, fn) {
  $("#confirm-slot").innerHTML = `<div class="rv-banner danger"><div class="rv-banner-body">
    <p class="rv-banner-title">${esc(title)}</p><p class="rv-banner-sub">${esc(text)}</p>
    <div class="rv-actions start" style="margin-top:8px"><button id="cf-yes" class="rv-btn danger">${esc(label)}</button><button id="cf-no" class="rv-btn ghost">Cancel</button></div></div></div>`;
  $("#cf-no").addEventListener("click", () => { $("#confirm-slot").innerHTML = ""; });
  $("#cf-yes").addEventListener("click", (ev) => fn(ev.currentTarget));
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
        </dl></div></div>
      <div class="rv-card"><div class="rv-card-head"><h3>Start the agent</h3><a class="rv-btn ghost sm" href="${esc(state.overview?.ui_url || "#")}" target="_blank" rel="noopener">Open agent UI ↗</a></div>
        <div class="rv-card-body">
          <p class="hint">Start a conversation with <b>riskvoid-planner</b> and name the engagement:</p>
          <pre class="rv-pre">${esc(prompt)}</pre>
          <div class="rv-actions start"><button id="copy-prompt" class="rv-btn sm">${ICON_COPY} Copy prompt</button></div>
        </div></div>
    </div>`;
  $("#copy-prompt").addEventListener("click", () => navigator.clipboard.writeText(prompt).then(() => toast("Copied.")).catch(() => toast("Copy failed: select the text instead.", true)));
  $$("[data-goto]").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.goto; renderDetail(); }));
}

function paneScope() {
  const d = state.detail, p = state.preview;
  $("#pane").innerHTML = `
    <p class="hint">Edit the scope and rules, preview what changes, then apply. Applying rebuilds the engagement's firewall at once.</p>
    <div class="rv-two">
      <label class="rv-field"><span class="rv-field-label">SCOPE.md</span><textarea id="scope-text" class="rv-input" rows="14" spellcheck="false">${esc(d.scope_text)}</textarea></label>
      <label class="rv-field"><span class="rv-field-label">RULES.md</span><textarea id="rules-text" class="rv-input" rows="14" spellcheck="false">${esc(d.rules_text)}</textarea></label>
    </div>
    <div class="rv-actions"><button id="preview-btn" class="rv-btn">Preview changes</button><button id="apply-btn" class="rv-btn accent" ${p && p.diff ? "" : "disabled"}>Apply</button></div>
    <div id="preview-out" class="rv-stack">${p ? previewHtml(p) : ""}</div>`;
  const reset = () => { state.preview = null; $("#apply-btn").disabled = true; $("#preview-out").innerHTML = ""; };
  $("#scope-text").addEventListener("input", reset); $("#rules-text").addEventListener("input", reset);
  $("#preview-btn").addEventListener("click", async (ev) => {
    const r = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/preview`, { scope: $("#scope-text").value, rules: $("#rules-text").value }));
    if (!r) return;
    state.preview = r; d.scope_text = $("#scope-text").value; d.rules_text = $("#rules-text").value;
    $("#preview-out").innerHTML = previewHtml(r); $("#apply-btn").disabled = !r.diff;
  });
  $("#apply-btn").addEventListener("click", async (ev) => {
    const r = await act(ev.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/apply`, { scope: $("#scope-text").value, rules: $("#rules-text").value }), "Applied. The firewall now uses the new scope.");
    if (r) { state.preview = null; await refresh(); await openEngagement(d.engagement, true); }
  });
}
function previewHtml(p) {
  const lines = (p.diff || "").split("\n").map((l) => `<span class="${l.startsWith("+++") || l.startsWith("---") || l.startsWith("@@") ? "hdr" : l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : ""}">${esc(l)}</span>`).join("\n");
  return `${p.warnings.length ? `<div class="rv-banner warn"><div class="rv-banner-body"><p class="rv-banner-title">The parser ignored some entries</p><ul>${p.warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul></div></div>` : ""}
    <div class="rv-card"><div class="rv-card-head"><h3>Preview</h3>${p.diff ? tag("changes", "warn") : tag("no changes")}</div><div class="rv-card-body">
      ${p.diff ? `<pre class="rv-pre">${lines}</pre>` : ""}
      <dl class="rv-kv"><dt>Will allow</dt><dd>${codeChips([...p.scope.nets, ...p.scope.domains, ...p.scope.paths])}</dd>
      <dt>Tiers</dt><dd>${tierTags(p.rules.tiers)}${p.rules.strict ? " " + tag("strict", "warn") : ""}</dd><dt>Rate / network</dt><dd>${esc(p.rules.max_rate)}/s · ${esc(p.rules.network)}</dd></dl>
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
    $("#fe-status").addEventListener("change", () => { $("#fe-dup-wrap").hidden = $("#fe-status").value !== "duplicate"; });
    save.addEventListener("click", async () => {
      const body = { id: state.openFinding, status: $("#fe-status").value, severity: $("#fe-sev").value, notes: $("#fe-notes").value };
      if (body.status === "duplicate") body.duplicate_of = $("#fe-dup").value.trim();
      const r = await act(save, () => api(`/api/eng/${enc(d.engagement)}/finding`, body), "Saved.");
      if (r) { await openEngagement(d.engagement, true); refresh(); }
    });
  }
}
function evidenceBadge(st) {
  if (!st) return "";
  if (st === "verified") return tag("verified", "ok");
  if (st === "code reference") return tag("code ref", "code");
  if (st.startsWith("not produced")) return tag("not audited", "warn");
  return tag(st, "fail");
}
function editor(f, ev) {
  const items = ev?.items?.[f.id] || (f.evidence || []).map((p) => ({ path: p }));
  const opt = (list, cur) => list.map((s) => `<option ${s === cur ? "selected" : ""}>${s}</option>`).join("");
  return `<div class="rv-editor">
    <div class="rv-form-grid">
      <label class="rv-field"><span class="rv-field-label">Status</span><select id="fe-status" class="rv-select">${opt(STATUSES, f.status)}</select></label>
      <label class="rv-field"><span class="rv-field-label">Severity</span><select id="fe-sev" class="rv-select">${opt(SEV, f.severity)}</select></label>
      <label id="fe-dup-wrap" class="rv-field" ${f.status === "duplicate" ? "" : "hidden"}><span class="rv-field-label">Duplicate of</span><input id="fe-dup" class="rv-input" value="${esc(f.duplicate_of || "")}" placeholder="F-001"></label>
    </div>
    <label class="rv-field"><span class="rv-field-label">Notes</span><textarea id="fe-notes" class="rv-input" rows="3">${esc(f.notes)}</textarea></label>
    <dl class="rv-kv">
      <dt>CWE / CVSS</dt><dd>${esc(f.cwe || "n/a")} · ${esc(f.cvss_score ?? "n/a")} <span class="mono rv-dim">${esc(f.cvss_vector || "")}</span></dd>
      <dt>Description</dt><dd><p class="rv-prose">${esc(f.description)}</p></dd>
      ${f.reproduction ? `<dt>Reproduction</dt><dd><pre class="rv-pre">${esc(f.reproduction)}</pre></dd>` : ""}
      ${f.remediation ? `<dt>Remediation</dt><dd><p class="rv-prose">${esc(f.remediation)}</p></dd>` : ""}
      <dt>Evidence</dt><dd>${items.length ? `<ul class="rv-evidence">${items.map((i) => `<li><span class="rv-code-chip">${esc(i.path)}</span>${i.note ? `<span class="rv-dim">${esc(i.note)}</span>` : ""}${evidenceBadge(i.status)}</li>`).join("")}</ul>` : `<span class="rv-dim">none</span>`}</dd>
      <dt>Source</dt><dd>${esc(f.source)} · updated ${fmtTime(f.updated)}</dd>
    </dl>
    <div class="rv-actions"><button id="fe-save" class="rv-btn accent">Save</button></div></div>`;
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
    <div class="rv-card"><div class="rv-card-head"><h3>Files</h3>${html.length ? `<a class="rv-btn sm" href="/report/${enc(d.engagement)}/${enc(html[0])}" target="_blank" rel="noopener">View HTML report ↗</a>` : ""}</div>
      ${files.length ? `<div class="rv-card-body flush"><table class="rv-table"><tbody>${files.map((f) => `<tr><td><span class="mono">${esc(f)}</span></td>
        <td style="text-align:right">${f.endsWith(".html") ? `<a href="/report/${enc(d.engagement)}/${enc(f)}" target="_blank" rel="noopener">View</a> · ` : ""}<a href="/files/${enc(d.engagement)}/${enc(f)}">Download</a></td></tr>`).join("")}</tbody></table></div>`
      : `<div class="rv-empty">No report yet.</div>`}</div>`;
  $("#m-save").addEventListener("click", (e) => act(e.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/meta`,
    { client: $("#m-client").value, "prepared by": $("#m-by").value, version: $("#m-ver").value, classification: $("#m-cls").value }), "Saved.").then(refresh));
  $("#exec-save").addEventListener("click", (e) => act(e.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/summary`, { text: $("#exec").value }), "Saved."));
  $("#gen-btn").addEventListener("click", async (e) => {
    $("#gen-out").innerHTML = `<div class="rv-banner"><div class="rv-banner-body"><p class="rv-banner-title">Building the report</p><p class="rv-banner-sub">Checking evidence and writing the HTML, Word, PDF and Excel files. Up to a minute.</p></div></div>`;
    const r = await act(e.currentTarget, () => api(`/api/eng/${enc(d.engagement)}/report`, {}));
    if (!r) { $("#gen-out").innerHTML = ""; return; }
    const draft = r.status === "DRAFT";
    const keep = `<div class="rv-banner ${draft ? "warn" : ""}"><div class="rv-banner-body">
      <p class="rv-banner-title">${draft ? tag("draft", "draft") : tag("final", "ok")} ${esc(r.findings)} finding(s) in the report</p>
      ${draft ? `<p class="rv-banner-sub">Not ready for the client. Fix these, then generate again:</p><ul>${r.issues.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : `<p class="rv-banner-sub">Ready to deliver.</p>`}</div></div>`;
    await openEngagement(d.engagement, true); $("#gen-out").innerHTML = keep;
  });
}

async function paneTasks() {
  const d = state.detail;
  $("#pane").innerHTML = `<p class="hint">Tasks the planner handed to the worker model, newest first. Full output of every step is in
    <code>evidence/tasks/&lt;task&gt;/</code>.</p><div id="tasks-out" class="rv-empty">Loading…</div>`;
  const load = async () => {
    if (state.tab !== "tasks" || state.current !== d.engagement) return;
    try {
      const r = await api(`/api/eng/${enc(d.engagement)}/tasks`);
      $("#tasks-out").outerHTML = `<div id="tasks-out" class="rv-stack">${r.tasks.map((t) => `<details class="rv-card rv-task" ${t.status === "running" ? "open" : ""}>
        <summary>${tag(t.status, t.status)} ${tag(t.tier, TIER_CLASS[t.tier] || "")}<span class="goal">${esc((t.goal || "").slice(0, 160))}</span></summary>
        <div class="rv-card-body">
          <div class="rv-meta"><span>${esc(t.id)}</span><span>started ${fmtTime(t.started)}</span>${t.finished ? `<span>${Math.max(0, Math.round((t.finished - t.started) / 60))} min</span>` : ""}
            <span>${t.steps.length} step(s)</span><span>${t.candidates} candidate(s)</span>${t.models.length ? `<span>model: ${t.models.map(esc).join(", ")}</span>` : ""}</div>
          ${t.error ? `<p class="err">${esc(t.error)}</p>` : ""}${t.summary ? `<p class="rv-prose">${esc(t.summary)}</p>` : ""}
          ${t.steps.length ? `<pre class="rv-pre">${t.steps.map((s, i) => `<span class="ln">${String(i + 1).padStart(2, " ")}</span>  ${esc(s)}`).join("\n")}</pre>` : ""}
        </div></details>`).join("") || `<div class="rv-card"><div class="rv-empty">No worker tasks yet.</div></div>`}</div>`;
      if (r.tasks.some((t) => t.status === "running" || t.status === "queued")) setTimeout(load, 5000);
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
    const pct = sp && sp.budget ? Math.min(100, (100 * sp.spend) / sp.budget) : 0;
    const spendKpi = sp ? kpi("OpenRouter today", `$${sp.spend.toFixed(2)}`, "", sp.budget ? `of $${sp.budget.toFixed(2)} daily budget · ${pct.toFixed(0)}%` : "no daily budget set")
      : kpi("OpenRouter today", "–", "", "LiteLLM isn't answering");
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
  const load = async () => {
    if (!active()) return;
    if (!document.hidden) {
      try {
        const r = await api(`/api/eng/${enc(eng)}/live`);
        if (!active()) return;
        skew = Date.now() / 1000 - r.now;
        render(r);
      } catch (e) { const o = $("#live-out"); if (o) o.textContent = e.message; }
    }
    setTimeout(load, 3000);
  };
  const timer = setInterval(() => { if (!active()) clearInterval(timer); else tick(); }, 1000);
  load();
}

async function paneAudit() {
  const d = state.detail;
  $("#pane").innerHTML = `<p class="hint">Newest first. The authoritative log is in the kit's control volume.</p><div id="audit-out" class="rv-empty">Loading…</div>`;
  try {
    const r = await api(`/api/eng/${enc(d.engagement)}/audit?n=300`);
    $("#audit-out").outerHTML = `<div class="rv-table-wrap"><table class="rv-table"><thead><tr><th>Time</th><th>What</th><th>Tier</th><th>Result</th></tr></thead><tbody>
      ${r.entries.map((e) => {
        const what = e.command ? `<code>${esc(e.command)}</code>` : esc(e.event || "");
        const res = e.refused ? `${tag("refused", "fail")} <span class="rv-dim">${esc(e.refused)}</span>` : e.exit !== undefined ? `<span class="mono">exit ${esc(e.exit)} · ${esc(e.seconds)}s</span>` : esc(e.archive || e.status || "");
        return `<tr><td class="nowrap">${fmtTime(e.ts)}</td><td>${what}</td><td>${e.tier ? tag(e.tier, TIER_CLASS[e.tier] || "") : ""}</td><td>${res}</td></tr>`;
      }).join("") || `<tr><td colspan="4"><div class="rv-empty">No activity yet.</div></td></tr>`}</tbody></table></div>`;
  } catch (e) { $("#audit-out").textContent = e.message; }
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

refresh().then(route);
setInterval(refresh, 5000);
