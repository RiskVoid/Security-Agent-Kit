// RiskVoid Console front end. Plain JS, no build step. Text that comes from the agent (findings, commands, notes)
// is untrusted: it only ever reaches the page through esc() or textContent.
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEV = ["critical", "high", "medium", "low", "info"];
const STATUSES = ["candidate", "confirmed", "false-positive", "duplicate", "fixed", "accepted-risk"];

const state = { overview: null, current: null, detail: null, tab: "overview", seenApprovals: null, findingFilter: "all", openFinding: null, preview: null, evidence: null };

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
  t.textContent = msg; t.className = "toast" + (bad ? " bad" : ""); t.hidden = false;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => { t.hidden = true; }, bad ? 8000 : 3500);
}

async function act(btn, fn, okMsg) {
  if (btn) btn.disabled = true;
  try { const r = await fn(); if (okMsg) toast(okMsg); return r; }
  catch (e) { toast(e.message, true); }
  finally { if (btn) btn.disabled = false; }
}

const tierChips = (tiers) => (tiers || []).map((t) => `<span class="chip ${esc(t)}">${esc(t)}</span>`).join(" ");
const fmtTime = (v) => { if (!v) return ""; const d = typeof v === "number" ? new Date(v * 1000) : new Date(v); return isNaN(d) ? esc(v) : d.toLocaleString(); };

// ---------------------------------------------------------------- routing
function show(view) {
  for (const v of ["engagements", "approvals", "status"]) $(`#view-${v}`).hidden = v !== view;
  $$(".top nav a").forEach((a) => a.classList.toggle("on", a.dataset.view === view));
  if (view === "status") loadStatus();
}
function route() {
  const h = location.hash.replace("#", "");
  if (h === "approvals" || h === "status") return show(h);
  show("engagements");
  if (h.startsWith("eng-")) { const name = h.slice(4); if (name !== state.current) openEngagement(name); }
}
window.addEventListener("hashchange", route);

// ---------------------------------------------------------------- overview + approvals polling
async function refresh() {
  try {
    const o = await api("/api/overview");
    state.overview = o;
    $("#agent-ui").href = o.ui_url;
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
    $("#eng-list").innerHTML = `<li class="err">${esc(e.message)}</li>`;
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
    const flags = [e.closed ? `<span class="chip closed">closed</span>` : e.halted ? `<span class="chip halted">halted</span>` : "",
      e.pending ? `<span class="badge" title="pending approvals">${e.pending}</span>` : ""].join(" ");
    const sub = [e.client, `${f.confirmed || 0} confirmed`, f.candidate ? `${f.candidate} to triage` : ""].filter(Boolean).map(esc).join(" · ");
    return `<li><button data-eng="${esc(e.engagement)}" class="${e.engagement === state.current ? "on" : ""}">
      <span class="eng-name">${esc(e.engagement)} ${flags}</span><span class="eng-sub">${sub}</span></button></li>`;
  }).join("") || `<li class="eng-sub">No engagements yet.</li>`;
}
$("#eng-list").addEventListener("click", (ev) => { const b = ev.target.closest("button[data-eng]"); if (b) location.hash = "eng-" + b.dataset.eng; });
$("#eng-filter").addEventListener("input", renderList);

function approvalCard(a, withEng) {
  return `<div class="appr">
    <div class="meta">${withEng ? `<b>${esc(a.engagement)}</b>` : ""}<span class="chip intrusive">${esc(a.tier)}</span>
      <span>id ${esc(a.id)}</span><span>${fmtTime(a.created)}</span></div>
    <pre>${esc(a.command)}</pre>
    <div class="actions">
      <button data-deny="${esc(a.engagement)}/${esc(a.id)}">Deny</button>
      <button class="primary" data-approve="${esc(a.engagement)}/${esc(a.id)}">Approve this command</button>
    </div></div>`;
}
function renderApprovals() {
  const list = state.overview?.approvals || [];
  $("#appr-all").innerHTML = list.length ? list.map((a) => approvalCard(a, true)).join("") : `<p class="hint">Nothing is waiting for approval.</p>`;
}
document.addEventListener("click", async (ev) => {
  const b = ev.target.closest("[data-approve],[data-deny]");
  if (!b) return;
  const approve = b.hasAttribute("data-approve");
  const [eng, id] = (b.dataset.approve || b.dataset.deny).split("/");
  await act(b, () => api(`/api/approvals/${encodeURIComponent(eng)}/${id}/${approve ? "approve" : "deny"}`, {}),
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
  renderList();
  $("#detail").innerHTML = `<div class="empty">Loading ${esc(name)}…</div>`;
  try { state.detail = await api(`/api/eng/${encodeURIComponent(name)}`); renderDetail(); }
  catch (e) { $("#detail").innerHTML = `<div class="empty err">${esc(e.message)}</div>`; }
}

function renderDetail() {
  const d = state.detail, i = d.info, r = i.rules;
  const ov = (state.overview?.engagements || []).find((e) => e.engagement === d.engagement) || {};
  const status = ov.closed ? `<span class="chip closed">closed</span>` : i.halted ? `<span class="chip halted">halted</span>` : `<span class="chip ok">active</span>`;
  $("#detail").innerHTML = `
    <div class="d-head">
      <div class="d-title"><h2>${esc(d.engagement)}</h2>${status} ${tierChips(r.tiers)}</div>
      <div class="eng-sub">${esc(d.meta.client || "No client name yet")} · ${esc(r.network)} · max ${esc(r.max_rate)}/s${r.worker === "private" ? " · private worker" : ""}</div>
      <div class="d-actions">
        ${i.halted ? `<button id="resume-btn">Resume</button>` : `<button id="halt-btn" class="danger">Halt now</button>`}
        <button id="close-btn">Close out…</button>
        <button id="delete-btn" class="danger">Delete…</button>
      </div>
      <div id="confirm-slot"></div>
    </div>
    <div class="tabs" role="tablist">
      ${["overview", "scope", "findings", "tasks", "report", "audit"].map((t) => `<button role="tab" data-tab="${t}" class="${state.tab === t ? "on" : ""}">${{ overview: "Overview", scope: "Scope & rules", findings: `Findings (${d.findings.length})`, tasks: "Worker tasks", report: "Report", audit: "Audit log" }[t]}</button>`).join("")}
    </div>
    <div id="pane" class="pane"></div>`;
  $$(".tabs button").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.tab; renderDetail(); }));
  $("#halt-btn")?.addEventListener("click", (ev) => lifecycle(ev.target, "halt", "Halted: running commands were killed."));
  $("#resume-btn")?.addEventListener("click", (ev) => lifecycle(ev.target, "resume", "Resumed."));
  $("#close-btn").addEventListener("click", () => confirmBox("Close out " + d.engagement + "?",
    "Writes the audit extract and a SHA-256 manifest, archives the folder to _archive/, and halts the engagement. You can resume it later for a retest.",
    "Close out", (btn) => lifecycle(btn, "close", "Closed and archived.")));
  $("#delete-btn").addEventListener("click", () => confirmBox("Delete " + d.engagement + "?",
    ov.closed ? "Removes its scope, rules, approvals and firewall rules and frees its slot. The folder is kept, renamed to _deleted-…; archives and the audit history stay."
      : "This engagement isn't closed, so there's no archive or manifest. Close it first unless it's a practice engagement. The folder is kept, renamed to _deleted-….",
    ov.closed ? "Delete" : "Delete without closing", async (btn) => {
      await act(btn, () => api(`/api/eng/${encodeURIComponent(d.engagement)}/delete`, { force: !ov.closed }), "Deleted.");
      state.current = null; location.hash = "engagements"; $("#detail").innerHTML = `<div class="empty">Pick an engagement, or create one.</div>`; refresh();
    }));
  ({ overview: paneOverview, scope: paneScope, findings: paneFindings, tasks: paneTasks, report: paneReport, audit: paneAudit })[state.tab]();
}

function confirmBox(title, text, label, fn) {
  $("#confirm-slot").innerHTML = `<div class="confirm"><b>${esc(title)}</b><p class="hint">${esc(text)}</p>
    <div class="actions"><button id="cf-no">Cancel</button><button id="cf-yes" class="danger">${esc(label)}</button></div></div>`;
  $("#cf-no").addEventListener("click", () => { $("#confirm-slot").innerHTML = ""; });
  $("#cf-yes").addEventListener("click", (ev) => fn(ev.target));
}

async function lifecycle(btn, action, msg) {
  const name = state.current;
  const r = await act(btn, () => api(`/api/eng/${encodeURIComponent(name)}/${action}`, {}), msg);
  if (r) { await refresh(); await openEngagement(name, true); }
}

function paneOverview() {
  const d = state.detail, i = d.info, sc = i.scope, c = {};
  d.findings.forEach((f) => { c[f.status] = (c[f.status] || 0) + 1; });
  const conf = d.findings.filter((f) => f.status === "confirmed");
  const bySev = SEV.map((s) => [s, conf.filter((f) => f.severity === s).length]);
  const targets = [...sc.nets, ...sc.domains, ...sc.paths];
  const prompt = `Engagement \`${d.engagement}\`: <what to test>. Follow the matching playbooks, then write the executive summary and generate the report.`;
  $("#pane").innerHTML = `
    ${d.approvals.length ? `<div><h3>Waiting for your approval</h3>${d.approvals.map((a) => approvalCard(a, false)).join("")}</div>` : ""}
    <div class="counts">
      ${bySev.map(([s, n]) => `<div class="count"><b class="sev ${s}">${n}</b><span>${s}</span></div>`).join("")}
      <div class="count"><b>${c.candidate || 0}</b><span>to triage</span></div>
    </div>
    <dl class="kv">
      <dt>Targets</dt><dd>${targets.map((t) => `<code>${esc(t)}</code>`).join(" ") || "none"}</dd>
      <dt>Tiers</dt><dd>${tierChips(i.rules.tiers)}</dd>
      <dt>Rate</dt><dd>${esc(i.rules.max_rate)} per second</dd>
      <dt>Network</dt><dd>${esc(i.rules.network)}</dd>
      <dt>Window</dt><dd>${i.rules.window ? esc(i.rules.window.join(":")) : "any time"}</dd>
      <dt>Worker</dt><dd>${i.rules.worker === "private" ? "private (never the fallback model)" : "fallback allowed when switched on"}</dd>
    </dl>
    <div><h3>Start the agent</h3><p class="hint">Open the agent UI, start a conversation with <b>riskvoid-planner</b> and name the engagement:</p>
      <pre class="diff" id="start-prompt">${esc(prompt)}</pre><div class="actions"><button id="copy-prompt">Copy</button></div></div>`;
  $("#copy-prompt").addEventListener("click", () => navigator.clipboard.writeText(prompt).then(() => toast("Copied.")).catch(() => toast("Copy failed: select the text instead.", true)));
}

function paneScope() {
  const d = state.detail, p = state.preview;
  $("#pane").innerHTML = `
    <p class="hint">Edit the scope and rules, preview what changes, then apply. Applying rebuilds the firewall at once.</p>
    <div class="two">
      <label>SCOPE.md <textarea id="scope-text" rows="14" spellcheck="false">${esc(d.scope_text)}</textarea></label>
      <label>RULES.md <textarea id="rules-text" rows="14" spellcheck="false">${esc(d.rules_text)}</textarea></label>
    </div>
    <div class="actions"><button id="preview-btn">Preview changes</button><button id="apply-btn" class="primary" ${p && p.diff ? "" : "disabled"}>Apply</button></div>
    <div id="preview-out">${p ? previewHtml(p) : ""}</div>`;
  const reset = () => { state.preview = null; $("#apply-btn").disabled = true; $("#preview-out").innerHTML = ""; };
  $("#scope-text").addEventListener("input", reset); $("#rules-text").addEventListener("input", reset);
  $("#preview-btn").addEventListener("click", async (ev) => {
    const r = await act(ev.target, () => api(`/api/eng/${encodeURIComponent(d.engagement)}/preview`, { scope: $("#scope-text").value, rules: $("#rules-text").value }));
    if (!r) return;
    state.preview = r; d.scope_text = $("#scope-text").value; d.rules_text = $("#rules-text").value;
    $("#preview-out").innerHTML = previewHtml(r); $("#apply-btn").disabled = !r.diff;
  });
  $("#apply-btn").addEventListener("click", async (ev) => {
    const r = await act(ev.target, () => api(`/api/eng/${encodeURIComponent(d.engagement)}/apply`, { scope: $("#scope-text").value, rules: $("#rules-text").value }), "Applied. The firewall now uses the new scope.");
    if (r) { state.preview = null; await refresh(); await openEngagement(d.engagement, true); }
  });
}
function previewHtml(p) {
  const lines = (p.diff || "").split("\n").map((l) => `<span class="${l.startsWith("+++") || l.startsWith("---") || l.startsWith("@@") ? "hdr" : l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : ""}">${esc(l)}</span>`).join("\n");
  const targets = [...p.scope.nets, ...p.scope.domains, ...p.scope.paths];
  return `${p.warnings.length ? `<ul class="issues">${p.warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}
    ${p.diff ? `<pre class="diff">${lines}</pre>` : `<p class="hint">No changes.</p>`}
    <dl class="kv"><dt>Will allow</dt><dd>${targets.map((t) => `<code>${esc(t)}</code>`).join(" ") || "nothing"}</dd>
    <dt>Tiers</dt><dd>${tierChips(p.rules.tiers)}</dd><dt>Rate / network</dt><dd>${esc(p.rules.max_rate)}/s · ${esc(p.rules.network)}</dd></dl>`;
}

function paneFindings() {
  const d = state.detail, filt = state.findingFilter;
  const rows = d.findings.filter((f) => filt === "all" || f.status === filt).sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || a.id.localeCompare(b.id));
  const ev = state.evidence;
  $("#pane").innerHTML = `
    <div class="page-head">
      <label class="inline">Show <select id="f-filter">${["all", ...STATUSES].map((s) => `<option ${s === filt ? "selected" : ""}>${s}</option>`).join("")}</select></label>
      <button id="ev-btn">Check evidence integrity</button>
    </div>
    ${ev && ev.issues.length ? `<ul class="issues">${ev.issues.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ev ? `<p class="hint">All evidence checks out.</p>` : ""}
    <div class="tbl-wrap"><table>
      <thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Status</th><th>Asset</th></tr></thead>
      <tbody>${rows.map((f) => `<tr class="click" data-fid="${esc(f.id)}"><td class="num mono">${esc(f.id)}</td><td class="sev ${esc(f.severity)}">${esc(f.severity)}</td>
        <td>${esc(f.title)}</td><td>${esc(f.status)}${f.duplicate_of ? ` of ${esc(f.duplicate_of)}` : ""}</td><td class="mono">${esc(f.asset)}</td></tr>
        ${state.openFinding === f.id ? editorRow(f, ev) : ""}`).join("") || `<tr><td colspan="5" class="hint">No findings${filt === "all" ? " yet" : " with this status"}.</td></tr>`}</tbody>
    </table></div>`;
  $("#f-filter").addEventListener("change", (e) => { state.findingFilter = e.target.value; paneFindings(); });
  $("#ev-btn").addEventListener("click", async (e) => {
    const r = await act(e.target, () => api(`/api/eng/${encodeURIComponent(d.engagement)}/evidence`));
    if (r) { state.evidence = r; paneFindings(); }
  });
  $$("tr[data-fid]").forEach((tr) => tr.addEventListener("click", () => { state.openFinding = state.openFinding === tr.dataset.fid ? null : tr.dataset.fid; paneFindings(); }));
  const save = $("#fe-save");
  if (save) {
    $("#fe-status").addEventListener("change", () => { $("#fe-dup-wrap").hidden = $("#fe-status").value !== "duplicate"; });
    save.addEventListener("click", async () => {
      const body = { id: state.openFinding, status: $("#fe-status").value, severity: $("#fe-sev").value, notes: $("#fe-notes").value };
      if (body.status === "duplicate") body.duplicate_of = $("#fe-dup").value.trim();
      const r = await act(save, () => api(`/api/eng/${encodeURIComponent(d.engagement)}/finding`, body), "Saved.");
      if (r) { await openEngagement(d.engagement, true); refresh(); }
    });
  }
}
const BADGE = { verified: ["ok", "verified"], "code reference": ["passive", "code ref"] };
function editorRow(f, ev) {
  const items = ev?.items?.[f.id];
  const evid = (items || (f.evidence || []).map((p) => ({ path: p }))).map((i) => {
    const st = i.status ? (BADGE[i.status] || [i.status.startsWith("not produced") ? "warn" : "halted", i.status.startsWith("not produced") ? "not audited" : i.status]) : null;
    return `<li><code>${esc(i.path)}</code>${i.note ? ` ${esc(i.note)}` : ""} ${st ? `<span class="chip ${st[0]}">${esc(st[1])}</span>` : ""}</li>`;
  }).join("");
  return `<tr class="editor"><td colspan="5"><div class="ed-grid">
      <label>Status <select id="fe-status">${STATUSES.map((s) => `<option ${s === f.status ? "selected" : ""}>${s}</option>`).join("")}</select></label>
      <label>Severity <select id="fe-sev">${SEV.map((s) => `<option ${s === f.severity ? "selected" : ""}>${s}</option>`).join("")}</select></label>
      <label id="fe-dup-wrap" ${f.status === "duplicate" ? "" : "hidden"}>Duplicate of <input id="fe-dup" value="${esc(f.duplicate_of || "")}" placeholder="F-001"></label>
    </div>
    <label>Notes <textarea id="fe-notes" rows="3">${esc(f.notes)}</textarea></label>
    <dl class="kv">
      <dt>CWE / CVSS</dt><dd>${esc(f.cwe || "n/a")} · ${esc(f.cvss_score ?? "n/a")} <span class="mono">${esc(f.cvss_vector || "")}</span></dd>
      <dt>Description</dt><dd style="white-space:pre-wrap">${esc(f.description)}</dd>
      ${f.reproduction ? `<dt>Reproduction</dt><dd style="white-space:pre-wrap">${esc(f.reproduction)}</dd>` : ""}
      ${f.remediation ? `<dt>Remediation</dt><dd style="white-space:pre-wrap">${esc(f.remediation)}</dd>` : ""}
      <dt>Evidence</dt><dd><ul style="margin:0;padding-left:1.1rem">${evid || "none"}</ul></dd>
      <dt>Source</dt><dd>${esc(f.source)} · updated ${fmtTime(f.updated)}</dd>
    </dl>
    <div class="actions"><button id="fe-save" class="primary">Save</button></div></td></tr>`;
}

function paneReport() {
  const d = state.detail, m = d.meta;
  $("#pane").innerHTML = `
    <div class="row">
      <label>Client <input id="m-client" value="${esc(m.client || "")}"></label>
      <label>Prepared by <input id="m-by" value="${esc(m["prepared by"] || "")}"></label>
      <label>Version <input id="m-ver" value="${esc(m.version || "1.0")}"></label>
      <label>Classification <input id="m-cls" value="${esc(m.classification || "Confidential")}"></label>
    </div>
    <div class="actions"><button id="m-save">Save details</button></div>
    <label>Executive summary (markdown) <textarea id="exec" rows="10">${esc(d.executive_summary)}</textarea></label>
    <div class="actions"><button id="exec-save">Save summary</button><button id="gen-btn" class="primary">Generate report</button></div>
    <div id="gen-out"></div>
    <div><h3>Files</h3>${d.report_files.length ? `<ul>${d.report_files.map((f) => `<li><a href="/files/${encodeURIComponent(d.engagement)}/${encodeURIComponent(f)}">${esc(f)}</a></li>`).join("")}</ul>` : `<p class="hint">No report yet.</p>`}</div>`;
  $("#m-save").addEventListener("click", (e) => act(e.target, () => api(`/api/eng/${encodeURIComponent(d.engagement)}/meta`,
    { client: $("#m-client").value, "prepared by": $("#m-by").value, version: $("#m-ver").value, classification: $("#m-cls").value }), "Saved.").then(refresh));
  $("#exec-save").addEventListener("click", (e) => act(e.target, () => api(`/api/eng/${encodeURIComponent(d.engagement)}/summary`, { text: $("#exec").value }), "Saved."));
  $("#gen-btn").addEventListener("click", async (e) => {
    $("#gen-out").innerHTML = `<p class="hint">Building the report (up to a minute)…</p>`;
    const r = await act(e.target, () => api(`/api/eng/${encodeURIComponent(d.engagement)}/report`, {}));
    if (!r) { $("#gen-out").innerHTML = ""; return; }
    const draft = r.status === "DRAFT";
    $("#gen-out").innerHTML = `<p><span class="chip ${draft ? "warn" : "ok"}">${draft ? "DRAFT" : "final"}</span> ${esc(r.findings)} finding(s) in the report.</p>
      ${draft ? `<p class="hint">Fix these, then generate again:</p><ul class="issues">${r.issues.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}`;
    const keep = $("#gen-out").innerHTML;
    await openEngagement(d.engagement, true); $("#gen-out").innerHTML = keep;
  });
}

async function paneTasks() {
  const d = state.detail;
  $("#pane").innerHTML = `<p class="hint">Tasks the planner handed to the worker model, newest first. Full output of every step is in
    <code>evidence/tasks/&lt;task&gt;/</code>.</p><div id="tasks-out" class="hint">Loading…</div>`;
  const load = async () => {
    if (state.tab !== "tasks" || state.current !== d.engagement) return;
    try {
      const r = await api(`/api/eng/${encodeURIComponent(d.engagement)}/tasks`);
      const chip = { done: "ok", running: "active", queued: "passive", error: "halted", interrupted: "warn" };
      $("#tasks-out").outerHTML = `<div id="tasks-out">${r.tasks.map((t) => `<details class="appr" style="border-left-color:var(--rule)" ${t.status === "running" ? "open" : ""}>
        <summary><span class="chip ${chip[t.status] || ""}">${esc(t.status)}</span> <span class="chip ${esc(t.tier)}">${esc(t.tier)}</span>
          ${esc((t.goal || "").slice(0, 140))}</summary>
        <div class="meta"><span>${esc(t.id)}</span><span>started ${fmtTime(t.started)}</span>${t.finished ? `<span>${Math.round((t.finished - t.started) / 60)} min</span>` : ""}
          <span>${t.steps.length} step(s)</span><span>${t.candidates} candidate(s)</span>${t.models.length ? `<span>model: ${t.models.map(esc).join(", ")}</span>` : ""}</div>
        ${t.error ? `<p class="err">${esc(t.error)}</p>` : ""}${t.summary ? `<p style="white-space:pre-wrap">${esc(t.summary)}</p>` : ""}
        ${t.steps.length ? `<pre>${t.steps.map((s, i) => `${String(i + 1).padStart(2, " ")}  ${esc(s)}`).join("\n")}</pre>` : ""}
      </details>`).join("") || `<p class="hint">No worker tasks yet.</p>`}</div>`;
      if (r.tasks.some((t) => t.status === "running" || t.status === "queued")) setTimeout(load, 5000);
    } catch (e) { $("#tasks-out").textContent = e.message; }
  };
  load();
}

async function paneAudit() {
  const d = state.detail;
  $("#pane").innerHTML = `<p class="hint">Newest first. The authoritative log is in the kit's control volume.</p><div id="audit-out" class="hint">Loading…</div>`;
  try {
    const r = await api(`/api/eng/${encodeURIComponent(d.engagement)}/audit?n=300`);
    $("#audit-out").outerHTML = `<div class="tbl-wrap"><table><thead><tr><th>Time</th><th>What</th><th>Tier</th><th>Result</th></tr></thead><tbody>
      ${r.entries.map((e) => {
        const what = e.command ? `<code>${esc(e.command)}</code>` : esc(e.event || "");
        const res = e.refused ? `<span class="chip halted">refused</span> ${esc(e.refused)}` : e.exit !== undefined ? `exit ${esc(e.exit)} · ${esc(e.seconds)}s` : esc(e.archive || e.status || "");
        return `<tr><td class="num">${fmtTime(e.ts)}</td><td>${what}</td><td>${e.tier ? `<span class="chip ${esc(e.tier)}">${esc(e.tier)}</span>` : ""}</td><td>${res}</td></tr>`;
      }).join("") || `<tr><td colspan="4" class="hint">No activity yet.</td></tr>`}</tbody></table></div>`;
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
