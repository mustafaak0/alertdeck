/* AlertDeck dashboard logic — vanilla JS, no dependencies. */
"use strict";

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[c]));

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const STATUSES = ["new", "in_progress", "resolved", "false_positive"];

const state = {
  filters: { q: "", severity: "", status: "", source: "", sort: "newest" },
  currentId: null,
};

/* ---------------------------------------------------------------- helpers */

async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch { /* keep status line */ }
    throw new Error(detail);
  }
  return res.json();
}

function toast(message, ok = false) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.toggle("ok", ok);
  el.hidden = false;
  clearTimeout(el._timer);
  el._timer = setTimeout(() => { el.hidden = true; }, 3500);
}

function relTime(iso) {
  const diff = Date.now() - new Date(iso + "Z".slice(iso.endsWith("Z") ? 1 : 0)).getTime();
  const mins = Math.round(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function fmtTs(iso) { return iso ? iso.replace("T", " ").replace("Z", "") : "—"; }

/* ------------------------------------------------------------------ stats */

function renderStats(s) {
  const cards = [
    { num: s.by_status.new, lbl: "New", filter: { status: "new" } },
    { num: s.by_status.in_progress, lbl: "In progress", filter: { status: "in_progress" } },
    { num: s.by_severity.critical, lbl: "Critical", filter: { severity: "critical" } },
    { num: s.total, lbl: "Total", filter: null },
  ];
  $("#stats-cards").innerHTML = cards.map((c, i) => {
    const active = c.filter &&
      Object.entries(c.filter).every(([k, v]) => state.filters[k] === v);
    return `<div class="card ${c.filter ? "clickable" + (active ? " active" : "") : ""}"
                 data-i="${i}">
              <div class="num">${c.num}</div>
              <div class="lbl">${c.lbl}</div>
            </div>`;
  }).join("");
  [...$("#stats-cards").children].forEach((el) => el.addEventListener("click", () => {
    const card = cards[Number(el.dataset.i)];
    if (!card.filter) return;
    for (const [key, value] of Object.entries(card.filter)) {
      state.filters[key] = state.filters[key] === value ? "" : value;
    }
    syncFilterInputs();
    refresh();
  }));

  const max = Math.max(1, ...s.timeline.map((d) => d.count));
  $("#timeline").innerHTML = s.timeline.map((d) =>
    `<div class="bar" style="height:${Math.max(4, (d.count / max) * 100)}%"
          title="${d.date}: ${d.count} alerts"></div>`
  ).join("");

  const maxSev = Math.max(1, ...Object.values(s.by_severity));
  const maxSt = Math.max(1, ...Object.values(s.by_status));
  const row = (label, count, maxCount, cls) => `
    <div class="dist-row">
      <span>${label}</span>
      <span class="mono">${count}</span>
      <span class="track"><span class="fill ${cls}" style="width:${(count / maxCount) * 100}%;background:var(--${cls});color:var(--${cls})"></span></span>
    </div>`;
  $("#dist").innerHTML =
    SEVERITIES.map((sev) => row(sev, s.by_severity[sev], maxSev, `sev-${sev}`)).join("") +
    `<div style="height:8px"></div>` +
    STATUSES.map((st) => row(st.replace("_", " "), s.by_status[st], maxSt, `st-${st}`)).join("");

  const tops = (title, items) => items.length
    ? `<div class="k dim" style="margin-bottom:4px">${title}</div>` +
      items.map((i) => `<div class="row"><span class="mono">${esc(i.value)}</span><span class="dim">${i.count}</span></div>`).join("")
    : "";
  $("#tops").innerHTML = tops("Sources", s.top_sources) + tops("Source IPs", s.top_src_ips) || '<span class="dim">No data yet.</span>';
}

/* ------------------------------------------------------------------ table */

function renderTable(alerts) {
  const body = $("#alerts-body");
  $("#empty").hidden = alerts.length > 0;
  body.innerHTML = alerts.map((a) => `
    <tr data-id="${a.id}">
      <td class="mono dim">${a.id}</td>
      <td class="mono dim" title="${fmtTs(a.detected_at)}">${relTime(a.detected_at)}</td>
      <td><span class="badge ${a.severity}">${a.severity}</span></td>
      <td><span class="pill ${a.status}">${a.status.replace("_", " ")}</span></td>
      <td>${esc(a.source)}</td>
      <td class="rule">${esc(a.rule_name)}</td>
      <td class="mono">${esc(a.src_ip ?? "—")}</td>
      <td>${esc(a.username ?? "—")}</td>
      <td class="${a.assignee ? "" : "dim"}">${esc(a.assignee ?? "—")}</td>
    </tr>`).join("");
  [...body.children].forEach((tr) =>
    tr.addEventListener("click", () => openDrawer(Number(tr.dataset.id))));
}

/* ----------------------------------------------------------------- drawer */

async function openDrawer(id) {
  try {
    const a = await api(`/api/alerts/${id}`);
    state.currentId = id;
    renderDrawer(a);
    $("#drawer").hidden = false;
    $("#backdrop").hidden = false;
  } catch (e) {
    toast(`Failed to load alert #${id}: ${e.message}`);
  }
}

function closeDrawer() {
  state.currentId = null;
  $("#drawer").hidden = true;
  $("#backdrop").hidden = true;
}

function renderDrawer(a) {
  const drawer = $("#drawer");
  drawer.innerHTML = `
    <button class="close" title="Close (Esc)">✕</button>
    <h2>${esc(a.rule_name)}</h2>
    <div class="sub">
      <span class="badge ${a.severity}">${a.severity}</span><span class="sep">·</span>
      <span>${esc(a.source)}</span><span class="sep">·</span>
      <span class="mono">#${a.id}</span>
    </div>

    <div class="fields">
      <div class="f"><div class="k">Detected</div><div class="v">${fmtTs(a.detected_at)}</div></div>
      <div class="f"><div class="k">Ingested</div><div class="v">${fmtTs(a.created_at)}</div></div>
      <div class="f"><div class="k">Source IP</div><div class="v">${esc(a.src_ip ?? "—")}</div></div>
      <div class="f"><div class="k">Dest IP</div><div class="v">${esc(a.dst_ip ?? "—")}</div></div>
      <div class="f"><div class="k">User</div><div class="v">${esc(a.username ?? "—")}</div></div>
      <div class="f"><div class="k">Host</div><div class="v">${esc(a.host ?? "—")}</div></div>
    </div>

    ${a.description ? `<p class="desc">${esc(a.description)}</p>` : ""}

    <h4>Status</h4>
    <div class="status-btns">
      ${STATUSES.map((st) => `<button class="btn ${st} ${a.status === st ? "active" : ""}"
        data-status="${st}" ${a.status === st ? "disabled" : ""}>
        ${st.replace("_", " ")}</button>`).join("")}
    </div>

    <h4>Severity &amp; assignment</h4>
    <div class="assign-row">
      <select id="d-severity">
        ${SEVERITIES.map((s) => `<option value="${s}" ${a.severity === s ? "selected" : ""}>${s}</option>`).join("")}
      </select>
      <input id="d-assignee" placeholder="assignee" value="${esc(a.assignee ?? "")}">
      <button id="d-save-meta" class="btn primary">Save</button>
    </div>

    <h4>Investigation notes</h4>
    <div id="d-notes">
      ${a.notes.length ? a.notes.map((n) => `
        <div class="note">
          <div class="head"><b>${esc(n.author)}</b> · ${fmtTs(n.created_at)} (${relTime(n.created_at)})</div>
          <div class="body">${esc(n.text)}</div>
        </div>`).join("")
      : '<div class="dim" style="margin-bottom:8px">No notes yet.</div>'}
    </div>
    <div class="note-form">
      <textarea id="d-note-text" placeholder="What did you find? e.g. confirmed C2 beacon, host isolated…"></textarea>
      <div class="row">
        <input id="d-note-author" placeholder="analyst" value="analyst">
        <button id="d-note-add" class="btn primary">Add note</button>
      </div>
    </div>

    ${a.raw ? `<h4>Raw event</h4><div class="raw-block">${esc(a.raw)}</div>` : ""}
  `;

  drawer.querySelector(".close").addEventListener("click", closeDrawer);
  drawer.querySelectorAll("[data-status]").forEach((btn) =>
    btn.addEventListener("click", () => patchAlert(a.id, { status: btn.dataset.status })));
  drawer.querySelector("#d-save-meta").addEventListener("click", () => {
    patchAlert(a.id, {
      severity: drawer.querySelector("#d-severity").value,
      assignee: drawer.querySelector("#d-assignee").value,
    });
  });
  drawer.querySelector("#d-note-add").addEventListener("click", async () => {
    const text = drawer.querySelector("#d-note-text").value.trim();
    if (!text) return toast("Note text is empty.");
    try {
      await api(`/api/alerts/${a.id}/notes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text,
          author: drawer.querySelector("#d-note-author").value.trim() || "analyst",
        }),
      });
      toast("Note added.", true);
      await refresh();
      await openDrawer(a.id);
    } catch (e) { toast(e.message); }
  });
}

async function patchAlert(id, fields) {
  try {
    await api(`/api/alerts/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(fields),
    });
    toast("Alert updated.", true);
    await refresh();
    if (state.currentId === id) await openDrawer(id);
  } catch (e) { toast(e.message); }
}

/* -------------------------------------------------------------- data flow */

async function refresh() {
  const f = state.filters;
  const params = new URLSearchParams(
    Object.entries(f).filter(([, v]) => v !== ""));
  try {
    const [alerts, s] = await Promise.all([
      api(`/api/alerts?${params}`),
      api("/api/stats"),
    ]);
    renderTable(alerts);
    renderStats(s);
  } catch (e) {
    toast(e.message);
  }
}

function syncFilterInputs() {
  const f = state.filters;
  $("#f-q").value = f.q;
  $("#f-severity").value = f.severity;
  $("#f-status").value = f.status;
  $("#f-source").value = f.source;
  $("#f-sort").value = f.sort;
}

async function loadSources() {
  const meta = await api("/api/meta");
  fillSelect("#f-severity", "All severities", meta.severities);
  fillSelect("#f-status", "All statuses", meta.statuses.map((s) => [s, s.replace("_", " ")]));
  fillSelect("#f-source", "All sources", meta.sources);
}

function fillSelect(sel, allLabel, values) {
  const el = $(sel);
  el.innerHTML = `<option value="">${allLabel}</option>` +
    values.map((v) => Array.isArray(v)
      ? `<option value="${v[0]}">${esc(v[1])}</option>`
      : `<option value="${v}">${esc(v)}</option>`).join("");
}

/* ------------------------------------------------------------------- init */

async function init() {
  try {
    await loadSources();
  } catch (e) { toast(e.message); }

  syncFilterInputs();

  let debounce;
  $("#f-q").addEventListener("input", (e) => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      state.filters.q = e.target.value.trim();
      refresh();
    }, 300);
  });
  for (const [sel, key] of [
    ["#f-severity", "severity"], ["#f-status", "status"],
    ["#f-source", "source"], ["#f-sort", "sort"],
  ]) {
    $(sel).addEventListener("change", (e) => {
      state.filters[key] = e.target.value;
      refresh();
    });
  }
  $("#btn-refresh").addEventListener("click", refresh);
  $("#backdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDrawer();
  });

  await refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, 20000);
}

init();
