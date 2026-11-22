"use strict";

const $ = id => document.getElementById(id);
const RISK_ORDER = { high: 3, medium: 2, low: 1, info: 0 };
const RISK_LABEL = { high: "Υψηλός", medium: "Μεσαίος", low: "Χαμηλός", info: "Πληροφορία" };
const GROUP_LABEL = {
  target: "Στόχος", host: "Hostnames", affiliate: "Εκτός scope", network: "Δίκτυο", dns: "DNS / email",
  registry: "Καταχώριση", people: "Άνθρωποι", cert: "Certificates", web: "Web", code: "Κώδικας"
};

let TYPES = {};     // τύπος → { label, group }
let MODULES = [];   // τα διαθέσιμα modules

/** Η κατάσταση της σελίδας ενός scan. */
const state = { id: null, scan: null, running: false, events: [], edges: [], byId: new Map(), cy: null, timer: null, hidden: new Set() };

/**
 * Κάνει escape σε κείμενο για ασφαλή εισαγωγή σε HTML (προστασία από XSS: τα δεδομένα έρχονται από τρίτους).
 * @param {*} s Το κείμενο.
 * @returns {string} Το κείμενο με escaped χαρακτήρες.
 */
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/**
 * Μορφοποιεί ημερομηνία ISO σε ελληνική μορφή.
 * @param {string} iso Η ημερομηνία.
 * @returns {string} Π.χ. "22/11/26, 14:05".
 */
function fmtDate(iso) {
  return iso ? new Date(iso).toLocaleString("el-GR", { dateStyle: "short", timeStyle: "short" }) : "";
}

/**
 * Καλεί το API και επιστρέφει το JSON. Πετά Error με το μήνυμα του server αν αποτύχει.
 * @param {string} path Το path, π.χ. "/api/scans".
 * @param {RequestInit} [opts] Επιλογές του fetch.
 * @returns {Promise<any>} Το JSON της απάντησης (ή null αν είναι κενή).
 */
async function api(path, opts) {
  const res = await fetch(path, opts);
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error(data?.error || data?.detail || res.statusText);
  return data;
}

/**
 * Επιστρέφει την ετικέτα ενός τύπου event.
 * @param {string} type Ο τύπος.
 * @returns {string} Η ελληνική ετικέτα, ή ο ίδιος ο τύπος αν δεν είναι γνωστός.
 */
const typeLabel = type => TYPES[type]?.label ?? type;

/**
 * Επιστρέφει την ομάδα ενός τύπου event.
 * @param {string} type Ο τύπος.
 * @returns {string} Η ομάδα (π.χ. "host").
 */
const typeGroup = type => TYPES[type]?.group ?? "code";

/**
 * Διαβάζει το χρώμα μιας ομάδας από τις CSS μεταβλητές, ώστε ο γράφος να ακολουθεί light/dark mode.
 * @param {string} group Η ομάδα.
 * @returns {string} Το χρώμα.
 */
const groupColor = group => getComputedStyle(document.documentElement).getPropertyValue(`--g-${group}`).trim() || "#888";

/**
 * Φτιάχνει το HTML ενός badge κινδύνου.
 * @param {string|null} risk Το επίπεδο.
 * @returns {string} Το HTML, ή κενό αν δεν υπάρχει κίνδυνος.
 */
const riskBadge = risk => risk ? `<span class="risk ${risk}">${RISK_LABEL[risk] ?? risk}</span>` : "";

// ───────────────────────── πλοήγηση ─────────────────────────

let navIdx = history.state?.idx ?? 0, navMax = navIdx;
if (history.state?.idx == null) history.replaceState({ idx: 0 }, "", location.hash || "#/");

/**
 * Πηγαίνει σε νέα "σελίδα" και την προσθέτει στο ιστορικό του browser.
 * @param {string} hash Το νέο hash, π.χ. "#/scan/3".
 * @param {boolean} [replace] Αν true, αντικαθιστά την τρέχουσα εγγραφή αντί να προσθέσει νέα.
 */
function navigate(hash, replace = false) {
  if (location.hash === hash) { route(); return; }
  if (replace) history.replaceState({ idx: navIdx }, "", hash);
  else { navIdx++; navMax = navIdx; history.pushState({ idx: navIdx }, "", hash); }
  updateNav();
  route();
}

/** Ενεργοποιεί/απενεργοποιεί τα κουμπιά Πίσω/Μπροστά ανάλογα με τη θέση στο ιστορικό. */
function updateNav() {
  $("navBack").disabled = navIdx <= 0;
  $("navFwd").disabled = navIdx >= navMax;
}

/** Δείχνει τη σελίδα που αντιστοιχεί στο τρέχον hash. */
function route() {
  stopPolling();
  const m = location.hash.match(/^#\/scan\/(\d+)$/);
  $("home").hidden = !!m;
  $("scanPage").hidden = !m;
  if (m) openScan(+m[1]); else showHome();
}

window.addEventListener("popstate", e => { navIdx = e.state?.idx ?? 0; updateNav(); route(); });
$("navBack").onclick = () => history.back();
$("navFwd").onclick = () => history.forward();
$("navHome").onclick = () => navigate("#/");
document.addEventListener("keydown", e => {
  if (!e.altKey || e.target.matches("input, textarea")) return;
  if (e.key === "ArrowLeft") { e.preventDefault(); history.back(); }
  if (e.key === "ArrowRight") { e.preventDefault(); history.forward(); }
});

/** Σταματά την περιοδική ανανέωση της σελίδας. */
function stopPolling() {
  clearTimeout(state.timer);
  state.timer = null;
}

// ───────────────────────── αρχική ─────────────────────────

/** Δείχνει την αρχική σελίδα: φόρμα νέου scan και ιστορικό. */
async function showHome() {
  renderModules();
  checkGitleaks();
  await renderHistory();
}

/** Ζωγραφίζει τη λίστα των modules, απενεργοποιώντας όσα είναι πάνω από το επιλεγμένο επίπεδο. */
function renderModules() {
  const level = document.querySelector("input[name=level]:checked").value;
  const allowed = m => level === "footprint" || m.level === "passive";
  const previous = new Map([...document.querySelectorAll("#modules input")].map(i => [i.value, i.checked]));
  $("modules").innerHTML = MODULES.map(m => `
    <label class="module ${allowed(m) ? "" : "disabled"}">
      <input type="checkbox" value="${esc(m.name)}" ${allowed(m) ? "" : "disabled"} ${previous.get(m.name) ?? true ? "checked" : ""}>
      <span><b>${esc(m.name)}</b> <span class="lvl">${m.level}</span><br>${esc(m.description)}</span>
    </label>`).join("");
  $("authRow").hidden = level !== "footprint";
}

/** Ελέγχει αν τρέχει το Gitleaks Scanner και το δείχνει δίπλα στην επιλογή. */
async function checkGitleaks() {
  try {
    const h = await api("/api/gitleaks/health");
    $("glStatus").textContent = h.available
      ? `(✓ διαθέσιμο στο ${h.url})`
      : `(⚠ δεν τρέχει στο ${h.url}: cd ~/GitleaksScanner && dotnet run)`;
  } catch { $("glStatus").textContent = ""; }
}

/** Ζωγραφίζει το ιστορικό των scans· αν κάποιο τρέχει, ανανεώνει κάθε 3 δευτερόλεπτα. */
async function renderHistory() {
  const list = await api("/api/scans");
  $("history").innerHTML = list.length ? list.map(({ scan: s, running }) => `
    <div class="hist" data-id="${s.id}">
      <div>
        <b>${esc(s.target)}</b> <span class="lvl">${esc(s.level)}</span>
        <div class="muted" style="font-size:13px">#${s.id} · ${fmtDate(s.startedAt)} · ${s.eventCount} δεδομένα · ${s.issueCount} ευρήματα</div>
      </div>
      <span><span class="status ${running ? "running" : esc(s.status)}">${running ? "τρέχει" : statusLabel(s.status)}</span></span>
    </div>`).join("") : `<div class="empty">Κανένα scan ακόμα.</div>`;
  if (list.some(x => x.running) && !$("home").hidden) state.timer = setTimeout(renderHistory, 3000);
}

/**
 * Μεταφράζει την κατάσταση ενός scan.
 * @param {string} s Η κατάσταση.
 * @returns {string} Η ελληνική ετικέτα.
 */
function statusLabel(s) {
  return { running: "τρέχει", finished: "ολοκληρώθηκε", stopped: "σταμάτησε", failed: "απέτυχε", interrupted: "διακόπηκε" }[s] ?? s;
}

$("history").addEventListener("click", e => {
  const row = e.target.closest(".hist");
  if (row) navigate(`#/scan/${row.dataset.id}`);
});
document.querySelectorAll("input[name=level]").forEach(r => r.addEventListener("change", renderModules));

$("form").addEventListener("submit", async e => {
  e.preventDefault();
  const level = document.querySelector("input[name=level]:checked").value;
  const boxes = [...document.querySelectorAll("#modules input:not(:disabled)")];
  const selected = boxes.filter(b => b.checked).map(b => b.value);
  $("formError").textContent = "";
  if (!selected.length) { $("formError").textContent = "Επίλεξε τουλάχιστον ένα module."; return; }
  try {
    const { id } = await startScan({
      target: $("target").value, level,
      modules: selected.length === boxes.length ? [] : selected,
      gitleaks: $("gitleaks").checked, authorized: $("authorized").checked
    });
    navigate(`#/scan/${id}`);
  } catch (err) {
    $("formError").textContent = "❌ " + err.message;
  }
});

/**
 * Ξεκινά νέο scan μέσω του API.
 * @param {object} body Οι ρυθμίσεις (target, level, modules, gitleaks, authorized).
 * @returns {Promise<{id:number}>} Το id του νέου scan.
 */
function startScan(body) {
  return api("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

// ───────────────────────── σελίδα scan ─────────────────────────

/**
 * Ανοίγει τη σελίδα ενός scan και, αν τρέχει ακόμα, την ανανεώνει περιοδικά.
 * @param {number} id Το id του scan.
 */
async function openScan(id) {
  if (state.id !== id) {
    state.id = id;
    state.events = []; state.edges = []; state.byId = new Map(); state.hidden.clear();
    state.cy?.destroy(); state.cy = null;
    $("details").hidden = true;
    showTab("graph");
  }
  await refresh();
}

/** Φέρνει ξανά τα δεδομένα του scan και ενημερώνει όλες τις καρτέλες. */
async function refresh() {
  let summary, graph;
  try {
    [summary, graph] = await Promise.all([api(`/api/scans/${state.id}`), api(`/api/scans/${state.id}/graph`)]);
  } catch (err) {
    $("scanTarget").textContent = "Το scan δεν βρέθηκε";
    $("scanMeta").textContent = err.message;
    return;
  }
  const changed = graph.events.length !== state.events.length;
  state.scan = summary.scan;
  state.running = summary.running;
  state.events = graph.events;
  state.edges = graph.edges;
  state.byId = new Map(graph.events.map(e => [e.id, e]));

  renderHeader(summary);
  if (changed || !state.cy) renderGraph();
  renderIssues();
  renderData();
  renderLog();

  if (state.running) state.timer = setTimeout(refresh, 2500);
}

/**
 * Ζωγραφίζει την κεφαλίδα: στόχο, κατάσταση, στατιστικά και κουμπιά.
 * @param {{scan: object, running: boolean, counts: Object<string, number>}} summary Η σύνοψη από το API.
 */
function renderHeader({ scan, running, counts }) {
  $("scanTarget").textContent = scan.target;
  const status = running ? "running" : scan.status;
  $("scanMeta").innerHTML = `<span class="status ${esc(status)}">${running ? "τρέχει…" : statusLabel(scan.status)}</span>
    · #${scan.id} · ${esc(scan.level)} · ${fmtDate(scan.startedAt)}${scan.finishedAt ? " → " + fmtDate(scan.finishedAt) : ""}
    ${scan.error ? `<div class="err">${esc(scan.error)}</div>` : ""}`;
  $("stopBtn").hidden = !running;
  $("deleteBtn").disabled = running;
  $("rescanBtn").disabled = running;

  const c = t => counts[t] ?? 0;
  const stats = [
    ["Hostnames", c("INTERNET_NAME")],
    ["IP", c("IP_ADDRESS") + c("IPV6_ADDRESS")],
    ["Δίκτυα (ASN)", c("BGP_AS_OWNER")],
    ["Τεχνολογίες", c("WEBSERVER_TECHNOLOGY") + c("SAAS_SERVICE")],
    ["Repos", c("CODE_REPOSITORY")],
    ["Ευρήματα", scan.issueCount],
  ];
  $("stats").innerHTML = stats.map(([l, n]) => `<div class="stat"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");
  $("issueBadge").textContent = scan.issueCount || "";
}

/** Αλλάζει καρτέλα (γράφος, ευρήματα, δεδομένα, log). */
function showTab(name) {
  document.querySelectorAll(".tabs button").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab").forEach(t => t.hidden = t.id !== `tab-${name}`);
  if (name === "graph") state.cy?.resize();
}
document.querySelectorAll(".tabs button").forEach(b => b.addEventListener("click", () => showTab(b.dataset.tab)));

// ───────────────────────── γράφος ─────────────────────────

/** Ζωγραφίζει (ή ανανεώνει) τον γράφο του attack surface με το Cytoscape.js. */
function renderGraph() {
  const elements = [
    ...state.events.map(e => ({
      data: { id: String(e.id), label: shortLabel(e), group: typeGroup(e.type), risk: e.risk ?? "", root: e.parentId == null ? 1 : 0 }
    })),
    ...state.edges
      .filter(x => state.byId.has(x.from) && state.byId.has(x.to))
      .map(x => ({ data: { id: `e${x.from}-${x.to}`, source: String(x.from), target: String(x.to) } })),
  ];

  if (!state.cy) {
    state.cy = cytoscape({
      container: $("cy"),
      elements,
      wheelSensitivity: 0.25,
      style: graphStyle(),
    });
    state.cy.on("tap", "node", ev => showDetails(+ev.target.id()));
    state.cy.on("tap", ev => { if (ev.target === state.cy) $("details").hidden = true; });
  } else {
    const existing = new Set(state.cy.elements().map(el => el.id()));
    state.cy.add(elements.filter(el => !existing.has(el.data.id)));
    state.cy.nodes().forEach(n => {
      const e = state.byId.get(+n.id());
      if (e) n.data("risk", e.risk ?? "");
    });
  }
  applyHidden();
  layout();
  renderLegend();
}

/**
 * Φτιάχνει σύντομη ετικέτα για έναν κόμβο, ώστε ο γράφος να μένει ευανάγνωστος.
 * @param {object} e Το event.
 * @returns {string} Η ετικέτα (το πολύ 34 χαρακτήρες).
 */
function shortLabel(e) {
  const s = e.data.replace(/^https?:\/\//, "");
  return s.length > 34 ? s.slice(0, 32) + "…" : s;
}

/**
 * Επιστρέφει το στυλ του γράφου: χρώμα ανά ομάδα, κόκκινο/πορτοκαλί περίγραμμα για κινδύνους.
 * @returns {object[]} Το stylesheet του Cytoscape.
 */
function graphStyle() {
  const text = getComputedStyle(document.documentElement).getPropertyValue("--text").trim();
  const border = getComputedStyle(document.documentElement).getPropertyValue("--border").trim();
  return [
    {
      selector: "node", style: {
        "background-color": n => groupColor(n.data("group")), label: "data(label)", color: text,
        "font-size": 9, "text-valign": "bottom", "text-margin-y": 3, width: 14, height: 14,
        "text-max-width": 160, "text-wrap": "ellipsis", "min-zoomed-font-size": 6
      }
    },
    { selector: "node[root = 1]", style: { width: 30, height: 30, "font-size": 13, "font-weight": 700 } },
    { selector: "node[risk = 'high']", style: { "border-width": 3, "border-color": "#d92d20" } },
    { selector: "node[risk = 'medium']", style: { "border-width": 3, "border-color": "#dc6803" } },
    { selector: "node[risk = 'low']", style: { "border-width": 2, "border-color": "#ca8a04" } },
    { selector: "node:selected", style: { "overlay-color": "#2f6fed", "overlay-opacity": 0.25, "overlay-padding": 6 } },
    { selector: "edge", style: { width: 1, "line-color": border, "curve-style": "haystack", opacity: 0.8 } },
    { selector: ".hidden", style: { display: "none" } },
  ];
}

/** Τρέχει τον αλγόριθμο διάταξης (force-directed) για όσους κόμβους φαίνονται. */
function layout() {
  const visible = state.cy.elements().not(".hidden");
  visible.layout({
    name: "cose", animate: false, randomize: false, fit: true, padding: 30,
    nodeRepulsion: () => 9000, idealEdgeLength: () => 60, numIter: visible.length > 1500 ? 400 : 1000
  }).run();
}

/** Ζωγραφίζει το υπόμνημα των ομάδων· με κλικ σε μια ομάδα κρύβεται/εμφανίζεται στον γράφο. */
function renderLegend() {
  const counts = {};
  state.events.forEach(e => { const g = typeGroup(e.type); counts[g] = (counts[g] ?? 0) + 1; });
  $("legend").innerHTML = Object.keys(GROUP_LABEL).filter(g => counts[g]).map(g => `
    <label class="${state.hidden.has(g) ? "off" : ""}" data-group="${g}">
      <input type="checkbox" ${state.hidden.has(g) ? "" : "checked"}>
      <span class="dot" style="background:${groupColor(g)}"></span>${GROUP_LABEL[g]} (${counts[g]})
    </label>`).join("");
}

$("legend").addEventListener("change", e => {
  const g = e.target.closest("label").dataset.group;
  if (e.target.checked) state.hidden.delete(g); else state.hidden.add(g);
  applyHidden();
  layout();
  renderLegend();
});

/** Κρύβει στον γράφο τους κόμβους των ομάδων που απενεργοποίησε ο χρήστης. */
function applyHidden() {
  state.cy.nodes().forEach(n => n.toggleClass("hidden", state.hidden.has(n.data("group"))));
}

$("relayout").onclick = () => layout();
$("fit").onclick = () => state.cy?.fit(undefined, 30);

/**
 * Επιστρέφει τη "διαδρομή" από τη ρίζα μέχρι ένα event, δηλαδή πώς βρέθηκε.
 * @param {object} e Το event.
 * @returns {object[]} Τα events από τη ρίζα μέχρι το e.
 */
function pathTo(e) {
  const path = [];
  for (let cur = e, guard = 0; cur && guard < 30; cur = state.byId.get(cur.parentId), guard++) path.unshift(cur);
  return path;
}

/**
 * Δείχνει τις λεπτομέρειες ενός κόμβου: τύπο, τιμή, πώς βρέθηκε, γονείς και παιδιά.
 * @param {number} id Το id του event.
 */
function showDetails(id) {
  const e = state.byId.get(id);
  if (!e) return;
  const parents = state.edges.filter(x => x.to === id).map(x => state.byId.get(x.from)).filter(Boolean);
  const children = state.edges.filter(x => x.from === id).map(x => state.byId.get(x.to)).filter(Boolean);
  const item = x => `<li><a data-node="${x.id}">${esc(typeLabel(x.type))}: ${esc(shortLabel(x))}</a></li>`;

  $("details").hidden = false;
  $("details").innerHTML = `
    <button class="ghost small close" type="button">✕</button>
    <div><b>${esc(typeLabel(e.type))}</b> ${riskBadge(e.risk)}</div>
    <div class="val">${esc(e.data)}</div>
    ${e.link ? `<div><a href="${esc(e.link)}" target="_blank" rel="noopener">Άνοιγμα ↗</a></div>` : ""}
    <div class="muted" style="font-size:12px">module: ${esc(e.module)} · <code>${esc(e.type)}</code></div>
    <div style="margin-top:10px"><b>Πώς βρέθηκε</b></div>
    <div class="path">${pathTo(e).map(x => esc(shortLabel(x))).join(" → ")}</div>
    ${parents.length > 1 ? `<div style="margin-top:10px"><b>Συνδέεται επίσης με (${parents.length})</b></div><ul>${parents.slice(0, 30).map(item).join("")}</ul>` : ""}
    ${children.length ? `<div style="margin-top:10px"><b>Οδήγησε σε (${children.length})</b></div><ul>${children.slice(0, 50).map(item).join("")}</ul>` : ""}`;
}

$("details").addEventListener("click", e => {
  if (e.target.closest(".close")) { $("details").hidden = true; return; }
  const a = e.target.closest("a[data-node]");
  if (a) focusNode(+a.dataset.node);
});

/**
 * Πηγαίνει στον γράφο, επιλέγει έναν κόμβο, τον κεντράρει και δείχνει τις λεπτομέρειές του.
 * @param {number} id Το id του event.
 */
function focusNode(id) {
  showTab("graph");
  const node = state.cy?.$id(String(id));
  if (!node || node.empty()) return;
  if (node.hasClass("hidden")) { state.hidden.delete(node.data("group")); applyHidden(); renderLegend(); }
  state.cy.elements().unselect();
  node.select();
  state.cy.animate({ center: { eles: node }, zoom: Math.max(state.cy.zoom(), 1.2) }, { duration: 300 });
  showDetails(id);
}

// ───────────────────────── ευρήματα, δεδομένα, log ─────────────────────────

/** Ζωγραφίζει τα ευρήματα (events με κίνδυνο), από τον υψηλότερο κίνδυνο στον χαμηλότερο. */
function renderIssues() {
  const issues = state.events
    .filter(e => e.risk && e.risk !== "info")
    .sort((a, b) => RISK_ORDER[b.risk] - RISK_ORDER[a.risk] || a.type.localeCompare(b.type));
  $("issues").innerHTML = issues.length ? issues.map(e => `
    <div class="issue">
      <div class="head">${riskBadge(e.risk)} <b>${esc(typeLabel(e.type))}</b></div>
      <div class="data">${esc(e.data)}</div>
      <div class="path">${pathTo(e).slice(0, -1).map(x => esc(shortLabel(x))).join(" → ")}
        · <a data-node="${e.id}" href="#">στον γράφο</a>${e.link ? ` · <a href="${esc(e.link)}" target="_blank" rel="noopener">άνοιγμα ↗</a>` : ""}</div>
    </div>`).join("")
    : `<div class="empty">${state.running ? "Το scan τρέχει ακόμα…" : "✅ Δεν βρέθηκαν προβλήματα."}</div>`;
}

$("issues").addEventListener("click", e => {
  const a = e.target.closest("a[data-node]");
  if (a) { e.preventDefault(); focusNode(+a.dataset.node); }
});

/** Ζωγραφίζει όλα τα δεδομένα, ομαδοποιημένα ανά τύπο, με φίλτρο αναζήτησης. */
function renderData() {
  const q = $("dataFilter").value.toLowerCase();
  const open = new Set([...document.querySelectorAll("#data details[open]")].map(d => d.dataset.type));
  const byType = new Map();
  for (const e of state.events) {
    if (q && !e.data.toLowerCase().includes(q) && !typeLabel(e.type).toLowerCase().includes(q)) continue;
    if (!byType.has(e.type)) byType.set(e.type, []);
    byType.get(e.type).push(e);
  }
  const order = Object.keys(TYPES);
  const types = [...byType.keys()].sort((a, b) => order.indexOf(a) - order.indexOf(b));
  $("data").innerHTML = types.map(t => {
    const rows = byType.get(t);
    const isOpen = open.has(t) || q || rows.length <= 10;
    return `<details class="group" data-type="${esc(t)}" ${isOpen ? "open" : ""}>
      <summary>${esc(typeLabel(t))} <span class="muted">(${rows.length})</span></summary>
      <table>${rows.map(e => `<tr>
        <td class="v">${e.link ? `<a href="${esc(e.link)}" target="_blank" rel="noopener">${esc(e.data)}</a>` : esc(e.data)}</td>
        <td class="m">${riskBadge(e.risk)}</td>
        <td class="m"><a href="#" data-node="${e.id}">γράφος</a></td>
        <td class="m">${esc(e.module)}</td></tr>`).join("")}</table>
    </details>`;
  }).join("") || `<div class="empty">Κανένα αποτέλεσμα.</div>`;
}

$("dataFilter").addEventListener("input", renderData);
$("data").addEventListener("click", e => {
  const a = e.target.closest("a[data-node]");
  if (a) { e.preventDefault(); focusNode(+a.dataset.node); }
});

/** Φέρνει και ζωγραφίζει το log του scan. */
async function renderLog() {
  const lines = await api(`/api/scans/${state.id}/log`);
  $("log").innerHTML = lines.map(l =>
    `<div class="${esc(l.level)}">${esc(new Date(l.at).toLocaleTimeString("el-GR"))} [${esc(l.module)}] ${esc(l.message)}</div>`).join("")
    || `<div class="muted">Κενό.</div>`;
}

// ───────────────────────── ενέργειες ─────────────────────────

$("stopBtn").onclick = async () => {
  await api(`/api/scans/${state.id}/stop`, { method: "POST" }).catch(() => {});
  stopPolling();
  setTimeout(refresh, 800);
};

$("deleteBtn").onclick = async () => {
  if (!confirm(`Διαγραφή του scan #${state.id} (${state.scan?.target});`)) return;
  try {
    await api(`/api/scans/${state.id}`, { method: "DELETE" });
    state.id = null;
    navigate("#/", true);   // replace: το "Πίσω" να μη γυρίζει σε διαγραμμένο scan
  } catch (err) { alert(err.message); }
};

$("rescanBtn").onclick = async () => {
  const s = state.scan;
  const footprint = s.level === "footprint";
  if (footprint && !confirm(`Footprint scan στο ${s.target}: επιβεβαιώνεις ότι έχεις άδεια;`)) return;
  try {
    const { id } = await startScan({ target: s.target, level: s.level, modules: [], gitleaks: false, authorized: footprint });
    navigate(`#/scan/${id}`);
  } catch (err) { alert(err.message); }
};

/**
 * Κατεβάζει ένα αρχείο που φτιάχνεται στον browser.
 * @param {string} name Το όνομα του αρχείου.
 * @param {string} content Το περιεχόμενο.
 * @param {string} type Ο MIME type.
 */
function download(name, content, type) {
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([content], { type })), download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

$("exportJson").onclick = () =>
  download(`surface-${state.scan.target}-${state.id}.json`,
    JSON.stringify({ scan: state.scan, events: state.events, edges: state.edges }, null, 2), "application/json");

$("exportCsv").onclick = () => {
  /** Κάνει escape ένα κελί CSV (και εξουδετερώνει formulas του Excel: =, +, -, @). */
  const cell = v => {
    let s = String(v ?? "");
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const rows = [["type", "label", "data", "risk", "module", "found_from", "link"]].concat(
    state.events.map(e => [e.type, typeLabel(e.type), e.data, e.risk, e.module, state.byId.get(e.parentId)?.data, e.link]));
  // BOM ώστε το Excel να διαβάζει σωστά τα ελληνικά
  download(`surface-${state.scan.target}-${state.id}.csv`, "﻿" + rows.map(r => r.map(cell).join(",")).join("\r\n"), "text/csv");
};

// ───────────────────────── εκκίνηση ─────────────────────────

/** Φορτώνει τους τύπους και τα modules από το API και δείχνει την τρέχουσα σελίδα. */
async function init() {
  [TYPES, MODULES] = await Promise.all([api("/api/types"), api("/api/modules")]);
  updateNav();
  route();
}

init();
