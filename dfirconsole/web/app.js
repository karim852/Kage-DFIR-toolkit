/* Kage DFIR Toolkit — front-end controller.
   A single WebSocket feeds the console, the step states and the results; REST
   calls are only used for actions (run, stop, configure). */

const $ = (sel) => document.querySelector(sel);
const LEVELS = ["critical", "high", "medium", "low", "informational"];
const CAT_LABEL = {
  auth: "Authentication", infection: "Infection", execution: "Execution",
  network: "Network", evasion: "Evasion", other: "Other",
};

// The table column is narrow and the colour already carries the identity, so
// the badge uses a short form there. Filter chips keep the full name.
const CAT_SHORT = {
  auth: "Auth", infection: "Infection", execution: "Execution",
  network: "Network", evasion: "Evasion", other: "Other",
};
const CAT_ORDER = ["auth", "infection", "execution", "network", "evasion", "other"];

const LEVEL_LABEL = {
  critical: "critical", high: "high", medium: "medium",
  low: "low", informational: "info",
};
const STATUS_LABEL = {
  pending: "pending", running: "running", done: "sealed",
  failed: "failed", skipped: "skipped",
};

const state = {
  steps: [],
  report: null,
  ai: null,
  selected: new Set(),
  filters: new Set(["critical", "high", "medium"]),
  search: "",
  running: false,
  startedAt: null,
  finishedAt: null,
  selectionReady: false,
  yara: [],
  system: null,
  cats: new Set(CAT_ORDER),
  yaraLevels: new Set(LEVELS),
  yaraSearch: "",
  route: "/",
  pendingProvider: "anthropic",
  reader: { list: [], index: 0, kind: "alert" },
};

/* ---------------- view navigation ----------------
   The analysis lives on the server, so switching views triggers no reload and
   cannot lose anything. We simply reveal one section.                        */
const ROUTES = ["/", "/alerts", "/indicators", "/system", "/yara", "/attack",
                "/summary", "/log"];

function navigate(route, push = true) {
  if (!ROUTES.includes(route)) route = "/";
  state.route = route;
  if (push && location.pathname !== route) history.pushState({ route }, "", route);

  document.querySelectorAll(".view").forEach((view) => {
    view.hidden = view.dataset.view !== route;
  });
  document.querySelectorAll(".nav__item").forEach((item) => {
    item.classList.toggle("is-active", item.dataset.route === route);
  });

  // Some views redraw on display: their tables may have been filled while
  // they were hidden.
  if (route === "/alerts") renderAlerts();
  if (route === "/indicators") renderIocs();
  if (route === "/system") renderSystem();
  if (route === "/yara") renderYara();
  if (route === "/attack") renderAttack();
  if (route === "/summary") renderAi();
  if (route === "/") renderOverview();
  if (route === "/log") syncSecondConsole();
}

document.getElementById("nav").addEventListener("click", (event) => {
  const link = event.target.closest(".nav__item");
  if (!link) return;
  event.preventDefault();
  navigate(link.dataset.route);
});

window.addEventListener("popstate", () => navigate(location.pathname, false));

/* ---------------- AI provider catalogue ---------------- */
let providers = [];

async function loadProviders() {
  try {
    const response = await fetch("/api/providers");
    providers = (await response.json()).providers || [];
  } catch (_) {
    providers = [];
  }
  const select = $("#setProvider");
  select.innerHTML = "";
  providers.forEach((p) => {
    const option = document.createElement("option");
    option.value = p.id;
    option.textContent = p.label;
    select.append(option);
  });
  if (state.pendingProvider) {
    select.value = state.pendingProvider;
    describeProvider();
  }
}

function describeProvider() {
  const spec = providers.find((p) => p.id === $("#setProvider").value);
  const hint = $("#baseUrlHint");
  const input = $("#setBaseUrl");
  if (!spec) return;
  input.placeholder = spec.base_url || "https://…";
  $("#setModel").placeholder = spec.default_model || "model name";
  hint.textContent = spec.base_url
    ? `defaults to ${spec.base_url}`
    : spec.id === "custom" ? "required for this choice" : "not applicable";
}

$("#setProvider").addEventListener("change", describeProvider);

/* ---------------- connection ---------------- */
let socket = null;
let retry = 0;

function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${proto}://${location.host}/ws`);

  socket.onopen = () => {
    retry = 0;
    setLink("is-live", "stream open");
  };
  socket.onclose = () => {
    setLink("is-down", "stream lost — reconnecting…");
    retry = Math.min(retry + 1, 6);
    setTimeout(connect, 500 * retry);
  };
  socket.onmessage = (event) => handle(JSON.parse(event.data));
}

function setLink(cls, label) {
  const dot = $("#linkDot");
  dot.className = "dot " + cls;
  $("#linkLabel").textContent = label;
}

function handle(event) {
  switch (event.kind) {
    case "hello":
      // The backlog can hold thousands of entries: keep only the tail, the log
      // file remains the complete source.
      (event.backlog || []).slice(-MAX_LINES).forEach(handle);
      applySnapshot(event.snapshot);
      break;
    case "log":
      appendLog(event);
      break;
    case "step":
      mergeStep(event.step);
      break;
    case "ioc":
      patchIoc(event.ioc);
      break;
    case "system":
      state.system = event.system;
      renderSystem();
      renderOverview();
      break;
    case "yara":
      state.yara.push(event.alert);
      renderYara();
      break;
    case "ai":
      state.ai = event.ai;
      renderAi();
      break;
    case "settings":
      applySettings(event.settings);
      break;
    case "run":
      if (event.state === "started") {
        state.running = true;
        state.startedAt = Date.now();
        state.finishedAt = null;
      } else {
        state.running = false;
        // Freeze the clock: a timer still counting after the chain ended
        // suggests something is still working when nothing is.
        state.finishedAt = Date.now();
      }
      if (event.snapshot) applySnapshot(event.snapshot);
      renderControls();
      break;
  }
}

/* ---------------- state ---------------- */
function applySnapshot(snap) {
  if (!snap) return;
  state.steps = snap.steps || [];
  state.report = snap.report;
  if (snap.thor) {
    state.yara = Array.isArray(snap.thor.entries) && snap.thor.entries.length
      ? snap.thor.entries : (snap.thor.alerts || []);
  }
  state.system = snap.system || state.system;
  state.ai = snap.ai;
  state.running = !!snap.running;
  state.startedAt = snap.started_at ? snap.started_at * 1000 : null;
  state.finishedAt = snap.finished_at && !snap.running ? snap.finished_at * 1000 : null;
  if (!state.selectionReady && state.steps.length) {
    state.selectionReady = true;
    // Each step carries its own default: the YARA scan stays unticked.
    state.steps.forEach((s) => { if (s.default_on !== false) state.selected.add(s.id); });
  }
  applySettings(snap.settings);
  renderChain();
  renderControls();
  renderReport();
  renderAi();
  renderYara();
  renderSystem();
  renderOverview();
  updateCounters();
}

function updateCounters() {
  const system = state.system || {};
  const alerts = (system.findings || []).length;
  $("#nSystem").textContent = alerts;
  $("#nYara").textContent = (state.yara || []).length;
  $("#nIocs").textContent = ((state.report && state.report.iocs) || []).length;
  $("#nAlerts").textContent = ((state.report && state.report.findings) || []).length;
}

function applySettings(settings) {
  if (!settings) return;
  $("#caseName").textContent = settings.case_name || "NO REFERENCE";
  $("#wsLabel").textContent = settings.workspace || "—";
  $("#modeLabel").textContent = settings.demo_mode
    ? "demonstration mode"
    : `live run · ${settings.platform}`;

  $("#setWorkspace").value = settings.workspace || "";
  $("#setCase").value = settings.case_name || "";
  $("#setAnalyst").value = settings.analyst || "";
  $("#setModel").value = settings.ai_model || "";
  state.pendingProvider = settings.ai_provider || "anthropic";
  if (providers.length) {
    $("#setProvider").value = state.pendingProvider;
    describeProvider();
  }
  $("#setBaseUrl").value = settings.ai_base_url || "";
  $("#setLimit").value = settings.enrich_limit ?? 0;
  $("#setLogsSource").value = settings.logs_source || "collector";
  $("#setCylrArgs").value = settings.cylr_args || "";
  $("#setThorArgs").value = settings.thor_args || "";
  $("#setYaraPath").value = settings.yara_path || "";
  $("#setThorTimeout").value = settings.thor_timeout_min ?? 45;
  $("#setLogsPath").value = settings.logs_path || "";
  $("#setDemo").checked = !!settings.demo_mode;

  if (settings.keyfile) {
    $("#keyfilePath").textContent = settings.keyfile;
    $("#keyfileState").textContent = settings.keyfile_present
      ? "(file detected)" : "(file missing — see apikeys.env.example)";
  }

  const keys = settings.keys || {};
  const previews = settings.key_previews || {};
  const origins = settings.key_origins || {};

  [["#setVT", "#hintVT", "virustotal", "virustotal_key"],
   ["#setAbuse", "#hintAbuse", "abuseipdb", "abuseipdb_key"],
   ["#setAI", "#hintAI", "anthropic", "anthropic_key"]].forEach(
    ([input, hint, key, field]) => {
      const present = keys[key];
      $(input).placeholder = present
        ? "loaded — leave empty to keep it"
        : "not configured";
      // Truncated preview: enough to recognise the key, never enough to use
      // it. Together with its origin, that answers the first question asked
      // when a key does not work.
      $(hint).textContent = present
        ? `${previews[key] || ""} · ${origins[field] || "config.json"}`
        : "";
    });
}

function mergeStep(step) {
  const index = state.steps.findIndex((s) => s.id === step.id);
  if (index === -1) state.steps.push(step);
  else state.steps[index] = step;
  renderChain();
  if (step.id === "analyse" && step.status === "done") fetchState();
}

async function fetchState() {
  try {
    const response = await fetch("/api/state");
    applySnapshot(await response.json());
  } catch (_) { /* the WebSocket will catch up */ }
}

/* ---------------- chain of custody ---------------- */
function renderChain() {
  const list = $("#chainList");
  list.innerHTML = "";

  state.steps.forEach((step) => {
    const li = document.createElement("li");
    li.className = `tag is-${step.status}`;
    li.tabIndex = 0;
    li.title = "Double-click: replay this step alone";

    const top = document.createElement("div");
    top.className = "tag__top";

    const check = document.createElement("input");
    check.type = "checkbox";
    check.className = "tag__check";
    check.checked = state.selected.has(step.id);
    check.disabled = state.running;
    check.addEventListener("change", () => {
      check.checked ? state.selected.add(step.id) : state.selected.delete(step.id);
      renderControls();
    });

    const label = document.createElement("span");
    label.className = "tag__label";
    label.textContent = step.label;

    const badge = document.createElement("span");
    badge.className = "tag__badge";
    badge.textContent = step.duration != null
      ? `${STATUS_LABEL[step.status]} ${step.duration}s`
      : STATUS_LABEL[step.status];

    top.append(check, label, badge);
    li.append(top);

    const hint = document.createElement("p");
    hint.className = "tag__hint";
    hint.textContent = step.hint + (step.admin ? " · administrator required" : "");
    li.append(hint);

    if (step.command) {
      const cmd = document.createElement("p");
      cmd.className = "tag__cmd";
      cmd.textContent = step.command;
      li.append(cmd);
    }

    if (step.message) {
      const msg = document.createElement("p");
      msg.className = "tag__msg";
      msg.textContent = step.message;
      li.append(msg);
    }

    if (step.seal) {
      const seal = document.createElement("p");
      seal.className = "tag__seal";
      const icon = document.createElement("i");
      const text = document.createElement("span");
      text.textContent = `seal ${step.seal}`;
      // What the seal actually covers — the question everyone asks first.
      seal.title = step.seal_basis
        ? `SHA-256 over the ${step.seal_basis}`
        : "SHA-256 of the execution record";
      seal.append(icon, text);
      li.append(seal);
    }

    const replay = () => { if (!state.running) run([step.id]); };
    li.addEventListener("dblclick", replay);
    li.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); replay(); }
    });

    list.append(li);
  });
}

function renderControls() {
  $("#btnRun").disabled = state.running || state.selected.size === 0;
  $("#btnRun").textContent = state.selected.size === state.steps.length
    ? "Run the chain"
    : `Run ${state.selected.size} step${state.selected.size > 1 ? "s" : ""}`;
  $("#btnStop").disabled = !state.running;
  $("#btnReset").disabled = state.running;

  const dot = $("#linkDot");
  if (state.running && dot.classList.contains("is-live")) {
    dot.className = "dot is-busy";
    $("#linkLabel").textContent = "run in progress";
  } else if (!state.running && dot.classList.contains("is-busy")) {
    setLink("is-live", "stream open");
  }

  const hasReport = !!state.report;
  $("#btnHtml").classList.toggle("is-off", !hasReport);
  $("#btnJson").classList.toggle("is-off", !hasReport);
}

/* ---------------- console ---------------- */
const NOISE = new Set(["out"]);

/* Logs arrive in bursts of several thousand (update-rules). They are buffered
   and the DOM is touched once per frame, as a single fragment — otherwise the
   tab freezes. */
const MAX_LINES = 1200;
let pending = [];
let flushScheduled = false;

function appendLog(event) {
  pending.push(event);
  if (pending.length > 4000) pending = pending.slice(-2000);  // extreme burst
  if (!flushScheduled) {
    flushScheduled = true;
    requestAnimationFrame(flushLogs);
  }
}

function flushLogs() {
  flushScheduled = false;
  if (!pending.length) return;

  const batch = pending;
  pending = [];

  const box = $("#console");
  const hideNoise = $("#onlyImportant").checked;
  const fragment = document.createDocumentFragment();

  for (const event of batch) {
    const level = event.level || "info";
    const line = document.createElement("div");
    line.className = `line line--${level}`;
    line.dataset.level = level;

    const time = document.createElement("span");
    time.className = "line__t";
    time.textContent = new Date(event.ts * 1000).toLocaleTimeString("en-GB", { hour12: false });

    const message = document.createElement("span");
    message.className = "line__m";
    message.textContent = event.message;

    line.append(time, message);
    if (hideNoise && NOISE.has(level)) line.hidden = true;
    fragment.append(line);
  }

  box.append(fragment);
  while (box.childElementCount > MAX_LINES) box.removeChild(box.firstChild);
  if ($("#autoScroll").checked) box.scrollTop = box.scrollHeight;
  if (state.route === "/log") syncSecondConsole();
}

/* The Log view reuses the same content: it is copied on display rather than
   maintaining two parallel lists. */
function syncSecondConsole() {
  const source = $("#console");
  const target = $("#console2");
  target.innerHTML = source.innerHTML;
  target.scrollTop = target.scrollHeight;
}

$("#onlyImportant2").addEventListener("change", (e) => {
  $("#onlyImportant").checked = e.target.checked;
  $("#onlyImportant").dispatchEvent(new Event("change"));
  syncSecondConsole();
});

$("#onlyImportant").addEventListener("change", (e) => {
  document.querySelectorAll(".line").forEach((line) => {
    line.hidden = e.target.checked && NOISE.has(line.dataset.level);
  });
});

/* ---------------- verdict ---------------- */
function renderReport() {
  const report = state.report;
  const verdict = $("#verdict");

  if (!report) {
    $("#scoreValue").textContent = "—";
    $("#gaugeArc").style.strokeDashoffset = 327;
    $("#verdictLine").textContent = "Waiting for a collection.";
    $("#tallies").innerHTML = "";
    $("#windowLine").textContent = "—";
    $("#spark").innerHTML = "";
    verdict.className = "verdict";
    renderAlerts();
    renderIocs();
    renderAttack();
    return;
  }

  const score = report.risk_score || 0;
  $("#scoreValue").textContent = score;
  const arc = $("#gaugeArc");
  arc.style.strokeDashoffset = 327 - (327 * score) / 100;

  const severity = score >= 75 ? "critical" : score >= 45 ? "high" : score >= 20 ? "medium" : "clean";
  const colour = { critical: "--crit", high: "--high", medium: "--med", clean: "--ok" }[severity];
  arc.style.stroke = `var(${colour})`;
  verdict.className = `verdict sev-${severity}`;

  $("#verdictLine").textContent = report.verdict || "—";

  // The score is published with its breakdown: an analyst should be able to
  // disagree with a component rather than with an opaque number.
  const breakdown = report.score_breakdown;
  const box = $("#scoreDetail");
  box.innerHTML = "";
  if (breakdown) {
    const conf = document.createElement("span");
    conf.className = "conf conf-" + breakdown.confidence;
    conf.textContent = `confidence ${breakdown.confidence}`;
    box.append(conf);
    breakdown.components.forEach((c) => {
      const chip = document.createElement("span");
      chip.className = "scomp" + (c.value ? "" : " is-zero");
      chip.title = c.detail;
      chip.innerHTML = `${c.name} <b>${c.value}</b><i>/${c.max}</i>`;
      box.append(chip);
    });
  }

  $("#tallies").innerHTML = "";
  LEVELS.forEach((level) => {
    const count = (report.levels || {})[level] || 0;
    const tally = document.createElement("div");
    tally.className = `tally ${level}`;
    tally.innerHTML = `<b>${count}</b><span>${LEVEL_LABEL[level]}</span>`;
    $("#tallies").append(tally);
  });

  const host = (report.computers || [])[0];
  $("#hostLabel").textContent = host ? `${host[0]} · ${report.total} events` : "host not identified";
  $("#windowLine").textContent = report.first_seen
    ? `${fmt(report.first_seen)} → ${fmt(report.last_seen)}`
    : "no timestamp available";

  drawSpark(report.activity || []);
  renderAlerts();
  renderIocs();
  renderAttack();
}

function fmt(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleString("en-GB", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
}

const CAT_COLOUR = {
  auth: "#4A9FD4", infection: "#E5484D", execution: "#F0793B",
  network: "#2FA98C", evasion: "#B36BC4", other: "#64798A",
};

/* The histogram is the whole observed window; the highlight is what the alert
   filters currently select. Seeing *when* the selected family fired is the
   question the chart should answer. */
function drawSpark(activity, highlight = null) {
  const svg = $("#spark");
  svg.innerHTML = "";
  if (!activity.length) return;

  const peak = Math.max(...activity.map(([, n]) => n), 1);
  const width = 300 / activity.length;
  const marks = highlight ? highlight.buckets : null;
  const colour = highlight ? highlight.colour : "var(--brass)";

  activity.forEach(([bucket, n], index) => {
    const height = Math.max(1.5, (n / peak) * 40);
    const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    rect.setAttribute("x", (index * width).toFixed(2));
    rect.setAttribute("y", (44 - height).toFixed(2));
    rect.setAttribute("width", Math.max(0.8, width - 0.7).toFixed(2));
    rect.setAttribute("height", height.toFixed(2));
    if (marks) {
      rect.setAttribute("fill", marks.has(bucket) ? colour : "var(--line-soft)");
    } else {
      rect.setAttribute("fill", n >= peak * 0.65 ? "var(--brass)" : "var(--line)");
    }
    svg.append(rect);
  });

  // A tick under the busiest selected bucket: the moment to look at first.
  if (marks && marks.size) {
    let best = null;
    activity.forEach(([bucket, n], index) => {
      if (marks.has(bucket) && (!best || n > best.n)) best = { index, n };
    });
    if (best) {
      const tick = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      tick.setAttribute("x", (best.index * width).toFixed(2));
      tick.setAttribute("y", "41");
      tick.setAttribute("width", Math.max(1.2, width - 0.7).toFixed(2));
      tick.setAttribute("height", "3");
      tick.setAttribute("fill", colour);
      svg.append(tick);
    }
  }
}

/* Which time buckets the currently filtered alerts fall into, and the colour
   of the selected family when exactly one is active. */
function spark_highlight(rows) {
  if (state.route !== "/alerts" || !state.report) return null;
  const buckets = new Set(
    rows.map((f) => (f.timestamp || "").slice(0, 15)).filter(Boolean)
  );
  const selected = [...state.cats];
  const colour = selected.length === 1 ? CAT_COLOUR[selected[0]] : "var(--brass)";
  return { buckets, colour };
}

/* ---------------- alerts ---------------- */
function renderCatChips() {
  const box = $("#catChips");
  if (box.childElementCount) return;
  const counts = {};
  ((state.report && state.report.categories) || []).forEach((c) => { counts[c.id] = c.count; });

  CAT_ORDER.forEach((id) => {
    const chip = document.createElement("button");
    chip.className = "chip chip--cat" + (state.cats.has(id) ? " is-on" : "");
    chip.dataset.cat = id;
    chip.textContent = CAT_LABEL[id];
    const badge = document.createElement("i");
    badge.textContent = counts[id] ?? 0;
    chip.append(badge);
    chip.addEventListener("click", () => {
      state.cats.has(id) ? state.cats.delete(id) : state.cats.add(id);
      chip.classList.toggle("is-on");
      renderAlerts();
    });
    box.append(chip);
  });
}

function updateCatCounts() {
  const counts = {};
  ((state.report && state.report.categories) || []).forEach((c) => { counts[c.id] = c.count; });
  document.querySelectorAll("#catChips .chip--cat i").forEach((badge) => {
    badge.textContent = counts[badge.parentElement.dataset.cat] ?? 0;
  });
}

function renderAlerts() {
  const chips = $("#levelChips");
  if (!chips.childElementCount) {
    ["critical", "high", "medium"].forEach((level) => {
      const chip = document.createElement("button");
      chip.className = "chip" + (state.filters.has(level) ? " is-on" : "");
      chip.dataset.level = level;
      chip.textContent = LEVEL_LABEL[level];
      chip.addEventListener("click", () => {
        state.filters.has(level) ? state.filters.delete(level) : state.filters.add(level);
        chip.classList.toggle("is-on");
        renderAlerts();
      });
      chips.append(chip);
    });
  }

  renderCatChips();
  updateCatCounts();

  const findings = (state.report && state.report.findings) || [];
  const needle = state.search.toLowerCase();
  const rows = findings.filter((f) =>
    state.filters.has(f.level) &&
    state.cats.has(f.category || "other") &&
    (!needle || `${f.rule} ${f.details}`.toLowerCase().includes(needle))
  );

  $("#nAlerts").textContent = findings.length;
  $("#alertCount").textContent = rows.length === findings.length
    ? `${findings.length} alert(s)`
    : `${rows.length} of ${findings.length}`;
  $("#alertEmpty").hidden = rows.length > 0;
  $("#alertEmpty").textContent = findings.length
    ? "No alert matches the filter."
    : "No alert: the timeline has not been analysed yet.";

  const body = $("#alertTable").tBodies[0];
  body.innerHTML = "";
  // The histogram is the whole window; the highlight is the current selection.
  drawSpark((state.report && state.report.activity) || [], spark_highlight(rows));

  // The table renders a window; the counts above always describe the full set.
  const visible = rows.slice(0, 1500);
  if (rows.length > visible.length) {
    $("#alertCount").textContent += ` — showing the first ${visible.length}`;
  }
  visible.forEach((f, index) => {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    tr.tabIndex = 0;
    tr.append(
      cell(fmt(f.timestamp), "c-ts"),
      levelCell(f.level),
      catCell(f.category),
      ruleCell(f),
      cell(f.event_id || "—", "c-mono"),
      cell(f.details || "—", "c-detail"),
    );
    const open = () => openReader(visible, index, "alert");
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
    body.append(tr);
  });
}

function cell(text, cls) {
  const td = document.createElement("td");
  if (cls) td.className = cls;
  td.textContent = text;
  return td;
}

function levelCell(level) {
  const td = document.createElement("td");
  const span = document.createElement("span");
  span.className = `lvl lvl-${level}`;
  span.textContent = LEVEL_LABEL[level] || level;
  td.append(span);
  return td;
}

function yaraLevelCell(level) {
  const td = document.createElement("td");
  const span = document.createElement("span");
  span.className = `lvl lvl-${level}`;
  span.textContent = YARA_LEVEL_LABEL[level] || level;
  td.append(span);
  return td;
}

function catCell(category) {
  const td = document.createElement("td");
  const span = document.createElement("span");
  span.className = `cat cat-${category || "other"}`;
  span.textContent = CAT_SHORT[category] || "Other";
  span.title = CAT_LABEL[category] || "Other";
  td.append(span);
  return td;
}

function ruleCell(finding) {
  const td = document.createElement("td");
  td.className = "c-rule";
  td.textContent = finding.rule;
  if (finding.tactics && finding.tactics.length) {
    const wrap = document.createElement("div");
    wrap.className = "tacs";
    finding.tactics.forEach((tactic) => {
      const tag = document.createElement("span");
      tag.className = "tac";
      tag.textContent = tactic;
      wrap.append(tag);
    });
    td.append(wrap);
  }
  return td;
}

$("#yaraSearch").addEventListener("input", (e) => {
  state.yaraSearch = e.target.value.trim();
  renderYara();
});

$("#alertSearch").addEventListener("input", (e) => {
  state.search = e.target.value.trim();
  renderAlerts();
});

/* ---------------- indicators ---------------- */
function patchIoc(ioc) {
  if (!state.report) return;
  const target = state.report.iocs.find(
    (i) => i.type === ioc.type && i.value === ioc.value
  );
  if (target) Object.assign(target, ioc);
  renderIocs();
}

function renderIocs() {
  const iocs = (state.report && state.report.iocs) || [];
  $("#nIocs").textContent = iocs.length;
  $("#iocCount").textContent = `${iocs.length} indicator(s)`;
  $("#iocEmpty").hidden = iocs.length > 0;

  const body = $("#iocTable").tBodies[0];
  body.innerHTML = "";

  iocs.forEach((ioc) => {
    const tr = document.createElement("tr");
    const verdict = ioc.threat || "unchecked";

    const verdictCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "verd verd-" + verdict.replace(/\s/g, "");
    badge.textContent = verdict;
    verdictCell.append(badge);

    tr.append(
      cell(ioc.type, "c-mono"),
      cell(ioc.value, "c-mono"),
      cell(String(ioc.count), "c-mono"),
      verdictCell,
      reputationCell(ioc),
      cell((ioc.rules || []).slice(0, 2).join(" · ") || "—", "c-detail"),
    );
    body.append(tr);
  });
}

function reputationCell(ioc) {
  const td = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.className = "rep";
  const data = ioc.enrichment || {};
  const vt = data.virustotal;
  const abuse = data.abuseipdb;

  if (vt && vt.error) wrap.append(text(`VT: ${vt.error}`));
  else if (vt && vt.found === false) wrap.append(text("VT: unknown to the service"));
  else if (vt) {
    const total = (vt.malicious || 0) + (vt.harmless || 0) + (vt.undetected || 0) + (vt.suspicious || 0);
    wrap.append(text(`VT ${vt.malicious || 0}/${total || "?"}${vt.label ? " · " + vt.label : ""}`, true));
    if (vt.as_owner) wrap.append(text(vt.as_owner));
  }

  if (abuse && abuse.error) wrap.append(text(`AbuseIPDB: ${abuse.error}`));
  else if (abuse) {
    wrap.append(text(`AbuseIPDB ${abuse.score}% · ${abuse.reports} report(s)`, true));
    if (abuse.isp) wrap.append(text(`${abuse.country || "??"} · ${abuse.isp}`));
  }

  if (!wrap.childElementCount) wrap.append(text("—"));
  td.append(wrap);
  return td;
}

function text(value, strong) {
  const node = document.createElement(strong ? "b" : "span");
  node.textContent = value;
  return node;
}

/* ---------------- YARA verdicts ---------------- */
const YARA_LEVEL_LABEL = {
  critical: "alert", high: "warning", medium: "notice",
  low: "low", informational: "clean",
};

function renderYaraChips() {
  const box = $("#yaraChips");
  if (box.childElementCount) return;
  ["critical", "high", "medium", "informational"].forEach((level) => {
    const chip = document.createElement("button");
    chip.className = "chip" + (state.yaraLevels.has(level) ? " is-on" : "");
    chip.dataset.level = level;
    chip.textContent = YARA_LEVEL_LABEL[level];
    chip.addEventListener("click", () => {
      state.yaraLevels.has(level) ? state.yaraLevels.delete(level)
                                  : state.yaraLevels.add(level);
      chip.classList.toggle("is-on");
      renderYara();
    });
    box.append(chip);
  });
}

function renderYara() {
  renderYaraChips();
  const all = state.yara || [];
  const needle = state.yaraSearch.toLowerCase();
  const rows = all.filter((entry) =>
    state.yaraLevels.has(entry.level || "critical") &&
    (!needle || `${entry.message} ${entry.file} ${entry.rule} ${entry.sha256}`
      .toLowerCase().includes(needle))
  );

  $("#nYara").textContent = all.length;
  $("#yaraCount").textContent = rows.length === all.length
    ? `${all.length} verdict(s)`
    : `${rows.length} of ${all.length}`;
  $("#yaraEmpty").hidden = rows.length > 0;
  $("#yaraEmpty").textContent = all.length
    ? "No verdict matches the filter."
    : "Verdicts appear here during the scan.";

  const body = $("#yaraTable").tBodies[0];
  body.innerHTML = "";

  rows.slice(0, 600).forEach((alert, index) => {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    tr.tabIndex = 0;
    tr.append(
      yaraLevelCell(alert.level || "critical"),
      cell(alert.message || alert.rule || "—", "c-rule"),
      cell(alert.file || "—", "c-detail"),
      cell(alert.module || "—", "c-detail"),
      // The full hash stays in the reading pane; here it would only make the
      // row unreadable.
      cell(alert.sha256 ? alert.sha256.slice(0, 16) + "…" : "—", "c-mono"),
      cell(alert.score != null ? String(alert.score) : "—", "c-mono"),
    );
    const open = () => openReader(rows, index, "yara");
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
    body.append(tr);
  });
}

/* ---------------- system context ---------------- */
function renderSystem() {
  const box = $("#sysgrid");
  const system = state.system;
  $("#sysEmpty").hidden = !!system;
  box.innerHTML = "";
  if (!system) return;

  // -- machine identity
  const host = system.host || {};
  const identity = card("Machine identity");
  const dl = document.createElement("dl");
  dl.className = "kv";
  [["hostname", "Name"], ["os_name", "Operating system"], ["os_version", "Version"],
   ["domain", "Domain"], ["logon_server", "Domain controller"], ["model", "Hardware"],
   ["install_date", "Installed on"], ["boot_time", "Booted on"],
   ["hotfix_count", "Hotfixes"]].forEach(([key, label]) => {
    if (!host[key]) return;
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = host[key];
    dl.append(dt, dd);
  });
  identity.body.append(dl);
  box.append(identity.el);

  // -- cross-cutting findings, first because that is what gets read first
  const findings = system.findings || [];
  if (findings.length) {
    const flags = card(`Findings (${findings.length})`);
    findings.slice(0, 25).forEach((finding) => {
      const line = document.createElement("div");
      line.className = `sysfind lvl-${finding.level}`;
      const title = document.createElement("b");
      title.textContent = finding.title;
      const detail = document.createElement("span");
      detail.textContent = finding.detail;
      line.append(title, detail);
      flags.body.append(line);
    });
    box.append(flags.el);
  }

  // -- accounts
  const users = system.users || [];
  const accounts = card(`Local accounts (${users.length})`, true);
  accounts.body.append(table(
    ["Account", "Admin", "State", "Last logon", "Observations"],
    users.map((user) => [
      { text: user.name, cls: "c-rule" },
      { text: user.admin ? "yes" : "no", cls: user.admin ? "c-flag" : "" },
      { text: user.enabled === null ? "—" : (user.enabled ? "enabled" : "disabled"),
        cls: user.enabled === false ? "c-detail" : "" },
      { text: user.last_logon ? fmt(user.last_logon) : "never", cls: "c-ts" },
      { text: (user.flags || []).join(" · ") || "—", cls: "c-detail" },
    ]),
    users.map((user) => () => openReader(users, users.indexOf(user), "user")),
  ));
  box.append(accounts.el);

  // -- network
  const network = system.network || {};
  const connections = system.connections || [];
  const net = card(
    `Network — ${network.listening || 0} listening, ${network.established || 0} established, ` +
    `${network.flagged || 0} flagged`, true);
  net.body.append(table(
    ["Risk", "Proto", "Local", "Remote", "State", "Process", "Observations"],
    connections.map((c) => [
      { text: c.risk === "high" ? "high" : c.risk === "medium" ? "medium" : "—",
        cls: `c-risk risk-${c.risk}` },
      { text: c.proto, cls: "c-mono" },
      { text: `${c.local_ip}:${c.local_port ?? ""}`, cls: "c-mono" },
      { text: c.remote_ip ? `${c.remote_ip}${c.remote_port ? ":" + c.remote_port : ""}` : "—",
        cls: "c-mono" },
      { text: c.state || "—", cls: "c-detail" },
      { text: c.process || `PID ${c.pid}`, cls: "c-rule" },
      { text: (c.flags || []).join(" · ") || (c.service || "—"), cls: "c-detail" },
    ]),
    connections.map((c) => () => openReader(connections, connections.indexOf(c), "connection")),
  ));
  box.append(net.el);

  // -- logging coverage
  const coverage = system.coverage;
  if (coverage) {
    const cov = card(`Logging & audit — coverage ${coverage.score}/100 · ${coverage.verdict}`, true);

    if ((coverage.gaps || []).length) {
      const warn = document.createElement("p");
      warn.className = "covgap";
      warn.textContent = "Blind spots: " + coverage.gaps.join(" · ");
      cov.body.append(warn);
    }

    const sub = document.createElement("p");
    sub.className = "covsub";
    sub.textContent = "Event channels";
    cov.body.append(sub);
    cov.body.append(table(
      ["State", "Channel", "Importance", "Events", "Observations"],
      (coverage.channels || []).map((c) => [
        { text: c.verdict, cls: `c-risk cov-${c.verdict}` },
        { text: c.label, cls: "c-rule" },
        { text: c.importance, cls: "c-detail" },
        { text: c.records ? c.records.toLocaleString("en-GB") : "—", cls: "c-mono" },
        { text: c.comment, cls: "c-detail" },
      ]),
    ));

    const sub2 = document.createElement("p");
    sub2.className = "covsub";
    sub2.textContent = "Local audit policy";
    cov.body.append(sub2);
    cov.body.append(table(
      ["State", "Subcategory", "Importance"],
      (coverage.audit || []).map((a) => [
        { text: a.state, cls: `c-risk cov-${a.state === "disabled" ? "missing" : "active"}` },
        { text: a.label, cls: "c-rule" },
        { text: a.importance, cls: "c-detail" },
      ]),
    ));
    box.append(cov.el);
  }

  // -- disk root
  const roots = system.root_entries || [];
  const disk = card(`Root ${system.root_path || "C:\\"} — ${roots.length} flagged entry(ies)`, true);
  if (roots.length) {
    disk.body.append(table(
      ["Risk", "Path", "Type", "Created", "Observations"],
      roots.map((entry) => [
        { text: entry.risk === "high" ? "high" : "medium", cls: `c-risk risk-${entry.risk}` },
        { text: entry.path, cls: "c-mono" },
        { text: entry.kind, cls: "c-detail" },
        { text: entry.created ? fmt(entry.created) : "—", cls: "c-ts" },
        { text: (entry.flags || []).join(" · "), cls: "c-detail" },
      ]),
      roots.map((entry) => () => openReader(roots, roots.indexOf(entry), "root")),
    ));
  } else {
    const ok = document.createElement("p");
    ok.className = "empty";
    ok.textContent = "Nothing unusual at the disk root.";
    disk.body.append(ok);
  }
  box.append(disk.el);
}

function card(title, wide) {
  const el = document.createElement("section");
  el.className = "panel syscard" + (wide ? " syscard--wide" : "");
  const head = document.createElement("header");
  head.className = "panel__head";
  const h = document.createElement("h2");
  h.className = "eyebrow";
  h.textContent = title;
  head.append(h);
  const body = document.createElement("div");
  body.className = "syscard__body";
  el.append(head, body);
  return { el, body };
}

function table(headers, rows, handlers) {
  const wrap = document.createElement("div");
  wrap.className = "tablewrap";
  const tableEl = document.createElement("table");
  tableEl.className = "grid";

  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  headers.forEach((label) => {
    const th = document.createElement("th");
    th.textContent = label;
    headRow.append(th);
  });
  thead.append(headRow);

  const tbody = document.createElement("tbody");
  rows.forEach((cells, index) => {
    const tr = document.createElement("tr");
    cells.forEach((c) => tr.append(cell(c.text, c.cls)));
    if (handlers && handlers[index]) {
      tr.className = "clickable";
      tr.tabIndex = 0;
      tr.addEventListener("click", handlers[index]);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter") handlers[index](); });
    }
    tbody.append(tr);
  });

  tableEl.append(thead, tbody);
  wrap.append(tableEl);
  return wrap;
}

/* ---------------- reading pane ---------------- */
const READER_LABELS = {
  timestamp: "Timestamp", level: "Level", rule: "Rule", computer: "Machine",
  channel: "Channel", event_id: "Event ID", tactics: "ATT&CK tactics",
  category: "Family", details: "Detail", message: "Detection", file: "File",
  module: "Module", score: "Score", sha256: "SHA-256", raw: "Raw line",
  name: "Name", enabled: "Enabled", admin: "Administrator", sid: "SID",
  last_logon: "Last logon", created: "Created", description: "Description",
  flags: "Observations", proto: "Protocol", local_ip: "Local address",
  local_port: "Local port", remote_ip: "Remote address", remote_port: "Remote port",
  state: "State", pid: "PID", process: "Process", service: "Service",
  risk: "Risk", path: "Path", kind: "Type", age_days: "Age (days)",
};

const READER_VIEWS = {
  alert: { kind: "Timeline alert", title: ["rule", "message"],
           order: ["timestamp", "level", "category", "rule", "computer", "channel",
                   "event_id", "tactics"] },
  yara: { kind: "YARA verdict", title: ["message", "rule"],
          order: ["level", "message", "file", "module", "rule", "score", "sha256"] },
  user: { kind: "Local account", title: ["name"],
          order: ["name", "enabled", "admin", "sid", "last_logon", "created",
                  "description", "flags"] },
  connection: { kind: "Network socket", title: ["process"],
                order: ["risk", "proto", "state", "local_ip", "local_port",
                        "remote_ip", "remote_port", "process", "pid", "service",
                        "flags"] },
  root: { kind: "Disk root entry", title: ["path", "name"],
          order: ["risk", "path", "kind", "created", "age_days", "flags"] },
};

function openReader(list, index, kind) {
  state.reader = { list, index, kind };
  $("#reader").hidden = false;
  document.body.style.overflow = "hidden";
  drawReader();
  $("#readerClose").focus();
}

function closeReader() {
  $("#reader").hidden = true;
  document.body.style.overflow = "";
}

function drawReader() {
  const { list, index, kind } = state.reader;
  const item = list[index];
  if (!item) return closeReader();

  const view = READER_VIEWS[kind] || READER_VIEWS.alert;
  $("#readerKind").textContent = view.kind;
  $("#readerTitle").textContent =
    view.title.map((k) => item[k]).find(Boolean) || "Untitled";
  $("#readerPos").textContent = `${index + 1} / ${list.length}`;
  $("#readerPrev").disabled = index === 0;
  $("#readerNext").disabled = index === list.length - 1;

  const body = $("#readerBody");
  body.innerHTML = "";

  const main = document.createElement("dl");
  for (const key of view.order) {
    let value = item[key];
    if (value == null || value === "" || (Array.isArray(value) && !value.length)) continue;
    if (Array.isArray(value)) value = value.join(" · ");
    if (typeof value === "boolean") value = value ? "oui" : "non";
    if (key === "level") value = LEVEL_LABEL[value] || value;
    if (key === "category") value = CAT_LABEL[value] || value;
    if (key === "timestamp") value = `${fmt(value)}   (${item[key]})`;
    if (key === "last_logon" || key === "created") value = fmt(value);
    main.append(field(READER_LABELS[key] || key, String(value)));
  }
  body.append(main);

  // The raw detail earns its place: that is where paths, command lines and
  // hashes hide.
  const detail = item.details || item.raw;
  if (detail) {
    body.append(sectionTitle(item.details ? "Event detail" : "Raw line"));
    const dl = document.createElement("dl");
    dl.append(field("Content", detail, true));
    body.append(dl);
  }

  // Additional fields returned by THOR, none of them dropped.
  if (item.fields && Object.keys(item.fields).length) {
    body.append(sectionTitle("THOR fields"));
    const dl = document.createElement("dl");
    Object.entries(item.fields).forEach(([k, v]) => dl.append(field(k, String(v))));
    body.append(dl);
  }
}

function field(label, value, long) {
  const wrap = document.createElement("div");
  wrap.className = "rfield";
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  if (long) dd.className = "long";
  dd.textContent = value;
  wrap.append(dt, dd);
  return wrap;
}

function sectionTitle(text) {
  const h = document.createElement("p");
  h.className = "reader__section";
  h.textContent = text;
  return h;
}

function moveReader(delta) {
  const next = state.reader.index + delta;
  if (next < 0 || next >= state.reader.list.length) return;
  state.reader.index = next;
  drawReader();
}

$("#readerPrev").addEventListener("click", () => moveReader(-1));
$("#readerNext").addEventListener("click", () => moveReader(1));
$("#readerClose").addEventListener("click", closeReader);
$("#reader").addEventListener("click", (e) => { if (e.target.id === "reader") closeReader(); });

$("#readerCopy").addEventListener("click", async () => {
  const item = state.reader.list[state.reader.index];
  const text = JSON.stringify(item, null, 2);
  try {
    await navigator.clipboard.writeText(text);
    $("#readerCopy").textContent = "Copied";
    setTimeout(() => { $("#readerCopy").textContent = "Copy"; }, 1400);
  } catch (_) {
    // Clipboard refused (insecure page): select the text instead.
    const range = document.createRange();
    range.selectNodeContents($("#readerBody"));
    getSelection().removeAllRanges();
    getSelection().addRange(range);
  }
});

document.addEventListener("keydown", (e) => {
  if ($("#reader").hidden) return;
  if (e.key === "Escape") closeReader();
  if (e.key === "ArrowLeft") moveReader(-1);
  if (e.key === "ArrowRight") moveReader(1);
});

/* ---------------- overview ---------------- */
function renderOverview() {
  const box = $("#overview");
  box.innerHTML = "";
  const report = state.report;

  if (!report) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "Analysing the timeline will populate this view.";
    box.append(empty);
    return;
  }

  const cats = (report.categories || []).filter((c) => c.count > 0);
  const peak = Math.max(...cats.map((c) => c.count), 1);

  cats.forEach((cat) => {
    const row = document.createElement("div");
    row.className = "tacrow";
    const top = document.createElement("div");
    top.className = "tacrow__top";
    const label = document.createElement("b");
    label.textContent = CAT_LABEL[cat.id] || cat.label;
    const count = document.createElement("span");
    count.textContent = `${cat.count} alert${cat.count > 1 ? "s" : ""}`;
    top.append(label, count);
    const bar = document.createElement("div");
    bar.className = "tacrow__bar";
    const fill = document.createElement("i");
    fill.className = `fill-${cat.id}`;
    fill.style.width = `${(cat.count / peak) * 100}%`;
    bar.append(fill);
    row.append(top, bar);
    row.addEventListener("click", () => {
      state.cats = new Set([cat.id]);
      $("#catChips").innerHTML = "";
  $("#yaraChips").innerHTML = "";
      navigate("/alerts");
    });
    row.classList.add("clickable");
    box.append(row);
  });

  if (state.system) {
    const findings = state.system.findings || [];
    const note = document.createElement("p");
    note.className = "overview__note";
    note.textContent = findings.length
      ? `${findings.length} finding(s) on the system context — see the System view.`
      : "System context captured, nothing flagged.";
    box.append(note);
  }
}

/* ---------------- ATT&CK ---------------- */
function renderAttack() {
  const tactics = (state.report && state.report.tactics) || [];
  const box = $("#attack");
  box.innerHTML = "";
  $("#attackEmpty").hidden = tactics.length > 0;
  if (!tactics.length) return;

  const peak = Math.max(...tactics.map(([, n]) => n), 1);
  tactics.forEach(([name, count]) => {
    const row = document.createElement("div");
    row.className = "tacrow";
    row.innerHTML =
      `<div class="tacrow__top"><b>${escapeHtml(name)}</b><span>${count} event${count > 1 ? "s" : ""}</span></div>` +
      `<div class="tacrow__bar"><i style="width:${(count / peak) * 100}%"></i></div>`;
    box.append(row);
  });
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value;
  return div.innerHTML;
}

/* ---------------- summary ---------------- */
function renderAi() {
  const ai = state.ai;
  const box = $("#aiReport");
  $("#aiEmpty").hidden = !!ai;
  box.innerHTML = "";
  if (!ai) return;

  const lead = document.createElement("p");
  lead.className = "report__lead";
  lead.textContent = ai.verdict || "—";
  box.append(lead);

  const by = document.createElement("p");
  by.className = "report__by";
  by.textContent = `confidence ${ai.confidence || "n/a"} · written by ${ai.generated_by || "?"}`;
  box.append(by);

  if (ai.note) {
    const note = document.createElement("p");
    note.className = "report__note";
    note.textContent = ai.note;
    box.append(note);
  }

  if (ai.summary) box.append(section("Summary", paragraph(ai.summary)));
  if (ai.attack_story?.length) box.append(section("Probable sequence", list(ai.attack_story, "ol")));

  if (Array.isArray(ai.key_findings) && ai.key_findings.length) {
    const ul = document.createElement("ul");
    ai.key_findings.forEach((item) => {
      const li = document.createElement("li");
      const strong = document.createElement("strong");
      strong.textContent = item.title || "";
      li.append(strong, document.createTextNode(item.why ? ` — ${item.why}` : ""));
      ul.append(li);
    });
    box.append(section("Key findings", ul));
  }

  if (Array.isArray(ai.iocs_to_block) && ai.iocs_to_block.length) {
    const ul = document.createElement("ul");
    ai.iocs_to_block.forEach((item) => {
      const li = document.createElement("li");
      const code = document.createElement("strong");
      code.textContent = item.value || "";
      li.append(code, document.createTextNode(` (${item.type || "?"}) — ${item.reason || ""}`));
      ul.append(li);
    });
    box.append(section("Block immediately", ul));
  }

  if (ai.containment?.length) box.append(section("Immediate containment", list(ai.containment, "ol")));
  if (ai.next_steps?.length) box.append(section("Next steps", list(ai.next_steps, "ol")));
  if (ai.false_positive_risk) {
    const wrap = document.createElement("div");
    wrap.className = "block";
    wrap.append(paragraph(ai.false_positive_risk));
    box.append(section("False-positive risk", wrap));
  }
}

function section(title, node) {
  const fragment = document.createDocumentFragment();
  const heading = document.createElement("h3");
  heading.textContent = title;
  fragment.append(heading, node);
  return fragment;
}

function paragraph(value) {
  const p = document.createElement("p");
  p.textContent = value;
  return p;
}

function list(values, tag) {
  const el = document.createElement(tag);
  // The model may return a string where a list is expected: absorb it.
  (Array.isArray(values) ? values : [values]).forEach((value) => {
    const li = document.createElement("li");
    li.textContent = typeof value === "string" ? value : JSON.stringify(value);
    el.append(li);
  });
  return el;
}

/* ---------------- actions ---------------- */
async function run(steps) {
  const body = JSON.stringify({ steps: steps || state.steps.filter((s) => state.selected.has(s.id)).map((s) => s.id) });
  const response = await fetch("/api/run", {
    method: "POST", headers: { "Content-Type": "application/json" }, body,
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "unknown error" }));
    appendLog({ ts: Date.now() / 1000, level: "error", message: `Run refused: ${error.detail}` });
  }
}

$("#btnRun").addEventListener("click", () => run());
$("#btnStop").addEventListener("click", () => fetch("/api/cancel", { method: "POST" }));
$("#btnReset").addEventListener("click", async () => {
  await fetch("/api/reset", { method: "POST" });
  $("#console").innerHTML = "";
  state.report = state.ai = state.system = null;
  state.yara = [];
  $("#catChips").innerHTML = "";
  $("#yaraChips").innerHTML = "";
  renderReport();
  renderAi();
  renderYara();
  renderSystem();
  renderOverview();
  updateCounters();
});


$("#btnSettings").addEventListener("click", () => {
  const drawer = $("#drawer");
  drawer.hidden = !drawer.hidden;
  $("#btnSettings").setAttribute("aria-expanded", String(!drawer.hidden));
});

$("#btnSaveSettings").addEventListener("click", async () => {
  const payload = {
    workspace: $("#setWorkspace").value.trim(),
    case_name: $("#setCase").value.trim() || "CASE-001",
    analyst: $("#setAnalyst").value.trim(),
    ai_model: $("#setModel").value.trim() || "claude-sonnet-4-6",
    ai_provider: $("#setProvider").value,
    ai_base_url: $("#setBaseUrl").value.trim(),
    enrich_limit: Math.max(0, Number($("#setLimit").value) || 0),
    logs_source: $("#setLogsSource").value,
    cylr_args: $("#setCylrArgs").value.trim() || "-v",
    thor_args: $("#setThorArgs").value.trim() || "--quick --nocsv",
    yara_path: $("#setYaraPath").value.trim(),
    thor_timeout_min: Number($("#setThorTimeout").value) || 0,
    logs_path: $("#setLogsPath").value.trim(),
    demo_mode: $("#setDemo").checked,
  };
  // A field left empty keeps the key already stored server-side.
  const secrets = { virustotal_key: "#setVT", abuseipdb_key: "#setAbuse", anthropic_key: "#setAI" };
  for (const [key, sel] of Object.entries(secrets)) {
    const value = $(sel).value.trim();
    if (value) payload[key] = value;
  }

  const response = await fetch("/api/settings", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  });
  if (response.ok) {
    applySettings(await response.json());
    Object.values(secrets).forEach((sel) => { $(sel).value = ""; });
    $("#drawer").hidden = true;
    $("#btnSettings").setAttribute("aria-expanded", "false");
  }
});

/* ---------------- elapsed timer ---------------- */
setInterval(() => {
  if (!state.startedAt) return;
  const end = state.running ? Date.now() : (state.finishedAt || Date.now());
  const seconds = Math.max(0, Math.floor((end - state.startedAt) / 1000));
  const mm = String(Math.floor(seconds / 60)).padStart(2, "0");
  const ss = String(seconds % 60).padStart(2, "0");
  $("#clockLabel").textContent = `${mm}:${ss}`;
}, 1000);

navigate(location.pathname, false);
loadProviders().then(fetchState);
connect();
