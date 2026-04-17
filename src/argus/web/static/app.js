// ============================================================
// ARGUS War Room — Multi-page SPA with client-side router
// ============================================================

// --- Auth ---
const AUTH = {
  token: localStorage.getItem('argus_token') || '',
  setToken(t) { this.token = t; localStorage.setItem('argus_token', t); },
  clear() { this.token = ''; localStorage.removeItem('argus_token'); },
  headers() {
    const h = { 'Content-Type': 'application/json' };
    if (this.token) {
      h['Authorization'] = `Bearer ${this.token}`;
      h['X-Argus-Token'] = this.token;
    }
    return h;
  },
};

// Check for server-injected token (loopback)
(() => {
  const meta = document.querySelector('meta[name="argus-token"]');
  if (meta && meta.getAttribute('content')) {
    AUTH.setToken(meta.getAttribute('content'));
  }
})();

async function apiFetch(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { ...AUTH.headers(), ...opts.headers } });
  if (res.status === 401) { showLogin(); throw new Error('Unauthorized'); }
  return res;
}

async function apiJson(path, opts) {
  const res = await apiFetch(path, opts);
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

// --- Escape helper ---
function escapeHtml(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
    .replace(/\//g, '&#x2F;');
}
var esc = escapeHtml;

// --- Finding rendering helpers ---
function renderFindingRow(finding) {
  var sev = escapeHtml(finding.severity || 'info');
  var tierClass = String(finding.severity || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  var title = escapeHtml(finding.title || '');
  var agent = escapeHtml(finding.agent_type || '');
  return '<tr class="clickable-row"><td><span class="severity-badge severity-' + tierClass + '">' + sev + '</span></td>' +
    '<td class="mono">' + agent + '</td><td>' + title + '</td>' +
    '<td class="mono">' + escapeHtml(finding.technique || '') + '</td>' +
    '<td><span class="' + (finding.status === 'validated' ? 'finding-validated' : 'finding-unvalidated') + '">' +
    (finding.status === 'validated' ? '\u2713 validated' : '\u25CB pending') + '</span></td></tr>';
}

function renderVerdictTooltip(verdict) {
  if (!verdict) return '';
  var text = escapeHtml(verdict.interpretation || verdict.description || '');
  return ' title="' + text + '"';
}

// --- Terminal line helper (atomic replacement) ---
function appendTerminalLine(lines, newLine) {
  var next = lines.concat([newLine]);
  return next.slice(-5);
}

function fmtDate(d) {
  if (!d) return '-';
  const dt = new Date(d);
  if (isNaN(dt.getTime())) return String(d).slice(0, 19);
  return dt.toLocaleString();
}

// --- Agent display map (13 agents) ---
const AGENTS = {
  prompt_injection_hunter: { name: 'Prompt Injection Hunter', badge: 'PI-01', icon: '\u26A1', color: '#ef4444' },
  tool_poisoning: { name: 'Tool Poisoning Agent', badge: 'TP-02', icon: '\u2620', color: '#f97316' },
  memory_poisoning: { name: 'Memory Poisoning Agent', badge: 'MP-03', icon: '\uD83E\uDDE0', color: '#8b5cf6' },
  identity_spoof: { name: 'Identity Spoof Agent', badge: 'IS-04', icon: '\uD83C\uDFAD', color: '#ec4899' },
  context_window: { name: 'Context Window Agent', badge: 'CW-05', icon: '\uD83E\uDE9F', color: '#06b6d4' },
  cross_agent_exfiltration: { name: 'Cross-Agent Exfil', badge: 'CX-06', icon: '\u2194', color: '#14b8a6' },
  privilege_escalation: { name: 'Privilege Escalation', badge: 'PE-07', icon: '\u2B06', color: '#f59e0b' },
  race_condition: { name: 'Race Condition Agent', badge: 'RC-08', icon: '\u23F1', color: '#6366f1' },
  supply_chain: { name: 'Supply Chain Agent', badge: 'SC-09', icon: '\uD83D\uDD17', color: '#10b981' },
  model_extraction: { name: 'Model Extraction Agent', badge: 'ME-10', icon: '\uD83D\uDCE4', color: '#3b82f6' },
  persona_hijacking: { name: 'Persona Hijacking', badge: 'PH-11', icon: '\uD83C\uDFAD', color: '#a855f7' },
  memory_boundary_collapse: { name: 'Memory Boundary Collapse', badge: 'MB-12', icon: '\uD83E\uDDEC', color: '#d946ef' },
  mcp_scanner: { name: 'MCP Scanner', badge: 'MC-13', icon: '\uD83D\uDD0D', color: '#0ea5e9' },
};

function agentName(type) {
  return (AGENTS[type] || {}).name || type;
}

// --- Router ---
const pages = {};
let currentPage = '';
let currentParams = {};
let navGeneration = 0;

function registerPage(name, renderFn) { pages[name] = renderFn; }

function navigateTo(page, params) {
  if (!pages[page]) return;
  navGeneration++;
  var gen = navGeneration;
  currentPage = page;
  currentParams = params || {};
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.getAttribute('data-page') === page);
  });
  const main = document.getElementById('main-content');
  main.innerHTML = '<div class="page-loading">Loading\u2026</div>';
  try {
    pages[page](main, currentParams, gen);
  } catch (e) {
    if (gen === navGeneration) {
      main.innerHTML = '<div class="page-error">Error loading page: ' + esc(e.message) + '</div>';
    }
  }
}

function isStaleNav(gen) { return gen !== navGeneration; }

// --- SSE ---
let sseSource = null;
const scanState = {
  status: 'idle', agents: {}, findings: [], elapsed: 0,
  totalFindings: 0, validatedFindings: 0, signalCount: 0,
  agentsRunning: 0, agentsTotal: 0, activityLog: [],
};

function connectSSE() {
  if (sseSource) { sseSource.close(); sseSource = null; }
  const url = AUTH.token
    ? '/api/events?token=' + encodeURIComponent(AUTH.token)
    : '/api/events';
  sseSource = new EventSource(url);

  sseSource.addEventListener('snapshot', function (e) {
    Object.assign(scanState, flattenSnap(JSON.parse(e.data)));
    if (currentPage === 'live-scan') updateLiveScan();
  });
  sseSource.addEventListener('signal', function (e) {
    Object.assign(scanState, flattenSnap(JSON.parse(e.data)));
    if (currentPage === 'live-scan') updateLiveScan();
  });
  sseSource.addEventListener('finding', function (e) {
    var f = JSON.parse(e.data);
    scanState.findings.unshift(f);
    if (scanState.findings.length > 100) scanState.findings.length = 100;
    if (currentPage === 'live-scan') updateLiveScan();
  });
  sseSource.addEventListener('activity', function (e) {
    var a = JSON.parse(e.data);
    scanState.activityLog.push(a);
    if (scanState.activityLog.length > 300) scanState.activityLog = scanState.activityLog.slice(-300);
    if (currentPage === 'live-scan') appendActivity(a);
  });
  sseSource.addEventListener('scan_started', function (e) {
    scanState.status = 'running';
    Object.assign(scanState, flattenSnap(JSON.parse(e.data)));
    if (currentPage === 'live-scan') updateLiveScan();
  });
  sseSource.addEventListener('complete', function (e) {
    scanState.status = 'completed';
    Object.assign(scanState, flattenSnap(JSON.parse(e.data)));
    if (currentPage === 'live-scan') updateLiveScan();
  });
  sseSource.addEventListener('failed', function () { scanState.status = 'failed'; });
  sseSource.addEventListener('cancelled', function () { scanState.status = 'cancelled'; });
  sseSource.addEventListener('ping', function () {});
  sseSource.onerror = function () {};
}

function flattenSnap(s) {
  return {
    status: s.status || 'idle',
    agents: s.agents || {},
    elapsed: s.elapsed_seconds || 0,
    totalFindings: s.total_findings || 0,
    validatedFindings: s.validated_findings || 0,
    signalCount: s.signal_count || 0,
    agentsRunning: s.agents_running || 0,
    agentsTotal: s.agents_total || 0,
    targetName: s.target_name || '',
    scanId: s.scan_id || '',
    activityLog: s.activity_log || scanState.activityLog,
  };
}

// --- Login ---
function showLogin() {
  document.getElementById('login-overlay').style.display = 'flex';
}

function hideLogin() {
  document.getElementById('login-overlay').style.display = 'none';
}

async function attemptLogin(token) {
  AUTH.setToken(token);
  try {
    var res = await fetch('/api/health');
    if (!res.ok) throw new Error('Health check failed');
    var r2 = await fetch('/api/status', { headers: AUTH.headers() });
    if (r2.status === 401) throw new Error('Invalid token');
    hideLogin();
    connectSSE();
    navigateTo('dashboard');
    updateBadges();
  } catch (e) {
    document.getElementById('login-error').textContent = 'Authentication failed. Check your token.';
    AUTH.clear();
  }
}

async function updateBadges() {
  try {
    var d = await apiJson('/api/dashboard/stats');
    var bf = document.getElementById('badge-findings');
    if (bf) bf.textContent = d.total_findings || 0;
    var bs = document.getElementById('badge-scans');
    if (bs) bs.textContent = d.total_scans || 0;
  } catch (e) { /* ignore */ }
}

// ============================================================
// PAGE: Dashboard
// ============================================================
registerPage('dashboard', async function (el, _params, gen) {
  el.innerHTML = '<div class="page-loading">Loading dashboard\u2026</div>';
  try {
    var stats = await apiJson('/api/dashboard/stats');
    if (isStaleNav(gen)) return;
    var sevBars = (stats.severity_distribution || []).map(function (s) {
      var pct = stats.total_findings ? Math.round(s.value / stats.total_findings * 100) : 0;
      return '<div class="sev-bar-row">' +
        '<span class="sev-bar-label">' + esc(s.name) + '</span>' +
        '<div class="sev-bar-track"><div class="sev-bar-fill" style="width:' + pct + '%;background:' + esc(s.color) + '"></div></div>' +
        '<span class="sev-bar-count">' + s.value + '</span></div>';
    }).join('');

    var trendMax = Math.max.apply(null, (stats.trend || []).map(function (t) { return t.findings; }).concat([1]));
    var trendBars = (stats.trend || []).map(function (t) {
      var h = Math.max(4, (t.findings / trendMax) * 80);
      return '<div class="trend-bar-col"><div class="trend-bar" style="height:' + h + 'px"></div>' +
        '<div class="trend-label">' + esc(t.date).slice(5) + '</div></div>';
    }).join('');
    if (!trendBars) trendBars = '<div class="empty-state">No scan data yet</div>';

    el.innerHTML =
      '<div class="content">' +
        '<div class="page-header"><h1>Dashboard</h1></div>' +
        '<div class="kpi-row">' +
          '<div class="kpi-card"><div class="kpi-value">' + stats.total_findings + '</div><div class="kpi-label">Total Findings</div></div>' +
          '<div class="kpi-card kpi-critical"><div class="kpi-value">' + stats.critical + '</div><div class="kpi-label">Critical</div></div>' +
          '<div class="kpi-card kpi-high"><div class="kpi-value">' + stats.high + '</div><div class="kpi-label">High</div></div>' +
          '<div class="kpi-card"><div class="kpi-value">' + stats.total_scans + '</div><div class="kpi-label">Total Scans</div></div>' +
          '<div class="kpi-card"><div class="kpi-value">' + stats.active_targets + '</div><div class="kpi-label">Targets</div></div>' +
          '<div class="kpi-card"><div class="kpi-value">' + stats.compound_chains + '</div><div class="kpi-label">Attack Chains</div></div>' +
        '</div>' +
        '<div class="dashboard-grid">' +
          '<div class="card"><h3 class="card-title">Severity Distribution</h3><div class="severity-bars">' + sevBars + '</div></div>' +
          '<div class="card"><h3 class="card-title">Scan Trend</h3><div class="trend-chart">' + trendBars + '</div></div>' +
        '</div>' +
      '</div>';
  } catch (e) {
    el.innerHTML = '<div class="content"><div class="page-error">Failed to load dashboard: ' + esc(e.message) + '</div></div>';
  }
});

// ============================================================
// PAGE: Live Scan
// ============================================================
var liveScanInterval = null;

registerPage('live-scan', function (el) {
  el.innerHTML =
    '<div class="content">' +
      '<div class="page-header"><h1>Live Scan</h1>' +
        '<div class="topbar-actions">' +
          '<button class="btn-secondary" id="btn-stop">\u23F9 Stop</button>' +
          '<button class="btn-primary" id="btn-start">\u25B6 Start Scan</button>' +
        '</div>' +
      '</div>' +
      '<div class="scan-form" id="scan-form">' +
        '<input type="text" id="scan-target" class="input" placeholder="Target URL (e.g. http://localhost:9001/chat)" />' +
        '<input type="text" id="scan-mcp" class="input" placeholder="MCP URLs (comma-separated, optional)" />' +
        '<input type="text" id="scan-api-key" class="input" placeholder="Target API Key (optional)" />' +
      '</div>' +
      '<div class="status-card" id="status-card">' +
        '<div class="status-left">' +
          '<div class="status-icon" id="status-icon">\u23F8</div>' +
          '<div><div class="status-title" id="status-title">Idle</div>' +
            '<div class="status-sub" id="status-sub">Enter a target URL and click Start Scan</div></div>' +
        '</div>' +
        '<div class="status-right">' +
          '<div class="metric"><div class="metric-label">Elapsed</div><div class="metric-value" id="m-elapsed">0.0s</div></div>' +
          '<div class="metric"><div class="metric-label">Findings</div><div class="metric-value" id="m-findings">0</div></div>' +
          '<div class="metric"><div class="metric-label">Validated</div><div class="metric-value highlight-green" id="m-validated">0</div></div>' +
          '<div class="metric"><div class="metric-label">Signals</div><div class="metric-value highlight-purple" id="m-signals">0</div></div>' +
        '</div>' +
      '</div>' +
      '<div class="live-split">' +
        '<div class="agent-panel" id="agent-panel"></div>' +
        '<div class="activity-feed" id="activity-feed">' +
          '<div class="feed-header">Agent Activity</div>' +
          '<div class="feed-body" id="feed-body"></div>' +
        '</div>' +
      '</div>' +
    '</div>';

  renderAgentPanel();
  renderActivityFromState();

  document.getElementById('btn-start').addEventListener('click', startScan);
  document.getElementById('btn-stop').addEventListener('click', stopScan);

  if (liveScanInterval) clearInterval(liveScanInterval);
  liveScanInterval = setInterval(function () {
    if (scanState.status === 'running') {
      var mel = document.getElementById('m-elapsed');
      if (mel) mel.textContent = scanState.elapsed.toFixed(1) + 's';
    }
  }, 500);
});

function renderAgentPanel() {
  var panel = document.getElementById('agent-panel');
  if (!panel) return;
  var keys = Object.keys(AGENTS);
  panel.innerHTML = keys.map(function (key) {
    var a = AGENTS[key];
    var st = scanState.agents[key] || {};
    var status = st.status || 'idle';
    var findings = st.findings_count || 0;
    var techniques = st.techniques_attempted || 0;
    return '<div class="agent-row agent-' + esc(status) + '">' +
      '<span class="agent-dot" style="background:' + a.color + '"></span>' +
      '<span class="agent-name-sm">' + esc(a.badge) + '</span>' +
      '<span class="agent-name-full">' + esc(a.name) + '</span>' +
      '<span class="agent-stat">' + findings + 'f</span>' +
      '<span class="agent-stat">' + techniques + 't</span>' +
      '<span class="agent-status-label">' + esc(status) + '</span>' +
    '</div>';
  }).join('');
}

function renderActivityFromState() {
  var body = document.getElementById('feed-body');
  if (!body) return;
  body.innerHTML = '';
  (scanState.activityLog || []).slice(-100).forEach(function (a) { appendActivity(a); });
}

function appendActivity(a) {
  var body = document.getElementById('feed-body');
  if (!body) return;
  var cat = a.category || 'status';
  var catMap = { finding: 'act-finding', probe: 'act-probe', status: 'act-status', technique: 'act-technique', recon: 'act-recon' };
  var catClass = catMap[cat] || 'act-status';
  var line = document.createElement('div');
  line.className = 'feed-line ' + catClass;
  line.innerHTML = '<span class="feed-agent">' + esc((AGENTS[a.agent] || {}).badge || a.agent) + '</span> <span class="feed-cat">' + esc(cat) + '</span> ' + esc(a.action || '');
  body.appendChild(line);
  if (body.scrollHeight - body.scrollTop - body.clientHeight < 80) {
    body.scrollTop = body.scrollHeight;
  }
}

function updateLiveScan() {
  renderAgentPanel();
  var iconMap = { running: '\u25C9', completed: '\u2713', failed: '\u2717', idle: '\u23F8', cancelled: '\u2298' };
  var el_icon = document.getElementById('status-icon');
  var el_title = document.getElementById('status-title');
  var el_sub = document.getElementById('status-sub');
  if (el_icon) el_icon.textContent = iconMap[scanState.status] || '\u25CF';
  if (el_title) el_title.textContent = scanState.status === 'running' ? 'Running' : scanState.status === 'completed' ? 'Scan Complete' : scanState.status.charAt(0).toUpperCase() + scanState.status.slice(1);
  if (el_sub) {
    if (scanState.status === 'running') el_sub.textContent = scanState.agentsRunning + ' of ' + scanState.agentsTotal + ' agents active';
    else if (scanState.status === 'completed') el_sub.textContent = scanState.totalFindings + ' findings \u00B7 ' + scanState.validatedFindings + ' validated';
    else el_sub.textContent = 'Enter a target URL and click Start Scan';
  }
  var card = document.getElementById('status-card');
  if (card) card.className = 'status-card ' + (scanState.status === 'running' ? 'running' : scanState.status === 'completed' ? 'completed' : '');
  var mel = document.getElementById('m-elapsed');
  if (mel) mel.textContent = scanState.elapsed.toFixed(1) + 's';
  var mf = document.getElementById('m-findings');
  if (mf) mf.textContent = scanState.totalFindings;
  var mv = document.getElementById('m-validated');
  if (mv) mv.textContent = scanState.validatedFindings;
  var ms = document.getElementById('m-signals');
  if (ms) ms.textContent = scanState.signalCount;
}

async function startScan() {
  var targetInput = document.getElementById('scan-target');
  var mcpInput = document.getElementById('scan-mcp');
  var apiKeyInput = document.getElementById('scan-api-key');
  if (!targetInput || !targetInput.value.trim()) { alert('Enter a target URL'); return; }
  var target = targetInput.value.trim();
  var mcpUrls = mcpInput && mcpInput.value.trim() ? mcpInput.value.split(',').map(function (s) { return s.trim(); }).filter(Boolean) : [];
  var apiKey = apiKeyInput ? apiKeyInput.value.trim() : '';

  scanState.findings = [];
  scanState.activityLog = [];
  scanState.agents = {};
  scanState.status = 'running';

  var reqBody = { target_name: target, mcp_urls: mcpUrls, agent_endpoint: target, timeout: 600, demo_pace_seconds: 0.5 };
  if (apiKey) reqBody.agent_api_key = apiKey;

  try {
    var res = await apiFetch('/api/scan/start', { method: 'POST', body: JSON.stringify(reqBody) });
    if (!res.ok) {
      var err = await res.json().catch(function () { return {}; });
      alert('Failed to start scan: ' + (err.detail || res.statusText));
    }
  } catch (e) {
    alert('Failed to start scan: ' + e.message);
  }
}

async function stopScan() {
  await apiFetch('/api/scan/stop', { method: 'POST' }).catch(function () {});
}

// ============================================================
// PAGE: Scan History
// ============================================================
registerPage('scan-history', async function (el, _params, gen) {
  el.innerHTML = '<div class="content"><div class="page-header"><h1>Scan History</h1></div><div class="page-loading">Loading\u2026</div></div>';
  try {
    var data = await apiJson('/api/scans?limit=100');
    if (isStaleNav(gen)) return;
    var scans = data.scans || [];
    var rows = scans.map(function (s) {
      var sid = s.id || s.scan_id || '';
      return '<tr class="clickable-row" data-scan-id="' + esc(sid) + '">' +
        '<td class="mono">' + esc(sid.slice(0, 8)) + '</td>' +
        '<td>' + esc(s.target_name || '-') + '</td>' +
        '<td><span class="status-pill status-' + esc(s.status || 'unknown') + '">' + esc(s.status || '-') + '</span></td>' +
        '<td>' + (s.total_findings || 0) + '</td>' +
        '<td>' + (s.duration ? s.duration.toFixed(1) + 's' : '-') + '</td>' +
        '<td>' + fmtDate(s.created_at) + '</td></tr>';
    }).join('');
    el.innerHTML =
      '<div class="content"><div class="page-header"><h1>Scan History</h1><p class="page-sub">' + (data.total || 0) + ' scans recorded</p></div>' +
      (scans.length === 0 ? '<div class="empty-state">No scans yet. Run your first scan from Live Scan.</div>' :
        '<div class="data-table"><table><thead><tr><th>Scan ID</th><th>Target</th><th>Status</th><th>Findings</th><th>Duration</th><th>Date</th></tr></thead><tbody>' + rows + '</tbody></table></div>') +
      '</div>';
    el.querySelectorAll('.clickable-row').forEach(function (row) {
      row.addEventListener('click', function () {
        var id = row.getAttribute('data-scan-id');
        if (id) navigateTo('scan-detail', { scanId: id });
      });
    });
  } catch (e) {
    el.innerHTML = '<div class="content"><div class="page-error">Failed to load scans: ' + esc(e.message) + '</div></div>';
  }
});

// ============================================================
// PAGE: Scan Detail
// ============================================================
registerPage('scan-detail', async function (el, params, gen) {
  var scanId = params.scanId;
  el.innerHTML = '<div class="content"><div class="page-loading">Loading scan details\u2026</div></div>';
  try {
    var results = await Promise.all([
      apiJson('/api/scans/' + scanId),
      apiJson('/api/scans/' + scanId + '/findings'),
      apiJson('/api/scans/' + scanId + '/compound-paths').catch(function () { return { compound_paths: [] }; }),
    ]);
    if (isStaleNav(gen)) return;
    var scan = results[0].scan || {};
    var agents = results[0].agents || [];
    var findings = results[1].findings || [];
    var paths = results[2].compound_paths || [];

    var findingRows = findings.map(function (f) {
      return renderFindingRow(f);
    }).join('');

    var pathCards = paths.map(function (p) {
      var steps = p.steps || p.chain_steps || [];
      var stepHtml = steps.map(function (s, i) {
        var txt = typeof s === 'string' ? s : (s.description || s.title || JSON.stringify(s));
        return '<div class="chain-step">' + (i + 1) + '. ' + esc(txt) + '</div>';
      }).join('');
      return '<div class="chain-card"><div class="chain-title">' + esc(p.title || p.name || 'Attack Chain') + '</div>' +
        '<div class="chain-meta">Exploitability: ' + (p.exploitability_score || '-') + '/10 \u00B7 Steps: ' + steps.length + '</div>' +
        (stepHtml ? '<div class="chain-steps">' + stepHtml + '</div>' : '') + '</div>';
    }).join('');

    var agentRows = agents.map(function (a) {
      return '<tr><td>' + esc(agentName(a.agent_type)) + '</td>' +
        '<td><span class="status-pill status-' + esc(a.status || '') + '">' + esc(a.status || '') + '</span></td>' +
        '<td>' + (a.findings_count || 0) + '</td>' +
        '<td>' + (a.techniques_attempted || 0) + '</td>' +
        '<td>' + (a.duration ? a.duration.toFixed(1) + 's' : '-') + '</td></tr>';
    }).join('');

    var sid = scan.id || scan.scan_id || scanId;
    el.innerHTML =
      '<div class="content">' +
        '<div class="page-header"><div class="breadcrumb-nav"><a class="back-link" id="back-to-history">\u2190 Scan History</a></div>' +
          '<h1>Scan ' + esc(sid.slice(0, 8)) + '</h1>' +
          '<p class="page-sub">' + esc(scan.target_name || '') + ' \u00B7 ' + esc(scan.status || '') + ' \u00B7 ' + fmtDate(scan.created_at) + '</p></div>' +
        '<div class="kpi-row">' +
          '<div class="kpi-card"><div class="kpi-value">' + (scan.total_findings || 0) + '</div><div class="kpi-label">Findings</div></div>' +
          '<div class="kpi-card kpi-critical"><div class="kpi-value">' + findings.filter(function (f) { return f.severity === 'critical'; }).length + '</div><div class="kpi-label">Critical</div></div>' +
          '<div class="kpi-card kpi-high"><div class="kpi-value">' + findings.filter(function (f) { return f.severity === 'high'; }).length + '</div><div class="kpi-label">High</div></div>' +
          '<div class="kpi-card"><div class="kpi-value">' + paths.length + '</div><div class="kpi-label">Attack Chains</div></div>' +
        '</div>' +
        '<h3 class="section-title">Findings (' + findings.length + ')</h3>' +
        (findings.length === 0 ? '<div class="empty-state">No findings for this scan.</div>' :
          '<div class="data-table"><table><thead><tr><th>Severity</th><th>Agent</th><th>Title</th><th>Technique</th><th>Status</th></tr></thead><tbody>' + findingRows + '</tbody></table></div>') +
        (paths.length > 0 ? '<h3 class="section-title">Compound Attack Paths (' + paths.length + ')</h3><div class="chain-list">' + pathCards + '</div>' : '') +
        (agents.length > 0 ? '<h3 class="section-title">Agent Results (' + agents.length + ')</h3><div class="data-table"><table><thead><tr><th>Agent</th><th>Status</th><th>Findings</th><th>Techniques</th><th>Duration</th></tr></thead><tbody>' + agentRows + '</tbody></table></div>' : '') +
      '</div>';
    document.getElementById('back-to-history').addEventListener('click', function () { navigateTo('scan-history'); });
  } catch (e) {
    el.innerHTML = '<div class="content"><div class="page-error">Failed to load scan: ' + esc(e.message) + '</div></div>';
  }
});

// ============================================================
// PAGE: Findings
// ============================================================
registerPage('findings', async function (el, _params, gen) {
  el.innerHTML = '<div class="content"><div class="page-header"><h1>All Findings</h1></div><div class="page-loading">Loading\u2026</div></div>';
  try {
    var data = await apiJson('/api/findings?limit=200');
    if (isStaleNav(gen)) return;
    var findings = data.findings || [];
    var rows = findings.map(function (f) {
      return '<tr><td><span class="severity-badge severity-' + esc(f.severity || 'info') + '">' + esc(f.severity || 'info') + '</span></td>' +
        '<td class="mono">' + esc(agentName(f.agent_type)) + '</td>' +
        '<td>' + esc(f.title || '') + '</td>' +
        '<td class="mono">' + esc((f.scan_id || '').slice(0, 8)) + '</td>' +
        '<td><span class="' + (f.status === 'validated' ? 'finding-validated' : 'finding-unvalidated') + '">' + (f.status === 'validated' ? '\u2713 validated' : '\u25CB pending') + '</span></td></tr>';
    }).join('');
    el.innerHTML =
      '<div class="content"><div class="page-header"><h1>All Findings</h1><p class="page-sub">' + (data.total || findings.length) + ' total</p></div>' +
      (findings.length === 0 ? '<div class="empty-state">No findings recorded yet.</div>' :
        '<div class="data-table"><table><thead><tr><th>Severity</th><th>Agent</th><th>Title</th><th>Scan</th><th>Status</th></tr></thead><tbody>' + rows + '</tbody></table></div>') +
      '</div>';
  } catch (e) {
    el.innerHTML = '<div class="content"><div class="page-error">Failed to load findings: ' + esc(e.message) + '</div></div>';
  }
});

// ============================================================
// PAGE: Attack Chains
// ============================================================
registerPage('attack-chains', async function (el, _params, gen) {
  el.innerHTML = '<div class="content"><div class="page-header"><h1>Compound Attack Paths</h1></div><div class="page-loading">Loading\u2026</div></div>';
  try {
    var data = await apiJson('/api/compound-paths?limit=100');
    if (isStaleNav(gen)) return;
    var paths = data.compound_paths || [];
    var cards = paths.map(function (p) {
      var steps = p.steps || p.chain_steps || [];
      var stepHtml = steps.map(function (s, i) {
        var txt = typeof s === 'string' ? s : (s.description || s.title || JSON.stringify(s));
        return '<div class="chain-step">' + (i + 1) + '. ' + esc(txt) + '</div>';
      }).join('');
      return '<div class="chain-card"><div class="chain-header">' +
        '<div class="chain-title">' + esc(p.title || p.name || 'Attack Chain') + '</div>' +
        '<span class="severity-badge severity-' + esc(p.severity || 'critical') + '">' + esc(p.severity || 'critical') + '</span></div>' +
        '<div class="chain-meta">Exploitability: <strong>' + (p.exploitability_score || '-') + '/10</strong> \u00B7 Steps: ' + steps.length + ' \u00B7 Scan: ' + esc((p.scan_id || '').slice(0, 8)) + '</div>' +
        (stepHtml ? '<div class="chain-steps">' + stepHtml + '</div>' : '') + '</div>';
    }).join('');
    el.innerHTML =
      '<div class="content"><div class="page-header"><h1>Compound Attack Paths</h1><p class="page-sub">' + (data.total || paths.length) + ' chains detected</p></div>' +
      (paths.length === 0 ? '<div class="empty-state">No compound attack paths found yet.</div>' :
        '<div class="chain-list">' + cards + '</div>') +
      '</div>';
  } catch (e) {
    el.innerHTML = '<div class="content"><div class="page-error">Failed to load attack chains: ' + esc(e.message) + '</div></div>';
  }
});

// ============================================================
// PAGE: OWASP Coverage
// ============================================================
registerPage('owasp', async function (el, _params, gen) {
  el.innerHTML = '<div class="content"><div class="page-header"><h1>OWASP Coverage</h1></div><div class="page-loading">Loading\u2026</div></div>';
  try {
    var data = await apiJson('/api/owasp/coverage');
    if (isStaleNav(gen)) return;
    var categories = data.categories || [];
    var cards = categories.map(function (c) {
      var agentTags = (c.agents || []).map(function (a) { return '<span class="owasp-agent">' + esc(a) + '</span>'; }).join(' ');
      return '<div class="owasp-card"><div class="owasp-id">' + esc(c.id || '') + '</div>' +
        '<div class="owasp-name">' + esc(c.name || '') + '</div>' +
        '<div class="owasp-agents">' + agentTags + '</div>' +
        '<div class="owasp-count">' + (c.finding_count || 0) + ' findings</div></div>';
    }).join('');
    el.innerHTML =
      '<div class="content"><div class="page-header"><h1>OWASP Agentic AI Coverage</h1><p class="page-sub">' + categories.length + ' categories mapped</p></div>' +
      (categories.length === 0 ? '<div class="empty-state">No OWASP data available.</div>' :
        '<div class="owasp-grid">' + cards + '</div>') +
      '</div>';
  } catch (e) {
    el.innerHTML = '<div class="content"><div class="page-error">Failed to load OWASP data: ' + esc(e.message) + '</div></div>';
  }
});

// ============================================================
// PAGE: Targets
// ============================================================
registerPage('targets', async function (el, _params, gen) {
  el.innerHTML = '<div class="content"><div class="page-header"><h1>Target Registry</h1></div><div class="page-loading">Loading\u2026</div></div>';
  try {
    var data = await apiJson('/api/targets');
    if (isStaleNav(gen)) return;
    var targets = data.targets || [];
    var rows = targets.map(function (t) {
      var ep = t.agent_endpoint || (t.mcp_server_urls && t.mcp_server_urls[0]) || '-';
      return '<tr><td><strong>' + esc(t.name || '') + '</strong></td>' +
        '<td><span class="status-pill">' + esc(t.target_type || 'generic') + '</span></td>' +
        '<td>' + esc(t.environment || '-') + '</td>' +
        '<td class="mono">' + esc(ep.slice(0, 50)) + '</td>' +
        '<td>' + fmtDate(t.created_at) + '</td></tr>';
    }).join('');
    el.innerHTML =
      '<div class="content"><div class="page-header"><h1>Target Registry</h1><p class="page-sub">' + (data.total || targets.length) + ' targets registered</p></div>' +
      (targets.length === 0 ? '<div class="empty-state">No targets registered. Add targets via CLI or API.</div>' :
        '<div class="data-table"><table><thead><tr><th>Name</th><th>Type</th><th>Environment</th><th>Endpoint</th><th>Created</th></tr></thead><tbody>' + rows + '</tbody></table></div>') +
      '</div>';
  } catch (e) {
    el.innerHTML = '<div class="content"><div class="page-error">Failed to load targets: ' + esc(e.message) + '</div></div>';
  }
});

// ============================================================
// PAGE: Agent Status
// ============================================================
registerPage('agents', async function (el, _params, gen) {
  el.innerHTML = '<div class="content"><div class="page-header"><h1>Agent Status</h1></div><div class="page-loading">Loading\u2026</div></div>';
  try {
    var data = await apiJson('/api/agents/status');
    if (isStaleNav(gen)) return;
    var agentList = data.agents || [];
    var cards = agentList.map(function (a) {
      var display = AGENTS[a.type] || { name: a.type, badge: '?', icon: '?', color: '#888' };
      return '<div class="attacker-card">' +
        '<div class="attacker-header"><div class="attacker-name"><span>' + display.icon + '</span> <span>' + esc(display.name) + '</span> <span class="attacker-badge">' + esc(display.badge) + '</span></div></div>' +
        '<div class="attacker-stats">' +
          '<div class="stat-item">scans <span class="stat-item-value">' + (a.scans || 0) + '</span></div>' +
          '<div class="stat-item">findings <span class="stat-item-value yellow">' + (a.findings || 0) + '</span></div>' +
          '<div class="stat-item">techniques <span class="stat-item-value">' + (a.techniques || 0) + '</span></div>' +
        '</div></div>';
    }).join('');
    el.innerHTML =
      '<div class="content"><div class="page-header"><h1>Agent Status</h1><p class="page-sub">' + agentList.length + ' agents registered</p></div>' +
      '<div class="attacker-grid">' + cards + '</div></div>';
  } catch (e) {
    el.innerHTML = '<div class="content"><div class="page-error">Failed to load agents: ' + esc(e.message) + '</div></div>';
  }
});

// ============================================================
// PAGE: Attack Corpus
// ============================================================
registerPage('corpus', async function (el, _params, gen) {
  el.innerHTML = '<div class="content"><div class="page-header"><h1>Attack Corpus</h1></div><div class="page-loading">Loading\u2026</div></div>';
  try {
    var data = await apiJson('/api/corpus/patterns');
    if (isStaleNav(gen)) return;
    var patterns = data.patterns || [];
    var rows = patterns.map(function (p) {
      return '<tr><td><span class="status-pill">' + esc(p.category || '') + '</span></td>' +
        '<td>' + esc(p.name || p.title || '') + '</td>' +
        '<td>' + ((p.variants || []).length || p.variant_count || 0) + '</td>' +
        '<td class="mono">' + esc(p.agent_type || '-') + '</td></tr>';
    }).join('');
    el.innerHTML =
      '<div class="content"><div class="page-header"><h1>Attack Corpus</h1><p class="page-sub">' + (data.total || patterns.length) + ' patterns loaded</p></div>' +
      (patterns.length === 0 ? '<div class="empty-state">No corpus patterns loaded.</div>' :
        '<div class="data-table"><table><thead><tr><th>Category</th><th>Name</th><th>Variants</th><th>Agent</th></tr></thead><tbody>' + rows + '</tbody></table></div>') +
      '</div>';
  } catch (e) {
    el.innerHTML = '<div class="content"><div class="page-error">Failed to load corpus: ' + esc(e.message) + '</div></div>';
  }
});

// ============================================================
// PAGE: Settings (with LLM API Key Management)
// ============================================================

var LLM_PROVIDERS = [
  { id: 'anthropic', name: 'Anthropic', models: 'Claude Sonnet, Opus, Haiku', placeholder: 'sk-ant-api03-...', icon: '\u25C6' },
  { id: 'openai', name: 'OpenAI', models: 'GPT-4o, GPT-4 Turbo, o1', placeholder: 'sk-proj-...', icon: '\u25CF' },
  { id: 'google', name: 'Google Gemini', models: 'Gemini 2.5 Pro, Flash, Ultra', placeholder: 'AIza...', icon: '\u25C6' },
  { id: 'custom', name: 'Custom Provider', models: 'Any OpenAI-compatible endpoint', placeholder: 'API key...', icon: '\u2699', hasEndpoint: true },
];

function renderProviderCard(p, keyData) {
  var configured = keyData && keyData.configured;
  var masked = keyData ? keyData.masked_key || '' : '';
  var borderStyle = configured ? 'border-color: var(--accent-green);' : '';
  var dotColor = configured ? 'var(--accent-green)' : 'var(--text-muted)';
  var nameColor = configured ? 'var(--accent-purple)' : 'var(--text-secondary)';
  var statusText = configured ? '\u2713 Configured \u00B7 ' + esc(masked) : 'Not configured';
  var statusColor = configured ? 'var(--accent-green)' : 'var(--text-muted)';

  var endpointField = '';
  if (p.hasEndpoint) {
    var epVal = (keyData && keyData.endpoint) || '';
    endpointField = '<input type="text" class="input key-endpoint-input" data-provider="' + p.id + '" placeholder="https://your-endpoint.com/v1" value="' + esc(epVal) + '" style="margin-bottom:8px;" />';
  }

  return '<div class="card provider-card" style="' + borderStyle + '">' +
    '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">' +
      '<div style="display:flex;align-items:center;gap:8px;">' +
        '<span style="font-size:16px;">' + p.icon + '</span>' +
        '<div><div style="font-weight:700;color:' + nameColor + ';">' + esc(p.name) + '</div>' +
          '<div style="font-size:11px;color:var(--text-muted);">' + esc(p.models) + '</div></div>' +
      '</div>' +
      '<div style="width:10px;height:10px;border-radius:50%;background:' + dotColor + ';"></div>' +
    '</div>' +
    endpointField +
    '<div style="display:flex;gap:6px;align-items:center;margin-bottom:8px;">' +
      '<input type="password" class="input key-input" data-provider="' + p.id + '" placeholder="' + esc(p.placeholder) + '" style="flex:1;font-family:var(--font-mono);font-size:12px;" />' +
      '<button class="btn-secondary key-toggle-btn" style="padding:8px 10px;" title="Show/hide">\uD83D\uDC41</button>' +
    '</div>' +
    '<div style="display:flex;gap:6px;align-items:center;">' +
      '<button class="btn-primary key-save-btn" data-provider="' + p.id + '" style="font-size:12px;padding:6px 14px;">Save</button>' +
      '<button class="btn-secondary key-test-btn" data-provider="' + p.id + '" style="font-size:12px;padding:6px 14px;">Test</button>' +
      (configured ? '<button class="btn-secondary key-remove-btn" data-provider="' + p.id + '" style="font-size:12px;padding:6px 14px;color:var(--accent-red);border-color:var(--accent-red);">Remove</button>' : '') +
    '</div>' +
    '<div class="key-status" data-provider="' + p.id + '" style="font-size:11px;color:' + statusColor + ';margin-top:6px;">' + statusText + '</div>' +
  '</div>';
}

registerPage('settings', async function (el, _params, gen) {
  el.innerHTML = '<div class="content"><div class="page-header"><h1>Settings</h1></div><div class="page-loading">Loading\u2026</div></div>';
  try {
    var results = await Promise.all([
      apiJson('/api/system/tier').catch(function () { return {}; }),
      apiJson('/api/system/db-status').catch(function () { return {}; }),
      apiJson('/api/settings/llm-keys').catch(function () { return { providers: [] }; }),
    ]);
    if (isStaleNav(gen)) return;
    var tierData = results[0];
    var dbData = results[1];
    var keysData = results[2];

    // Build provider key lookup
    var keyMap = {};
    (keysData.providers || []).forEach(function (k) { keyMap[k.provider] = k; });
    var activeCount = (keysData.providers || []).filter(function (k) { return k.configured; }).length;

    var providerCards = LLM_PROVIDERS.map(function (p) {
      return renderProviderCard(p, keyMap[p.id]);
    }).join('');

    var dbRows = '';
    if (dbData.tables) {
      Object.keys(dbData.tables).forEach(function (k) {
        dbRows += '<div class="setting-row"><span class="setting-label">' + esc(k) + '</span><span class="setting-value mono">' + esc(String(dbData.tables[k])) + '</span></div>';
      });
    }

    el.innerHTML =
      '<div class="content"><div class="page-header"><h1>Settings</h1></div>' +

      // LLM API Keys Section
      '<div class="card" style="margin-bottom:20px;">' +
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">' +
          '<div><h3 class="card-title" style="margin:0;">LLM API Keys</h3>' +
            '<div style="font-size:12px;color:var(--text-muted);margin-top:2px;">Configure API keys for LLM-augmented attack phases (4\u20136). Keys are stored in <code style="font-family:var(--font-mono);font-size:11px;">~/.argusrc</code> with 0600 permissions.</div></div>' +
          '<span class="badge" style="background:' + (activeCount > 0 ? 'rgba(16,185,129,0.15)' : 'rgba(255,255,255,0.08)') + ';color:' + (activeCount > 0 ? 'var(--accent-green)' : 'var(--text-muted)') + ';">' + activeCount + ' active</span>' +
        '</div>' +
        '<div class="settings-grid">' + providerCards + '</div>' +
        '<div style="margin-top:12px;padding:10px 14px;background:rgba(139,92,246,0.06);border:1px solid rgba(139,92,246,0.15);border-radius:var(--radius-sm);font-size:12px;color:var(--accent-purple);">' +
          '\uD83D\uDD12 Keys never leave your machine. Core tier uses keys for Phases 4\u20136 (LLM-augmented variants). Without a key, ARGUS runs in deterministic mode (Phases 1\u20133).' +
        '</div>' +
      '</div>' +

      // Tier + DB + Session
      '<div class="settings-grid">' +
        '<div class="card"><h3 class="card-title">Tier Information</h3>' +
          '<div class="setting-row"><span class="setting-label">Active Tier</span><span class="setting-value" style="font-weight:700;color:var(--accent-purple);">' + esc(tierData.name || tierData.tier || 'CORE').toUpperCase() + '</span></div>' +
          '<div class="setting-row"><span class="setting-label">Version</span><span class="setting-value mono">v' + esc(tierData.version || '0.1.8') + '</span></div>' +
          '<div class="setting-row"><span class="setting-label">Features</span><span class="setting-value">' + (tierData.enabled_count || '-') + ' / ' + (tierData.total_count || '-') + '</span></div>' +
        '</div>' +
        '<div class="card"><h3 class="card-title">Database</h3>' +
          '<div class="setting-row"><span class="setting-label">Status</span><span class="setting-value">' +
            '<span style="color:' + (dbData.status === 'healthy' ? 'var(--accent-green)' : 'var(--accent-red)') + ';">' + esc(dbData.status || 'unknown') + '</span></span></div>' +
          dbRows +
        '</div>' +
        '<div class="card"><h3 class="card-title">Session</h3>' +
          '<div class="setting-row"><span class="setting-label">Auth Token</span><span class="setting-value mono">' + esc(AUTH.token.slice(0, 12)) + '\u2026</span></div>' +
          '<button class="btn-secondary" id="btn-logout" style="margin-top:8px;">Logout</button>' +
        '</div>' +
      '</div>' +
      '</div>';

    // --- Wire up event handlers ---

    // Logout
    document.getElementById('btn-logout').addEventListener('click', function () {
      AUTH.clear();
      if (sseSource) { sseSource.close(); sseSource = null; }
      showLogin();
    });

    // Toggle password visibility
    el.querySelectorAll('.key-toggle-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var input = btn.previousElementSibling;
        if (input) input.type = input.type === 'password' ? 'text' : 'password';
      });
    });

    // Save key
    el.querySelectorAll('.key-save-btn').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        var provider = btn.getAttribute('data-provider');
        var input = el.querySelector('.key-input[data-provider="' + provider + '"]');
        var statusEl = el.querySelector('.key-status[data-provider="' + provider + '"]');
        if (!input || !input.value.trim()) { if (statusEl) statusEl.textContent = 'Enter an API key first'; return; }
        try {
          var body = { provider: provider, api_key: input.value.trim() };
          var epInput = el.querySelector('.key-endpoint-input[data-provider="' + provider + '"]');
          if (epInput && epInput.value.trim()) body.endpoint = epInput.value.trim();
          if (statusEl) { statusEl.textContent = 'Saving\u2026'; statusEl.style.color = 'var(--text-muted)'; }
          var res = await apiJson('/api/settings/llm-keys', { method: 'POST', body: JSON.stringify(body) });
          navigateTo('settings'); // Refresh page to update card state
          return;
        } catch (e) {
          if (statusEl) { statusEl.textContent = 'Failed: ' + e.message; statusEl.style.color = 'var(--accent-red)'; }
        }
      });
    });

    // Test key
    el.querySelectorAll('.key-test-btn').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        var provider = btn.getAttribute('data-provider');
        var statusEl = el.querySelector('.key-status[data-provider="' + provider + '"]');
        try {
          if (statusEl) { statusEl.textContent = 'Testing\u2026'; statusEl.style.color = 'var(--text-muted)'; }
          var res = await apiJson('/api/settings/llm-keys/' + provider + '/test', { method: 'POST' });
          if (statusEl) {
            statusEl.textContent = (res.status === 'ok' ? '\u2713 ' : '\u2717 ') + (res.message || '');
            statusEl.style.color = res.status === 'ok' ? 'var(--accent-green)' : 'var(--accent-red)';
          }
        } catch (e) {
          if (statusEl) { statusEl.textContent = 'Test failed: ' + e.message; statusEl.style.color = 'var(--accent-red)'; }
        }
      });
    });

    // Remove key
    el.querySelectorAll('.key-remove-btn').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        var provider = btn.getAttribute('data-provider');
        if (!confirm('Remove ' + provider + ' API key?')) return;
        try {
          await apiFetch('/api/settings/llm-keys/' + provider, { method: 'DELETE' });
          navigateTo('settings'); // Refresh page
        } catch (e) {
          alert('Failed to remove key: ' + e.message);
        }
      });
    });

  } catch (e) {
    el.innerHTML = '<div class="content"><div class="page-error">Failed to load settings: ' + esc(e.message) + '</div></div>';
  }
});

// ============================================================
// Init
// ============================================================
document.addEventListener('DOMContentLoaded', async function () {
  document.querySelectorAll('.nav-item[data-page]').forEach(function (item) {
    item.addEventListener('click', function (e) {
      e.preventDefault();
      navigateTo(item.getAttribute('data-page'));
    });
  });

  var loginBtn = document.getElementById('login-btn');
  var loginInput = document.getElementById('login-token');
  if (loginBtn) {
    loginBtn.addEventListener('click', function () {
      var token = loginInput.value.trim();
      if (token) attemptLogin(token);
    });
  }
  if (loginInput) {
    loginInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        var token = loginInput.value.trim();
        if (token) attemptLogin(token);
      }
    });
  }

  if (AUTH.token) {
    try {
      var res = await fetch('/api/status', { headers: AUTH.headers() });
      if (res.ok) {
        hideLogin();
        connectSSE();
        navigateTo('dashboard');
        updateBadges();
        return;
      }
    } catch (e) { /* fall through to login */ }
    AUTH.clear();
  }
  showLogin();
});
