// ============================================================
// ARGUS Web Dashboard — frontend SSE client + UI updater
// ============================================================

// Auth token injected by the server into a meta tag for loopback requests.
// For non-loopback access, the operator must set it manually before page load.
const ARGUS_TOKEN = (() => {
  const meta = document.querySelector('meta[name="argus-token"]');
  return meta ? meta.getAttribute('content') : '';
})();

function authHeaders() {
  return ARGUS_TOKEN ? { 'Authorization': `Bearer ${ARGUS_TOKEN}` } : {};
}

const AGENT_DISPLAY = {
  prompt_injection_hunter: {
    name: 'Prompt Injection Hunter',
    badge: 'PI-01',
    icon: '⚡',
  },
  tool_poisoning: {
    name: 'Tool Poisoning Agent',
    badge: 'TP-02',
    icon: '☠',
  },
  supply_chain: {
    name: 'Supply Chain Agent',
    badge: 'SC-09',
    icon: '🔗',
  },
  memory_poisoning: { name: 'Memory Poisoning Agent', badge: 'MP-03', icon: '🧠' },
  identity_spoof: { name: 'Identity Spoof Agent', badge: 'IS-04', icon: '🎭' },
  context_window: { name: 'Context Window Agent', badge: 'CW-05', icon: '🪟' },
  cross_agent_exfiltration: { name: 'Cross-Agent Exfil Agent', badge: 'CX-06', icon: '↔' },
  privilege_escalation: { name: 'Privilege Escalation Agent', badge: 'PE-07', icon: '⬆' },
  race_condition: { name: 'Race Condition Agent', badge: 'RC-08', icon: '⏱' },
  model_extraction: { name: 'Model Extraction Agent', badge: 'ME-10', icon: '📤' },
  persona_hijacking: { name: 'Persona Hijacking Agent', badge: 'PH-11', icon: '🎭' },
  memory_boundary_collapse: { name: 'Memory Boundary Collapse', badge: 'MB-12', icon: '🧬' },
};

const state = {
  agents: {},
  findings: [],
  agentTerminalLines: {},
  scanRunning: false,
};

// ============================================================
// Setup
// ============================================================

// Embed mode: ?embed=cards renders only the attacker grid (for GIF capture).
// In this mode we MUST NOT open the SSE EventSource — it's a long-lived
// connection that prevents headless Chrome's load event from firing.
const EMBED_MODE = new URLSearchParams(window.location.search).get('embed') === 'cards';

document.addEventListener('DOMContentLoaded', async () => {
  renderEmptyAttackerCards();

  // Pull current state immediately so headless screenshots and reloads
  // see live data before SSE begins streaming.
  try {
    const res = await fetch('/api/status', { headers: authHeaders() });
    if (res.ok) {
      const snap = await res.json();
      applySnapshot(snap);

      // Also pull all findings to populate the stream from history
      const fres = await fetch('/api/findings', { headers: authHeaders() });
      if (fres.ok) {
        const data = await fres.json();
        const findings = data.findings || [];
        // Render most recent 25 in the stream
        document.getElementById('findings-stream').innerHTML = '';
        findings.slice(-25).forEach(addFinding);
      }
    }
  } catch (e) {
    console.warn('Initial fetch failed:', e);
  }

  if (!EMBED_MODE) {
    connectEventStream();
  }

  const startBtn = document.getElementById('btn-start');
  const stopBtn = document.getElementById('btn-stop');
  if (startBtn) startBtn.addEventListener('click', startScan);
  if (stopBtn) stopBtn.addEventListener('click', stopScan);
});

// ============================================================
// SSE event stream
// ============================================================

function connectEventStream() {
  // EventSource cannot send custom headers — pass token via query param
  const url = ARGUS_TOKEN
    ? `/api/events?token=${encodeURIComponent(ARGUS_TOKEN)}`
    : '/api/events';
  const source = new EventSource(url);

  source.addEventListener('snapshot', (e) => {
    const snap = JSON.parse(e.data);
    applySnapshot(snap);
  });

  source.addEventListener('signal', (e) => {
    const snap = JSON.parse(e.data);
    applySnapshot(snap);
  });

  source.addEventListener('finding', (e) => {
    const finding = JSON.parse(e.data);
    addFinding(finding);
    appendTerminalLine(finding.agent_type, formatFindingLine(finding));
  });

  source.addEventListener('scan_started', (e) => {
    const snap = JSON.parse(e.data);
    state.scanRunning = true;
    applySnapshot(snap);
  });

  source.addEventListener('complete', (e) => {
    const snap = JSON.parse(e.data);
    state.scanRunning = false;
    applySnapshot(snap);
    setStatus('completed', 'Scan Complete', `${snap.total_findings} findings · ${snap.validated_findings} validated`);
  });

  source.addEventListener('failed', (e) => {
    state.scanRunning = false;
    setStatus('failed', 'Scan Failed', JSON.parse(e.data).error || 'Unknown error');
  });

  source.addEventListener('cancelled', () => {
    state.scanRunning = false;
    setStatus('cancelled', 'Scan Cancelled', 'Scan was stopped by operator');
  });

  source.addEventListener('ping', () => {
    // heartbeat — no-op
  });

  source.onerror = () => {
    console.warn('SSE connection error, will retry...');
  };
}

// ============================================================
// State application
// ============================================================

function applySnapshot(snap) {
  // Update top metrics
  document.getElementById('metric-elapsed').textContent = `${snap.elapsed_seconds.toFixed(1)}s`;
  document.getElementById('metric-findings').textContent = snap.total_findings;
  document.getElementById('metric-validated').textContent = snap.validated_findings;
  document.getElementById('metric-signals').textContent = snap.signal_count || 0;

  document.getElementById('tab-findings-count').textContent = snap.total_findings;
  document.getElementById('tab-attackers-count').textContent = snap.agents_total || 3;

  if (snap.target_name) {
    document.getElementById('crumb-target').textContent = snap.target_name;
  }

  // Update status card
  if (snap.status === 'running') {
    setStatus('running', 'Running', `${snap.agents_running} of ${snap.agents_total} agents active · ${snap.target_endpoints?.length || 0} endpoints`);
  } else if (snap.status === 'completed') {
    setStatus('completed', 'Scan Complete', `${snap.total_findings} findings · ${snap.validated_findings} validated`);
  } else if (snap.status === 'failed') {
    setStatus('failed', 'Scan Failed', 'See logs for details');
  } else if (snap.status === 'idle') {
    setStatus('idle', 'Idle', 'Click Start Scan to begin');
  }

  // Update agent cards
  if (snap.agents) {
    Object.keys(snap.agents).forEach((agentType) => {
      const agent = snap.agents[agentType];
      state.agents[agentType] = agent;
      updateAttackerCard(agentType, agent);
    });
  }
}

function setStatus(status, title, sub) {
  const card = document.getElementById('status-card');
  card.classList.remove('running', 'completed', 'failed');
  if (status === 'running') card.classList.add('running');
  if (status === 'completed') card.classList.add('completed');

  const iconMap = { running: '◉', completed: '✓', failed: '✗', idle: '⏸', cancelled: '⊘' };
  document.getElementById('status-icon').textContent = iconMap[status] || '●';
  document.getElementById('status-title').textContent = title;
  document.getElementById('status-sub').textContent = sub;
}

// ============================================================
// Attacker cards
// ============================================================

function renderEmptyAttackerCards() {
  const grid = document.getElementById('attacker-grid');
  const defaultAgents = [
    'prompt_injection_hunter',
    'tool_poisoning',
    'supply_chain',
    'memory_poisoning',
    'identity_spoof',
    'context_window',
    'cross_agent_exfiltration',
    'privilege_escalation',
    'race_condition',
    'model_extraction',
    'persona_hijacking',
    'memory_boundary_collapse',
  ];

  grid.innerHTML = '';
  defaultAgents.forEach((agentType) => {
    const display = AGENT_DISPLAY[agentType] || { name: agentType, badge: '???', icon: '?' };
    const card = document.createElement('div');
    card.className = 'attacker-card';
    card.id = `card-${agentType}`;
    card.innerHTML = `
      <div class="attacker-header">
        <div class="attacker-name">
          <span>${display.icon}</span>
          <span>${display.name}</span>
          <span class="attacker-badge">${display.badge}</span>
        </div>
        <div class="attacker-status status-pending" id="status-${agentType}">
          <span class="status-dot"></span>
          <span>Pending</span>
        </div>
      </div>
      <div class="attacker-terminal" id="terminal-${agentType}">
        <div class="terminal-line cmd">$ argus-agent ${agentType} --target awaiting</div>
        <div class="terminal-line out">[ ready ] waiting for swarm deployment</div>
        <div class="terminal-line out">[ ready ] corpus loaded · 47 patterns</div>
        <div class="terminal-line out">                      <span class="terminal-cursor"></span></div>
      </div>
      <div class="attacker-stats">
        <div class="stat-item">findings <span class="stat-item-value yellow" id="findings-${agentType}">0</span></div>
        <div class="stat-item">validated <span class="stat-item-value green" id="validated-${agentType}">0</span></div>
        <div class="stat-item">techniques <span class="stat-item-value" id="techniques-${agentType}">0</span></div>
      </div>
    `;
    grid.appendChild(card);
    state.agentTerminalLines[agentType] = [];
  });
}

function updateAttackerCard(agentType, agent) {
  const statusEl = document.getElementById(`status-${agentType}`);
  if (!statusEl) return;

  // Update status
  statusEl.className = `attacker-status status-${agent.status}`;
  const statusText = {
    pending: 'Pending',
    running: 'Running',
    completed: 'Completed',
    failed: 'Failed',
  }[agent.status] || agent.status;
  statusEl.innerHTML = `<span class="status-dot"></span><span>${statusText}</span>`;

  // Update stats
  document.getElementById(`findings-${agentType}`).textContent = agent.findings_count || 0;
  document.getElementById(`validated-${agentType}`).textContent = agent.validated_count || 0;
  document.getElementById(`techniques-${agentType}`).textContent = agent.techniques_attempted || 0;

  // Update terminal preview if action changed
  if (agent.current_action && agent.status === 'running') {
    appendTerminalLine(agentType, agent.current_action.toLowerCase().includes('found')
      ? `[ HIT  ] ${agent.current_action.replace(/^Found:\s*/i, '')}`
      : `[ ${agent.status} ] ${agent.current_action}`);
  }
}

function appendTerminalLine(agentType, text) {
  const terminal = document.getElementById(`terminal-${agentType}`);
  if (!terminal) return;

  if (!state.agentTerminalLines[agentType]) {
    state.agentTerminalLines[agentType] = [];
  }

  let lineClass = 'out';
  if (text.includes('[ HIT')) lineClass = 'success';
  else if (text.includes('CRITICAL') || text.includes('[ CRIT')) lineClass = 'crit';
  else if (text.includes('WARN') || text.includes('[ HIGH')) lineClass = 'warn';

  // Atomic replacement: build the new array, then assign in one shot.
  // Prevents read/write races between concurrent SSE callbacks.
  const next = [...state.agentTerminalLines[agentType], { text, cls: lineClass }];
  state.agentTerminalLines[agentType] = next.slice(-5);

  const linesHtml = state.agentTerminalLines[agentType]
    .map((l) => `<div class="terminal-line ${escapeHtml(l.cls)}">${escapeHtml(l.text.slice(0, 60))}</div>`)
    .join('');

  // agentType is from the signal bus (server-controlled) but escape it anyway —
  // defense in depth against future code paths that pass arbitrary values.
  const safeAgent = escapeHtml(agentType);
  terminal.innerHTML = `
    <div class="terminal-line cmd">$ argus-agent ${safeAgent} --target gauntlet</div>
    ${linesHtml}
    <div class="terminal-line out">                      <span class="terminal-cursor"></span></div>
  `;
}

// ============================================================
// Findings stream
// ============================================================

function addFinding(finding) {
  state.findings.unshift(finding);

  const stream = document.getElementById('findings-stream');
  // Remove empty state
  const empty = stream.querySelector('.empty-state');
  if (empty) empty.remove();

  const row = document.createElement('div');
  row.className = 'finding-row';
  const sev = (finding.severity || 'info').toLowerCase();
  const sevClass = escapeHtml(sev);
  const validated = finding.status === 'validated';
  const verdict = finding.verdict_score || {};
  const cw = verdict.consequence_weight;
  // Sanitize tier to alphanumeric only — used as a CSS class suffix
  const tierRaw = String(verdict.action_tier || '');
  const tierClass = tierRaw.toLowerCase().replace(/[^a-z0-9]/g, '');
  const tierLabel = escapeHtml(tierRaw);
  const interp = escapeHtml(verdict.interpretation || '');
  const cwBadge = (cw !== undefined && cw !== null && typeof cw === 'number')
    ? `<div class="cw-badge cw-${tierClass}" title="VERDICT WEIGHT ${tierLabel}: ${interp}">CW ${cw.toFixed(2)}</div>`
    : '';

  row.innerHTML = `
    <div class="severity-badge severity-${sevClass}">${sevClass}</div>
    <div class="finding-agent">${escapeHtml(finding.agent_type || 'unknown')}</div>
    <div class="finding-title">${escapeHtml(finding.title || '')}</div>
    ${cwBadge}
    <div class="finding-status ${validated ? 'finding-validated' : 'finding-unvalidated'}">
      ${validated ? '✓ validated' : '○ pending'}
    </div>
  `;

  stream.insertBefore(row, stream.firstChild);

  // Cap stream length
  while (stream.children.length > 25) {
    stream.removeChild(stream.lastChild);
  }
}

function formatFindingLine(finding) {
  const sev = (finding.severity || 'info').toUpperCase();
  return `[ ${sev.padEnd(4)} ] ${(finding.title || '').slice(0, 50)}`;
}

// ============================================================
// API actions
// ============================================================

async function startScan() {
  if (state.scanRunning) return;

  const body = {
    target_name: 'ARGUS Gauntlet',
    mcp_urls: [
      'http://localhost:8001',  // Scenario 01 — Tool Poisoning MCP
      'http://localhost:8003',  // Scenario 02 — Memory Poisoning
      'http://localhost:8005',  // Scenario 03 — Identity Spoof
      'http://localhost:8007',  // Scenario 04 — Privilege Chain
      'http://localhost:8009',  // Scenario 05 — Injection Gauntlet
      'http://localhost:8011',  // Scenario 06 — Supply Chain
      'http://localhost:8013',  // Scenario 07 — Race Condition
    ],
    agent_endpoint: 'http://localhost:8002/chat',
    timeout: 300,
    demo_pace_seconds: 0.4,
  };

  // Reset findings stream
  document.getElementById('findings-stream').innerHTML = '<div class="empty-state">Deploying agents...</div>';
  state.findings = [];

  // Reset agent cards
  renderEmptyAttackerCards();

  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json();
      // FastAPI returns err.detail as an array of {loc, msg, type} objects
      // for pydantic validation errors. Flatten to readable text instead of
      // letting the array stringify to "[object Object],[object Object]".
      let detailText = res.statusText;
      if (Array.isArray(err.detail)) {
        detailText = err.detail.map((e) => e.msg || JSON.stringify(e)).join('\n');
      } else if (typeof err.detail === 'string') {
        detailText = err.detail;
      } else if (err.detail) {
        detailText = JSON.stringify(err.detail);
      }
      alert(`Failed to start scan:\n${detailText}`);
    }
  } catch (e) {
    alert(`Failed to start scan: ${e.message}`);
  }
}

async function stopScan() {
  await fetch('/api/scan/stop', { method: 'POST', headers: authHeaders() });
}

// ============================================================
// Helpers
// ============================================================

function escapeHtml(str) {
  // Escapes &, <, >, ", ', / — safe for both element content and attribute values.
  // Escaping the slash defends against scripts that try to break out via </script>.
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/\//g, '&#x2F;');
}
