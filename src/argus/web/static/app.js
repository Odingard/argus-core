// ============================================================
// ARGUS Web Dashboard — frontend SSE client + UI updater
// ============================================================

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

document.addEventListener('DOMContentLoaded', async () => {
  renderEmptyAttackerCards();

  // Pull current state immediately so headless screenshots and reloads
  // see live data before SSE begins streaming.
  try {
    const res = await fetch('/api/status');
    if (res.ok) {
      const snap = await res.json();
      applySnapshot(snap);

      // Also pull all findings to populate the stream from history
      const fres = await fetch('/api/findings');
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

  connectEventStream();

  document.getElementById('btn-start').addEventListener('click', startScan);
  document.getElementById('btn-stop').addEventListener('click', stopScan);
});

// ============================================================
// SSE event stream
// ============================================================

function connectEventStream() {
  const source = new EventSource('/api/events');

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
  const defaultAgents = ['prompt_injection_hunter', 'tool_poisoning', 'supply_chain'];

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

  state.agentTerminalLines[agentType].push({ text, cls: lineClass });

  // Keep last 5 lines for the preview
  if (state.agentTerminalLines[agentType].length > 5) {
    state.agentTerminalLines[agentType].shift();
  }

  const lines = state.agentTerminalLines[agentType]
    .map((l) => `<div class="terminal-line ${l.cls}">${escapeHtml(l.text.slice(0, 60))}</div>`)
    .join('');

  terminal.innerHTML = `
    <div class="terminal-line cmd">$ argus-agent ${agentType} --target gauntlet</div>
    ${lines}
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
  const validated = finding.status === 'validated';
  const verdict = finding.verdict_score || {};
  const cw = verdict.consequence_weight;
  const tier = verdict.action_tier || '';
  const cwBadge = (cw !== undefined && cw !== null)
    ? `<div class="cw-badge cw-${tier.toLowerCase()}" title="VERDICT WEIGHT™ ${tier}: ${verdict.interpretation || ''}">CW ${cw.toFixed(2)}</div>`
    : '';

  row.innerHTML = `
    <div class="severity-badge severity-${sev}">${sev}</div>
    <div class="finding-agent">${finding.agent_type || 'unknown'}</div>
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
      'http://localhost:8001',
      'http://localhost:8003',
      'http://localhost:8004',
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
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json();
      alert(`Failed to start scan: ${err.detail || res.statusText}`);
    }
  } catch (e) {
    alert(`Failed to start scan: ${e.message}`);
  }
}

async function stopScan() {
  await fetch('/api/scan/stop', { method: 'POST' });
}

// ============================================================
// Helpers
// ============================================================

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
