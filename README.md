# ARGUS — Autonomous AI Red Team Platform

**Odingard Security · Six Sense Enterprise Services**

ARGUS is a continuous AI security platform that deploys 12 specialized offensive agents simultaneously against AI systems, MCP servers, and multi-agent workflows. Every agent attacks a different AI-specific attack domain in parallel. A Correlation Engine chains individual findings into multi-step compound attack paths. Every finding is validated with proof of exploitation and scored by VERDICT WEIGHT™ before it is surfaced.

## ARGUS in Action

![ARGUS Web Dashboard scanning the Gauntlet benchmark](benchmark/assets/argus-web-action.gif)

*The ARGUS Web Dashboard live-streaming a scan — 12 agents deployed in parallel, findings scored by VERDICT WEIGHT™, compound attack paths chained by the Correlation Engine.*

## Every finding is mathematically certified

Every ARGUS finding ships with a **Consequence Weight (CW)** — a 0-1 confidence score from [VERDICT WEIGHT™](https://github.com/Odingard/verdict-weight), a patent-pending eight-stream confidence certification framework (USPTO #64/032,606, peer-reviewed via SSRN #6532658, F1=1.0 across 297,000+ scenarios).

Instead of binary validated/unvalidated, you get:

- **Stream 1 — Source Reliability** — how trustworthy is the agent that produced this finding?
- **Stream 2 — Cross-Feed Corroboration** — how many independent techniques confirmed it?
- **Stream 3 — Temporal Decay** — how fresh is the underlying corpus pattern?
- **Stream 4 — Historical Source Accuracy** — what's the track record of this technique?
- **Stream 5 — Cross-Temporal Consistency** — does the trajectory look legitimate or fabricated? **Defeats LLM hallucinations in compound chains.**

ARGUS is the first production deployment of VERDICT WEIGHT scoring for autonomous offensive security testing.

> *"Every organization deploying AI agents into production is asking the same question their security team cannot answer: 'Has this been red-teamed?' ARGUS answers that question autonomously, at machine speed, before the agent touches production data."*

---

## The Problem

Traditional security testing tools cannot test AI agent vulnerabilities. They were built for a different attack surface. A SQL injection scanner does not know what tool poisoning is. A network vulnerability scanner cannot detect cross-agent exfiltration.

**ARGUS tests the layer above** — the AI systems, agent workflows, and tool connections that sit on top of traditional infrastructure and are becoming the primary attack surface in the enterprise.

---

## The 12 Attack Agents

| # | Agent | Phase | Primary Attack Surface |
|---|-------|-------|----------------------|
| 1 | **Prompt Injection Hunter** | 1 | All input surfaces — system prompt, user input, tool descriptions, memory, retrieved context |
| 2 | **Tool Poisoning Agent** | 1 | MCP tool definitions, metadata, schema manipulation |
| 3 | **Supply Chain Agent** | 1 | External MCP servers and tool packages |
| 4 | **Memory Poisoning Agent** | 2 | Agent persistent memory and session state |
| 5 | **Identity Spoof Agent** | 2 | Agent-to-agent authentication channels |
| 6 | **Context Window Agent** | 3 | Multi-turn conversation state, attention manipulation |
| 7 | **Cross-Agent Exfiltration Agent** | 3 | Multi-agent data flow boundaries |
| 8 | **Privilege Escalation Agent** | 3 | Tool call chains and permission boundaries |
| 9 | **Race Condition Agent** | 3 | Parallel agent execution timing |
| 10 | **Model Extraction Agent** | 4 | Agent API and output interface, system prompt extraction |
| 11 | **Persona Hijacking Agent** | 5 | Identity drift, role confusion, behavioral persistence |
| 12 | **Memory Boundary Collapse Agent** | 5 | Cross-store memory bleed, instruction hierarchy collapse |
| — | **Correlation Engine** | — | All agent outputs — chains findings into compound attack paths |

### OWASP Mapping

Agents 1–10 map to the OWASP Top 10 for Agentic AI and LLM Applications. Agents 11–12 are **ARGUS-defined categories** (AA11:ARGUS Persona Hijacking, AA12:ARGUS Memory Boundary Collapse) — attack surfaces ARGUS identified that are not yet covered by OWASP.

---

## Interfaces

ARGUS ships with **three interfaces** — a production React frontend for operators, a web API dashboard for live monitoring, and a cinematic terminal UI for demos:

| Interface | Use Case | Command |
|---|---|---|
| **Production Frontend** | Operators, CISOs — login, target management, scan history, findings, OWASP coverage | `cd argus-frontend && npm run dev` |
| **Web Dashboard** | Live scan monitoring, real-time agent status, SSE event stream | `argus serve` |
| **Cinematic Terminal** | Screen recordings, GIF demos, CLI workflows | `argus live --cinematic` |

### Production Frontend

The React frontend (`argus-frontend/`) provides a continuous platform experience:

- **Login** — API key authentication with role-based access
- **Dashboard** — Real-time scan monitoring with all 12 agents, trend charts, severity breakdown
- **Sidebar Navigation** — Activity (Live Scan, Pending, Completed), Targets (MCP Servers, AI Agents, Pipelines, Memory Stores), Findings (All, Compound Chains, OWASP Mapping), Platform (Corpus, Gauntlet, Monitoring, Settings)
- **Target Management** — CRUD for MCP servers, AI agent endpoints, multi-agent pipelines
- **Findings** — Expandable rows with attack chains, VERDICT WEIGHT scores, reproduction steps
- **OWASP Coverage** — Coverage heatmap across all OWASP Agentic AI and LLM categories

**Tech Stack:** Vite + React 18 + TypeScript + Tailwind CSS + shadcn/ui + recharts + lucide-react

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      FRONTEND LAYER                           │
│                                                               │
│   React/TypeScript         Web Dashboard       Terminal UI    │
│   (argus-frontend/)        (argus serve)       (argus live)   │
│        :5173                   :8765              CLI          │
│                                                               │
├───────────────────────────┬──────────────────────────────────┤
│                     API LAYER                                 │
│                                                               │
│   FastAPI + CORS + Bearer Auth + Rate Limiter                │
│   /api/auth  /api/targets  /api/scans  /api/findings         │
│   /api/scan/start  /api/scan/stop  /api/events (SSE)         │
│                                                               │
├───────────────────────────┬──────────────────────────────────┤
│                   ATTACK LAYER                                │
│                                                               │
│  ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐                 │
│  │ PI │ │ TP │ │ SC │ │ MP │ │ IS │ │ CW │                 │
│  └──┬─┘ └──┬─┘ └──┬─┘ └──┬─┘ └──┬─┘ └──┬─┘                 │
│  ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐                 │
│  │ CX │ │ PE │ │ RC │ │ ME │ │ PH │ │ MB │    ×12 agents   │
│  └──┬─┘ └──┬─┘ └──┬─┘ └──┬─┘ └──┬─┘ └──┬─┘                 │
│     └───────┴───────┴───┬──┴──────┴───────┘                  │
│                         │                                     │
│              ┌──────────▼──────────┐                          │
│              │     Signal Bus      │                          │
│              └──────────┬──────────┘                          │
├─────────────────────────┼────────────────────────────────────┤
│                CORRELATION LAYER                              │
│              ┌──────────▼──────────┐                          │
│              │  Correlation Engine │                          │
│              │  Compound Chains    │                          │
│              └──────────┬──────────┘                          │
├─────────────────────────┼────────────────────────────────────┤
│                 SCORING + REPORTING                           │
│              ┌──────────▼──────────┐                          │
│              │  VERDICT WEIGHT™    │                          │
│              │  Validation Engine  │                          │
│              └──────────┬──────────┘                          │
│              ┌──────────▼──────────┐                          │
│              │   Report Renderer   │ → HTML, JSON, ALEC      │
│              │   CERBERUS Rules    │ → Detection rules        │
│              │   OWASP Mapping     │ → Agentic AI + LLM      │
│              └─────────────────────┘                          │
├──────────────────────────────────────────────────────────────┤
│                 PERSISTENCE LAYER                             │
│                                                               │
│   SQLAlchemy + SQLite (default) / PostgreSQL                 │
│   Targets │ Scans │ Findings │ Compound Paths │ API Keys     │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

## Attack Surfaces Tested

1. **MCP Tool Chains** — Tool poisoning, confused deputy, cross-server shadowing, schema manipulation, prompt injection in tool definitions
2. **Agent-to-Agent Communication** — Identity spoofing, orchestrator impersonation, trust chain exploitation
3. **Agent Memory and Context** — Cross-session memory poisoning, context window manipulation, memory summary attacks, boundary collapse between memory stores
4. **Multi-Agent Pipeline Logic** — Race conditions, privilege escalation through chaining, business logic abuse
5. **Agent Identity** — Persona hijacking, identity drift, behavioral persistence, role confusion across sessions
6. **Memory Boundaries** — Cross-store bleed, preference contamination, instruction hierarchy collapse, temporal confusion

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+ (for the frontend)
- An LLM API key (Anthropic or OpenAI)

### Install

```bash
# Option 1: Install from PyPI
pip install argus-redteam

# Option 2: Install from source
git clone https://github.com/Odingard/Argus.git
cd Argus
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Initialize the database
argus db-status

# Create an API key for authentication
argus auth create-key my-admin --role admin
# Save the key — it's shown only once

# Start the backend API server
argus serve --port 8765
```

### Start the Frontend

```bash
cd argus-frontend
npm install
npm run dev
# Open http://localhost:5173 and log in with your API key
```

### Run a Scan

```bash
# Via CLI — scan a target and generate a report
argus scan "My AI Agent" \
  --mcp-url https://mcp.example.com \
  --output report.json

# Via Web Dashboard — click Start Scan at http://localhost:8765

# Via Frontend — use the Live Scan page at http://localhost:5173
```

### Test with the Built-in Mock Target

```bash
# Start the deliberately vulnerable mock AI target
argus test-target start --port 9999

# In another terminal, scan it
argus scan "Mock Target" --mcp-url http://localhost:9999 --output mock-report.json

# Or use the cinematic terminal dashboard
argus live "Mock Target" --mcp-url http://localhost:9999 --cinematic
```

### Export ALEC Evidence Package (Enterprise)

```bash
# Run a scan and export a legal-grade evidence package
argus alec-export "Target Name" \
  --mcp-url https://mcp.example.com \
  --output evidence.json
```

---

## Core vs Enterprise

ARGUS ships in two tiers. **The full attack engine is open-source.** All 12 agents, every technique, and the Correlation Engine are included in Core. Enterprise gates the output infrastructure — not the offensive capability.

| Feature | Core (Free) | Enterprise |
|---------|:-----------:|:----------:|
| **All 12 Attack Agents** | ✓ | ✓ |
| **Correlation Engine** | ✓ | ✓ |
| **VERDICT WEIGHT™ Scoring** | ✓ | ✓ |
| **Attack Corpus** | ✓ | ✓ |
| **Callback Beacon Server** | ✓ | ✓ |
| **CERBERUS Detection Rules** | ✓ | ✓ |
| **JSON Reports** | ✓ | ✓ |
| **HTML Reports** | ✓ | ✓ |
| **CLI Interface** | ✓ | ✓ |
| **Web Dashboard** | ✓ | ✓ |
| **React Frontend** | ✓ | ✓ |
| **ARGUS Arena (12 targets)** | ✓ | ✓ |
| ALEC Evidence Packages | — | ✓ |
| PDF Executive Reports | — | ✓ |
| SIEM Integration (Splunk, Sentinel) | — | ✓ |
| Scheduled / Recurring Scans | — | ✓ |
| Multi-Tenant Support | — | ✓ |
| PostgreSQL Backend | — | ✓ |
| SSO / SAML Authentication | — | ✓ |
| Custom Branding | — | ✓ |
| Priority Support | — | ✓ |

```bash
# Check your current tier
argus tier

# Activate Enterprise via environment variable
export ARGUS_TIER=enterprise

# Or provide a licence key
export ARGUS_LICENSE_KEY=your-key-here
```

---

## Community

- **GitHub Issues** — Bug reports, feature requests
- **[Discord](https://discord.gg/pyyuurcS)** — Join the ARGUS community

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `argus serve` | Start the web API server (default: port 8765) |
| `argus status` | Show system status, agent registry, and corpus stats |
| `argus scan` | Run a scan against a target with JSON/HTML output |
| `argus live` | Run a scan with the cinematic terminal dashboard |
| `argus probe` | Probe an MCP server for hidden content and attack surfaces |
| `argus alec-export` | Run a scan and export an ALEC evidence package |
| `argus corpus` | Display attack corpus statistics |
| `argus target create` | Register a new scan target |
| `argus target list` | List all registered targets |
| `argus target show` | Show target details |
| `argus target delete` | Delete a target |
| `argus history list` | List past scans |
| `argus history show` | Show scan details with findings |
| `argus history report` | Generate a report from a past scan |
| `argus auth create-key` | Create an API key (admin/operator/viewer) |
| `argus auth list-keys` | List all API keys |
| `argus auth revoke-key` | Revoke an API key |
| `argus tier` | Show active tier and feature matrix |
| `argus db-status` | Show database health and table counts |
| `argus test-target start` | Start the mock vulnerable AI target |
| `argus test-target status` | Check mock target status |

---

## Authentication & RBAC

ARGUS uses API key authentication with three roles:

| Role | Permissions |
|------|------------|
| **admin** | Full access — manage keys, targets, scans, settings |
| **operator** | Run scans, manage targets, view findings |
| **viewer** | Read-only — view scans, findings, reports |

```bash
# Create keys for your team
argus auth create-key ops-team --role operator
argus auth create-key auditor --role viewer

# List all keys
argus auth list-keys

# Revoke a key
argus auth revoke-key <key-id>
```

The frontend and API both use Bearer token authentication. Pass the API key as `Authorization: Bearer <key>` in API requests.

---

## Database

ARGUS persists all scan data to a SQLAlchemy-backed database:

| Table | Contents |
|-------|----------|
| `targets` | Registered scan targets with MCP URLs, agent endpoints, rate limits |
| `scans` | Scan history — status, duration, agent counts, finding counts |
| `scan_agents` | Per-agent results — techniques attempted, findings, errors |
| `findings` | Individual findings with attack chains, reproduction steps, VERDICT scores |
| `compound_paths` | Compound attack paths from the Correlation Engine |
| `api_keys` | API keys with roles, expiry, usage tracking |

**Default:** SQLite at `~/.argus/argus.db` (zero-config). For production, set `ARGUS_DATABASE_URL` to a PostgreSQL connection string.

---

## Client Environment Safety

When deployed in client environments, ARGUS includes built-in safety mechanisms:

- **Rate Limiter** — Configurable per-minute request limits with token bucket algorithm
- **Circuit Breaker** — Automatically stops attacks if the target system shows signs of degradation
- **Non-Destructive Mode** — Default mode that validates findings without modifying production data
- **SSRF Protection** — All target URLs are validated against private IP ranges and cloud metadata endpoints
- **Health Checks** — Continuous target health monitoring during scans

---

## Reporting

ARGUS generates three types of output:

| Format | Use Case | Command |
|--------|----------|---------|
| **JSON Report** | Machine-readable, pipeline integration | `argus scan --output report.json` |
| **HTML Report** | Executive summary for client delivery | `argus history report <scan-id> --format html` |
| **ALEC Evidence Package** | Legal-grade evidence chain with SHA-256 integrity hashes | `argus alec-export --output evidence.json` |

Every report includes:
- Executive summary with risk metrics
- Findings by severity with full attack chains
- OWASP Agentic AI and LLM Application mappings
- Compound attack paths from the Correlation Engine
- **CERBERUS detection rules** — automatically generated detection rules for the defensive product
- Remediation guidance per finding

---

## Run Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test suites
pytest tests/test_phase5_agents.py -v   # Phase 5 agent tests
pytest tests/test_conductor.py -v       # Conductor/session tests
pytest tests/test_survey.py -v          # Endpoint survey tests

# Lint and format
ruff check src/ tests/
ruff format src/ tests/
```

**Current test suite:** 163 tests across Python 3.11, 3.12, and 3.13.

---

## Project Structure

```
src/argus/
├── cli.py                    # CLI entry point — 20+ commands
├── client_safety.py          # Rate limiter, circuit breaker, health checks
├── rate_limiter.py           # Token bucket rate limiting
├── agents/
│   ├── base.py               # LLMAttackAgent base class
│   ├── prompt_injection.py   # Agent 1 — Prompt Injection Hunter
│   ├── tool_poisoning.py     # Agent 2 — Tool Poisoning
│   ├── supply_chain.py       # Agent 3 — Supply Chain
│   ├── memory_poisoning.py   # Agent 4 — Memory Poisoning
│   ├── identity_spoof.py     # Agent 5 — Identity Spoof
│   ├── context_window.py     # Agent 6 — Context Window
│   ├── cross_agent_exfil.py  # Agent 7 — Cross-Agent Exfiltration
│   ├── privilege_escalation.py # Agent 8 — Privilege Escalation
│   ├── race_condition.py     # Agent 9 — Race Condition
│   ├── model_extraction.py   # Agent 10 — Model Extraction
│   ├── persona_hijacking.py  # Agent 11 — Persona Hijacking
│   └── memory_boundary_collapse.py  # Agent 12 — Memory Boundary Collapse
├── orchestrator/
│   ├── engine.py             # Core orchestrator — parallel agent deployment
│   └── signal_bus.py         # Inter-agent real-time signal bus
├── correlation/
│   └── engine.py             # Compound attack path detection (16 patterns)
├── conductor/
│   └── session.py            # Conversation session management for agents
├── survey/
│   └── prober.py             # Endpoint discovery and surface classification
├── validation/
│   └── engine.py             # Deterministic proof-of-exploitation validation
├── scoring/
│   └── verdict_adapter.py    # VERDICT WEIGHT™ integration
├── models/
│   ├── findings.py           # Finding schema, OWASP mappings, CerberusRule
│   └── agents.py             # Agent config, results, target definitions
├── db/
│   ├── models.py             # SQLAlchemy ORM models
│   ├── repository.py         # CRUD repositories (Target, APIKey, Scan)
│   ├── scan_persistence.py   # Auto-persist scan results
│   └── session.py            # Database session management
├── web/
│   ├── server.py             # FastAPI app — CORS, auth, SSE, scan endpoints
│   ├── api_routes.py         # Production API — targets, scans, findings, auth
│   ├── auth.py               # API key auth middleware with RBAC
│   └── static/               # Legacy web dashboard (HTML/CSS/JS)
├── reporting/
│   ├── html_report.py        # HTML executive summary generator
│   ├── cerberus_rules.py     # CERBERUS detection rule generator
│   ├── alec_export.py        # ALEC legal evidence package exporter
│   └── renderer.py           # JSON report generation
├── corpus/
│   ├── manager.py            # Attack pattern corpus management
│   └── data/                 # Attack pattern JSON files (12 domains)
├── mcp_client/
│   ├── client.py             # MCP protocol attack client
│   └── models.py             # MCP protocol models
├── sandbox/
│   └── environment.py        # Isolated agent execution environments
├── llm/
│   └── client.py             # LLM client (Anthropic/OpenAI)
├── prometheus/               # PROMETHEUS attack module framework
│   ├── modules.py            # Module registry
│   ├── registry.py           # Module discovery
│   └── modules_lib/          # Injection, auxiliary, enumeration modules
├── test_harness/
│   ├── __init__.py           # Test harness entry point
│   └── mock_target.py        # Deliberately vulnerable mock AI target
└── ui/                       # Terminal UI components

argus-frontend/               # Production React frontend
├── src/
│   ├── api/client.ts         # API client — auth, scans, targets, findings
│   ├── components/
│   │   ├── layout/           # AppLayout, Header, Sidebar
│   │   └── ui/               # shadcn/ui components (16 components)
│   ├── pages/                # 16 pages — Login, Dashboard, LiveScan, etc.
│   └── types/index.ts        # TypeScript type definitions
├── package.json
├── tailwind.config.cjs
├── tsconfig.json
└── vite.config.ts
```

---

## Build Roadmap

| Phase | Status | Milestone |
|-------|--------|-----------|
| **Phase 0 — Orchestration** | ✅ Complete | Parallel agent framework, signal bus, validation engine |
| **Phase 1 — First 3 Agents** | ✅ Complete | Prompt Injection, Tool Poisoning, Supply Chain |
| **Phase 2 — Memory + Identity** | ✅ Complete | Memory Poisoning, Identity Spoof, Correlation Engine v1 |
| **Phase 3 — Pipeline Agents** | ✅ Complete | Context Window, Cross-Agent Exfil, Privilege Escalation, Race Condition |
| **Phase 4 — Complete Swarm** | ✅ Complete | Model Extraction, CERBERUS integration, ALEC export |
| **Phase 5 — Advanced Agents** | ✅ Complete | Persona Hijacking, Memory Boundary Collapse, test harness |
| **Production Infrastructure** | ✅ Complete | Database, auth/RBAC, scan persistence, rate limiter, HTML reports |
| **Production Frontend** | ✅ Complete | React/TypeScript, 16 pages, login, dashboard, targets, findings |
| **Phase 6 — Live API Integration** | ✅ Complete | Frontend wired to live backend APIs, real data everywhere |
| **Tiering System** | ✅ Complete | Core/Enterprise feature gates, `argus tier` command |
| **Callback Beacon Server** | ✅ Complete | Real exfiltration path verification via HTTP beacon callbacks |
| **Phase 7 — Vertical Deepening** | 🔲 Next | Deeper techniques across all 12 agents |
| **Phase 8 — Enterprise Features** | 🔲 Planned | Scheduled scans, PDF reports, SIEM integrations, multi-tenant |
| **Phase 9 — Pilots** | 🔲 Planned | First paying enterprise customer |

**Current Status:** All 12 agents operational. Tiering system enforced. Production frontend, database, auth, and CLI complete. Ready for public launch.

---

## Portfolio Position

| Product | Function | When |
|---------|----------|------|
| **ARGUS** | Autonomous AI Red Team — finds vulnerabilities before deployment | Before production |
| **CERBERUS** | Runtime AI Agent Security — detects attacks in production using ARGUS-generated rules | In production |
| **ALEC** | Autonomous Legal Evidence Chain — seals evidence after incidents | After incident |

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Agent Orchestrator | Python 3.11+ — parallel async agent coordination, signal bus |
| Attack Agent Runtime | LLM-powered reasoning (Claude / GPT) + deterministic tool access |
| Validation Engine | Deterministic Python — reproducible proof-of-exploitation |
| Scoring | VERDICT WEIGHT™ — 8-stream confidence certification |
| Correlation Engine | 16 compound attack path detection patterns |
| Attack Corpus | 12-domain AI-specific attack pattern database |
| MCP Client | Full MCP protocol client — attacker perspective |
| Database | SQLAlchemy + SQLite (default) / PostgreSQL |
| Backend API | FastAPI + Uvicorn + SSE + Bearer auth + CORS |
| Frontend | React 18 + TypeScript + Vite + Tailwind CSS + shadcn/ui |
| Reporting | HTML, JSON, ALEC evidence packages, CERBERUS rules |
| CI/CD | GitHub Actions — ruff lint, pip-audit, pytest (3.11/3.12/3.13) |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude-based agents | — |
| `OPENAI_API_KEY` | OpenAI API key for GPT-based agents | — |
| `ARGUS_DATABASE_URL` | Database connection string | `sqlite:///~/.argus/argus.db` |
| `ARGUS_WEB_TOKEN` | Bearer token for the legacy web dashboard | auto-generated |
| `ARGUS_TIER` | Active tier: `core` (default) or `enterprise` | `core` |
| `ARGUS_LICENSE_KEY` | Enterprise licence key (presence activates enterprise) | — |
| `ARGUS_WEB_ALLOW_ORIGIN` | Additional CORS origin for the frontend | — |
| `VITE_API_URL` | Backend API URL for the React frontend | `http://localhost:8765` |

---

**CONFIDENTIAL — Odingard Security · Six Sense Enterprise Services · Houston, TX**
