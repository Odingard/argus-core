# ARGUS — Autonomous AI Red Team Platform

**Odingard Security · Six Sense Enterprise Services**

ARGUS is an autonomous AI red team platform that deploys a swarm of specialized offensive agents simultaneously against AI systems, MCP servers, and multi-agent workflows. Every agent attacks a different AI-specific attack domain in parallel. A Correlation Agent chains individual findings into multi-step attack paths. Every finding is validated with proof of exploitation before it is surfaced.

## ARGUS in Action

![ARGUS Web Dashboard scanning the Gauntlet benchmark](benchmark/assets/argus-web-action.gif)

*The ARGUS Web Dashboard live-streaming a scan against the [ARGUS Gauntlet](benchmark/) — 3 agents deployed in parallel, 30 findings, every one scored by VERDICT WEIGHT™, end-to-end in under 25 seconds.*

## Every finding is mathematically certified

Every ARGUS finding ships with a **Consequence Weight (CW)** — a 0-1 confidence score from [VERDICT WEIGHT™](https://github.com/Odingard/verdict-weight), a patent-pending eight-stream confidence certification framework (USPTO #64/032,606, peer-reviewed via SSRN #6532658, F1=1.0 across 297,000+ scenarios).

Instead of binary validated/unvalidated, you get:

- **Stream 1 — Source Reliability** — how trustworthy is the agent that produced this finding?
- **Stream 2 — Cross-Feed Corroboration** — how many independent techniques confirmed it?
- **Stream 3 — Temporal Decay** — how fresh is the underlying corpus pattern?
- **Stream 4 — Historical Source Accuracy** — what's the track record of this technique?
- **Stream 5 — Cross-Temporal Consistency** *(Phase 2+)* — does the trajectory look legitimate or fabricated? **Defeats LLM hallucinations in compound chains.**

ARGUS is the first production deployment of VERDICT WEIGHT scoring for autonomous offensive security testing.

> *"Every organization deploying AI agents into production is asking the same question their security team cannot answer: 'Has this been red-teamed?' ARGUS answers that question autonomously, at machine speed, before the agent touches production data."*

ARGUS ships with **two interfaces** — a web dashboard for operators and a cinematic terminal UI for screen recordings:

| Interface | Use Case | Command |
|---|---|---|
| **Web Dashboard** (Aikido-style) | Operators, CISOs, demo for stakeholders | `argus serve` |
| **Cinematic Terminal** (Shannon-style) | Screen recordings, GIF demos, CLI workflows | `argus live --cinematic` |

---

## The Problem

Traditional security testing tools cannot test AI agent vulnerabilities. They were built for a different attack surface. A SQL injection scanner does not know what tool poisoning is. A network vulnerability scanner cannot detect cross-agent exfiltration.

**ARGUS tests the layer above** — the AI systems, agent workflows, and tool connections that sit on top of traditional infrastructure and are becoming the primary attack surface in the enterprise.

---

## The 10 Attack Agents

| # | Agent | Primary Attack Surface |
|---|-------|----------------------|
| 1 | **Prompt Injection Hunter** | All input surfaces — system prompt, user input, tool descriptions, memory, retrieved context |
| 2 | **Tool Poisoning Agent** | MCP tool definitions and metadata |
| 3 | **Memory Poisoning Agent** | Agent persistent memory and session state |
| 4 | **Identity Spoof Agent** | Agent-to-agent authentication channels |
| 5 | **Context Window Agent** | Multi-turn conversation state |
| 6 | **Cross-Agent Exfiltration Agent** | Multi-agent data flow boundaries |
| 7 | **Privilege Escalation Agent** | Tool call chains and permission boundaries |
| 8 | **Race Condition Agent** | Parallel agent execution timing |
| 9 | **Supply Chain Agent** | External MCP servers and tool packages |
| 10 | **Model Extraction Agent** | Agent API and output interface |
| 11 | **Correlation Agent** | All agent outputs — chains findings into compound attack paths |

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                  ATTACK LAYER                         │
│                                                       │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐           │
│  │ PI  │ │ TP  │ │ MP  │ │ IS  │ │ CW  │           │
│  │Agent│ │Agent│ │Agent│ │Agent│ │Agent│   ...×10   │
│  └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘           │
│     │       │       │       │       │                │
│     └───────┴───────┴───┬───┴───────┘                │
│                         │                             │
│              ┌──────────▼──────────┐                  │
│              │    Signal Bus       │                  │
│              └──────────┬──────────┘                  │
├─────────────────────────┼────────────────────────────┤
│                CORRELATION LAYER                      │
│              ┌──────────▼──────────┐                  │
│              │  Correlation Agent  │                  │
│              │  Compound Chains    │                  │
│              └──────────┬──────────┘                  │
├─────────────────────────┼────────────────────────────┤
│                 REPORTING LAYER                       │
│              ┌──────────▼──────────┐                  │
│              │  Validation Engine  │                  │
│              │  Proof of Exploit   │                  │
│              └──────────┬──────────┘                  │
│              ┌──────────▼──────────┐                  │
│              │   Report Renderer   │                  │
│              │   OWASP Mapping     │                  │
│              └─────────────────────┘                  │
└──────────────────────────────────────────────────────┘
```

---

## Attack Surfaces Tested

1. **MCP Tool Chains** — Tool poisoning, confused deputy, cross-server shadowing, prompt injection in tool definitions
2. **Agent-to-Agent Communication** — Identity spoofing, orchestrator impersonation, trust chain exploitation
3. **Agent Memory and Context** — Cross-session memory poisoning, context window manipulation, memory summary attacks
4. **Multi-Agent Pipeline Logic** — Race conditions, privilege escalation through chaining, business logic abuse

---

## Quick Start — Watch ARGUS Work

```bash
git clone https://github.com/Odingard/Argus.git
cd Argus
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Spin up 4 deliberately vulnerable AI agent containers
docker compose -f benchmark/docker-compose.yml up -d

# Option 1 — Web Dashboard (recommended)
argus serve
# Open http://localhost:8765 and click Start Scan

# Option 2 — Cinematic Terminal Dashboard
python benchmark/run_cinematic.py
```

The web dashboard gives you the live operator view (sidebar nav, attacker cards, findings stream), while the cinematic dashboard gives you a Shannon-style retro-terminal view perfect for screen recordings.

### Other CLI Commands

```bash
# Show system status and corpus stats
argus status

# Launch the web dashboard
argus serve --port 8765

# Run a scan with the cinematic dashboard
argus live my-target --mcp-url https://mcp.example.com --cinematic

# Probe an MCP server for hidden content
argus probe https://mcp-server.example.com

# Run a full scan with JSON output
argus scan "My AI Agent" --mcp-url https://mcp.example.com --output report.json
```

### Run Tests

```bash
pytest tests/ -v
```

---

## Build Roadmap

| Phase | Duration | Milestone |
|-------|----------|-----------|
| **Phase 0 — Orchestration** | Weeks 1-3 | Parallel agent framework operational |
| **Phase 1 — First 3 Agents** | Weeks 4-8 | Shippable product — first customer test |
| **Phase 2 — Memory + Identity** | Weeks 9-13 | Compound attack chains surfacing |
| **Phase 3 — Pipeline Agents** | Weeks 14-18 | Full multi-agent pipeline testing |
| **Phase 4 — Complete Swarm** | Weeks 19-22 | 10 agents + CERBERUS integration |
| **Phase 5 — Pilots** | Weeks 23-28 | First paying enterprise customer |

**Current Status: Phase 0 Complete** — Orchestration framework, validation engine, MCP client, sandbox, attack corpus v0.1, and CLI operational.

---

## Portfolio Position

| Product | Function | When |
|---------|----------|------|
| **ARGUS** | Autonomous AI Red Team — finds vulnerabilities before deployment | Before production |
| **CERBERUS** | Runtime AI Agent Security — detects attacks in production | In production |
| **ALEC** | Autonomous Legal Evidence Chain — seals evidence after incidents | After incident |

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Agent Orchestrator | Python — parallel agent coordination, signal bus, execution management |
| Attack Agent Runtime | LLM-powered reasoning (Claude / GPT) + tool access |
| Validation Engine | Deterministic Python — reproducible proof-of-exploitation |
| Attack Corpus | Custom AI-specific attack pattern database |
| MCP Client | Full MCP protocol client — attacker perspective |
| Reporting | Structured output with OWASP Agentic AI mapping |
| API | ASP.NET Core (Phase 4+) |

---

## Project Structure

```
src/argus/
├── __init__.py              # Package root
├── cli.py                   # CLI entry point
├── models/
│   ├── findings.py          # Finding schema, OWASP mappings, validation results
│   └── agents.py            # Agent config, results, target definitions
├── orchestrator/
│   ├── engine.py            # Core orchestrator — parallel agent deployment
│   └── signal_bus.py        # Inter-agent real-time signal bus
├── validation/
│   └── engine.py            # Deterministic proof-of-exploitation validation
├── mcp_client/
│   ├── client.py            # MCP attack client — tool enum, hidden content scan
│   └── models.py            # MCP protocol models
├── sandbox/
│   └── environment.py       # Isolated execution environments
├── corpus/
│   └── manager.py           # Attack pattern corpus — the moat
├── reporting/
│   └── renderer.py          # Report generation — JSON and summary
└── agents/                  # Attack agents (Phase 1+)
```

---

**CONFIDENTIAL — Odingard Security · Six Sense Enterprise Services · Houston, TX**
