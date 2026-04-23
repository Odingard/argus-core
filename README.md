<p align="center">
  <img src="docs/assets/banner.svg" alt="ARGUS — Autonomous AI Red Team Platform">
</p>

[![PyPI](https://img.shields.io/pypi/v/argus-core.svg)](https://pypi.org/project/argus-core/)
[![Python](https://img.shields.io/pypi/pyversions/argus-core.svg)](https://pypi.org/project/argus-core/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE-CORE)
[![CI](https://github.com/Odingard/argus-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Odingard/argus-core/actions/workflows/ci.yml)

## 1. Positioning

ARGUS does not compete with traditional pentesting tools. It does something they inherently cannot do — **test the AI-specific attack surface** that none of them were built to find. If you run SAST against your infrastructure, you still need ARGUS against the agents running on top of it. They are complementary, not competing.

## 2. Quick start

```bash
pip install argus-core
```

One input, auto-routed — the same `argus <anything>` command engages an MCP server, clones a GitHub repo, npx-launches an MCP package, runs a local script, or opens a labrat fixture:

```bash
argus mcp://customer.example/sse              # live MCP over SSE
argus github.com/vercel/mcp-handler           # clone + dispatch
argus @modelcontextprotocol/server-filesystem # npx-launched stdio MCP
argus ./my_server.py                          # local file
argus crewai://labrat                         # in-process crewAI fixture
argus --list-targets                          # every registered scheme
argus --help                                  # full operational surface
```

Engagements land in `results/`; render an offline HTML report with `argus --report results/<run>/`.

## 3. What you get in Core

**12 offensive agents covering all 9 MAAC phases:**

| Agent | Class | MAAC phases |
|---|---|---|
| PI-02 | Prompt Injection Hunter | 2 |
| TP-02 | Tool Poisoning | 1, 2 |
| MP-03 | Memory Poisoning | 4 |
| IS-04 | Identity Spoof | 2 |
| RC-08 | Race Condition | 5 |
| OD-06 | Orchestration Drift | 6 |
| PE-07 | Privilege Escalation | 5, 7 |
| XE-06 | Cross-Agent Exfiltration | 7, 8 |
| SC-09 | Supply Chain | 1 |
| ME-10 | Model Extraction | 1, 3 |
| EP-11 | Environment Pivoting | 8 |
| MC-15 | Handoff Auditor | 2, 5, 7 |

**Platform:**

- **Coordinated swarm runtime** — blackboard + live correlator, phase-pair triggers, pheromone decay, Haiku/Opus budget caps
- **Stateful runtime harness** — deterministic multi-turn replay, 5 invariants, scenario library
- **Real MCP engagement** — stdio / SSE / HTTP transports; wraps untrusted servers in docker with `--cap-drop ALL`
- **Adversarial tooling** — attacker-controlled MCP server + npm/PyPI typosquat scanner
- **In-process real-framework adapters** — crewAI, AutoGen, LangGraph, LlamaIndex, Parlant, Hermes
- **Forensic Wilson bundles** — signed, reproducible evidence suitable for regulator submission
- **Impact Optimizer / BlastRadiusMap** — harm-scoring with SOC2 / PCI-DSS / HIPAA / FedRAMP / GDPR tags
- **Workflow integration** — GitHub Action, pre-commit hook, FastAPI webhook receiver

## 4. Core vs. Pro

ARGUS is open-core:

- **Core (this package)** — MIT licensed. Everything above. Self-sufficient for operators running their own engagements.
- **Pro** (`src/argus/pro/`, source-available) — Monte Carlo Tree Search exploit-chain planning, multi-model consensus gate for CRITICAL findings, eBPF/tcpdump L7 pcap, fleet-scale webhook store. Gated by `argus.license.require()` at import; today a permissive stub, tightens with first PRO customer.

Source for both tiers lives in this repo. Pro license terms land before any Pro release; see [`LICENSE-PRO`](./LICENSE-PRO).

## 5. Migrating from `argus-redteam`

`argus-redteam==0.4.1` is now a deprecation shim that simply pulls
`argus-core` as a dependency, so existing `pip install argus-redteam`
commands and `requirements.txt` pins continue to work with no code
change. Update at your convenience:

```diff
- pip install argus-redteam
+ pip install argus-core
```

The Python import name (`import argus`) did not change; source code
works identically under either install name.

## 6. Docs

- [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) — operator guide
- [`docs/ADDING_A_LABRAT.md`](docs/ADDING_A_LABRAT.md) — extend ARGUS to a new framework
- [`docs/NO_CHEATING.md`](docs/NO_CHEATING.md) — the integrity contract every finding must honour
- [`PHASES.md`](PHASES.md) — full build plan + moat map
- [`SECURITY.md`](SECURITY.md) — responsible disclosure

## 7. Enterprise

The Core Execution Engine is self-contained. Teams with compliance, reporting, and scale requirements — correlation synthesis at fleet scale, validator-grade reporting, managed infrastructure — can reach the full-swarm commercial offering at:

👉 **[sixsenseenterprise.com](https://sixsenseenterprise.com)**

## 8. License

Core is MIT — see [`LICENSE-CORE`](./LICENSE-CORE). Pro modules under `src/argus/pro/` are covered by [`LICENSE-PRO`](./LICENSE-PRO) (placeholder today; formal source-available terms to follow before first Pro release).

Responsible-disclosure contact: `security@sixsenseenterprise.com`.
