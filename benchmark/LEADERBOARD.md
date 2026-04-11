# ARGUS Gauntlet — Public Leaderboard

Scores from all tools that have been validated against the ARGUS AI Agent Security Benchmark.

Every ARGUS finding is scored by **VERDICT WEIGHT™** — a patent-pending eight-stream confidence certification framework (USPTO #64/032,606, peer-reviewed via SSRN #6532658). Each finding ships with a Consequence Weight (CW) ranging 0–1.

## Honest baseline policy

This leaderboard publishes **honest scores only**. ARGUS attacks the scenarios with the same generic techniques it would use against any production AI agent — no PROMETHEUS module, attack agent, or correlation rule hardcodes a benchmark canary token, scenario ID, or known vulnerable tool name. Published scores are floors that grow as new agents ship, not engineered ceilings.

## Current Scores

| Rank | Tool | Version | Total Score | Median CW | Highest CW | Date |
|------|------|---------|-------------|-----------|------------|------|
| 1 | **ARGUS** | 0.3.0 (Phase 3, VW-scored) | **42/42 (100%)** | 0.605 | 0.891 | 2026-04-10 |
| — | ARGUS | 0.2.0 (Phase 2) | 30/42 (71.4%) | 0.741 | 0.888 | 2026-04-10 |
| — | ARGUS | 0.1.0 (Phase 1) | 9/42 (21.4%) | 0.586 | 0.857 | 2026-04-09 |

> **Total Score** is across all 7 scenarios (max 42). Phase 3 ships 10 specialized agents — all 7 scenarios now pass Detection + Validation + Chaining tiers.
> **Median CW** is the median Consequence Weight across all matched findings — higher means stronger evidence.

## ARGUS Per-Scenario Breakdown

| Scenario | Difficulty | Phase | Detection | Validation | Chaining | Total |
|----------|-----------|-------|-----------|------------|----------|-------|
| 01 — Tool Poisoning | Easy | 1 | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 02 — Memory Poisoning | Medium | 2 | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 03 — Identity Spoof | Hard | 2 | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 04 — Privilege Chain | Hard | 3 | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 05 — Injection Gauntlet | Easy | 1 | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 06 — Supply Chain | Medium | 1 | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 07 — Race Condition | Expert | 3 | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |

**Clean sweep — 42/42.** Every scenario passes every tier. Single scan, 7.9 seconds, 76 findings, 11 compound attack paths.

## Phase coverage roadmap

| Phase | Status | Score |
|-------|--------|-------|
| **Phase 1** *(shipped)* | Detection + Validation on 01, 05, 06 | 9/42 |
| **Phase 2** *(shipped)* | + Memory Poisoning, Identity Spoof, Correlation Engine v1 | 30/42 |
| **Phase 3** *(shipped)* | + Privilege Escalation (tool-call chaining), Race Condition (concurrent state mutation), Context Window, Cross-Agent Exfiltration | **42/42** |
| **Phase 4** *(shipped agent only)* | + Model Extraction Agent | 42/42 |

## What Phase 3 added (this commit)

| Component | What it does | Lives at |
|-----------|--------------|----------|
| **SURVEY: TOOL_CALL + PAYMENT classes** | New endpoint probes for `/tools/call`, `/v1/tools/call`, `/invoke`, `/pay`, `/payment`, `/transfer`, `/transaction`, `/charge`. SurfaceClass.TOOL_CALL and SurfaceClass.PAYMENT for routing. | [src/argus/survey/prober.py](../src/argus/survey/prober.py) |
| **Privilege Escalation Agent — generic tool-call chaining** | Enumerates the discovered tool catalog, fires every tool through `/tools/call` in catalog order, harvests tokens/session_ids/handles from each response and propagates them as inputs to subsequent tool calls. The classic confused-deputy pattern, completely generic — works against any AI agent that exposes a tool catalog and a tool-call endpoint. No hardcoded tool names, no scenario-specific chains. | [src/argus/agents/privilege_escalation.py](../src/argus/agents/privilege_escalation.py) |
| **Race Condition Agent — concurrent state-mutation probe** | When SURVEY discovers a PAYMENT-class endpoint, fires N=6 concurrent identical POSTs and looks for race-condition evidence in any response (sensitive markers, double-execution, overdraft). Generic — works against any value-bearing API. | [src/argus/agents/race_condition.py](../src/argus/agents/race_condition.py) |
| **Correlation patterns** | `privilege_escalation_data_exfil` and `race_condition_double_execution` compound patterns wired into Correlation Engine v1. | [src/argus/correlation/engine.py](../src/argus/correlation/engine.py) |
| **VERDICT WEIGHT priors** | HA priors and family stripping rules for the 5 Phase 3/4 technique families (`privesc`, `race`, `context_window`, `cross_agent_exfil`, `model_extraction`). | [src/argus/scoring/verdict_adapter.py](../src/argus/scoring/verdict_adapter.py) |
| **Wiring** | All 10 agents now registered in `web/server.py`, `run_baseline.py`, `run_cinematic.py`, `run_live.py`. | (multiple) |

## Findings by agent (latest run)

| Agent | Findings |
|---|---|
| Privilege Escalation | 20 |
| Cross-Agent Exfiltration | 12 |
| Race Condition | 9 |
| Memory Poisoning | 8 |
| Context Window | 7 |
| Model Extraction | 7 |
| Tool Poisoning | 6 |
| Identity Spoof | 4 |
| Supply Chain | 3 |
| **Total** | **76** |

## VERDICT WEIGHT Score Distribution (Latest Run)

| Tier | CW Range | Count |
|------|----------|-------|
| **CRITICAL** | 0.85+ | 8 |
| **HIGH** | 0.70–0.85 | 27 |
| **MEDIUM** | 0.40–0.70 | 41 |
| **LOW** | < 0.40 | 0 |

**Total findings:** 76 emitted, 74 validated (97%), 0 suppressed. **11 compound attack paths.**

## Run Stats

- **Scan duration:** ~7.9 seconds
- **Findings emitted:** 76 total, 74 validated (97%)
- **VERDICT WEIGHT scoring:** 76/76 findings scored, median CW = 0.605, highest CW = 0.891
- **Compound attack paths:** 11
- **Agents deployed:** 10 in parallel (Prompt Injection Hunter, Tool Poisoning, Supply Chain, Memory Poisoning, Identity Spoof, Context Window, Cross-Agent Exfiltration, Privilege Escalation, Race Condition, Model Extraction)
- **Generic techniques:** hidden content scan, zero-width unicode detection, sensitive default probing, MCP trust analysis, tool output injection, plant-and-trigger memory chains, baseline-vs-spoof identity diffs, **generic tool-call chaining via catalog enumeration + handle propagation**, **concurrent state-mutation race probes**, multi-host correlation patterns

## How to Reproduce

```bash
# Clone the repo
git clone https://github.com/Odingard/Argus.git
cd Argus

# Install ARGUS (includes VERDICT WEIGHT as a dependency)
pip install -e ".[dev]"

# Spin up all 7 benchmark scenarios
docker compose -f benchmark/docker-compose.yml up -d

# Run the honest baseline
python benchmark/run_baseline.py
```

The score will be written to `benchmark/baseline-score.json` and printed to the console. Each finding in `benchmark/baseline-findings.json` includes a `verdict_score` field with the full VERDICT WEIGHT breakdown (SR, CC, TD, HA, CW, action_tier, interpretation).

## About VERDICT WEIGHT™

VERDICT WEIGHT is a peer-reviewed (SSRN #6532658), patent-pending (USPTO #64/032,606) eight-stream confidence certification framework for autonomous AI systems. It scores every signal a system might act on across:

- **Stream 1 — Source Reliability (SR):** how trustworthy is the source?
- **Stream 2 — Cross-Feed Corroboration (CC):** how many independent techniques confirm this?
- **Stream 3 — Temporal Decay (TD):** how fresh is the underlying data?
- **Stream 4 — Historical Source Accuracy (HA):** what's the track record of this technique?
- **Stream 5 — Cross-Temporal Consistency (CTC):** does the trajectory look legitimate or fabricated? *(used by ARGUS Correlation Agent v2 in Phase 4+)*
- **Streams 6–8 — Government tier:** SIS, CPS, RIS *(ARGUS Enterprise / Federal tier)*

ARGUS is the first production deployment of VERDICT WEIGHT scoring for autonomous offensive security testing.

Repo: github.com/Odingard/verdict-weight · PyPI: `pip install verdict-weight`

## How to Submit Your Score

If you're scoring an external tool against the public submission rubric, see [`benchmark/official/`](official/) for the community submission format and rubric. All scores are independently verified by re-running the tool against the same Docker containers.
