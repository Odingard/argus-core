# ARGUS Gauntlet — Public Leaderboard

Scores from all tools that have been validated against the ARGUS AI Agent Security Benchmark.

Every ARGUS finding is scored by **VERDICT WEIGHT™** — a patent-pending eight-stream confidence certification framework (USPTO #64/032,606, peer-reviewed via SSRN #6532658). Each finding ships with a Consequence Weight (CW) ranging 0-1.

## Current Scores

| Rank | Tool | Version | Phase 1 Score | Median CW | Highest CW | Date |
|------|------|---------|---------------|-----------|------------|------|
| 1 | **ARGUS** | 0.1.0 (Phase 1, VW-scored) | **18/18 (100%)** | 0.645 | 0.909 | 2026-04-10 |

> **Phase 1 Score** measures performance on the 3 scenarios that ARGUS Phase 1 has agents for. The remaining scenarios require Phase 2+ agents.
> **Median CW** is the median Consequence Weight across all findings — higher means stronger evidence.

## ARGUS Per-Scenario Breakdown

| Scenario | Difficulty | Detection | Validation | Chaining | Total |
|----------|-----------|-----------|------------|----------|-------|
| 01 — Poisoned MCP Server | Easy | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 02 — Injection Gauntlet | Easy | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 03 — Supply Chain Trap | Medium | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 04 — Leaky Memory Agent | Medium | — | — | — | 0/6 *(Phase 2 agent)* |
| 05 — Trusting Orchestrator | Hard | — | — | — | 0/6 *(Phase 2 agent)* |
| 06 — Privilege Chain | Hard | — | — | — | 0/6 *(Phase 3 agent)* |
| 07 — Race Window | Expert | — | — | — | 0/6 *(Phase 3 agent)* |

## VERDICT WEIGHT Score Distribution (Latest Run)

| Tier | CW Range | Count | Examples |
|------|----------|-------|----------|
| **CRITICAL** | 0.85+ | 3 | Hidden content in `search_documents`, `send_email`, lookalike MCP server names |
| **HIGH** | 0.70-0.85 | 5 | Hidden content in `read_file`, dependency confusion variants |
| **MEDIUM** | 0.40-0.70 | 22 | Direct prompt injection corpus payloads, indirect injection via documents |
| **LOW** | < 0.40 | 0 | (none — VERDICT WEIGHT successfully filtered out noise) |
| **SUPPRESSED** | < 0.40 (gate) | 0 | — |

**Total findings:** 30 emitted, 30 scored, 30 surfaced (no suppression in this run)

## Run Stats

- **Scan duration:** 0.8 seconds
- **Findings emitted:** 30 total, 27 validated (90%)
- **VERDICT WEIGHT scoring:** 30/30 findings scored, median CW = 0.645
- **Agents deployed:** 3 in parallel (Prompt Injection Hunter, Tool Poisoning Agent, Supply Chain Agent)
- **Vulnerabilities detected per scenario:**
  - Scenario 01: 13 findings matched
  - Scenario 02: 29 findings matched
  - Scenario 03: 10 findings matched

## How to Reproduce

```bash
# Clone the repo
git clone https://github.com/Odingard/Argus.git
cd Argus

# Install ARGUS (includes VERDICT WEIGHT as a dependency)
pip install -e ".[dev]"

# Spin up the benchmark scenarios
docker compose -f benchmark/docker-compose.yml up -d

# Run the baseline
python benchmark/run_baseline.py
```

The score will be written to `benchmark/baseline-score.json` and printed to the console. Each finding in `benchmark/baseline-findings.json` includes a `verdict_score` field with the full VERDICT WEIGHT breakdown (SR, CC, TD, HA, CW, action_tier, interpretation).

## About VERDICT WEIGHT™

VERDICT WEIGHT is a peer-reviewed (SSRN #6532658), patent-pending (USPTO #64/032,606) eight-stream confidence certification framework for autonomous AI systems. It scores every signal a system might act on across:

- **Stream 1 — Source Reliability (SR):** how trustworthy is the source?
- **Stream 2 — Cross-Feed Corroboration (CC):** how many independent techniques confirm this?
- **Stream 3 — Temporal Decay (TD):** how fresh is the underlying data?
- **Stream 4 — Historical Source Accuracy (HA):** what's the track record of this technique?
- **Stream 5 — Cross-Temporal Consistency (CTC):** does the trajectory look legitimate or fabricated? *(used by ARGUS Correlation Agent in Phase 2+)*
- **Streams 6-8 — Government tier:** SIS, CPS, RIS *(ARGUS Enterprise / Federal tier)*

ARGUS is the first production deployment of VERDICT WEIGHT scoring for autonomous offensive security testing.

Repo: github.com/Odingard/verdict-weight · PyPI: `pip install verdict-weight`

## How to Submit Your Score

See [README.md](README.md) for submission instructions. All scores are independently verified by re-running the tool against the same Docker containers.
