# ARGUS Gauntlet — Public Leaderboard

Scores from all tools that have been validated against the ARGUS AI Agent Security Benchmark.

Every ARGUS finding is scored by **VERDICT WEIGHT™** — a patent-pending eight-stream confidence certification framework (USPTO #64/032,606, peer-reviewed via SSRN #6532658). Each finding ships with a Consequence Weight (CW) ranging 0–1.

## Honest baseline policy

This leaderboard publishes **honest scores only**. ARGUS attacks the scenarios with the same generic techniques it would use against any production AI agent — no PROMETHEUS module, attack agent, or correlation rule hardcodes a benchmark canary token, scenario ID, or known vulnerable tool name. Published scores are floors that grow as new agents ship, not engineered ceilings.

## Current Scores

| Rank | Tool | Version | Total Score | Median CW | Highest CW | Date |
|------|------|---------|-------------|-----------|------------|------|
| 1 | **ARGUS** | 0.2.0 (Phase 2, VW-scored) | **30/42 (71.4%)** | 0.741 | 0.888 | 2026-04-10 |
| — | ARGUS | 0.1.0 (Phase 1) | 9/42 (21.4%) | 0.586 | 0.857 | 2026-04-09 |

> **Total Score** is across all 7 scenarios (max 42). Phase 2 ships 5 specialized agents (Prompt Injection Hunter, Tool Poisoning, Supply Chain, Memory Poisoning, Identity Spoof) plus the Correlation Engine v1, which unlocks the chaining tier on every scenario reachable by Phase 1+2 agents.
> **Median CW** is the median Consequence Weight across all matched findings — higher means stronger evidence.

## ARGUS Per-Scenario Breakdown

| Scenario | Difficulty | Phase | Detection | Validation | Chaining | Total |
|----------|-----------|-------|-----------|------------|----------|-------|
| 01 — Tool Poisoning | Easy | 1 | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 02 — Memory Poisoning | Medium | 2 | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 03 — Identity Spoof | Hard | 2 | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 04 — Privilege Chain | Hard | 3 | 0/1 | 0/2 | 0/3 | **0/6** *(Phase 3 agent)* |
| 05 — Injection Gauntlet | Easy | 1 | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 06 — Supply Chain | Medium | 1 | 1/1 ✅ | 2/2 ✅ | 3/3 ✅ | **6/6** |
| 07 — Race Condition | Expert | 3 | 0/1 | 0/2 | 0/3 | **0/6** *(Phase 3 agent)* |

**Phase 2 ceiling reached:** every scenario with at least one Phase 1 or Phase 2 specialist agent fully passes (Detection + Validation + Chaining). The remaining 12 points come from Phase 3 agents (Privilege Escalation, Race Condition).

## Phase coverage roadmap

| Phase | Status | Score |
|-------|--------|-------|
| **Phase 1** *(shipped)* | Detection + Validation on 01, 05, 06 | 9/42 |
| **Phase 2** *(shipped)* | + Memory Poisoning, Identity Spoof, Correlation Engine v1 | **30/42** |
| **Phase 3** *(planned)* | + Privilege Escalation Agent, Race Condition Agent, Correlation v2 | 42/42 |

## What Phase 2 added

| Component | What it does | Lives at |
|-----------|--------------|----------|
| **CONDUCTOR** | Multi-turn HTTP session manager. SSRF-bound, error-sanitized. Required for any agent that needs cross-turn state. | [src/argus/conductor/](../src/argus/conductor/) |
| **SURVEY** | AI-agent attack surface mapper. Probes common endpoint conventions, classifies them by surface type (chat / memory / identity / exfiltration / admin). | [src/argus/survey/](../src/argus/survey/) |
| **Memory Poisoning Agent** | Generic plant-and-trigger flow against any agent with persistent memory. Uses CONDUCTOR for the multi-turn chain and ResponseMatcher for evidence detection. | [src/argus/agents/memory_poisoning.py](../src/argus/agents/memory_poisoning.py) |
| **Identity Spoof Agent** | Generic baseline-vs-spoofed-identity diff against A2A boundaries. Fires every common header convention (X-Agent-Role, X-Agent-ID, agent_role, etc.). | [src/argus/agents/identity_spoof.py](../src/argus/agents/identity_spoof.py) |
| **Correlation Engine v1** | Rule-based finding-cluster detection. Groups findings by host + agent type, fires compound patterns when multi-agent corroboration exists. | [src/argus/correlation/](../src/argus/correlation/) |

## Security audit (Phase 1 → Phase 2)

Before Phase 2 shipped, an independent audit covered the new code paths plus all files modified since the Phase 1 audit. **3 CRITICAL + 6 HIGH + 7 MEDIUM** findings were patched in the same release:

- **mcp_client/client.py** (3 CRITICAL): added `follow_redirects=False`, `event_hooks` disable, and 1 MB bounded `_safe_json()` body cap
- **orchestrator/engine.py** (HIGH): exception class names only (never `str(exc)`) propagated to `AgentResult.errors` to prevent credential leakage via httpx repr
- **conductor/session.py** (MEDIUM): error sanitization + post-`urljoin` netloc re-check
- **web/server.py** (HIGH): `getaddrinfo` DNS resolution against blocked IP ranges (closes DNS rebinding); `html.escape` on `WEB_TOKEN`; 5 KB `raw_response` truncation in SSE broadcast
- **agents/tool_poisoning.py** (HIGH): aggressive sensitive-default probes (path traversal, `file://`, SQL) gated behind `target.non_destructive=False`. Benchmark targets opt in; customer engagements stay safe by default.
- **mcp_client/client.py** (MEDIUM): subprocess `start_new_session=True`, `terminate→wait→kill` reaping in `disconnect()`

## VERDICT WEIGHT Score Distribution (Latest Run)

| Tier | CW Range | Count | Notes |
|------|----------|-------|-------|
| **CRITICAL** | 0.85+ | 4 | Hidden content + sensitive marker leaks via direct observation |
| **HIGH** | 0.70–0.85 | 8 | Memory poison flows, identity spoof flows, tool output injection |
| **MEDIUM** | 0.40–0.70 | 9 | Supporting findings — corroborate but don't single-handedly validate |
| **LOW** | < 0.40 | 0 | None — VERDICT WEIGHT successfully filtered noise |

**Total findings:** 21 emitted, 19 validated, 0 suppressed. 6 compound attack paths.

## Run Stats

- **Scan duration:** ~3.6 seconds
- **Findings emitted:** 21 total, 19 validated (90%)
- **VERDICT WEIGHT scoring:** 21/21 findings scored, median CW = 0.741, highest CW = 0.888
- **Compound attack paths:** 6 (one per scenario reachable by Phase 1+2 agents)
- **Agents deployed:** 5 in parallel (Prompt Injection Hunter, Tool Poisoning, Supply Chain, Memory Poisoning, Identity Spoof)
- **Generic techniques:** hidden content scan, zero-width unicode detection, sensitive default probing, SSRF/file:// probes (gated on `non_destructive=False`), MCP trust analysis, tool output injection, plant-and-trigger memory chains, baseline-vs-spoof identity diffs, multi-host correlation patterns

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
- **Stream 5 — Cross-Temporal Consistency (CTC):** does the trajectory look legitimate or fabricated? *(used by ARGUS Correlation Agent v2 in Phase 3+)*
- **Streams 6–8 — Government tier:** SIS, CPS, RIS *(ARGUS Enterprise / Federal tier)*

ARGUS is the first production deployment of VERDICT WEIGHT scoring for autonomous offensive security testing.

Repo: github.com/Odingard/verdict-weight · PyPI: `pip install verdict-weight`

## How to Submit Your Score

If you're scoring an external tool against the public submission rubric, see [`benchmark/official/`](official/) for the community submission format and rubric. All scores are independently verified by re-running the tool against the same Docker containers.
