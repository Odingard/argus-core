# ARGUS Repository Layout

Map of where things live. Read this before adding new modules so you put
them where they belong, not where it feels easy.

---

## Top-level

| Path | What | Owned by |
|---|---|---|
| `src/argus/` | The platform. All production code. | Engineering |
| `tests/` | Pytest suite. Mirrors `src/argus/` structure where it makes sense. | Engineering |
| `legacy/` | Pre-2026-04-21 implementation. Reference only — not imported. | Archive |
| `packages/argus-redteam/` | PyPI compat shim, redirects to `argus-core`. | Distribution |
| `benchmark/` | Performance benchmarks (e.g. swarm vs legacy probe orchestration). | Engineering |
| `examples/` | Minimal target configs and example scripts for operators. | Docs |
| `docs/` | Operator-facing documentation. Getting-started, labrat-adding, etc. | Docs |
| `argus-targets/` | Local target labrats for testing (gitignored, regenerated per env). | Engineering |
| `results/` | Engagement output directories (gitignored). | Runtime |

## Top-level files

| File | Purpose |
|---|---|
| `DIRECTIVES.md` | Engineering directives. Canonical. Read before designing anything. |
| `KNOWN_REDS.md` | Tests known to fail in offline mode + why. Update when you add a marker. |
| `REPORT_VERIFICATION_2026-04-18.md` | Permanent record of the first VDP submission and its disposition. |
| `SWARM_SPRINT_STATE.md` | Live state of the swarm-migration sprint (which agents are migrated). |
| `REPO_LAYOUT.md` | This file. |
| `README.md` | Public-facing project intro. |
| `pyproject.toml` | Package metadata + deps + tool config. Single source for build. |
| `LICENSE` / `LICENSE-CORE` / `LICENSE-PRO` | Dual-license: MIT for core, commercial for `src/argus/pro/`. |
| `argus-run` | Operator-facing entry script (calls into `argus.cli`). |
| `Dockerfile` | Container image for running engagements. |
| `.env.example` | Template — copy to `.env` and fill in keys. `.env` is gitignored. |

---

## `src/argus/` — the platform

Modules grouped by purpose. Within each group, files are alphabetical
in the directory; the description is what the module does, not where to
find it.

### Core platform

| Module | Responsibility |
|---|---|
| `cli.py` | Operator entry point. `argus <target>` invocation. |
| `engagement/` | Engagement orchestration. `runner.py` is the loop. `registry.py`, `builtin.py`, `smart.py` resolve targets. |
| `policy/` | Engagement policy — what's in scope, what's out, what the operator authorised. |
| `consent/` | Pre-engagement consent gates. Operator confirms before live attacks fire. |
| `inventory/` | Discovered surfaces and assets per engagement. |
| `evidence/` | Finding evidence collection and persistence. |
| `report/` | Engagement report generation. Multiple personas (executive, technical, raw). |

### Targeting

| Module | Responsibility |
|---|---|
| `adapter/` | Target adapters. One file per target shape (`real_crewai.py`, `mcp.py`, `http_agent.py`, `a2a.py`, `generic_agent.py`, `sandboxed_stdio.py`). New target type → new adapter here. |
| `recon/` | Pre-engagement reconnaissance against the target. |
| `labrat/` | Local vulnerable target implementations for testing the platform. |

### Attack surfaces

| Module | Responsibility |
|---|---|
| `agents/` | The MAAC agent family. One file per agent (`agent_01_prompt_injection.py` … `agent_12_*.py`). Each exports a hunter class. |
| `attacks/` | Cross-agent attack primitives. `judge.py` is the LLM verdict layer. `adaptive.py`, `conversation.py`, `stochastic.py` are mutation strategies. |
| `corpus/`, `corpus_attacks/` | Probe corpora and corpus-mutation logic. |
| `mcp_attacker/` | MCP-specific attack module. `mcp_live_attacker.py` is the entry. |
| `shadow_mcp/` | Shadow-MCP attacker for stealthy MCP probing. |
| `adversarial/` | Adversarial mutation strategies layered on the corpus. |

### Detection / scoring

| Module | Responsibility |
|---|---|
| `validation/` | Finding validation gate. Probe → response → judge → finding. |
| `diagnostics/` | Runtime diagnostics for the engagement loop. |
| `drift/` | Behavioural drift detection across probes. |
| `impact/` | Impact scoring for confirmed findings. |
| `entropy.py` | Entropy-based heuristics for response novelty. |
| `evolve/`, `evolver/` | Corpus evolution (mutate-on-landing). |

### Infrastructure

| Module | Responsibility |
|---|---|
| `shared/` | Cross-cutting infrastructure. `client.py` is the universal LLM gateway (judge, agents, CVE pipeline, mcp_attacker — all 8+ LLM call sites consume `ArgusClient.messages.create`). |
| `swarm/` | Swarm orchestration — parallel probe execution. `engine.py`, `concurrency.py`, `agent_mixin.py`. |
| `harness/` | Test harness primitives — `stub_llm.py` for offline judge, `invariants.py` for runtime invariants. |
| `routing/` | LLM routing + cost-aware model selection. |
| `session/` | Per-target session state. |
| `memory/` | Cross-engagement learnings (memory poisoning agent + the platform's own memory). |
| `observation/` | Probe→response observation records. |
| `audit/` | Engagement audit trail. |

### Specialty subsystems

| Module | Responsibility |
|---|---|
| `cerberus/` | Cerberus runtime guard integration (one of the OdinGard portfolio products — ARGUS attacks it as a target type, doesn't import it). |
| `alec/` | ALEC rules engine for finding-to-rule synthesis. |
| `layer6/` | CVE confirmation pipeline (cve_pipeline.py — uses live exploitation to validate CVE candidates). |
| `r2r/` | Reason-to-Reason synthesis layer. |
| `wilson/` | Wilson score machinery for confidence intervals. |
| `personas/` | Operator personas — different report-rendering perspectives. |

### Productisation surface

| Module | Responsibility |
|---|---|
| `pro/` | Modules under commercial license (`LICENSE-PRO`). |
| `platform/` | Platform-level glue — multi-engagement coordination. |
| `autodeploy/`, `integrations/`, `plugins/` | Extension points for future productisation. Currently mostly scaffolding. |
| `license.py` | License-tier gating. |

### Demo / utility

| `demo/` | Demo invocations — used by `test_demo_generic_agent.py`. |

---

## `tests/`

Single flat directory. Naming follows: `test_<module_or_concept>.py`. Markers:

- `@pytest.mark.requires_judge` — skipped in offline mode (default). Set
  `ARGUS_JUDGE=1` plus a provider key to run. Documented in `KNOWN_REDS.md`.
- `@pytest.mark.requires_runtime_deps` — skipped unless
  `ARGUS_RUNTIME_TESTS=1` is set. For tests that spawn npx subprocesses
  or framework labrats with their own LLM clients.
- `@pytest.mark.xfail(strict=False)` — expected to fail until the
  underlying issue is resolved. Update `KNOWN_REDS.md` when you add one.

`conftest.py` registers the markers and their skip-conditions.

**Standard gate command:**
```
ARGUS_OFFLINE=1 python -m pytest tests/ --tb=short -q --timeout=120 \
    --ignore=argus-targets --ignore=tests/test_real_mcp.py
```

---

## What does NOT live in this repo

- **Customer engagement output** — engagements run from a separate
  ops directory; this repo is the platform code only.
- **The UI** — not built yet. When it is, it will live in a sibling
  directory or sibling repo, consuming ARGUS via API. (Directive 3.)
- **Customer-facing reports** — generated by `argus.report` at engagement
  time; templates live under `src/argus/report/`, not at repo root.

---

*Last updated: 2026-04-27. If you add a top-level directory, update this
document in the same commit.*
