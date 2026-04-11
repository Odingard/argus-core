# ARGUS — Project Conventions

## What is ARGUS
Autonomous AI Red Team Platform by Odingard Security / Six Sense Enterprise Services.
Deploys 12 specialized offensive AI agents in parallel against target AI systems.
Continuous security platform — not one-shot. Persistent deployment with scan history, baseline management, and alerting.

## Development Commands
- `pip install -e ".[dev]"` — Install with dev dependencies
- `pytest tests/ -v` — Run all 163 tests
- `ruff check src/ tests/` — Run ruff linter
- `ruff format src/ tests/` — Auto-format code
- `argus serve` — Start backend API server (port 8765)
- `cd argus-frontend && npm run dev` — Start React frontend (port 5173)
- `argus auth create-key <name> --role admin` — Create API key for auth

## Code Style
- Python 3.11+, type hints everywhere
- Pydantic models for all data structures
- Async-first — orchestrator and agents are async
- `ruff` for linting and formatting (config in pyproject.toml)
- Frontend: TypeScript strict, Tailwind CSS, shadcn/ui components

## Architecture
- `src/argus/agents/` — 12 attack agent implementations (Phase 1-5)
- `src/argus/orchestrator/` — Agent orchestrator, signal bus
- `src/argus/correlation/` — Compound attack path detection (16 patterns)
- `src/argus/conductor/` — Conversation session management for agents
- `src/argus/survey/` — Endpoint discovery and surface classification
- `src/argus/models/` — Finding schema, agent configs, CerberusRule
- `src/argus/validation/` — Deterministic proof-of-exploitation engine
- `src/argus/scoring/` — VERDICT WEIGHT™ integration
- `src/argus/mcp_client/` — MCP protocol attack client
- `src/argus/sandbox/` — Isolated agent execution environments
- `src/argus/corpus/` — AI attack pattern database (12 domains)
- `src/argus/db/` — SQLAlchemy ORM, repositories, scan persistence
- `src/argus/web/` — FastAPI server, API routes, auth middleware
- `src/argus/reporting/` — HTML reports, CERBERUS rules, ALEC export
- `src/argus/prometheus/` — PROMETHEUS attack module framework
- `src/argus/test_harness/` — Mock vulnerable AI target for testing
- `argus-frontend/` — React 18 + TypeScript + Vite + Tailwind + shadcn/ui

## Testing
- All tests in `tests/` — 163 tests across Python 3.11/3.12/3.13
- Use `pytest-asyncio` for async tests
- Every finding must have validation tests
- CI: GitHub Actions — ruff lint, pip-audit, pytest (3 Python versions)

## Branch Strategy
- `main` — stable releases
- Feature branches: `devin/<timestamp>-<descriptive-slug>`

## Key Principles
- Every finding must have reproducible proof-of-exploitation
- Agents are short-lived with narrow scope — fresh context every time
- Non-destructive validation — never modify production data
- The attack corpus is the IP — grow it continuously
- SSRF protection on all URL inputs (targets, scans)
- Bearer token auth with RBAC (admin/operator/viewer)
