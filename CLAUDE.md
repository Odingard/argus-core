# ARGUS — Project Conventions

## What is ARGUS
Autonomous AI Red Team Platform by Odingard Security / Six Sense Enterprise Services.
Deploys 12 specialized offensive AI agents in parallel against target AI systems.

## Development Commands
- `make dev` — Install with dev dependencies
- `make test` — Run tests
- `make lint` — Run ruff linter
- `make format` — Auto-format code
- `make docker-test` — Run tests in Docker

## Code Style
- Python 3.11+, type hints everywhere
- Pydantic models for all data structures
- Async-first — orchestrator and agents are async
- `ruff` for linting and formatting (config in pyproject.toml)

## Architecture
- `src/argus/orchestrator/` — Agent orchestrator, signal bus
- `src/argus/models/` — Finding schema, agent configs
- `src/argus/validation/` — Deterministic proof-of-exploitation engine
- `src/argus/mcp_client/` — MCP protocol attack client
- `src/argus/sandbox/` — Isolated agent execution environments
- `src/argus/corpus/` — AI attack pattern database (the moat)
- `src/argus/agents/` — Attack agent implementations (Phase 1+)
- `src/argus/reporting/` — Report generation

## Testing
- All tests in `tests/`
- Use `pytest-asyncio` for async tests
- Every finding must have validation tests

## Branch Strategy
- `main` — stable releases
- `develop` — integration branch
- Feature branches: `feature/<name>`
- Agent branches: `agent/<agent-name>`

## Key Principles
- Every finding must have reproducible proof-of-exploitation
- Agents are short-lived with narrow scope — fresh context every time
- Non-destructive validation — never modify production data
- The attack corpus is the IP — grow it continuously
