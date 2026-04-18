# Testing ARGUS

## Prerequisites

- ARGUS backend running: `ARGUS_WEB_TOKEN=argus-test-token-2026 ARGUS_WEB_ALLOW_PRIVATE=1 argus serve --host 127.0.0.1 --port 8765`
- Mock target (optional): `argus test-target start --host 127.0.0.1 --port 9999`
- Browser open to `http://127.0.0.1:8765/?token=argus-test-token-2026`

## War Room Dashboard

- Settings page: click "Settings" in sidebar — shows LLM API Keys section with 4 provider cards
- Live Scan: enter target URL (e.g. `http://127.0.0.1:9999/chat`) and click Launch
- Findings: check findings are grouped by scan ID, not pooled
- Scan History: verify completed scans show with drill-down to findings

## LLM API Key Management

- Config file location: `~/.argus/argusrc` (NOT `~/.argusrc`)
- Keys stored under `[keys]` section in TOML format
- File permissions must be 0600
- Save: enter key in provider card → click Save → card turns green with masked key (last 4 chars)
- Remove: click Remove → card reverts to "Not configured"
- Toggle: eye icon toggles password/text visibility
- Test: "Test" button validates key against provider API

## CLI Scan Commands

```bash
# Basic scan
argus scan <label> --target <url>

# With auth token for target
argus scan <label> --target <url> --agent-api-key <token>

# Quiet mode (suppress HTTP probe noise)
argus -q scan <label> --target <url>

# With demo pacing
argus scan <label> --target <url> --demo-pace 1.0

# Rate-limited
argus scan <label> --target <url> --max-rpm 20

# FormData targets (e.g. Gandalf)
argus scan gandalf --target https://gandalf-api.lakera.ai/api/send-message --body-format formdata --prompt-field prompt --extra-field defender=baseline

# MCP server scanning
argus scan mcp-test --target <url> --mcp-url <mcp-server-url>

# View scan history
argus history list
argus history show <scan-id>
argus history report <scan-id> -o report.html
```

## Auth

- Dashboard login: Bearer token via `ARGUS_WEB_TOKEN` env var or `X-Argus-Token` header
- Test token: `argus-test-token-2026`
- API keys for LLM providers: stored in `~/.argus/argusrc` via Settings page
- Target auth: `--agent-api-key` CLI flag passes Bearer token to target endpoints

## Known Issues

- `test_identity_spoof_detects_baseline_403_to_spoofed_200` is a pre-existing flaky test on main
- SPA targets (React/Vue/Next.js) return HTML for all routes — ARGUS filters these via T1 HTML filter
- Targets behind CSRF protection need the T3 CSRF handler (Phase B)
- PyPI version may lag behind `main` — install from git for latest: `pip install git+https://github.com/Odingard/Argus.git@main`
