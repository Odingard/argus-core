# Contributing to ARGUS Core

Thanks for your interest — ARGUS is the open-source autonomous red
team for agentic AI systems, and the bar for contributions is "will
this help an operator find a real bug on a real target." We welcome
PRs that move toward that bar.

## Scope — what lands in core

| Land here (MIT, `src/argus/`) | Land in pro (source-available, `src/argus/pro/`) | Do not submit |
|---|---|---|
| New adapters for frameworks, MCP transports, or agent protocols | Multi-model consensus, MCTS exploit-chain planners, fleet-scale infra, HSM-backed Wilson | Live exploits against specific named services without the vendor's authorization |
| New heuristic detections in existing agents (Phase 1–9) | | Findings that bypass responsible-disclosure timelines |
| Test fixtures, labrat targets, documentation, bug fixes | | Anything that requires credentials / API keys hard-coded into the tree |
| CI and tooling improvements | | Changes that silently relax the determinism contract (see `docs/NO_CHEATING.md`) |

If you're unsure which tier a contribution belongs in, open an issue
first — faster than a round-trip on a rejected PR.

## Local dev setup

```bash
git clone https://github.com/Odingard/argus-core
cd argus-core
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install ruff pytest bandit detect-secrets pip-audit
```

Run the full check locally before pushing:

```bash
pytest --ignore=argus-targets -q       # 478 tests, ~2 min
ruff check src/ tests/
bandit -r src/argus -q
pip-audit --skip-editable
```

CI runs the same matrix on every push — green locally usually means
green on GitHub. The 5 skipped tests are intentionally-skipped
integration tests that require network or optional deps.

## Submission guidelines

- Target the `main` branch. Feature branches welcome; we rebase-merge.
- Keep PRs focused — one coherent change per PR. The MAAC phase
  coverage matrix in the README tells you which agent each file
  belongs to.
- Every new offensive heuristic must come with at least one test
  that proves it catches a real-shape weakness (not a hardcoded
  string match). See `tests/test_pillar_oauth_supply_chain_acceptance.py`
  for the acceptance pattern we use.
- Commit messages follow `type(scope): summary` (e.g.
  `feat(agent): EP-T11 adds IMDS reachability probe`). The repo
  history shows the conventions — match them.
- The `argus.pro.*` namespace is behind `argus.license.require()`.
  Every new PRO module must call `require("<feature>")` at import
  time so the license seam stays honest.

## Licensing and CLA

By contributing, you agree that your code is licensed under the MIT
license in `LICENSE-CORE` for anything under `src/argus/` (excluding
`src/argus/pro/`), and under the commercial license in `LICENSE-PRO`
for anything under `src/argus/pro/`.

We require a **Contributor License Agreement** for non-trivial
contributions. The CLA gives Odingard Security the right to relicense
your contribution if we change the underlying license in the future
(e.g., moving core from MIT to Apache-2.0). Without a signed CLA on
file we cannot relicense your commits, which is the main reason we
ask.

Small fixes (typos, one-line bug fixes, tests) do not require a CLA;
anything touching more than ~20 lines of production code does. A
maintainer will surface the CLA link on your first qualifying PR.

## Responsible-disclosure guardrail

ARGUS is offensive tooling. **Do not submit a PR that demonstrates a
live exploit against a specific named service**, even if the service
is in a public bug-bounty program. Agents should be generic — they
detect a *class* of weakness — and labrat fixtures simulate the
weakness in-tree. If you found a real bug, disclose it to the vendor
before sending us a PR that reproduces it.

See `docs/NO_CHEATING.md` and `SECURITY.md` for the longer form.
