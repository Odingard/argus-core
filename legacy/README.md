# `legacy/` — archived pre-spec code

On 2026-04-21 the ARGUS codebase was reconciled against the original
Build-folder spec (Foundation / Agent_Specs / Tech_Architecture /
Build_Roadmap / GTM_Playbook). The honest gap analysis showed that
**the pre-2026-04-21 implementation was a static source-code scanner**,
while the spec describes an **autonomous offensive platform that
attacks live AI deployments**. Different product.

See [PHASES.md](../PHASES.md) for the rebuild plan. Option B committed:
build the spec. This directory is kept for reference only — none of
it is imported by the live `src/argus/` tree.

## What's here

| Path | What it was | Why archived |
|---|---|---|
| `layer1/` | Python/JS/TS source scanner producing `Finding` objects | Wrong target — spec attacks running systems, not source |
| `layer2/` | Static trust-graph surface analyser | Wrong target |
| `layer3/` | Static payload fuzzer | Wrong target |
| `layer4/` | Static deviation detector (simulated behaviour) | Wrong target — spec requires *observed* behaviour delta |
| `layer5/` | Opus chain synthesiser built on static inputs | Wrong inputs (receives static findings; spec receives runtime findings) |
| `layer7/sandbox.py` | Docker PoC runner that `pip install`-ed the target and ran a synth PoC | Wrong target shape (pip-installed library ≠ running AI deployment) |
| `agents/*.py` (12 files) | Source-code pattern scanners wearing offensive-agent names | Implementations are source scanners; the MAAC taxonomy and agent interface survive in `src/argus/agents/base.py` and will be rebuilt against the Phase 0 Target Adapter |

## Useful helpers promoted out of `legacy/`

Three helpers from the old `layer7/sandbox.py` remain live-relevant (they
validate PoC structure regardless of where the PoC runs):

    target_packages(repo_path)       → src/argus/validation/poc_gates.py
    poc_imports_target(code, pkgs)   → src/argus/validation/poc_gates.py
    poc_calls_target(code, pkgs)     → src/argus/validation/poc_gates.py

The rest of `layer7/sandbox.py` (Docker orchestration for PoC exec) is
archived.

## Rehabilitating any of this

Do not import from `legacy/`. If a piece becomes relevant again, copy it
back into `src/argus/` with a clear rationale and a PHASES.md reference.
The rule is one-way: archive → source is a deliberate decision, never
an accident.
