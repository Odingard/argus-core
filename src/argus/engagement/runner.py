"""
argus/engagement/runner.py — generic engagement runner.

One target URL → one artifact package, regardless of whether the
target is a labrat, a live MCP server, or an HTTP agent endpoint.
This is the flagship ``argus engage`` verb's engine.

Pipeline (identical shape to the packaged demos — the demos are
thin wrappers around this now):

    1. Resolve URL → TargetSpec via engagement.registry
    2. Enumerate surfaces
    3. Fire the target-declared agent slate (or full roster)
    4. Deterministic evidence replay
    5. CompoundChain v2 synthesis
    6. BlastRadiusMap (Phase 9 Impact Optimizer)
    7. CERBERUS rules + ALEC envelope (Phase 4 stubs)
    8. Raptor Cycle — promote landed payloads into corpus
    9. Persist SUMMARY.txt + findings/ + evidence/ + chain.json +
       impact.json + cerberus/ + wilson_bundle/ + alec_envelope.json
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from argus.adapter.base import Request
from argus.agents.base import AgentFinding
from argus.alec import build_envelope, write_envelope
from argus.cerberus import generate_rules, write_rules
from argus.corpus_attacks import EvolveCorpus
from argus.engagement.registry import TargetSpec, target_for_url
from argus.evidence import EvidenceCollector, attach_evidence
from argus.evidence.oob import OOBListener
from argus.impact import optimize_impact
from argus.swarm.chain_synthesis_v2 import synthesize_compound_chain


BOLD  = "\033[1m"
RED   = "\033[91m"
AMBER = "\033[93m"
BLUE  = "\033[94m"
GREEN = "\033[92m"
GRAY  = "\033[90m"
RESET = "\033[0m"


# ── Agent roster dispatch ──────────────────────────────────────────────────

def _run_agent(agent_id: str, *, factory, output_dir: Path,
               target_id: str, ev_corpus: EvolveCorpus) -> list:
    """One-call per-agent runner. Returns the agent's findings. Keeps
    all the per-agent argument-dispatch logic in one place."""

    if agent_id == "SC-09":
        from argus.agents.agent_09_supply_chain import SupplyChainAgent
        return asyncio.run(SupplyChainAgent(
            adapter_factory=factory, evolve_corpus=ev_corpus,
        ).run_async(
            target_id=target_id,
            output_dir=str(output_dir / "sc-09"),
        ))

    if agent_id == "TP-02":
        from argus.agents.agent_02_tool_poisoning import ToolPoisoningAgent
        return asyncio.run(ToolPoisoningAgent(
            adapter_factory=factory, evolve_corpus=ev_corpus,
        ).run_async(
            target_id=target_id,
            output_dir=str(output_dir / "tp-02"),
        ))

    if agent_id == "PI-01":
        from argus.agents.agent_01_prompt_injection import (
            PromptInjectionHunter,
        )
        return asyncio.run(PromptInjectionHunter(
            adapter_factory=factory, evolve_corpus=ev_corpus,
        ).run_async(
            target_id=target_id,
            output_dir=str(output_dir / "pi-01"),
            category="instruction_override",
            surface=_pick_chat_surface(factory),
            sample_n=8, sample_seed=3,
        ))

    if agent_id == "ME-10":
        from argus.agents.agent_10_model_extraction import (
            ModelExtractionAgent,
        )
        return asyncio.run(ModelExtractionAgent(
            adapter_factory=factory, evolve_corpus=ev_corpus,
        ).run_async(
            target_id=target_id,
            output_dir=str(output_dir / "me-10"),
            surface=_pick_chat_surface(factory),
        ))

    if agent_id == "MP-03":
        from argus.agents.agent_03_memory_poisoning import (
            MemoryPoisoningAgent,
        )
        return asyncio.run(MemoryPoisoningAgent(
            adapter_factory=factory, evolve_corpus=ev_corpus,
            retrieval_probes=("Who is the administrator here?",),
        ).run_async(
            target_id=target_id,
            output_dir=str(output_dir / "mp-03"),
            surface=_pick_chat_surface(factory),
            sample_n=1, sample_seed=5,
        ))

    if agent_id == "IS-04":
        from argus.agents.agent_04_identity_spoof import (
            IdentitySpoofAgent,
        )
        return asyncio.run(IdentitySpoofAgent(
            adapter_factory=factory, evolve_corpus=ev_corpus,
        ).run_async(
            target_id=target_id,
            output_dir=str(output_dir / "is-04"),
        ))

    if agent_id == "XE-06":
        from argus.agents.agent_06_cross_agent_exfil import (
            CrossAgentExfiltrationAgent,
        )
        return asyncio.run(CrossAgentExfiltrationAgent(
            adapter_factory=factory, evolve_corpus=ev_corpus,
        ).run_async(
            target_id=target_id,
            output_dir=str(output_dir / "xe-06"),
        ))

    if agent_id == "PE-07":
        from argus.agents.agent_07_privilege_escalation import (
            PrivilegeEscalationAgent,
        )
        return asyncio.run(PrivilegeEscalationAgent(
            adapter_factory=factory, evolve_corpus=ev_corpus,
        ).run_async(
            target_id=target_id,
            output_dir=str(output_dir / "pe-07"),
        ))

    if agent_id == "EP-11":
        from argus.agents.agent_11_environment_pivot import (
            EnvironmentPivotAgent,
        )
        return asyncio.run(EnvironmentPivotAgent(
            adapter_factory=factory, evolve_corpus=ev_corpus,
        ).run_async(
            target_id=target_id,
            output_dir=str(output_dir / "ep-11"),
        ))

    if agent_id == "CW-05":
        from argus.agents.agent_05_context_window import ContextWindowAgent
        return asyncio.run(ContextWindowAgent(
            adapter_factory=factory, evolve_corpus=ev_corpus,
        ).run_async(
            target_id=target_id,
            output_dir=str(output_dir / "cw-05"),
            surface=_pick_chat_surface(factory),
        ))

    if agent_id == "RC-08":
        from argus.agents.agent_08_race_condition import RaceConditionAgent
        return asyncio.run(RaceConditionAgent(
            adapter_factory=factory, evolve_corpus=ev_corpus,
            techniques=["RC-T1-parallel-burst"], burst_n=8,
        ).run_async(
            target_id=target_id,
            output_dir=str(output_dir / "rc-08"),
        ))

    raise ValueError(f"unknown agent_id: {agent_id}")


def _pick_chat_surface(factory) -> str:
    """Best-effort: pick the first chat:* surface the target exposes,
    fall back to ``chat``. Runs a throw-away enumeration — cheap."""
    try:
        adapter = factory("")
        async def go():
            async with adapter:
                surfaces = await adapter.enumerate()
            for s in surfaces:
                if s.name.startswith("chat:"):
                    return s.name
                if s.name == "chat":
                    return "chat"
            return "chat"
        return asyncio.run(go())
    except Exception:
        return "chat"


# ── Config + result ─────────────────────────────────────────────────────────

@dataclass
class EngagementConfig:
    target_url:   str
    output_dir:   Path
    verbose:      bool = False
    clean:        bool = False
    agent_slate:  Optional[tuple[str, ...]] = None   # override TargetSpec

    def resolve_target(self) -> TargetSpec:
        spec = target_for_url(self.target_url)
        if spec is None:
            raise ValueError(
                f"no target registered for {self.target_url!r}. "
                f"Known schemes: see argus.engagement.list_targets()"
            )
        return spec


def _sequential_slate(slate, kwargs):
    """Yield (agent_id, findings, error) tuples running the slate
    serially. Preserves slate order — deterministic, used for the
    ARGUS_SEQUENTIAL=1 test-mode path."""
    for agent_id in slate:
        try:
            agent_findings = _run_agent(agent_id, **kwargs)
        except Exception as e:
            yield agent_id, [], e
            continue
        yield agent_id, agent_findings, None


def _parallel_slate(slate, kwargs, workers: int):
    """Yield (agent_id, findings, error) tuples as agents complete
    in a ThreadPoolExecutor. Each agent's internal asyncio loop
    lives inside its own worker thread. Yield order is completion-
    order (not slate-order) — caller doesn't assume ordering.

    Rationale for threads-over-asyncio.gather: every agent's
    ``_run_agent`` entry already wraps ``asyncio.run`` around its
    own ``run_async``. Using a pool keeps the per-agent change
    surface at zero — we just parallelise the outer loop. An
    asyncio.gather refactor would require unwinding 11 nested
    ``asyncio.run`` calls, ~100 LOC of churn for equivalent
    concurrency on an I/O-bound workload."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    max_workers = max(1, min(workers, len(slate)))
    with ThreadPoolExecutor(
        max_workers=max_workers,
        thread_name_prefix="argus-slate",
    ) as pool:
        future_to_id = {
            pool.submit(_run_agent, aid, **kwargs): aid
            for aid in slate
        }
        for fut in as_completed(future_to_id):
            aid = future_to_id[fut]
            try:
                agent_findings = fut.result()
            except Exception as e:
                yield aid, [], e
                continue
            yield aid, agent_findings, None


def _build_reachability_map(
    *,
    target_id: str,
    spec: TargetSpec,
    surface_counts: dict[str, int],
    findings: list,
    by_agent: dict[str, int],
    oob_callbacks: list | None,
) -> dict:
    """Perimeter-First Rule 3 — every engagement report includes a
    Reachability Map from a public entry point.

    The map names:
      - the unauthenticated perimeter we started from (target URL +
        scheme + description),
      - the surface classes exposed at that perimeter (enumerated
        before any attack fires),
      - the interior sinks ARGUS actually landed on (findings carry
        a surface; we project them by class),
      - which agents produced landings (slate → outcome),
      - whether any OOB callback fired (deterministic proof that an
        internal component reached back out).

    Consumers: SUMMARY.txt, reachability.json artifact, and the
    Wilson bundle. Purely a report artifact; no side effects on the
    findings themselves."""
    sinks_reached: dict[str, int] = {}
    for f in findings:
        surface = getattr(f, "surface", None) or "—"
        klass = surface.split(":", 1)[0] if ":" in surface else surface
        sinks_reached[klass] = sinks_reached.get(klass, 0) + 1
    landing_agents = sorted(a for a, n in by_agent.items() if n > 0)
    silent_agents  = sorted(a for a, n in by_agent.items() if n == 0)
    oob_count = len(oob_callbacks) if oob_callbacks else 0
    return {
        "public_entry_point": {
            "target_url":  target_id,
            "scheme":      spec.scheme,
            "description": spec.description or "",
        },
        "surfaces_exposed":   dict(surface_counts),
        "sinks_reached":      sinks_reached,
        "landing_agents":     landing_agents,
        "silent_agents":      silent_agents,
        "oob_callback_count": oob_count,
        "oob_proof":          oob_count > 0,
    }


def _run_reasoning_audit(*, chain, artifact_root: str):
    """Pillar-3 reasoning auditor wired into the engagement.

    Extracts free-text premises from the chain (preconditions,
    step actions, step payloads) and verifies each by searching the
    artifact root — which after Phase 4 contains every finding's
    JSON with raw_response + observed_behavior. A premise whose
    claim text is grounded in the captured evidence is VERIFIED;
    otherwise UNVERIFIED or NO_PATTERN.

    This makes the "Pillar 3 — defence against AI-slop" claim
    operational: chains whose premises aren't grounded get an
    honest verified_ratio that can flow into the Wilson bundle and
    the operator's trust calculus."""
    try:
        from argus.audit.reasoning import (
            audit_chain_premises, extract_premises_from_chain,
        )
    except Exception:
        from argus.audit.reasoning import ReasoningAudit
        return ReasoningAudit()
    premises = extract_premises_from_chain(chain.to_dict())
    return audit_chain_premises(premises, artifact_root)


@dataclass
class EngagementResult:
    target_url:     str
    target_scheme:  str
    findings:       list[AgentFinding] = field(default_factory=list)
    by_agent:       dict[str, int]     = field(default_factory=dict)
    chain:          dict = field(default_factory=dict)
    impact:         dict = field(default_factory=dict)
    envelope_id:    str = ""
    artifact_root:  str = ""
    # Populated only when ARGUS_DIAGNOSTICS=1 is set. Summary of
    # the outer-loop classification written to diagnostic_priors.json
    # alongside the engagement artifacts. None when the flag is off.
    diagnostic:     Optional[dict] = None
    # Perimeter-First Rule 3 — Reachability Map projected from the
    # public entry point to the interior sinks ARGUS actually
    # reached. Always populated (empty when zero findings).
    reachability:   dict = field(default_factory=dict)
    # Count of OOB callbacks the per-engagement listener captured.
    # Zero when no agent embedded the listener URL or the target
    # never reached back out.
    oob_callbacks:  int  = 0

    def to_dict(self) -> dict:
        return {
            "target_url":    self.target_url,
            "target_scheme": self.target_scheme,
            "finding_count": len(self.findings),
            "by_agent":      dict(self.by_agent),
            "chain":         self.chain,
            "impact":        self.impact,
            "envelope_id":   self.envelope_id,
            "artifact_root": self.artifact_root,
            "diagnostic":    self.diagnostic,
            "reachability":  dict(self.reachability),
            "oob_callbacks": self.oob_callbacks,
        }


# ── Pretty-print ────────────────────────────────────────────────────────────

def _section(step: int, title: str) -> None:
    print()
    print(f"{BOLD}{BLUE}━━ Step {step} — {title} {RESET}")


def _ok(msg: str) -> None:
    print(f"   {GREEN}✓{RESET} {msg}")


def _note(msg: str) -> None:
    print(f"   {GRAY}·{RESET} {GRAY}{msg}{RESET}")


def _alert(msg: str) -> None:
    print(f"   {RED}!{RESET} {BOLD}{msg}{RESET}")


# ── Output layout ───────────────────────────────────────────────────────────

@dataclass
class _Paths:
    root:     Path
    findings: Path
    evidence: Path
    chain:    Path
    impact:   Path
    cerberus: Path
    alec:     Path
    summary:  Path

    @classmethod
    def under(cls, root: str | Path) -> "_Paths":
        r = Path(root).resolve()
        return cls(
            root=r, findings=r / "findings", evidence=r / "evidence",
            chain=r / "chain.json", impact=r / "impact.json",
            cerberus=r / "cerberus", alec=r / "alec_envelope.json",
            summary=r / "SUMMARY.txt",
        )

    def ensure(self) -> None:
        for d in (self.root, self.findings, self.evidence, self.cerberus):
            d.mkdir(parents=True, exist_ok=True)


# ── Runner ─────────────────────────────────────────────────────────────────

class EngagementRunner:
    """Generic engagement runner. The packaged demos are thin shims
    around this class."""

    def __init__(self, config: EngagementConfig) -> None:
        self.config = config
        self.paths  = _Paths.under(config.output_dir)
        if config.clean and self.paths.root.exists():
            shutil.rmtree(self.paths.root)
        self.paths.ensure()

    def run(self) -> EngagementResult:
        spec = self.config.resolve_target()
        target_id = self.config.target_url

        def factory(url: str = target_id):
            return spec.factory(url)

        print()
        print(f"{BOLD}ARGUS engagement — {spec.scheme}://…{RESET}")
        print(f"{GRAY}Target: {target_id}  |  "
              f"Output: {self.paths.root}{RESET}")
        if spec.description:
            print(f"{GRAY}Target class: {spec.description}{RESET}")

        # ── 1) Enumerate ────────────────────────────────────────
        _section(1, "Target enumeration")
        counts = asyncio.run(self._enumerate(factory))
        for kind, n in sorted(counts.items()):
            _ok(f"{kind:<8} surfaces: {n}")

        # ── 1b) OOB listener ────────────────────────────────────
        # Tier-3 AUDITOR doctrine: a finding is only 'Critical' if
        # it triggers an OOB callback. Start a loopback listener
        # once per engagement and expose its callback URL via env
        # var so agents (or mutators) can embed it in payloads.
        # Disabled with ARGUS_NO_OOB=1 for deterministic test runs
        # or environments where binding a loopback port is blocked.
        listener: Optional[OOBListener] = None
        prev_oob_url = os.environ.get("ARGUS_OOB_CALLBACK_URL")
        if os.environ.get("ARGUS_NO_OOB", "0") != "1":
            try:
                listener = OOBListener().start()
                os.environ["ARGUS_OOB_CALLBACK_URL"] = listener.callback_url
                _ok(f"OOB listener → {listener.callback_url}")
            except Exception as e:
                if self.config.verbose:
                    print(f"     [oob] listener failed (non-fatal): "
                          f"{type(e).__name__}: {e}")
                listener = None

        # ── 2) Fire agent slate (parallel by default) ───────────
        # The slate runs concurrently via a ThreadPoolExecutor —
        # each agent's internal asyncio loop lives inside its own
        # thread. Default 4-way concurrency caps simultaneous LLM
        # calls so we don't saturate Anthropic's per-minute quotas;
        # ARGUS_ENGAGEMENT_WORKERS=N overrides. Setting
        # ARGUS_SEQUENTIAL=1 falls back to the serial loop (useful
        # for deterministic test runs and debugging).
        _section(2, "Agent slate")
        slate = tuple(self.config.agent_slate or spec.agent_selection)
        ev_corpus = EvolveCorpus(
            discovered_dir=str(self.paths.root / "discovered"),
        )
        findings: list[AgentFinding] = []
        by_agent: dict[str, int] = {}

        _agent_kwargs = dict(
            factory=factory,
            output_dir=self.paths.findings,
            target_id=target_id,
            ev_corpus=ev_corpus,
        )

        if os.environ.get("ARGUS_SEQUENTIAL", "0") == "1":
            iterator = _sequential_slate(slate, _agent_kwargs)
        else:
            workers = int(os.environ.get(
                "ARGUS_ENGAGEMENT_WORKERS", "4",
            ))
            iterator = _parallel_slate(slate, _agent_kwargs, workers)

        for agent_id, agent_findings, error in iterator:
            if error is not None:
                if self.config.verbose:
                    print(
                        f"     [{agent_id}] error: "
                        f"{type(error).__name__}: {error}"
                    )
                continue
            by_agent[agent_id] = len(agent_findings)
            findings.extend(agent_findings)
            (_ok if agent_findings else _note)(
                f"{agent_id:<6} produced {len(agent_findings)} finding(s)"
                + ("" if agent_findings
                   else " (silent — surface class absent or hardened)")
            )

        # ── 2b) Drain OOB listener ──────────────────────────────
        # Stop the listener and pull any callbacks it captured
        # during the slate. Callbacks survive past the listener's
        # lifetime because drain() snapshots them first.
        oob_records: list = []
        if listener is not None:
            try:
                oob_records = listener.drain()
            finally:
                listener.stop()
                # Restore prior env state so consecutive engagements
                # in the same process don't inherit a stale URL.
                if prev_oob_url is None:
                    os.environ.pop("ARGUS_OOB_CALLBACK_URL", None)
                else:
                    os.environ["ARGUS_OOB_CALLBACK_URL"] = prev_oob_url
            if oob_records:
                _ok(f"OOB receipts captured: {len(oob_records)}")
                # Stamp findings' observed_behavior with a deterministic
                # receipt marker so the calibrator's AUDITOR gate
                # (sub-pass 2b) recognises the evidence and preserves
                # CRITICAL severity. Conservative: only attach to
                # findings whose current severity is CRITICAL so we
                # don't inflate HIGH→CRITICAL for unrelated findings.
                for f in findings:
                    if getattr(f, "severity", "") != "CRITICAL":
                        continue
                    marker = (
                        f"[oob:receipt n={len(oob_records)} "
                        f"src={oob_records[0].source_ip}]"
                    )
                    obs = getattr(f, "observed_behavior", "") or ""
                    if "[oob:receipt" not in obs:
                        f.observed_behavior = (marker + " " + obs).strip()

        if not findings:
            # Still write a minimal reachability map so the zero-
            # finding report honours Perimeter-First Rule 3.
            reach = _build_reachability_map(
                target_id=target_id, spec=spec,
                surface_counts=counts, findings=[], by_agent={},
                oob_callbacks=oob_records,
            )
            (self.paths.root / "reachability.json").write_text(
                json.dumps(reach, indent=2), encoding="utf-8",
            )
            _alert("Zero findings produced; target appears hardened.")
            empty = self._empty_result(spec)
            empty.reachability = reach
            empty.oob_callbacks = len(oob_records)
            return empty

        # ── 3) Deterministic evidence ───────────────────────────
        _section(3, "Deterministic evidence replay")
        evidence = asyncio.run(
            self._replay_evidence(factory, findings, oob_records),
        )
        evidence.write(self.paths.evidence)
        _ok(f"Evidence {evidence.evidence_id} — "
            f"pcap={len(evidence.pcap)} hops, "
            f"integrity_sha={evidence.integrity_sha[:16]}…")
        # Attach to one finding so the chain carries a proof-grade ref.
        for f in findings:
            if f.surface:
                attach_evidence(f, evidence)
                break

        # ── 4) Chain synthesis v2 ───────────────────────────────
        _section(4, "CompoundChain v2")
        chain = synthesize_compound_chain(findings, target_id=target_id)
        if chain is None:
            _alert("Chain synthesis returned None (need ≥2 findings)")
            return self._empty_result(spec)
        self.paths.chain.write_text(
            json.dumps(chain.to_dict(), indent=2), encoding="utf-8",
        )
        _ok(f"Chain {chain.chain_id} — {len(chain.steps)} steps, "
            f"severity {chain.severity}, "
            f"OWASP {', '.join(sorted(set(chain.owasp_categories)))}")

        # ── 4b) Reasoning audit (Pillar-3) ──────────────────────
        # Extract the chain's free-text premises and verify each
        # against the artifact root (findings + raw responses). A
        # chain whose premises can't be grounded is flagged so the
        # Wilson bundle carries the verified_ratio and the operator
        # sees which claims rest on evidence vs LLM narrative.
        reasoning_audit = _run_reasoning_audit(
            chain=chain,
            artifact_root=str(self.paths.root),
        )
        (self.paths.root / "reasoning_audit.json").write_text(
            json.dumps(reasoning_audit.to_dict(), indent=2),
            encoding="utf-8",
        )
        if reasoning_audit.total_count:
            _ok(
                f"reasoning audit: "
                f"{reasoning_audit.verified_count}/"
                f"{reasoning_audit.total_count} premises verified "
                f"({reasoning_audit.verified_ratio:.0%})"
            )
            if reasoning_audit.verified_ratio < 0.5:
                _alert(
                    "Fewer than half of chain premises grounded "
                    "in evidence — treat conclusions with caution."
                )

        # ── 5) Impact ───────────────────────────────────────────
        _section(5, "Phase 9 Impact Optimizer")
        brm = optimize_impact(
            chain=chain, findings=findings, evidences=[evidence],
        )
        self.paths.impact.write_text(
            json.dumps(brm.to_dict(), indent=2), encoding="utf-8",
        )
        _ok(f"harm_score={brm.harm_score}  "
            f"severity_label={brm.severity_label}")
        if brm.regulatory_impact:
            _alert(f"Regulatory exposure: "
                   f"{', '.join(brm.regulatory_impact)}")

        # ── 6) CERBERUS + ALEC ──────────────────────────────────
        _section(6, "CERBERUS + ALEC")
        rules = generate_rules(findings)
        rules_path = write_rules(rules, self.paths.cerberus)
        _ok(f"CERBERUS: {len(rules)} rule(s)")
        bundle_dir = self.paths.root / "wilson_bundle"
        self._assemble_bundle(
            bundle_dir=bundle_dir, target_id=target_id,
            chain=chain, findings=findings, evidence=evidence,
            brm=brm, rules_path=rules_path,
        )
        envelope = build_envelope(bundle_dir, target_id=target_id)
        write_envelope(envelope, self.paths.root,
                       filename="alec_envelope.json")
        _ok(f"ALEC envelope {envelope.envelope_id}")

        # ── 6b) Reachability Map (Perimeter-First Rule 3) ──────
        reachability = _build_reachability_map(
            target_id=target_id, spec=spec,
            surface_counts=counts, findings=findings,
            by_agent=by_agent, oob_callbacks=oob_records,
        )
        (self.paths.root / "reachability.json").write_text(
            json.dumps(reachability, indent=2), encoding="utf-8",
        )
        _ok(
            f"Reachability: {len(reachability['sinks_reached'])} "
            f"sink class(es) reached; oob_proof="
            f"{str(reachability['oob_proof']).lower()}"
        )

        # ── 7) SUMMARY + headline ───────────────────────────────
        self._write_summary(
            spec=spec, chain=chain, brm=brm, envelope=envelope,
            findings=findings, by_agent=by_agent,
            rules=rules, evidence=evidence,
            reachability=reachability,
        )
        _ok(f"SUMMARY → {self.paths.summary}")
        dc  = ",".join(sorted(brm.data_classes_exposed)) or "—"
        reg = ",".join(brm.regulatory_impact) or "—"
        print()
        print(f"{BOLD}{RED}→ {brm.severity_label}{RESET}: "
              f"{len(chain.steps)}-step chain on {target_id} "
              f"(harm_score={brm.harm_score}, data={dc}, reg={reg})")
        print()

        # ── 8) Diagnostic outer loop (ARGUS_DIAGNOSTICS=1) ──────
        # Classifies every agent in the slate that produced zero
        # findings into a SilenceCause tag and writes a priors
        # file for the next run. Gated by env flag so default
        # behaviour is unchanged; any failure is non-fatal.
        diagnostic_info: Optional[dict] = None
        if os.environ.get("ARGUS_DIAGNOSTICS", "0") == "1":
            try:
                diagnostic_info = self._run_diagnostic_pass(
                    slate=slate,
                    by_agent=by_agent,
                    findings=findings,
                    target_id=target_id,
                )
            except Exception as e:
                if self.config.verbose:
                    print(f"     [diagnostic] pass failed "
                          f"(non-fatal): {type(e).__name__}: {e}")

        # ── 9) Cross-run target-class memory ingest ─────────────
        # Append this run's priors (if written) to the per-class
        # bucket so baselines accumulate. After ≥3 runs per class,
        # the next engagement's calibrator auto-suppresses class-
        # typical patterns. Gated by the same diagnostic flag;
        # no-op when the diagnostic pass didn't run.
        if (os.environ.get("ARGUS_DIAGNOSTICS", "0") == "1"
                and diagnostic_info is not None):
            try:
                from argus.memory import TargetClassMemory
                mem_root = os.environ.get(
                    "ARGUS_MEMORY_ROOT",
                    str(Path.home() / ".argus" / "target_class_memory"),
                )
                mem = TargetClassMemory(root=mem_root)
                # Reuse the tool catalog the runner already enumerated
                # for a fast in-memory classify_target call — avoids
                # re-hitting the adapter.
                tool_catalog = [
                    {"name": name} for name in counts.keys()
                ]
                klass = mem.ingest_run(
                    run_dir=str(self.paths.root),
                    tool_catalog=tool_catalog,
                    target_url=target_id,
                )
                if klass is not None and self.config.verbose:
                    print(
                        f"     [memory] target classified as "
                        f"{klass.value}; baseline now covers "
                        f"{mem.baseline_for(klass).total_runs} run(s)"
                    )
            except Exception as e:
                if self.config.verbose:
                    print(f"     [memory] ingest failed "
                          f"(non-fatal): {type(e).__name__}: {e}")

        return EngagementResult(
            target_url=target_id,
            target_scheme=spec.scheme,
            findings=findings,
            by_agent=by_agent,
            chain=chain.to_dict(),
            impact=brm.to_dict(),
            envelope_id=envelope.envelope_id,
            artifact_root=str(self.paths.root),
            diagnostic=diagnostic_info,
            reachability=reachability,
            oob_callbacks=len(oob_records),
        )

    def _run_diagnostic_pass(
        self,
        *,
        slate: tuple[str, ...],
        by_agent: dict[str, int],  # noqa: ARG002 — symmetry for future use
        findings: list,
        target_id: str,
    ) -> Optional[dict]:
        """Build a classifier over the agent slate, feed per-agent
        log text from findings, write priors file + corpus seeds.

        This is the ACTUAL wiring point for the outer loop — the
        engagement runner knows which agents ran, which produced
        findings, and has all the evidence in hand. The flag-gated
        pass here means every `argus <target>` / `argus --engage`
        run can opt into the feedback loop with one env var."""
        from argus.diagnostics import (
            SilenceClassifier, dict_log_loader,
            write_diagnostic_feedback,
        )
        registry = {aid: None for aid in slate}
        # Aggregate per-agent finding text as the log blob the
        # classifier pattern-matches on.
        logs: dict[str, str] = {aid: "" for aid in slate}
        for f in findings:
            aid = getattr(f, "agent_id", None)
            if not aid or aid not in logs:
                continue
            parts = [logs[aid]] if logs[aid] else []
            parts.append(f"title: {getattr(f, 'title', '') or ''}")
            parts.append(
                f"observed: {getattr(f, 'observed_behavior', '') or ''}"
            )
            parts.append(
                f"raw: {(getattr(f, 'raw_response', '') or '')[:500]}"
            )
            logs[aid] = "\n".join(parts)

        # Adapter shim: classifier expects swarm_result["findings"]
        # with agent_id-bearing records; AgentFinding already has it.
        classifier = SilenceClassifier(registry=registry)
        diag = classifier.classify_run(
            swarm_result={"findings": findings},
            log_loader=dict_log_loader(logs),
            target=target_id,
            run_id=self.paths.root.name,
        )
        # EvolveCorpus is already constructed earlier in .run(); we
        # could thread it through, but for simplicity skip the corpus
        # side-effect in this pass. Priors file is the primary output.
        fb = write_diagnostic_feedback(
            diag, str(self.paths.root), evolver=None,
        )
        _ok(
            f"diagnostic: {diag.silent_count}/{diag.total_agents} "
            f"agents silent; priors → "
            f"{Path(fb['priors_path']).name}"
        )
        return {
            "run_id":           diag.run_id,
            "silent_count":     diag.silent_count,
            "productive_count": diag.productive_count,
            "aggregate_causes": dict(diag.aggregate_causes),
            "priors_path":      fb["priors_path"],
        }

    # ── Helpers ─────────────────────────────────────────────────────

    async def _enumerate(self, factory) -> dict[str, int]:
        adapter = factory()
        async with adapter:
            surfaces = await adapter.enumerate()
        out: dict[str, int] = {}
        for s in surfaces:
            prefix = s.name.split(":", 1)[0] if ":" in s.name else s.kind
            out[prefix] = out.get(prefix, 0) + 1
        return out

    async def _replay_evidence(self, factory, findings, oob_records=None):
        """Replay the first finding's surface with a benign payload to
        capture pcap + container_logs → proof-grade evidence.

        ``oob_records`` — callbacks captured by the engagement's OOB
        listener during the slate. Attached to the sealed evidence so
        the proof-grade envelope carries the receipt the AUDITOR
        doctrine requires for CRITICAL findings."""
        target_finding = next(
            (f for f in findings if f.surface), findings[0] if findings else None,
        )
        surface = (target_finding.surface if target_finding
                   and target_finding.surface else "chat")
        adapter = factory()
        await adapter.connect()
        try:
            with EvidenceCollector(
                target_id=self.config.target_url,
                session_id=f"engage_replay_{uuid.uuid4().hex[:8]}",
            ) as ec:
                # Deliberately benign payload — evidence proves the
                # probe happened, not that a malicious action ran.
                payload = {"identity": "user:guest"}
                req = Request(surface=surface, payload=payload)
                ec.record_request(surface=req.surface,
                                  request_id=req.id, payload=req.payload)
                obs = await adapter.interact(req)
                ec.record_response(surface=req.surface,
                                   request_id=req.id,
                                   payload=obs.response.body)
                ec.attach_container_logs(
                    f"[engage] probe {surface!r} replayed; "
                    f"response_len={len(str(obs.response.body or ''))}"
                )
                if oob_records:
                    ec.attach_oob_callbacks(oob_records)
            return ec.seal()
        finally:
            await adapter.disconnect()

    def _assemble_bundle(
        self, *, bundle_dir: Path, target_id: str,
        chain, findings, evidence, brm, rules_path,
    ) -> None:
        bundle_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "bundle_id":          f"engage-{chain.chain_id[:10]}",
            "target_id":          target_id,
            "compound_chain":     chain.to_dict(),
            "impact":             brm.to_dict(),
            "evidence_id":        evidence.evidence_id,
            "evidence_integrity": evidence.integrity_sha,
            "findings": [
                {
                    **f.to_dict(),
                    "owasp_id": next(
                        (s.owasp_id for s in chain.steps
                         if s.finding_id == f.id),
                        "AAI00",
                    ),
                }
                for f in findings
            ],
        }
        (bundle_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8",
        )
        evidence.write(bundle_dir)
        (bundle_dir / "cerberus_rules.json").write_bytes(
            rules_path.read_bytes(),
        )

    def _write_summary(
        self, *, spec, chain, brm, envelope,
        findings, by_agent, rules, evidence,
        reachability: Optional[dict] = None,
    ) -> None:
        lines: list[str] = []
        lines.append("ARGUS engagement — artifact package")
        lines.append("=" * 60)
        lines.append(f"Target URL   : {self.config.target_url}")
        lines.append(f"Target class : {spec.description}")
        lines.append(f"Chain id     : {chain.chain_id}")
        lines.append(f"Draft CVE    : {chain.cve_draft_id}")
        lines.append(f"Envelope id  : {envelope.envelope_id}")
        lines.append(f"Evidence id  : {evidence.evidence_id}")
        lines.append("")
        lines.append("Per-agent landings")
        for aid in sorted(by_agent):
            lines.append(f"  {aid:<6} : {by_agent[aid]} finding(s)")
        lines.append(f"  TOTAL  : {len(findings)} finding(s)")
        lines.append(f"  CERBERUS rules : {len(rules)}")
        lines.append("")
        lines.append("Severity")
        lines.append(f"  chain.severity : {chain.severity}")
        lines.append(f"  chain.blast    : {chain.blast_radius}")
        lines.append(f"  harm_score     : {brm.harm_score} / 100")
        lines.append(f"  severity_label : {brm.severity_label}")
        if brm.data_classes_exposed:
            lines.append(f"  data_classes   : "
                         f"{', '.join(sorted(brm.data_classes_exposed))}")
        if brm.regulatory_impact:
            lines.append(f"  regulatory     : "
                         f"{', '.join(brm.regulatory_impact)}")
        lines.append("")
        if reachability:
            lines.append("Perimeter reachability map")
            lines.append(
                f"  entry point   : {reachability['public_entry_point']['target_url']}"
            )
            exposed = reachability.get("surfaces_exposed") or {}
            if exposed:
                lines.append(
                    "  exposed       : "
                    + ", ".join(f"{k}×{v}" for k, v in sorted(exposed.items()))
                )
            reached = reachability.get("sinks_reached") or {}
            if reached:
                lines.append(
                    "  reached       : "
                    + ", ".join(f"{k}×{v}" for k, v in sorted(reached.items()))
                )
            landing = reachability.get("landing_agents") or []
            if landing:
                lines.append(
                    "  landing agents: " + ", ".join(landing)
                )
            lines.append(
                f"  oob_proof     : "
                f"{str(reachability.get('oob_proof', False)).lower()} "
                f"(receipts={reachability.get('oob_callback_count', 0)})"
            )
            lines.append("")
        lines.append("Kill-chain steps (MAAC-ordered)")
        for s in chain.steps[:25]:
            lines.append(
                f"  [{s.step:>2}] {s.owasp_id}/{s.vuln_class:<22} "
                f"{s.technique:<40} on {s.surface}"
            )
        if len(chain.steps) > 25:
            lines.append(f"  ... and {len(chain.steps) - 25} more step(s)")
        lines.append("")
        lines.append(brm.max_harm_scenario)
        self.paths.summary.write_text("\n".join(lines) + "\n",
                                      encoding="utf-8")

    def _empty_result(self, spec: TargetSpec) -> EngagementResult:
        return EngagementResult(
            target_url=self.config.target_url,
            target_scheme=spec.scheme,
            artifact_root=str(self.paths.root),
        )


# ── Convenience entry point ────────────────────────────────────────────────

def run_engagement(
    target_url:  str,
    *,
    output_dir:  str | Path = "results/engagements",
    clean:       bool = False,
    verbose:     bool = False,
    agent_slate: Optional[tuple[str, ...]] = None,
) -> EngagementResult:
    return EngagementRunner(EngagementConfig(
        target_url=target_url,
        output_dir=Path(output_dir),
        clean=clean, verbose=verbose,
        agent_slate=agent_slate,
    )).run()
