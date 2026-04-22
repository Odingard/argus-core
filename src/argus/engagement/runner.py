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
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from argus.adapter.base import Request
from argus.agents.base import AgentFinding
from argus.alec import build_envelope, write_envelope
from argus.cerberus import generate_rules, write_rules
from argus.corpus_attacks import EvolveCorpus
from argus.engagement.registry import TargetSpec, target_for_url
from argus.evidence import EvidenceCollector, attach_evidence
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

        # ── 2) Fire agent slate ─────────────────────────────────
        _section(2, "Agent slate")
        slate = tuple(self.config.agent_slate or spec.agent_selection)
        ev_corpus = EvolveCorpus(
            discovered_dir=str(self.paths.root / "discovered"),
        )
        findings: list[AgentFinding] = []
        by_agent: dict[str, int] = {}
        for agent_id in slate:
            try:
                agent_findings = _run_agent(
                    agent_id,
                    factory=factory,
                    output_dir=self.paths.findings,
                    target_id=target_id,
                    ev_corpus=ev_corpus,
                )
            except Exception as e:
                if self.config.verbose:
                    print(f"     [{agent_id}] error: {type(e).__name__}: {e}")
                continue
            by_agent[agent_id] = len(agent_findings)
            findings.extend(agent_findings)
            (_ok if agent_findings else _note)(
                f"{agent_id:<6} produced {len(agent_findings)} finding(s)"
                + ("" if agent_findings
                   else " (silent — surface class absent or hardened)")
            )

        if not findings:
            _alert("Zero findings produced; target appears hardened.")
            return self._empty_result(spec)

        # ── 3) Deterministic evidence ───────────────────────────
        _section(3, "Deterministic evidence replay")
        evidence = asyncio.run(
            self._replay_evidence(factory, findings),
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

        # ── 7) SUMMARY + headline ───────────────────────────────
        self._write_summary(
            spec=spec, chain=chain, brm=brm, envelope=envelope,
            findings=findings, by_agent=by_agent,
            rules=rules, evidence=evidence,
        )
        _ok(f"SUMMARY → {self.paths.summary}")
        dc  = ",".join(sorted(brm.data_classes_exposed)) or "—"
        reg = ",".join(brm.regulatory_impact) or "—"
        print()
        print(f"{BOLD}{RED}→ {brm.severity_label}{RESET}: "
              f"{len(chain.steps)}-step chain on {target_id} "
              f"(harm_score={brm.harm_score}, data={dc}, reg={reg})")
        print()

        return EngagementResult(
            target_url=target_id,
            target_scheme=spec.scheme,
            findings=findings,
            by_agent=by_agent,
            chain=chain.to_dict(),
            impact=brm.to_dict(),
            envelope_id=envelope.envelope_id,
            artifact_root=str(self.paths.root),
        )

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

    async def _replay_evidence(self, factory, findings):
        """Replay the first finding's surface with a benign payload to
        capture pcap + container_logs → proof-grade evidence."""
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
