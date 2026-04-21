"""
agents/agent_09_supply_chain.py
Agent 9 — Supply Chain Agent (Phase 1 per PHASES.md / spec).

Per Agent_Specs.docx §Agent 9: "modern agentic systems glue together
tools, models, memories, and middleware whose origins the operator
rarely audits. Supply-chain compromise replaces a trusted component
with an adversary-controlled one — a hostile MCP server registered in
place of the legitimate one, a model swapped for a finetune the
operator never signed off on, a library pulled from a typo-squatted
source."

Phase 1 scope (CLIENT-side audit against a live target we don't control):

  1. ORIGIN MANIFEST AUDIT
     Enumerate every tool/resource/prompt the target exposes. For each
     surface, scan metadata for:
       - External URLs (possible download / transitive-fetch origins)
       - Untrusted hosts (raw gists, pastebins, bare IPs, vanity short
         domains, typosquat-y patterns)
       - Missing provenance ("signed_by", "publisher", "source_url",
         "version" — absence is a signal in and of itself)
       - Capability-creep declarations ("exec", "shell", "filesystem
         write", "network.egress.*") without a declared scope
       - Transitive-fetch hooks ("fetch_from", "include_url",
         "remote_schema") where the target reaches back out to pull
         more policy at runtime — a classic hijack surface.

  2. SNAPSHOT DRIFT
     If a prior catalog snapshot is supplied (``baseline_snapshot``),
     compare the current enumeration against it. New surfaces,
     removed surfaces, changed schemas, or changed tool origins are
     all emitted as drift findings — "who changed what since last scan"
     is the supply-chain question.

What's intentionally Phase-3+: SBOM generation against the target's
process image, pip/npm dependency graph walks, CVE matching against
known-bad versions, active typosquat probing against package indices,
adversarial MCP server registration (belongs in labrat / Phase 4).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from argus.adapter.base import AdapterError, BaseAdapter, Surface
from argus.agents.base import AgentFinding, BaseAgent
from argus.corpus_attacks import EvolveCorpus
from argus.observation import BehaviorDelta, ObservationEngine, Verdict, default_detectors


# ── Supply-chain signature patterns ──────────────────────────────────────────

_URL = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)

# Hosts that are legitimate but commonly abused for supply-chain redirects.
# A match is not itself damning — it's a prompt to verify the origin is
# the intended one.
_SUSPECT_HOST_PATTERNS = [
    re.compile(r"(?i)^https?://(?:gist\.github|raw\.githubusercontent)\.com/"),
    re.compile(r"(?i)^https?://(?:pastebin|paste\.ee|hastebin)\.com/"),
    re.compile(r"(?i)^https?://(?:bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|"
               r"buff\.ly|ow\.ly|shorte\.st)/"),
    # Raw IPv4 address as host.
    re.compile(r"(?i)^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/"),
    # .top / .xyz / .click / .download — cheap TLDs widely used in
    # opportunistic campaigns.
    re.compile(r"(?i)^https?://[^/]+\.(?:top|xyz|click|download|zip|mov)(?::\d+)?/"),
]

# Capability tokens in tool descriptions that imply broad authority
# without a visible scope declaration.
_CAPABILITY_CREEP = re.compile(
    r"(?i)\b("
    r"execute (?:arbitrary|any) code|arbitrary shell|run (?:any |arbitrary )?"
    r"command|read any file|write any file|delete any|unrestricted (?:network|"
    r"access)|full (?:file|filesystem|network) access|sudo|root access|"
    r"privileged (?:exec|shell)|bypass (?:safety|auth|permissions)"
    r")\b"
)

# Transitive-fetch hooks: the tool itself will go out and pull more
# config/policy at runtime. This is where supply-chain hijacks land.
_TRANSITIVE_FETCH = re.compile(
    r"(?i)\b("
    r"fetch_from|include_url|remote_schema|external_schema|"
    r"load_from_url|pull_policy_from|import_from|"
    r"download (?:and )?(?:execute|run|load)"
    r")\b"
)

# Minimum provenance keys we expect on a well-governed tool surface.
# Absence of all of these = unsigned-origin signal.
_PROVENANCE_KEYS = {
    "signed_by", "publisher", "source_url", "origin", "version",
    "signature", "author", "x-signed-by", "x-publisher",
}


@dataclass
class _SCHit:
    technique:    str
    severity:     str
    where:        str
    snippet:      str
    pattern_name: str


# ── Pattern-level scans ──────────────────────────────────────────────────────

def _scan_urls(text: str, *, where: str) -> list[_SCHit]:
    out: list[_SCHit] = []
    if not text:
        return out
    for m in _URL.finditer(text):
        url = m.group(0)
        if any(pat.search(url) for pat in _SUSPECT_HOST_PATTERNS):
            out.append(_SCHit(
                technique="SC-T6-untrusted-host", severity="HIGH",
                where=where, snippet=url[:200],
                pattern_name="untrusted_host",
            ))
        else:
            out.append(_SCHit(
                technique="SC-T1-external-origin-url", severity="MEDIUM",
                where=where, snippet=url[:200],
                pattern_name="external_origin_url",
            ))
    return out


def _scan_capability_creep(text: str, *, where: str) -> list[_SCHit]:
    if not text:
        return []
    m = _CAPABILITY_CREEP.search(text)
    if not m:
        return []
    return [_SCHit(
        technique="SC-T3-capability-creep", severity="HIGH",
        where=where, snippet=m.group(0)[:160],
        pattern_name="capability_creep",
    )]


def _scan_transitive_fetch(text: str, *, where: str) -> list[_SCHit]:
    if not text:
        return []
    m = _TRANSITIVE_FETCH.search(text)
    if not m:
        return []
    return [_SCHit(
        technique="SC-T5-transitive-fetch", severity="HIGH",
        where=where, snippet=m.group(0)[:160],
        pattern_name="transitive_fetch",
    )]


def _has_provenance(surface: Surface) -> bool:
    """True iff the surface declares at least one provenance key."""
    schema = surface.schema or {}
    if not isinstance(schema, dict):
        return False
    # Check top-level schema keys.
    if any(k in schema for k in _PROVENANCE_KEYS):
        return True
    # Common: provenance nested under "meta" / "metadata" / "x-meta".
    for container_key in ("meta", "metadata", "x-meta", "provenance"):
        container = schema.get(container_key)
        if isinstance(container, dict) and any(
            k in container for k in _PROVENANCE_KEYS
        ):
            return True
    return False


def _audit_surface(surface: Surface) -> list[_SCHit]:
    hits: list[_SCHit] = []
    desc = surface.description or ""
    where_desc = f"{surface.name}.description"

    hits.extend(_scan_urls(desc, where=where_desc))
    hits.extend(_scan_capability_creep(desc, where=where_desc))
    hits.extend(_scan_transitive_fetch(desc, where=where_desc))

    # Walk schema properties for URLs / creep / fetch hooks.
    schema = surface.schema or {}
    props = (schema.get("properties") if isinstance(schema, dict) else None) or {}
    if isinstance(props, dict):
        for pname, pdef in props.items():
            if not isinstance(pdef, dict):
                continue
            pdesc = pdef.get("description", "") or ""
            where = f"{surface.name}.params.{pname}.description"
            hits.extend(_scan_urls(pdesc, where=where))
            hits.extend(_scan_capability_creep(pdesc, where=where))
            hits.extend(_scan_transitive_fetch(pdesc, where=where))

    # Unsigned-origin check. Only fires when there's SOMETHING to audit —
    # a bare "hello" tool with no schema isn't worth flagging as unsigned.
    if desc and not _has_provenance(surface):
        hits.append(_SCHit(
            technique="SC-T2-unsigned-origin", severity="MEDIUM",
            where=f"{surface.name}.metadata",
            snippet=(
                "no provenance keys declared; expected any of "
                f"{sorted(_PROVENANCE_KEYS)[:4]}…"
            ),
            pattern_name="unsigned_origin",
        ))
    return hits


# ── Snapshot drift ───────────────────────────────────────────────────────────

def _surface_fingerprint(s: Surface) -> str:
    """Stable hash of a surface's observable identity."""
    payload = {
        "kind":        s.kind,
        "name":        s.name,
        "description": s.description or "",
        "schema":      s.schema or {},
    }
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def _diff_snapshots(
    *,
    current:   list[Surface],
    baseline:  list[dict],
) -> list[_SCHit]:
    """
    Compare the current enumeration against a stored snapshot. Each
    baseline entry is a dict {kind, name, fingerprint}. We don't diff
    descriptions word-for-word — fingerprint mismatch is enough.
    """
    out: list[_SCHit] = []
    cur_map = {(s.kind, s.name): _surface_fingerprint(s) for s in current}
    base_map = {
        (e.get("kind", ""), e.get("name", "")): e.get("fingerprint", "")
        for e in baseline if isinstance(e, dict)
    }

    for key, fp in cur_map.items():
        if key not in base_map:
            out.append(_SCHit(
                technique="SC-T4-version-drift", severity="MEDIUM",
                where=f"{key[1]}.snapshot",
                snippet=f"new surface not present in baseline snapshot",
                pattern_name="snapshot_new_surface",
            ))
        elif base_map[key] != fp:
            out.append(_SCHit(
                technique="SC-T4-version-drift", severity="HIGH",
                where=f"{key[1]}.snapshot",
                snippet=(
                    f"surface fingerprint changed "
                    f"(was {base_map[key]}, now {fp})"
                ),
                pattern_name="snapshot_fingerprint_drift",
            ))
    for key in base_map:
        if key not in cur_map:
            out.append(_SCHit(
                technique="SC-T4-version-drift", severity="MEDIUM",
                where=f"{key[1]}.snapshot",
                snippet=f"surface removed since baseline snapshot",
                pattern_name="snapshot_surface_removed",
            ))
    return out


# ── Agent ────────────────────────────────────────────────────────────────────

@dataclass
class SupplyChainAuditResult:
    target_id:        str
    surfaces_audited: int = 0
    origin_findings:  int = 0
    drift_findings:   int = 0
    skipped_errors:   int = 0
    findings:         list[AgentFinding] = field(default_factory=list)


class SupplyChainAgent(BaseAgent):
    """
    Phase 1 Agent 9.

    Construction:

        adapter_factory = lambda: MCPAdapter(url="...")
        agent = SupplyChainAgent(
            adapter_factory=adapter_factory,
            baseline_snapshot_path="snapshots/customer_x.json",   # optional
        )
        findings = asyncio.run(agent.run_async(
            target_id="mcp://customer.example",
            output_dir="results/customer_x/SC-09",
        ))

    Running with ``snapshot_out`` writes a fresh snapshot of the target's
    current catalog that the NEXT engagement can diff against.
    """

    AGENT_ID    = "SC-09"
    AGENT_NAME  = "Supply Chain Agent"
    VULN_CLASS  = "SUPPLY_CHAIN"
    TECHNIQUES  = [
        "SC-T1-external-origin-url",
        "SC-T2-unsigned-origin",
        "SC-T3-capability-creep",
        "SC-T4-version-drift",
        "SC-T5-transitive-fetch",
        "SC-T6-untrusted-host",
    ]
    MAAC_PHASES = [1, 8]           # Reconnaissance + Environment Pivoting
    PERSONA     = "auditor"

    def __init__(
        self,
        *,
        adapter_factory:        Callable[[], BaseAdapter],
        observer:               Optional[ObservationEngine] = None,
        evolve_corpus:          Optional[EvolveCorpus] = None,
        baseline_snapshot_path: Optional[str | Path] = None,
        verbose:                bool = False,
    ) -> None:
        super().__init__(verbose=verbose)
        self.adapter_factory = adapter_factory
        self.observer = observer or ObservationEngine(detectors=default_detectors())
        self.evolve_corpus = evolve_corpus
        self.baseline_snapshot_path = (
            Path(baseline_snapshot_path) if baseline_snapshot_path else None
        )

    @property
    def technique_library(self) -> dict:
        return {t: lambda *a, **k: None for t in self.TECHNIQUES}

    def run(self, target: str, repo_path: str, output_dir: str) -> list[AgentFinding]:
        return asyncio.run(self.run_async(
            target_id=target, output_dir=output_dir,
        ))

    # ── Real entry point ─────────────────────────────────────────────────

    async def run_async(
        self,
        *,
        target_id:     str,
        output_dir:    str,
        snapshot_out:  Optional[str | Path] = None,
    ) -> list[AgentFinding]:
        self._print_header(target_id)
        result = SupplyChainAuditResult(target_id=target_id)

        try:
            surfaces = await self._enumerate_surfaces()
        except AdapterError as e:
            print(f"  [{self.AGENT_ID}] enumerate failed: {e}")
            self.save_findings(output_dir)
            return self.findings

        result.surfaces_audited = len(surfaces)

        # 1) Origin-manifest audit.
        for surface in surfaces:
            for hit in _audit_surface(surface):
                finding = self._finding_from_hit(
                    surface=surface, hit=hit, target_id=target_id,
                )
                self._add_finding(finding)
                result.findings.append(finding)
                result.origin_findings += 1
                self._maybe_evolve(finding, hit, surface, target_id)

        # 2) Optional snapshot drift.
        if self.baseline_snapshot_path and self.baseline_snapshot_path.exists():
            try:
                baseline = json.loads(self.baseline_snapshot_path.read_text())
            except (OSError, json.JSONDecodeError) as e:
                if self.verbose:
                    print(f"  [{self.AGENT_ID}] baseline snapshot unreadable: {e}")
                baseline = []
            for hit in _diff_snapshots(current=surfaces, baseline=baseline):
                finding = self._finding_from_drift_hit(
                    hit=hit, target_id=target_id,
                )
                self._add_finding(finding)
                result.findings.append(finding)
                result.drift_findings += 1

        # 3) Write a fresh snapshot for the next engagement to diff against.
        if snapshot_out is not None:
            self._write_snapshot(surfaces, Path(snapshot_out))

        out_path = self.save_findings(output_dir)
        self.save_history(target_id, output_dir)
        print(f"\n  [{self.AGENT_ID}] complete — "
              f"{result.surfaces_audited} surfaces audited, "
              f"{result.origin_findings} origin findings, "
              f"{result.drift_findings} drift findings, "
              f"{result.skipped_errors} adapter errors")
        print(f"  [{self.AGENT_ID}] findings → {out_path}")
        return self.findings

    # ── Helpers ──────────────────────────────────────────────────────────

    async def _enumerate_surfaces(self) -> list[Surface]:
        adapter = self.adapter_factory()
        async with adapter:
            return await adapter.enumerate()

    def _finding_from_hit(
        self,
        *,
        surface:   Surface,
        hit:       _SCHit,
        target_id: str,
    ) -> AgentFinding:
        title = (
            f"Supply-chain risk ({hit.pattern_name}) in {surface.name} "
            f"@ {hit.where}"
        )
        description = (
            f"Origin-manifest audit of target {target_id!r} found a "
            f"{hit.pattern_name} signal on surface {surface.name!r} at "
            f"{hit.where}. Snippet: {hit.snippet[:240]}. "
            f"Per Agent_Specs §Agent 9 ({hit.technique}), this is a "
            f"supply-chain surface where the operator may not control "
            f"the component's origin or integrity."
        )
        verdict = Verdict(
            delta=BehaviorDelta.AMBIGUOUS,
            kind=None,
            detector="supply_chain_origin_audit",
            evidence=hit.snippet,
            confidence=0.8,
            meta={
                "pattern_name": hit.pattern_name,
                "technique":    hit.technique,
                "where":        hit.where,
                "surface_kind": surface.kind,
            },
        )
        finding = AgentFinding.from_observation(
            verdict=verdict,
            agent_id=self.AGENT_ID,
            vuln_class=self.VULN_CLASS,
            title=title,
            description=description,
            surface=surface.name,
            session_id="",
            attack_variant_id=hit.technique,
            baseline_ref=f"{target_id}::catalog",
            severity=hit.severity,
        )
        finding.evidence_kind = "supply_chain_audit"
        finding.technique = hit.technique
        return finding

    def _finding_from_drift_hit(
        self,
        *,
        hit:       _SCHit,
        target_id: str,
    ) -> AgentFinding:
        title = f"Supply-chain drift ({hit.pattern_name}) @ {hit.where}"
        description = (
            f"Snapshot diff against baseline found {hit.pattern_name} on "
            f"target {target_id!r}. {hit.snippet}. Per Agent_Specs §Agent 9 "
            f"({hit.technique}), catalog churn between engagements is the "
            f"first observable signal of supply-chain tampering."
        )
        verdict = Verdict(
            delta=BehaviorDelta.AMBIGUOUS,
            kind=None,
            detector="supply_chain_snapshot_drift",
            evidence=hit.snippet,
            confidence=0.75,
            meta={
                "pattern_name": hit.pattern_name,
                "technique":    hit.technique,
                "where":        hit.where,
            },
        )
        finding = AgentFinding.from_observation(
            verdict=verdict,
            agent_id=self.AGENT_ID,
            vuln_class=self.VULN_CLASS,
            title=title,
            description=description,
            surface=hit.where.split(".")[0],
            session_id="",
            attack_variant_id=hit.technique,
            baseline_ref=str(self.baseline_snapshot_path or f"{target_id}::catalog"),
            severity=hit.severity,
        )
        finding.evidence_kind = "supply_chain_drift"
        finding.technique = hit.technique
        return finding

    def _write_snapshot(self, surfaces: list[Surface], path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        entries = [
            {
                "kind":        s.kind,
                "name":        s.name,
                "fingerprint": _surface_fingerprint(s),
            }
            for s in surfaces
        ]
        path.write_text(json.dumps(entries, indent=2), encoding="utf-8")

    def _maybe_evolve(
        self,
        finding:   AgentFinding,
        hit:       _SCHit,
        surface:   Surface,
        target_id: str,
    ) -> None:
        if self.evolve_corpus is None:
            return
        try:
            self.evolve_corpus.add_template(
                text=hit.snippet,
                category="supply_chain",
                tags=["discovered", hit.pattern_name, hit.technique],
                surfaces=[surface.kind],
                severity=hit.severity,
                target_id=target_id,
                finding_id=finding.id,
            )
        except Exception as e:
            if self.verbose:
                print(f"  [{self.AGENT_ID}] evolve_corpus.add_template "
                      f"failed: {e}")
