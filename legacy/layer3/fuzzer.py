"""
layer3/fuzzer.py
Semantic Fuzzing Engine — generates adversarial payloads targeting L2 hypotheses.

Three modalities:
  1. Schema Fuzzer    — adversarial MCP tool schema mutations
  2. Chain Fuzzer     — multi-turn trust escalation sequences  
  3. Memory Fuzzer    — vector store namespace boundary probes

Model: Haiku throughout (high volume, cost-controlled).
Opus is reserved for L5 exploit synthesis only.

Output: L3FuzzResults with payloads grouped by hypothesis.
"""
from __future__ import annotations

import json
import os
import sys
import hashlib
from pathlib import Path
from dataclasses import asdict
from typing import Optional

from argus.shared.client import ArgusClient


from argus.shared.models import (
    L1Report, L2SurfaceMap, L3FuzzResults,
    FuzzPayload, VulnHypothesis,
    SchemaInjectionPath, EscalationPath, MemoryBoundaryGap
)
from argus.shared.prompts import (
    L3_MODEL,
    L3_SCHEMA_FUZZER_PROMPT,
    L3_CHAIN_FUZZER_PROMPT,
    L3_MEMORY_FUZZER_PROMPT
)

# ── Config ────────────────────────────────────────────────────────────────────
PAYLOADS_PER_SCHEMA_TARGET  = 8    # per schema injection path
PAYLOADS_PER_CHAIN_TARGET   = 5    # per escalation path
PAYLOADS_PER_MEMORY_TARGET  = 6    # per memory boundary gap
MAX_HYPOTHESES_TO_FUZZ      = 15   # cap to control cost

# ── Helpers ───────────────────────────────────────────────────────────────────

def _strip_fences(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        start = 1
        end = len(lines) - 1 if lines[-1].strip() == "```" else len(lines)
        raw = "\n".join(lines[start:end]).strip()
    return raw


def _call_haiku(client: ArgusClient, prompt: str,
                max_tokens: int = 3000) -> dict:
    resp = client.messages.create(
        model=L3_MODEL,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}]
    )
    raw = _strip_fences(resp.content[0].text)
    return json.loads(raw)


def _payload_id(hypothesis_id: str, modality: str, index: int) -> str:
    raw = f"{hypothesis_id}:{modality}:{index}"
    return hashlib.md5(raw.encode()).hexdigest()[:8]


# ── Modality 1 — Schema Fuzzer ────────────────────────────────────────────────

def _fuzz_schema(
    client: ArgusClient,
    hypothesis: VulnHypothesis,
    schema_paths: list[SchemaInjectionPath],
    verbose: bool
) -> list[FuzzPayload]:
    """
    Generate adversarial MCP tool schema mutations.
    Payloads look like valid documentation but contain hidden adversarial instructions.
    Technique: preserve schema validity, inject in description/name/parameter fields.
    """
    results = []

    for i, path in enumerate(schema_paths[:3]):  # top 3 injection paths
        # Build a realistic-looking tool schema for mutation
        target_schema = {
            "name": path.source_function,
            "description": f"Tool that processes data from {path.source_file}",
            "parameters": {
                "type": "object",
                "properties": {
                    "input": {"type": "string", "description": "Input data to process"},
                    "config": {"type": "object", "description": "Configuration options"}
                }
            },
            "injection_path": path.injection_path,
            "blast_radius": path.blast_radius
        }

        try:
            prompt = L3_SCHEMA_FUZZER_PROMPT.format(
                hypothesis=f"{hypothesis.hypothesis_id}: {hypothesis.title}\n{hypothesis.description}",
                schema=json.dumps(target_schema, indent=2),
                count=PAYLOADS_PER_SCHEMA_TARGET
            )
            data = _call_haiku(client, prompt)

            for j, p in enumerate(data.get("payloads", [])):
                pid = _payload_id(hypothesis.hypothesis_id, "schema", i * 10 + j)
                results.append(FuzzPayload(
                    payload_id=pid,
                    hypothesis_id=hypothesis.hypothesis_id,
                    modality="schema",
                    payload=p.get("payload", {}),
                    intended_effect=p.get("intended_effect", ""),
                    target_function=p.get("target_function", path.source_function),
                    expected_deviation=p.get("expected_deviation", ""),
                    model_used=L3_MODEL
                ))

            if verbose:
                print(f"      [schema] {path.source_file}:{path.source_function} "
                      f"→ {len(data.get('payloads', []))} payloads")

        except Exception as e:
            if verbose:
                print(f"      [schema] Error on {path.source_file}: {e}")

    return results


# ── Modality 2 — Multi-Turn Chain Fuzzer ──────────────────────────────────────

def _fuzz_chains(
    client: ArgusClient,
    hypothesis: VulnHypothesis,
    escalation_paths: list[EscalationPath],
    verbose: bool
) -> list[FuzzPayload]:
    """
    Generate multi-turn agent interaction sequences targeting trust escalation paths.
    Each sequence traverses a path from untrusted source to privileged sink.
    Single-shot fuzzing misses multi-hop vulnerabilities — this generates the full chain.
    """
    results = []

    for i, path in enumerate(escalation_paths[:3]):
        path_desc = {
            "nodes": path.path,
            "hop_count": path.hop_count,
            "blast_radius": path.blast_radius,
            "start_trust": path.start_trust,
            "end_trust": path.end_trust,
            "edges": [
                {
                    "from": e.source,
                    "to": e.target,
                    "type": e.edge_type,
                    "trust_delta": e.trust_delta
                }
                for e in path.edges[:6]
            ]
        }

        try:
            prompt = L3_CHAIN_FUZZER_PROMPT.format(
                escalation_path=json.dumps(path_desc, indent=2),
                count=PAYLOADS_PER_CHAIN_TARGET
            )
            data = _call_haiku(client, prompt)

            for j, p in enumerate(data.get("payloads", [])):
                pid = _payload_id(hypothesis.hypothesis_id, "chain", i * 10 + j)
                results.append(FuzzPayload(
                    payload_id=pid,
                    hypothesis_id=hypothesis.hypothesis_id,
                    modality="chain",
                    payload=p.get("turns", []),
                    intended_effect=p.get("intended_effect", ""),
                    target_function=p.get("target_function", path.path[-1] if path.path else ""),
                    expected_deviation=p.get("expected_deviation", ""),
                    model_used=L3_MODEL
                ))

            if verbose:
                print(f"      [chain] {' -> '.join(path.path[:4])} "
                      f"→ {len(data.get('payloads', []))} sequences")

        except Exception as e:
            if verbose:
                print(f"      [chain] Error on path {i}: {e}")

    return results


# ── Modality 3 — Memory Poisoning Fuzzer ──────────────────────────────────────

def _fuzz_memory(
    client: ArgusClient,
    hypothesis: VulnHypothesis,
    memory_gaps: list[MemoryBoundaryGap],
    verbose: bool
) -> list[FuzzPayload]:
    """
    Generate adversarial document + query pairs probing vector store isolation.
    Tests whether adversarial content injected under one namespace:
    1. Appears in queries from a different namespace
    2. Survives embedding and retrieval as actionable instructions
    3. Crosses semantic similarity thresholds to adjacent tenants
    """
    results = []

    for i, gap in enumerate(memory_gaps[:3]):
        gap_desc = {
            "file": gap.file,
            "function": gap.function,
            "store_type": gap.store_type,
            "has_namespace_filter": gap.has_namespace_filter,
            "filter_at": gap.filter_at,
            "cross_tenant_risk": gap.cross_tenant_risk
        }

        try:
            prompt = L3_MEMORY_FUZZER_PROMPT.format(
                memory_gap=json.dumps(gap_desc, indent=2),
                count=PAYLOADS_PER_MEMORY_TARGET
            )
            data = _call_haiku(client, prompt)

            for j, p in enumerate(data.get("payloads", [])):
                pid = _payload_id(hypothesis.hypothesis_id, "memory", i * 10 + j)
                results.append(FuzzPayload(
                    payload_id=pid,
                    hypothesis_id=hypothesis.hypothesis_id,
                    modality="memory",
                    payload={
                        "document": p.get("document", ""),
                        "query": p.get("query", "")
                    },
                    intended_effect=p.get("intended_effect", ""),
                    target_function=p.get("target_function", gap.function),
                    expected_deviation=p.get("expected_deviation", ""),
                    model_used=L3_MODEL
                ))

            if verbose:
                print(f"      [memory] {gap.file}:{gap.function} ({gap.store_type}) "
                      f"→ {len(data.get('payloads', []))} payloads")

        except Exception as e:
            if verbose:
                print(f"      [memory] Error on {gap.file}: {e}")

    return results


# ── Route by attack class ─────────────────────────────────────────────────────

def _fuzz_hypothesis(
    client: ArgusClient,
    hypothesis: VulnHypothesis,
    surface: L2SurfaceMap,
    verbose: bool
) -> list[FuzzPayload]:
    """Route each hypothesis to the appropriate fuzzing modality/modalities."""
    payloads: list[FuzzPayload] = []
    attack_class = hypothesis.attack_class

    # Schema + tool injection classes → Modality 1
    if attack_class in ("TRACE_LATERAL", "TRUST_ESCALATION", "MESH_TRUST"):
        if surface.schema_injection_paths:
            payloads += _fuzz_schema(client, hypothesis,
                                     surface.schema_injection_paths, verbose)

    # Trust escalation paths → Modality 2
    if attack_class in ("MESH_TRUST", "TRUST_ESCALATION", "TRACE_LATERAL",
                        "AUTH_BYPASS"):
        if surface.escalation_paths:
            payloads += _fuzz_chains(client, hypothesis,
                                     surface.escalation_paths, verbose)

    # Deserialization → Modality 1 (schema injection is the delivery vector)
    if attack_class == "DESER":
        if surface.schema_injection_paths:
            payloads += _fuzz_schema(client, hypothesis,
                                     surface.schema_injection_paths, verbose)

    # Memory attacks → Modality 3
    if attack_class in ("PHANTOM_MEMORY", "MEM_NAMESPACE_LEAK"):
        if surface.memory_boundary_gaps:
            payloads += _fuzz_memory(client, hypothesis,
                                     surface.memory_boundary_gaps, verbose)

    # SSRF → Modality 2 (chain-based delivery through agent)
    if attack_class == "SSRF":
        if surface.escalation_paths:
            payloads += _fuzz_chains(client, hypothesis,
                                     surface.escalation_paths, verbose)
        # Also schema-based injection if no escalation paths
        if not surface.escalation_paths and surface.schema_injection_paths:
            payloads += _fuzz_schema(client, hypothesis,
                                     surface.schema_injection_paths, verbose)

    return payloads


# ── Main ──────────────────────────────────────────────────────────────────────

def run_layer3(
    surface: L2SurfaceMap,
    verbose: bool = False
) -> L3FuzzResults:
    """
    Generate adversarial payloads for all ranked hypotheses from Layer 2.
    Uses Haiku throughout — Opus reserved for Layer 5 synthesis.
    """
    client = ArgusClient()
    results = L3FuzzResults(target=surface.target)

    # Focus on top hypotheses ordered by likelihood × blast_radius
    hypotheses = surface.ranked_hypotheses[:MAX_HYPOTHESES_TO_FUZZ]

    print(f"\n[L3] Semantic Fuzzing Engine — {len(hypotheses)} hypotheses to fuzz")
    print(f"     Model: {L3_MODEL} (cost-controlled)")
    print(f"     Modalities: schema | chain | memory")

    all_payloads: list[FuzzPayload] = []

    for i, hypothesis in enumerate(hypotheses):
        br_indicator = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
            hypothesis.blast_radius, "⚪"
        )
        print(f"\n  [{i+1:>2}/{len(hypotheses)}] {br_indicator} {hypothesis.hypothesis_id} "
              f"({hypothesis.attack_class}) — {hypothesis.title[:55]}")
        print(f"         Likelihood: {hypothesis.likelihood:.0%} | "
              f"Blast radius: {hypothesis.blast_radius}")

        payloads = _fuzz_hypothesis(client, hypothesis, surface, verbose)

        schema_count = sum(1 for p in payloads if p.modality == "schema")
        chain_count  = sum(1 for p in payloads if p.modality == "chain")
        memory_count = sum(1 for p in payloads if p.modality == "memory")

        print(f"         Generated: {len(payloads)} payloads "
              f"(schema:{schema_count} chain:{chain_count} memory:{memory_count})")

        all_payloads.extend(payloads)

        # Group payloads under this hypothesis for the results
        results.fuzz_targets.append({
            "hypothesis_id": hypothesis.hypothesis_id,
            "attack_class": hypothesis.attack_class,
            "blast_radius": hypothesis.blast_radius,
            "payload_count": len(payloads),
            "payloads": [asdict(p) for p in payloads]
        })

    # Totals
    results.total_payloads  = len(all_payloads)
    results.schema_payloads = sum(1 for p in all_payloads if p.modality == "schema")
    results.chain_payloads  = sum(1 for p in all_payloads if p.modality == "chain")
    results.memory_payloads = sum(1 for p in all_payloads if p.modality == "memory")

    print(f"\n[L3] Complete — {results.total_payloads} total payloads")
    print(f"     Schema: {results.schema_payloads}  "
          f"Chain: {results.chain_payloads}  "
          f"Memory: {results.memory_payloads}")

    return results
