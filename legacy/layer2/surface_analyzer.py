"""
layer2/surface_analyzer.py
Vulnerability Surface Analyzer — takes L1 findings + repo and maps the full attack surface.

Five modules:
  A — MCP Schema Injection Mapper
  B — Trust Propagation Graph Builder (NetworkX)
  C — Deserialization Sink Cross-File Tracer
  D — Memory Boundary Surface Mapper
  E — Auth Gap Path Tracer

All analysis uses Haiku (high volume, cost-controlled).
Output: L2SurfaceMap with ranked VulnHypotheses feeding Layer 3.
"""
from __future__ import annotations

import json
import os
import hashlib
from argus.shared.client import ArgusClient
import networkx as nx
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import sys

from argus.shared.models import (
    L1Report, L1Finding, L2SurfaceMap,
    SchemaInjectionPath, TrustEdge, EscalationPath,
    DeserChain, MemoryBoundaryGap, AuthGapPath, VulnHypothesis
)
from argus.shared.flywheel_reader import FlywheelPriors, generate_priors, find_flywheel, read_flywheel
from argus.shared.prompts import (
    L2_MODEL,
    L2_SCHEMA_INJECTION_PROMPT, L2_TRUST_GRAPH_PROMPT,
    L2_DESER_TRACE_PROMPT, L2_MEMORY_BOUNDARY_PROMPT,
    L2_AUTH_GAP_PROMPT, L2_HYPOTHESIS_SYNTHESIS_PROMPT
)

# ── Config ────────────────────────────────────────────────────────────────────
MAX_FILE_SIZE   = 200_000   # bytes
CHUNK_SIZE      = 14_000    # chars per analysis window
MAX_WORKERS     = 4
RELEVANT_EXT    = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java"}
SKIP_DIRS       = {"node_modules", ".git", "__pycache__", "dist", "build",
                   "vendor", ".venv", "venv", "env", "coverage"}

# Sensitive sink types — graph pathfinding focuses only on these
SENSITIVE_SINKS = {
    "exec", "eval", "subprocess", "os.system", "os.popen",
    "pickle.loads", "yaml.load", "marshal.loads", "jsonpickle.decode",
    "open(", "write(", "requests.get", "requests.post",
    "httpx.get", "httpx.post", "fetch(", "aiohttp",
    "cursor.execute", "session.execute", "engine.execute",
    "agent.run", "crew.kickoff", "chain.invoke", "llm.predict"
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


def _call_haiku(client: ArgusClient, prompt: str, max_tokens: int = 2048) -> dict:
    resp = client.messages.create(
        model=L2_MODEL,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}]
    )
    raw = _strip_fences(resp.content[0].text)
    return json.loads(raw)


def _read_file(path: str) -> Optional[str]:
    try:
        size = os.path.getsize(path)
        if size > MAX_FILE_SIZE:
            return None
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None


def _chunk(code: str) -> list[str]:
    if len(code) <= CHUNK_SIZE:
        return [code]
    chunks, current, size = [], [], 0
    for line in code.split("\n"):
        lsize = len(line) + 1
        if size + lsize > CHUNK_SIZE and current:
            chunks.append("\n".join(current))
            current = current[-10:]
            size = sum(len(l) + 1 for l in current)
        current.append(line)
        size += lsize
    if current:
        chunks.append("\n".join(current))
    return chunks


def _discover_files(repo_dir: str) -> list[str]:
    files = []
    for root, dirs, filenames in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if Path(name).suffix in RELEVANT_EXT:
                fp = os.path.join(root, name)
                if 100 < os.path.getsize(fp) < MAX_FILE_SIZE:
                    files.append(fp)
    return sorted(files)


def _findings_for_file(findings: list[L1Finding], rel_path: str) -> list[str]:
    return [f.id for f in findings if f.file == rel_path]


# ── Layer 2 Perimeter-First Doctrine Update ───────────────────────────────────

class PerimeterTaintEngine:
    """Layer 2 Upgrade: Enforces 'Perimeter-to-Sink' reachability logic."""

    def __init__(self, repo_path: str):
        self.graph = nx.DiGraph()
        self.perimeter_types = ["fastapi_route", "cli_arg", "mcp_handshake", "web_socket"]
        self.sensitive_sinks = [
            "pickle.load", "cursor.execute", "os.system", "subprocess.run",
            "eval", "exec", "yaml.load", "session.execute", "agent.run", "crew.kickoff"
        ]

    def map_reachability(self, findings: list[L1Finding], base_graph: nx.DiGraph) -> list[L1Finding]:
        """Filters findings to only those reachable from unauthenticated perimeter nodes in the AST graph or those that cross identity boundaries."""
        valid_findings = []
        
        # 1. Identify Perimeter Entry Points (Source Nodes) and Low-Trust Agents
        unauth_nodes = [n for n in base_graph.nodes() if base_graph.in_degree(n) == 0]
        identity_nodes = [n for n in base_graph.nodes() if "agent" in str(n).lower() or "user" in str(n).lower()]
        
        # Identity Map: Assume explicit high-trust sinks are Database or OS
        high_trust_tools = ["PostgresLoader", "SQLTool", "OSCommand", "cursor", "db"]
        
        # 2. Add structural nodes for findings to the graph if tracking AST logic
        for finding in findings:
            is_valid = False
            # Check if finding inherently describes a sink vulnerability
            if any(sink in finding.title or sink in finding.description for sink in self.sensitive_sinks):
                
                # --- PILLAR 1: Identity-Aware Taint Engine ---
                # First, check if unauth perimeter reaches the sink.
                for unauth in unauth_nodes:
                    try:
                        target_nodes = [n for n in base_graph.nodes() if finding.file in str(base_graph.nodes[n].get('file', ''))]
                        for target in target_nodes:
                            path = nx.shortest_path(base_graph, source=unauth, target=target)
                            if path:
                                is_valid = True
                                break
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        continue
                    if is_valid: break
                
                # Second, check Identity Authorization Bypass (Low-Trust Agent -> High-Trust Component)
                if not is_valid:
                    for identity in identity_nodes:
                        # Determine if identity context traverses an explicit boundary
                        try:
                            target_nodes = [n for n in base_graph.nodes() if any(t_tool.lower() in str(n).lower() for t_tool in high_trust_tools)]
                            for target in target_nodes:
                                if nx.has_path(base_graph, source=identity, target=target):
                                    is_valid = True
                                    print(f"  [L2-Taint] Authorization Bypass Discovered: Identity {identity} -> High-Trust Sink {target}")
                                    break
                        except (nx.NetworkXNoPath, nx.NodeNotFound):
                            continue
                        if is_valid: break

            else:
                # Basic vulnerabilities not sinking to RCE bypass graph check here
                is_valid = True 

            if is_valid:
                valid_findings.append(finding)
                
        return valid_findings


# ── Module A — Schema Injection ───────────────────────────────────────────────

def _run_module_a(
    client: ArgusClient,
    files: list[str],
    repo_dir: str,
    all_findings: list[L1Finding],
    verbose: bool
) -> list[SchemaInjectionPath]:
    """Find MCP schema injection surfaces — tool output flowing to agent context."""
    results = []

    # Focus on files with tool definitions, agent execution, LLM calls
    keywords = ["execute", "@tool", "tool_schema", "tool_call", "agent.run",
                "llm.predict", "chain.invoke", "BaseTool", "Tool("]
    target_files = []
    for fp in files:
        code = _read_file(fp)
        if code and any(kw in code for kw in keywords):
            target_files.append((fp, code))

    if verbose:
        print(f"    [A] Schema injection — scanning {len(target_files)} tool/agent files")

    for fp, code in target_files:
        rel = os.path.relpath(fp, repo_dir)
        finding_ids = _findings_for_file(all_findings, rel)

        for chunk in _chunk(code):
            try:
                prompt = L2_SCHEMA_INJECTION_PROMPT.format(
                    filename=rel,
                    finding_ids=", ".join(finding_ids) or "none",
                    code=chunk
                )
                data = _call_haiku(client, prompt)
                for path in data.get("schema_injection_paths", []):
                    results.append(SchemaInjectionPath(
                        source_file=rel,
                        source_function=path.get("source_function", "unknown"),
                        injection_path=path.get("injection_path", []),
                        unsanitized_handoff=path.get("unsanitized_handoff", False),
                        blast_radius=path.get("blast_radius", "MEDIUM"),
                        finding_anchor_id=finding_ids[0] if finding_ids else None
                    ))
            except Exception as e:
                if verbose:
                    print(f"    [A] Error on {rel}: {e}")

    return results


# ── Module B — Trust Propagation Graph ───────────────────────────────────────

def _run_module_b(
    client: ArgusClient,
    files: list[str],
    repo_dir: str,
    all_findings: list[L1Finding],
    verbose: bool
) -> tuple[list[EscalationPath], nx.DiGraph, int, int]:
    """
    Build trust propagation graph using NetworkX.
    Find paths from untrusted sources to sensitive sinks.
    Per reviewer: focus pathfinding ONLY on sensitive sinks to avoid complexity explosion.
    """
    G = nx.DiGraph()
    all_edges: list[TrustEdge] = []
    sink_nodes: set[str] = set()

    if verbose:
        print(f"    [B] Trust graph — extracting edges from {len(files)} files")

    for fp in files:
        code = _read_file(fp)
        if not code:
            continue
        rel = os.path.relpath(fp, repo_dir)

        for chunk in _chunk(code):
            try:
                prompt = L2_TRUST_GRAPH_PROMPT.format(filename=rel, code=chunk)
                data = _call_haiku(client, prompt)

                for edge in data.get("edges", []):
                    src = edge.get("source", "unknown")
                    tgt = edge.get("target", "unknown")
                    etype = edge.get("edge_type", "data_flow")
                    delta = int(edge.get("trust_delta", 0))

                    G.add_node(src, trust_level=0)
                    G.add_node(tgt, trust_level=0)
                    G.add_edge(src, tgt, edge_type=etype, trust_delta=delta,
                               file=rel, line_hint=edge.get("line_hint", ""))

                    all_edges.append(TrustEdge(
                        source=src, target=tgt, edge_type=etype,
                        trust_delta=delta, file=rel,
                        line_hint=edge.get("line_hint", "")
                    ))

                # Register sensitive sinks
                for sink in data.get("sensitive_sinks", []):
                    sink_name = sink.get("name", "")
                    if sink_name:
                        sink_nodes.add(sink_name)
                        G.add_node(sink_name, is_sink=True,
                                   sink_type=sink.get("type", "unknown"))

            except Exception as e:
                if verbose:
                    print(f"    [B] Edge extraction error {rel}: {e}")

    if verbose:
        print(f"    [B] Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges, {len(sink_nodes)} sinks")

    # Find escalation paths — SOURCE: nodes with no predecessors (entry points)
    # TARGET: only sensitive sinks (reviewer's key suggestion)
    escalation_paths = []
    entry_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]

    for entry in entry_nodes:
        for sink in sink_nodes:
            if sink not in G:
                continue
            try:
                # Find all simple paths, limit to avoid explosion
                paths = list(nx.all_simple_paths(G, entry, sink, cutoff=6))
                for path in paths[:3]:  # cap at 3 per entry-sink pair
                    # Check if any edge escalates trust
                    escalates = any(
                        G.edges[path[i], path[i+1]].get("trust_delta", 0) > 0
                        for i in range(len(path) - 1)
                    )
                    if not escalates:
                        continue

                    edges = [
                        TrustEdge(
                            source=path[i], target=path[i+1],
                            edge_type=G.edges[path[i], path[i+1]].get("edge_type", ""),
                            trust_delta=G.edges[path[i], path[i+1]].get("trust_delta", 0),
                            file=G.edges[path[i], path[i+1]].get("file", ""),
                            line_hint=G.edges[path[i], path[i+1]].get("line_hint", "")
                        )
                        for i in range(len(path) - 1)
                    ]

                    # Collect finding IDs at path nodes
                    path_findings = [
                        f.id for f in all_findings
                        if any(n in f.title or n in f.file for n in path)
                    ][:5]

                    escalation_paths.append(EscalationPath(
                        path=path,
                        edges=edges,
                        start_trust="untrusted",
                        end_trust="privileged",
                        hop_count=len(path) - 1,
                        blast_radius="CRITICAL" if len(path) > 3 else "HIGH",
                        finding_ids=path_findings
                    ))
            except nx.NetworkXNoPath:
                pass
            except nx.NodeNotFound:
                pass

    # Sort by hop count (longer chains = more interesting)
    escalation_paths.sort(key=lambda p: p.hop_count, reverse=True)

    return escalation_paths[:20], G, G.number_of_nodes(), G.number_of_edges()


# ── Module C — Deserialization Sink Tracer ────────────────────────────────────

def _run_module_c(
    client: ArgusClient,
    files: list[str],
    repo_dir: str,
    all_findings: list[L1Finding],
    verbose: bool
) -> list[DeserChain]:
    """Trace deserialization sinks back to user-controlled input."""
    results = []

    # Focus on files with known deser findings + files with deser keywords
    deser_keywords = ["pickle", "yaml.load", "eval(", "exec(", "marshal",
                     "jsonpickle", "load_module", "checkpoint", "restore_"]

    # Start with L1 DESER findings as anchors
    deser_finding_files = {f.file for f in all_findings if f.vuln_class == "DESER"}

    target_files = []
    for fp in files:
        rel = os.path.relpath(fp, repo_dir)
        code = _read_file(fp)
        if not code:
            continue
        if rel in deser_finding_files or any(kw in code for kw in deser_keywords):
            target_files.append((fp, code, rel))

    if verbose:
        print(f"    [C] Deser tracing — {len(target_files)} files with deser patterns")

    for fp, code, rel in target_files:
        finding_ids = _findings_for_file(all_findings, rel)
        for chunk in _chunk(code):
            try:
                prompt = L2_DESER_TRACE_PROMPT.format(
                    filename=rel,
                    finding_ids=", ".join(finding_ids) or "none",
                    code=chunk
                )
                data = _call_haiku(client, prompt)
                for chain in data.get("deser_chains", []):
                    results.append(DeserChain(
                        sink_file=rel,
                        sink_function=chain.get("sink_function", "unknown"),
                        sink_pattern=chain.get("sink_pattern", "unknown"),
                        call_chain=chain.get("call_chain", []),
                        reachable=chain.get("reachable", False),
                        finding_id=finding_ids[0] if finding_ids else None
                    ))
            except Exception as e:
                if verbose:
                    print(f"    [C] Error on {rel}: {e}")

    # Sort: reachable first
    results.sort(key=lambda c: c.reachable, reverse=True)
    return results


# ── Module D — Memory Boundary Mapper ────────────────────────────────────────

def _run_module_d(
    client: ArgusClient,
    files: list[str],
    repo_dir: str,
    all_findings: list[L1Finding],
    verbose: bool
) -> list[MemoryBoundaryGap]:
    """Map vector store and RAG namespace isolation failures."""
    results = []

    mem_keywords = ["vectorstore", "vector_store", "similarity_search",
                   "collection.query", "retriever", "embedding", "upsert",
                   "add_texts", "from_documents", "chroma", "pinecone",
                   "weaviate", "qdrant", "milvus", "SimpleMemory", "BaseMemory"]

    target_files = []
    for fp in files:
        code = _read_file(fp)
        if code and any(kw.lower() in code.lower() for kw in mem_keywords):
            target_files.append((fp, code))

    if verbose:
        print(f"    [D] Memory boundary — {len(target_files)} vector store / RAG files")

    for fp, code in target_files:
        rel = os.path.relpath(fp, repo_dir)
        for chunk in _chunk(code):
            try:
                prompt = L2_MEMORY_BOUNDARY_PROMPT.format(filename=rel, code=chunk)
                data = _call_haiku(client, prompt)
                for gap in data.get("memory_gaps", []):
                    results.append(MemoryBoundaryGap(
                        file=rel,
                        function=gap.get("function", "unknown"),
                        store_type=gap.get("store_type", "unknown"),
                        has_namespace_filter=gap.get("has_namespace_filter", False),
                        filter_at=gap.get("filter_at", "none"),
                        cross_tenant_risk=gap.get("cross_tenant_risk", "MEDIUM")
                    ))
            except Exception as e:
                if verbose:
                    print(f"    [D] Error on {rel}: {e}")

    return results


# ── Module E — Auth Gap Path Tracer ──────────────────────────────────────────

def _run_module_e(
    client: ArgusClient,
    files: list[str],
    repo_dir: str,
    all_findings: list[L1Finding],
    verbose: bool
) -> list[AuthGapPath]:
    """Trace entry points to privileged sinks with missing auth gates."""
    results = []

    # Focus on files with both entry points AND privileged ops
    entry_keywords = ["@app.route", "@router.", "def execute(", "async def execute",
                     "tool_call", "handle_request", "run_agent", "def main("]
    priv_keywords  = ["subprocess", "os.system", "exec(", "eval(",
                     "open(", "pickle", "yaml.load", "cursor.execute"]

    target_files = []
    for fp in files:
        code = _read_file(fp)
        if not code:
            continue
        has_entry = any(kw in code for kw in entry_keywords)
        has_priv  = any(kw in code for kw in priv_keywords)
        if has_entry or has_priv:
            target_files.append((fp, code))

    if verbose:
        print(f"    [E] Auth gap tracing — {len(target_files)} entry/privileged files")

    for fp, code in target_files:
        rel = os.path.relpath(fp, repo_dir)
        finding_ids = _findings_for_file(all_findings, rel)
        for chunk in _chunk(code):
            try:
                prompt = L2_AUTH_GAP_PROMPT.format(filename=rel, code=chunk)
                data = _call_haiku(client, prompt)
                for gap in data.get("auth_gaps", []):
                    results.append(AuthGapPath(
                        entry_point=gap.get("entry_point", "unknown"),
                        entry_file=rel,
                        privileged_sink=gap.get("privileged_sink", "unknown"),
                        sink_file=rel,
                        call_chain=gap.get("call_chain", []),
                        auth_gates=int(gap.get("auth_gates", 0)),
                        finding_id=finding_ids[0] if finding_ids else None
                    ))
            except Exception as e:
                if verbose:
                    print(f"    [E] Error on {rel}: {e}")

    # Sort: zero auth gates first
    results.sort(key=lambda g: g.auth_gates)
    return results


# ── Hypothesis Synthesis ──────────────────────────────────────────────────────

def _synthesize_hypotheses(
    client: ArgusClient,
    surface_map: L2SurfaceMap,
    l1_findings: list[L1Finding],
    verbose: bool,
    priors: "FlywheelPriors | None" = None
) -> list[VulnHypothesis]:
    """Synthesize ranked vulnerability hypotheses from surface map.
    Priors from flywheel pre-boost historically effective attack classes."""

    surface_summary = f"""
SCHEMA INJECTION PATHS: {len(surface_map.schema_injection_paths)}
  High blast radius: {sum(1 for p in surface_map.schema_injection_paths if p.blast_radius in ('CRITICAL','HIGH'))}

TRUST ESCALATION PATHS: {len(surface_map.escalation_paths)}
  Longest chain: {max((p.hop_count for p in surface_map.escalation_paths), default=0)} hops

DESERIALIZATION CHAINS: {len(surface_map.deser_chains)}
  Reachable from user input: {sum(1 for c in surface_map.deser_chains if c.reachable)}

MEMORY BOUNDARY GAPS: {len(surface_map.memory_boundary_gaps)}
  No namespace filter: {sum(1 for g in surface_map.memory_boundary_gaps if not g.has_namespace_filter)}

AUTH GAP PATHS: {len(surface_map.auth_gap_paths)}
  Zero auth gates: {sum(1 for g in surface_map.auth_gap_paths if g.auth_gates == 0)}

TOP SCHEMA INJECTION FILES:
{chr(10).join(f'  - {p.source_file}: {p.source_function}' for p in surface_map.schema_injection_paths[:5])}

TOP ESCALATION PATHS:
{chr(10).join(f'  - {" -> ".join(p.path[:4])} ({p.hop_count} hops, {p.blast_radius})' for p in surface_map.escalation_paths[:5])}

TOP REACHABLE DESER SINKS:
{chr(10).join(f'  - {c.sink_file}: {c.sink_function} via {c.sink_pattern}' for c in surface_map.deser_chains if c.reachable)[:3]}
"""

    crit_findings = [f for f in l1_findings if f.severity == "CRITICAL"]
    findings_summary = "\n".join([
        f"- [{f.id}] {f.vuln_class} | {f.title} | {f.file}"
        for f in crit_findings[:20]
    ])

    # Inject flywheel priors into synthesis prompt
    flywheel_context = ""
    if priors and priors.prior_summary:
        flywheel_context = f"\n\nHISTORICAL INTELLIGENCE FROM FLYWHEEL:\n{priors.prior_summary}\n"
        if verbose:
            print(f"    [FLYWHEEL] Injecting priors: {len(priors.boosted_classes)} boosted, "
                  f"{len(priors.suppressed_classes)} suppressed")

    try:
        prompt = L2_HYPOTHESIS_SYNTHESIS_PROMPT.format(
            surface_summary=surface_summary + flywheel_context,
            findings_summary=findings_summary
        )
        resp = client.messages.create(
            model=L2_MODEL,
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = _strip_fences(resp.content[0].text)
        data = json.loads(raw)

        hypotheses = []
        for i, h in enumerate(data.get("hypotheses", [])):
            hid = f"H{str(i+1).zfill(3)}"
            hypotheses.append(VulnHypothesis(
                hypothesis_id=hid,
                attack_class=h.get("attack_class", "UNKNOWN"),
                title=h.get("title", ""),
                description=h.get("description", ""),
                likelihood=float(h.get("likelihood", 0.5)),
                blast_radius=h.get("blast_radius", "HIGH"),
                entry_points=h.get("entry_points", []),
                affected_files=h.get("affected_files", []),
                finding_ids=h.get("finding_ids", [])
            ))
        # Sort by likelihood * blast_radius weight
        br_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        hypotheses.sort(
            key=lambda h: h.likelihood * br_weight.get(h.blast_radius, 1),
            reverse=True
        )
        return hypotheses
    except Exception as e:
        if verbose:
            print(f"    [SYNTH] Hypothesis synthesis error: {e}")
        return []


# ── Main ──────────────────────────────────────────────────────────────────────

def run_layer2(
    l1_report: L1Report,
    verbose: bool = False,
    output_dir: str = None
) -> L2SurfaceMap:
    """
    Run all 5 surface analysis modules on the L1 report.
    Loads flywheel priors if flywheel.jsonl exists.
    Returns a complete L2SurfaceMap with ranked hypotheses.
    """
    if not l1_report.repo_path or not os.path.exists(l1_report.repo_path):
        raise ValueError(f"L2 requires a cloned repo path. Got: {l1_report.repo_path}")

    client  = ArgusClient()
    repo_dir = l1_report.repo_path
    files   = _discover_files(repo_dir)
    all_findings = l1_report.production_findings + l1_report.example_findings

    print(f"\n[L2] Surface Analyzer — {len(files)} files, {len(all_findings)} findings")
    surface = L2SurfaceMap(target=l1_report.target)

    # ── Module A ──────────────────────────────────────────
    print("[L2-A] Schema injection surface...")
    surface.schema_injection_paths = _run_module_a(
        client, files, repo_dir, all_findings, verbose
    )
    print(f"       → {len(surface.schema_injection_paths)} injection paths found")

    # ── Module B ──────────────────────────────────────────
    print("[L2-B] Trust propagation graph (NetworkX)...")
    surface.escalation_paths, graph, n_nodes, n_edges = _run_module_b(
        client, files, repo_dir, all_findings, verbose
    )
    surface.graph_node_count = n_nodes
    surface.graph_edge_count = n_edges
    print(f"       → {n_nodes} nodes, {n_edges} edges, {len(surface.escalation_paths)} escalation paths")

    # ── Perimeter-First Taint Filter ──────────────────────
    print("[L2-Taint] Enforcing Perimeter-to-Sink Taint Routing...")
    taint_engine = PerimeterTaintEngine(repo_dir)
    valid_findings = taint_engine.map_reachability(all_findings, graph)
    discarded = len(all_findings) - len(valid_findings)
    print(f"       → Dropped {discarded} theoretical findings; kept {len(valid_findings)} reachable from perimeter")
    all_findings = valid_findings

    # ── Module C ──────────────────────────────────────────
    print("[L2-C] Deserialization sink cross-file tracer...")
    surface.deser_chains = _run_module_c(
        client, files, repo_dir, all_findings, verbose
    )
    reachable = sum(1 for c in surface.deser_chains if c.reachable)
    print(f"       → {len(surface.deser_chains)} chains, {reachable} reachable from user input")

    # ── Module D ──────────────────────────────────────────
    print("[L2-D] Memory boundary surface mapper...")
    surface.memory_boundary_gaps = _run_module_d(
        client, files, repo_dir, all_findings, verbose
    )
    no_filter = sum(1 for g in surface.memory_boundary_gaps if not g.has_namespace_filter)
    print(f"       → {len(surface.memory_boundary_gaps)} gaps, {no_filter} with no namespace filter")

    # ── Module E ──────────────────────────────────────────
    print("[L2-E] Auth gap path tracer...")
    surface.auth_gap_paths = _run_module_e(
        client, files, repo_dir, all_findings, verbose
    )
    zero_auth = sum(1 for g in surface.auth_gap_paths if g.auth_gates == 0)
    print(f"       → {len(surface.auth_gap_paths)} paths, {zero_auth} with zero auth gates")

    # ── Flywheel Priors ────────────────────────────────────
    priors = None
    if output_dir:
        flywheel_path = find_flywheel(output_dir)
        flywheel_stats = read_flywheel(flywheel_path)
        if flywheel_stats.total_entries > 0:
            # Detect framework type from target URL
            target_lower = l1_report.target.lower()
            if any(x in target_lower for x in ["fastmcp","mcp-server"]):
                fw_type = "mcp_server"
            elif any(x in target_lower for x in ["crewai","langchain","llamaindex","autogen"]):
                fw_type = "orchestration"
            elif any(x in target_lower for x in ["chroma","weaviate","qdrant","pinecone"]):
                fw_type = "vector_db"
            else:
                fw_type = "agentic_ai"
            priors = generate_priors(flywheel_stats, fw_type, verbose=verbose)
            print(f"[L2] Flywheel: {flywheel_stats.total_entries} entries loaded "
                  f"| {len(priors.boosted_classes)} boosted, "
                  f"{len(priors.suppressed_classes)} suppressed classes")
        else:
            print("[L2] Flywheel: cold start (no prior history)")

    # ── Hypothesis Synthesis ───────────────────────────────
    print("[L2] Synthesizing ranked hypotheses...")
    surface.ranked_hypotheses = _synthesize_hypotheses(
        client, surface, all_findings, verbose, priors=priors
    )
    print(f"       → {len(surface.ranked_hypotheses)} hypotheses ranked by likelihood × blast radius")

    return surface
