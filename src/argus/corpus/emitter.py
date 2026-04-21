"""
argus/corpus/emitter.py — result directory → labeled JSONL training pairs.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator, Optional


@dataclass
class CorpusPair:
    """One (prompt, completion) training example with provenance."""
    source:          str     # "l1_finding" | "l5_chain" | "agent_finding" | "chain_poc"
    prompt:          str
    completion:      str
    label:           str     # vuln class / chain blast / agent id — for class balancing
    fingerprint:     str     # for dedup across runs
    provenance:      dict    # {run_dir, path, id}

    def to_dict(self) -> dict:
        return asdict(self)

    def to_oai_format(self) -> dict:
        """OpenAI fine-tune JSONL shape."""
        return {
            "messages": [
                {"role": "system",
                 "content": "You are ARGUS, an autonomous red-team AI for "
                            "agentic AI and MCP systems."},
                {"role": "user",      "content": self.prompt},
                {"role": "assistant", "content": self.completion},
            ]
        }

    def to_anthropic_format(self) -> dict:
        """Anthropic fine-tune message shape."""
        return {
            "prompt":     self.prompt,
            "completion": self.completion,
            "metadata":   {"label": self.label, "source": self.source},
        }


# ── Emitter ───────────────────────────────────────────────────────────────────

class CorpusEmitter:
    """Walks a results dir and yields training pairs."""

    def __init__(self, results_root: str,
                 min_prompt_chars: int = 40,
                 max_prompt_chars: int = 8_000) -> None:
        self.results_root = Path(results_root)
        self.min_prompt_chars = min_prompt_chars
        self.max_prompt_chars = max_prompt_chars

    def iter_pairs(self) -> Iterator[CorpusPair]:
        """Walk run directories under results_root and yield pairs."""
        if not self.results_root.exists():
            return

        for run_dir in sorted(self.results_root.iterdir()):
            if not run_dir.is_dir():
                continue
            yield from self._from_l1(run_dir)
            yield from self._from_l5(run_dir)
            yield from self._from_agents(run_dir)

    # ── Extractors ─────────────────────────────────────────────────────────

    def _from_l1(self, run_dir: Path) -> Iterator[CorpusPair]:
        p = run_dir / "layer1.json"
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return
        for f in (data.get("production_findings", [])
                  + data.get("example_findings", [])):
            title = f.get("title", "") or ""
            desc  = f.get("description", "") or ""
            snippet = f.get("code_snippet", "") or ""
            if not (title and desc):
                continue
            prompt = (
                "You are auditing an agentic AI repository. Given this "
                "code snippet, identify the vulnerability class and "
                "explain the attack.\n\n"
                f"FILE: {f.get('file', '?')}\n"
                f"CODE:\n{snippet[:self.max_prompt_chars]}"
            )
            completion = json.dumps({
                "vuln_class": f.get("vuln_class"),
                "severity":   f.get("severity"),
                "title":      title,
                "description": desc,
                "attack_vector": f.get("attack_vector"),
                "remediation": f.get("remediation"),
            }, indent=2)
            yield from self._emit(
                "l1_finding", prompt, completion,
                label=f.get("vuln_class", "UNKNOWN"),
                provenance={"run_dir": str(run_dir), "path": str(p),
                            "id": f.get("id", "")},
            )

    def _from_l5(self, run_dir: Path) -> Iterator[CorpusPair]:
        p = run_dir / "layer5.json"
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return
        for chain in data.get("chains", []):
            # Skip unvalidated chains — we only train on chains that
            # actually landed, otherwise we poison the model with
            # hallucinations. This is the whole point.
            if not chain.get("is_validated"):
                continue
            steps = chain.get("steps", [])
            prompt = (
                "You are ARGUS synthesizing an exploit chain. Given "
                "these component deviations, produce a reproducible "
                "multi-step chain with a real-library PoC.\n\n"
                f"COMPONENT_DEVIATIONS: {chain.get('component_deviations')}\n"
                f"TARGET_BLAST: {chain.get('blast_radius')}\n"
                f"ENTRY_POINT: {chain.get('entry_point')}"
            )
            completion = json.dumps({
                "title":  chain.get("title"),
                "steps":  steps,
                "poc_code": chain.get("poc_code", "")[:self.max_prompt_chars],
                "cvss_estimate": chain.get("cvss_estimate"),
            }, indent=2)
            yield from self._emit(
                "l5_chain", prompt, completion,
                label=chain.get("blast_radius", "MEDIUM"),
                provenance={"run_dir": str(run_dir),
                            "chain_id": chain.get("chain_id", "")},
            )

    def _from_agents(self, run_dir: Path) -> Iterator[CorpusPair]:
        agents_dir = run_dir / "agents"
        if not agents_dir.exists():
            return
        for agent_dir in agents_dir.iterdir():
            if not agent_dir.is_dir():
                continue
            for findings_file in agent_dir.glob("*_findings.json"):
                try:
                    data = json.loads(findings_file.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    continue
                for f in data.get("findings", []):
                    title = f.get("title", "") or ""
                    desc  = f.get("description", "") or ""
                    if not (title and desc):
                        continue
                    prompt = (
                        f"You are {data.get('agent_id', '?')} "
                        f"({data.get('agent_name', '')}), a specialist "
                        "offensive AI red-team agent. Given this file, "
                        "produce a finding if the vulnerability class "
                        "you specialize in is present.\n\n"
                        f"VULN_CLASS_SPECIALTY: {data.get('vuln_class')}\n"
                        f"FILE: {f.get('file', '?')}"
                    )
                    completion = json.dumps({
                        "severity":    f.get("severity"),
                        "title":       title,
                        "description": desc,
                        "technique":   f.get("technique"),
                        "remediation": f.get("remediation"),
                    }, indent=2)
                    yield from self._emit(
                        "agent_finding", prompt, completion,
                        label=data.get("agent_id", "UNKNOWN"),
                        provenance={"run_dir": str(run_dir),
                                    "path": str(findings_file),
                                    "id": f.get("id", "")},
                    )

    # ── Helpers ────────────────────────────────────────────────────────────

    def _emit(self, source: str, prompt: str, completion: str,
              label: str, provenance: dict) -> Iterator[CorpusPair]:
        if len(prompt) < self.min_prompt_chars:
            return
        fp = hashlib.sha256(
            (prompt[:2000] + "|" + completion[:2000]).encode("utf-8")
        ).hexdigest()[:16]
        yield CorpusPair(
            source=source, prompt=prompt, completion=completion,
            label=label, fingerprint=fp, provenance=provenance,
        )


# ── Convenience ───────────────────────────────────────────────────────────────

def emit_from_results(
    results_root: str,
    out_path:     str,
    format:       str = "anthropic",     # "anthropic" | "openai" | "raw"
    dedup:        bool = True,
) -> int:
    """
    Walk ``results_root`` and write a labeled JSONL at ``out_path``.
    Returns the number of pairs written. Dedup by fingerprint is on
    by default — same training pair across many runs counts once.
    """
    emitter = CorpusEmitter(results_root)
    seen: set[str] = set()
    written = 0
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        for pair in emitter.iter_pairs():
            if dedup and pair.fingerprint in seen:
                continue
            seen.add(pair.fingerprint)
            if format == "openai":
                rec = pair.to_oai_format()
            elif format == "anthropic":
                rec = pair.to_anthropic_format()
            else:
                rec = pair.to_dict()
            fh.write(json.dumps(rec) + "\n")
            written += 1
    return written
