"""
argus/swarm/correlator.py

Live Correlation Agent — the patent-defining piece.

While offensive agents post findings to the blackboard, this worker watches
the stream in real time and fires chain hypotheses as soon as findings
compose into something exploitable. The existing L5 Opus synthesizer runs
only ONCE at end-of-pipeline against a static snapshot; this correlator
runs continuously and catches chains that form across agents mid-run.

Trigger rules (cheap to evaluate, gate the expensive Haiku / Opus calls):

  1. Two findings sharing the same file path.
  2. Two findings whose agents' MAAC_PHASES are complementary (e.g.
     phase 2 Prompt-Layer Access composed with phase 5 Tool Misuse).
  3. Three or more findings within a rolling 30-second window.

When a trigger fires we ask Haiku "do these actually chain?" — if yes and
confidence >= COR_OPUS_THRESHOLD, we escalate to Opus for full synthesis
and post the resulting ChainHypothesis to the blackboard.

Budget (env vars, honoured by the blackboard subscription layer):
  ARGUS_CORRELATOR_HAIKU_CALLS   max Haiku calls per run   (default 40)
  ARGUS_CORRELATOR_OPUS_CALLS    max Opus calls per run    (default  5)
  ARGUS_CORRELATOR_WINDOW_SECS   rolling window for trigger rule 3 (30)
  ARGUS_CORRELATOR_OPUS_THRESHOLD Haiku->Opus promotion cut (0.7)
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Optional

from argus.agents.base import AgentFinding, BaseAgent
from argus.shared.client import ArgusClient
from argus.shared.prompts import HAIKU_MODEL, OPUS_MODEL
from argus.swarm.blackboard import Blackboard, ChainHypothesis


# ── Config ────────────────────────────────────────────────────────────────────

HAIKU_CALL_BUDGET    = int(os.environ.get("ARGUS_CORRELATOR_HAIKU_CALLS", "40"))
OPUS_CALL_BUDGET     = int(os.environ.get("ARGUS_CORRELATOR_OPUS_CALLS", "5"))
TRIGGER_WINDOW_SECS  = float(os.environ.get("ARGUS_CORRELATOR_WINDOW_SECS", "30"))
OPUS_THRESHOLD       = float(os.environ.get("ARGUS_CORRELATOR_OPUS_THRESHOLD", "0.7"))


# Precompute which MAAC phase pairs are "complementary" — i.e. the kill-chain
# expects them to compose. Source: Truong MAAC Chapter 320, Table MAAC Phase
# Summary. Pairs where an attacker uses A as the setup for B.
COMPLEMENTARY_MAAC_PAIRS: set[frozenset[int]] = {
    frozenset([1, 2]),   # Recon -> Prompt-Layer Access
    frozenset([2, 3]),   # Prompt-Layer -> Model-Layer Manip
    frozenset([2, 5]),   # Prompt-Layer -> Tool Misuse
    frozenset([2, 6]),   # Prompt-Layer -> Orchestration Drift
    frozenset([3, 6]),   # Model-Layer -> Orchestration Drift
    frozenset([4, 7]),   # Memory Corruption -> Multi-Agent Escalation
    frozenset([5, 8]),   # Tool Misuse -> Environment Pivoting
    frozenset([5, 9]),   # Tool Misuse -> Impact
    frozenset([6, 7]),   # Orchestration Drift -> Multi-Agent Escalation
    frozenset([7, 8]),   # Multi-Agent Escalation -> Environment Pivoting
    frozenset([8, 9]),   # Environment Pivoting -> Impact
}


# ── Data ──────────────────────────────────────────────────────────────────────

@dataclass
class _SeenFinding:
    finding: AgentFinding
    ts_mono: float


# ── Correlator ────────────────────────────────────────────────────────────────

class LiveCorrelator:
    """
    Runs in its own thread. Subscribes to finding events on the blackboard
    and fires ChainHypotheses when triggers match. Stops when `stop_event`
    is set (typically after all agent threads finish).
    """

    def __init__(
        self,
        blackboard: Blackboard,
        agent_registry: dict[str, type[BaseAgent]],
        stop_event: threading.Event,
        verbose: bool = False,
        priors: Optional[object] = None,
        repo_path: Optional[str] = None,
    ) -> None:
        self.bb           = blackboard
        self.registry     = agent_registry
        self.stop_event   = stop_event
        self.verbose      = verbose
        self.client       = ArgusClient()
        # FlywheelPriors or None. When present, Haiku/Opus prompts get a
        # short prior summary and confidence floors rise for boosted classes.
        self.priors       = priors
        self.repo_path    = repo_path
        # Resolve the target's installed-package namespace once so the
        # Opus synthesis prompt knows to write `from crewai...` rather
        # than `from crewai.src.crewai...` (the disk layout).
        self._target_packages: list[str] = []
        if repo_path:
            try:
                from argus.layer7.sandbox import target_packages as _tp
                self._target_packages = _tp(repo_path) or []
            except Exception:
                pass

        self._seen: list[_SeenFinding] = []
        self._lock  = threading.Lock()

        self._haiku_calls = 0
        self._opus_calls  = 0

        # Track clusters we've already asked Haiku about so we don't burn
        # budget on duplicates.
        self._evaluated_clusters: set[str] = set()

    def _prior_summary(self) -> str:
        """Short textual prior fed into Haiku/Opus prompts. Empty on cold start."""
        if not self.priors:
            return ""
        s = getattr(self.priors, "prior_summary", "") or ""
        return s[:500]  # hard cap — priors must not bloat correlator prompts

    # ── Thread entry point ────────────────────────────────────────────────

    def run(self) -> None:
        if self.verbose:
            print(f"[correlator] live correlator started "
                  f"(haiku budget {HAIKU_CALL_BUDGET}, opus budget {OPUS_CALL_BUDGET})")
        cursor = 0
        while not self.stop_event.is_set():
            new = self.bb.findings(after=cursor)
            if new:
                cursor += len(new)
                for f in new:
                    self._ingest(f)
            else:
                time.sleep(0.5)
        # Final flush — evaluate any triggers we deferred
        self._final_flush()
        if self.verbose:
            print(f"[correlator] done. haiku={self._haiku_calls}, "
                  f"opus={self._opus_calls}, "
                  f"hypotheses={len(self.bb.hypotheses())}")

    # ── Ingestion + triggers ──────────────────────────────────────────────

    def _ingest(self, f: AgentFinding) -> None:
        with self._lock:
            self._seen.append(_SeenFinding(finding=f, ts_mono=time.monotonic()))

        for cluster in self._candidate_clusters(f):
            self._evaluate_cluster(cluster)

    def _candidate_clusters(self, trigger: AgentFinding) -> list[list[AgentFinding]]:
        """
        Build small clusters (2-5 findings) worth asking the LLM about.
        Only returns clusters we haven't already evaluated this run.
        """
        with self._lock:
            seen = list(self._seen)

        clusters: list[list[AgentFinding]] = []

        # Rule 1: same-file pair
        same_file = [s.finding for s in seen
                     if s.finding.file == trigger.file
                     and s.finding.id != trigger.id]
        for other in same_file[-3:]:
            clusters.append([other, trigger])

        # Rule 2: complementary MAAC phase pair
        trigger_phases = set(self._phases_for(trigger.agent_id))
        for s in seen:
            if s.finding.id == trigger.id:
                continue
            other_phases = set(self._phases_for(s.finding.agent_id))
            for tp in trigger_phases:
                for op in other_phases:
                    if frozenset({tp, op}) in COMPLEMENTARY_MAAC_PAIRS:
                        clusters.append([s.finding, trigger])
                        break
                else:
                    continue
                break

        # Rule 3: 3+ findings in rolling window
        now = time.monotonic()
        recent = [s.finding for s in seen
                  if now - s.ts_mono <= TRIGGER_WINDOW_SECS]
        if len(recent) >= 3:
            # Take the top 5 by severity rank
            sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            recent.sort(key=lambda f: sev_rank.get(f.severity, 9))
            clusters.append(recent[:5])

        # Deduplicate by cluster-fingerprint
        unique: list[list[AgentFinding]] = []
        for c in clusters:
            fp = self._cluster_fingerprint(c)
            if fp not in self._evaluated_clusters:
                unique.append(c)
        return unique

    def _evaluate_cluster(self, cluster: list[AgentFinding]) -> None:
        fp = self._cluster_fingerprint(cluster)
        self._evaluated_clusters.add(fp)

        if self._haiku_calls >= HAIKU_CALL_BUDGET:
            return

        verdict = self._haiku_judge(cluster)
        self._haiku_calls += 1
        if verdict is None:
            return
        chains, confidence = verdict
        if not chains:
            return

        # Always post a hypothesis (cheap) so the operator can see the trail
        hyp = ChainHypothesis(
            hypothesis_id=fp,
            title=chains[0].get("title", "Unnamed chain"),
            finding_ids=[f.id for f in cluster],
            rationale=chains[0].get("rationale", "")[:400],
            confidence=confidence,
            proposed_by="correlator",
        )
        self.bb.post_hypothesis(hyp)

        # Escalate to Opus only if Haiku is confident enough and we have budget
        if (confidence >= OPUS_THRESHOLD
                and self._opus_calls < OPUS_CALL_BUDGET):
            self._opus_synthesize(cluster, hyp)
            self._opus_calls += 1

    def _final_flush(self) -> None:
        # Evaluate any remaining unique clusters we haven't hit yet.
        with self._lock:
            findings = [s.finding for s in self._seen]
        if len(findings) >= 3 and self._haiku_calls < HAIKU_CALL_BUDGET:
            sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            findings.sort(key=lambda f: sev_rank.get(f.severity, 9))
            cluster = findings[:6]
            fp = self._cluster_fingerprint(cluster)
            if fp not in self._evaluated_clusters:
                self._evaluate_cluster(cluster)

    # ── LLM calls ─────────────────────────────────────────────────────────

    def _haiku_judge(self, cluster: list[AgentFinding]) -> Optional[tuple[list[dict], float]]:
        """Ask Haiku: do these findings actually chain? Return (chains, confidence)."""
        summary = "\n".join(
            f"[{f.id}] {f.agent_id} {f.severity} {f.vuln_class} "
            f"| file={f.file} | technique={f.technique}\n"
            f"  {f.description[:200]}"
            for f in cluster
        )
        prior_block = self._prior_summary()
        prior_clause = (f"\n\nHISTORICAL PRIORS (bias toward these but do not "
                        f"fabricate evidence):\n{prior_block}\n") if prior_block else ""
        prompt = (
            "You are a senior red-team correlator. Given these findings "
            "from different offensive agents, decide whether they COMPOSE "
            "into a real attack chain against the same target, or whether "
            "they are independent. Do NOT invent new steps; only chain on "
            "evidence from the summaries.\n\n"
            "Return JSON ONLY:\n"
            '{"chains": [{"title": "...", "rationale": "...", '
            '"confidence": 0.0-1.0}]}\n'
            "If they do not chain, return {\"chains\": []}."
            f"{prior_clause}\n"
            f"FINDINGS:\n{summary}"
        )
        try:
            resp = self.client.messages.create(
                model=HAIKU_MODEL,
                max_tokens=800,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = resp.content[0].text.strip()
            if raw.startswith("```"):
                raw = "\n".join(raw.split("\n")[1:-1])
            data = json.loads(raw)
            chains = data.get("chains", [])
            if not chains:
                return [], 0.0
            confidence = float(chains[0].get("confidence", 0.0))
            return chains, max(0.0, min(1.0, confidence))
        except (json.JSONDecodeError, KeyError, ValueError, AttributeError) as e:
            if self.verbose:
                print(f"[correlator] haiku parse failed: {e}")
            return None
        except Exception as e:
            if self.verbose:
                print(f"[correlator] haiku call failed: {e}")
            return None

    def _opus_synthesize(self, cluster: list[AgentFinding], hyp: ChainHypothesis) -> None:
        """
        Escalate to Opus for a full chain synthesis with reproducible PoC.
        Writes the resulting chain back onto the blackboard as an annotation
        so L5 can ingest it at end-of-pipeline.
        """
        summary = "\n".join(
            f"[{f.id}] {f.agent_id} {f.severity} {f.vuln_class} "
            f"file={f.file}:{getattr(f, 'line_hint', '?')}\n"
            f"  {f.description[:300]}"
            for f in cluster
        )
        tpkg_line = (", ".join(self._target_packages)
                     if self._target_packages
                     else "(none resolved — derive from file paths shown)")
        prompt = (
            "You are a senior offensive security researcher. The findings "
            "below were flagged as a candidate chain by the correlator. "
            "Produce a reproducible attack chain per the ARGUS PoC contract:\n"
            "  - Import from the INSTALLED package namespace listed in "
            "    TARGET_PACKAGES below — NOT the repo's on-disk layout. "
            "    e.g. `from crewai.agents.agent_builder.base_agent "
            "    import BaseAgent`, never `from crewai.src.crewai ...`.\n"
            "  - NEVER redeclare the vulnerable class in the PoC.\n"
            "  - Actually CALL an imported symbol with attacker input. "
            "    PoCs that import but don't call are rejected by the "
            "    static gate before the sandbox ever runs.\n"
            "  - Prints `ARGUS_POC_LANDED:{chain_id}` on success.\n"
            "  - sys.exit(1) if the vulnerable path is not reached.\n"
            "  - Non-destructive; /tmp marker + stdout only.\n\n"
            f"TARGET_PACKAGES: {tpkg_line}\n"
            f"CHAIN_ID: {hyp.hypothesis_id}\n"
            f"CANDIDATE TITLE: {hyp.title}\n\n"
            f"FINDINGS:\n{summary}\n\n"
            "Return JSON ONLY:\n"
            '{"title": "...", "steps": ['
            '{"step": 1, "action": "...", "payload": "...", "achieves": "..."}], '
            '"poc_code": "complete python, \\n for newlines", '
            '"cvss_estimate": "...", "blast_radius": "CRITICAL|HIGH|MEDIUM", '
            '"preconditions": ["..."]}'
        )
        try:
            resp = self.client.messages.create(
                model=OPUS_MODEL,
                max_tokens=4000,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = resp.content[0].text.strip()
            if raw.startswith("```"):
                raw = "\n".join(raw.split("\n")[1:-1])
            data = json.loads(raw)
        except (json.JSONDecodeError, Exception) as e:
            if self.verbose:
                print(f"[correlator] opus synthesis failed: {e}")
            return

        # Persist the synthesized chain as an annotation so the final L5
        # sweep (or the CLI summariser) can pick it up.
        self.bb.annotate_finding(
            finding_id=hyp.hypothesis_id,
            key="opus_chain",
            value=data,
        )
        if self.verbose:
            title = data.get("title", "")[:60]
            print(f"[correlator] opus chain: {title}")

    # ── Utilities ─────────────────────────────────────────────────────────

    def _phases_for(self, agent_id: str) -> list[int]:
        cls = self.registry.get(agent_id)
        if not cls:
            return []
        return list(getattr(cls, "MAAC_PHASES", []) or [])

    @staticmethod
    def _cluster_fingerprint(cluster: list[AgentFinding]) -> str:
        ids = sorted(f.id for f in cluster)
        return "hyp-" + hashlib.md5("|".join(ids).encode()).hexdigest()[:10]
