"""VERDICT WEIGHT adapter for ARGUS findings.

Translates an ARGUS Finding into the inputs VERDICT WEIGHT expects,
calls the scoring engine, and returns a structured VerdictScore that
the agent can attach to the finding before emission.

Source Reliability priors are agent-type-specific:
- Deterministic scanners (Tool Poisoning hidden content) get high SR
- Pattern-based attacks (Prompt Injection corpus payloads) get medium SR
- LLM-generated novel variants get lower SR (more probabilistic)

Historical Accuracy priors are technique-specific:
- Built from observed track record across runs
- Bootstrapped from literature/benchmark validation rates
- Updated via Bayesian posterior as more outcomes accumulate

Temporal Decay uses corpus pattern age (when was this technique added?).
Cross-Feed Corroboration counts how many distinct techniques produced
findings against the same target surface.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import verdict_weight as vw

if TYPE_CHECKING:
    from argus.models.findings import Finding

logger = logging.getLogger(__name__)


# ============================================================
# Source Reliability priors per agent type
# ============================================================
#
# These are the per-source baseline credibility values fed into Stream 1
# (SR). Higher = more trusted source. Deterministic scanners with
# direct observation get the highest priors; probabilistic LLM-augmented
# techniques get lower priors.
#
# Bootstrap values from architectural reasoning. Updated via outcome
# data (Bayesian posterior) as ARGUS runs accumulate.

AGENT_RELIABILITY_PRIORS: dict[str, float] = {
    # Deterministic agents — direct observation, near-perfect FP rate
    "tool_poisoning": 0.95,  # zero-width / pattern scanners are deterministic
    "supply_chain": 0.92,  # typosquat detection is deterministic
    # Mixed agents — corpus-driven + LLM-augmented
    "prompt_injection_hunter": 0.78,  # corpus + canary detection
    # Phase 2+ agents (placeholder priors)
    "memory_poisoning": 0.85,
    "identity_spoof": 0.82,
    "context_window": 0.75,
    "cross_agent_exfiltration": 0.83,
    "privilege_escalation": 0.86,
    "race_condition": 0.80,
    "model_extraction": 0.70,
    # Correlation agent — uses LLM, lower SR until replay validates
    "correlation": 0.65,
}

DEFAULT_RELIABILITY_PRIOR = 0.75


# ============================================================
# Historical Accuracy priors per technique
# ============================================================
#
# Bootstrap track record per technique. These represent (correct,
# total) pairs that feed Stream 4 (HA) Bayesian update.
#
# Initial values are conservative — start with neutral 50% / Laplace
# smoothing and update from outcome data over time.

TECHNIQUE_HISTORICAL_ACCURACY: dict[str, tuple[int, int]] = {
    # Tool poisoning — deterministic scanners are very accurate
    "hidden_content_scan": (95, 100),
    "param_desc_scan_zero_width": (98, 100),
    "return_value_injection": (92, 100),
    # Prompt injection — corpus-based with canary validation
    "role_hijack_classic": (73, 100),
    "role_hijack_lowercase": (68, 100),
    "system_override": (71, 100),
    "you_are_now_admin": (66, 100),
    "role_hijack_debug_mode": (55, 100),
    "role_hijack_system_update": (50, 100),
    "delimiter_escape_xml": (62, 100),
    "delimiter_escape_markdown": (60, 100),
    "prompt_extraction_direct": (45, 100),
    "prompt_extraction_translate": (41, 100),
    "prompt_extraction_list": (48, 100),
    "guardrail_bypass_authorized": (35, 100),
    "guardrail_bypass_error_test": (32, 100),
    "tool_invocation_file_read": (40, 100),
    "tool_invocation_email": (38, 100),
    # Indirect injection
    "indirect_doc_markdown_comment": (70, 100),
    "indirect_doc_html_comment": (68, 100),
    "indirect_doc_visible_instruction": (55, 100),
    "indirect_web_html_comment": (66, 100),
    "indirect_web_override": (60, 100),
    # Encoded
    "encoded_base64": (35, 100),
    "encoded_rot13": (30, 100),
    "encoded_leetspeak": (28, 100),
    "encoded_unicode_homoglyph": (40, 100),
    "encoded_reverse": (25, 100),
    "encoded_pig_latin": (20, 100),
    # Multi-step
    "multistep:trust_then_exploit": (55, 100),
    "multistep:authority_escalation": (52, 100),
    "multistep:split_injection": (48, 100),
    # Supply chain
    "dependency_confusion_typosquat": (88, 100),
    "rug_pull_detection": (90, 100),
    "tool_output_injection": (75, 100),
    "mcp_trust_analysis": (70, 100),
    # Phase 2 — Memory poisoning. Two-step plant + observe-leak chain has very
    # low FP rate when sensitive markers are directly extracted from the
    # response (the gating condition for emission).
    "memory_poison": (90, 100),
    "memory_poison_system_override": (90, 100),
    "memory_poison_role_hijack": (88, 100),
    "memory_poison_indirect_extraction": (88, 100),
    "memory_poison_priv_escalation": (87, 100),
    # Phase 2 — Identity spoofing. Baseline vs spoof diff with concrete
    # status/marker change is high signal.
    "identity_spoof": (92, 100),
    "identity_baseline": (92, 100),
    # Phase 3 — Context window. Multi-turn attacks are harder to reproduce
    # deterministically, so priors are slightly lower.
    "early_authority_injection": (60, 100),
    "conditional_trigger": (55, 100),
    "trust_accumulation": (58, 100),
    "context_pollution": (62, 100),
    "instruction_burial": (50, 100),
    "attention_manipulation": (48, 100),
    "session_boundary_bypass": (52, 100),
    # Phase 3 — Cross-agent exfiltration. Relay-based attacks have moderate
    # FP rates because they depend on inter-agent communication being present.
    "agent_relay_exfil": (72, 100),
    "shared_resource_poisoning": (70, 100),
    "trust_chain_exploitation": (65, 100),
    "covert_channel": (60, 100),
    "output_aggregation_leak": (68, 100),
    # Phase 3 — Privilege escalation. Chained tool-call escalation has
    # high signal when the unauthorized outcome is directly observed.
    "sequential_chain_escalation": (78, 100),
    "confused_deputy": (75, 100),
    "scope_creep": (70, 100),
    "ordering_exploitation": (65, 100),
    "parameter_boundary_testing": (72, 100),
    "resource_exhaustion_bypass": (68, 100),
    # Phase 3 — Race condition. TOCTOU and parallel exploits are
    # inherently non-deterministic, lower confidence.
    "toctou_exploit": (55, 100),
    "parallel_session_isolation": (50, 100),
    "transaction_atomicity": (52, 100),
    "cache_poisoning_race": (48, 100),
    "quota_race": (45, 100),
    # Phase 4 — Model extraction. Prompt/config extraction is high
    # signal when system prompt content is directly observed.
    "system_prompt_extraction": (80, 100),
    "tool_inventory_extraction": (82, 100),
    "config_fingerprinting": (75, 100),
    "behavior_boundary_mapping": (60, 100),
    "training_data_inference": (45, 100),
    "user_data_inference": (50, 100),
}


@dataclass
class VerdictScore:
    """Structured VERDICT WEIGHT score result for an ARGUS finding."""

    consequence_weight: float
    signal_strength: float
    doubt_index: float
    action_tier: str
    interpretation: str
    streams: dict[str, float]
    source_reliability: float
    n_corroborating: int
    historical_accuracy: tuple[int, int]
    framework: str = "VERDICT WEIGHT"
    framework_version: str = vw.__version__ if hasattr(vw, "__version__") else "1.x"

    @property
    def is_validated(self) -> bool:
        """CW >= 0.70 means validated (high confidence, surface to operator)."""
        return self.consequence_weight >= 0.70

    @property
    def is_low_confidence(self) -> bool:
        """0.40 <= CW < 0.70 means surface with low-confidence caveat."""
        return 0.40 <= self.consequence_weight < 0.70

    @property
    def is_suppressed(self) -> bool:
        """CW < 0.40 means suppress from operator-facing output."""
        return self.consequence_weight < 0.40

    def to_dict(self) -> dict[str, Any]:
        return {
            "consequence_weight": round(self.consequence_weight, 4),
            "signal_strength": round(self.signal_strength, 4),
            "doubt_index": round(self.doubt_index, 4),
            "action_tier": self.action_tier,
            "interpretation": self.interpretation,
            "streams": {k: round(v, 4) for k, v in self.streams.items()},
            "source_reliability": round(self.source_reliability, 4),
            "n_corroborating": self.n_corroborating,
            "historical_accuracy": list(self.historical_accuracy),
            "framework": self.framework,
            "framework_version": self.framework_version,
            "validated": self.is_validated,
            "low_confidence": self.is_low_confidence,
            "suppressed": self.is_suppressed,
        }


class VerdictAdapter:
    """Adapter that translates ARGUS findings into VERDICT WEIGHT scoring calls.

    The adapter is stateful in one important way: it tracks corroboration
    counts across findings within a single scan. When two findings share
    the same target surface and technique family, the second finding's
    n_corroborating goes up.

    Usage:
        adapter = VerdictAdapter()
        score = adapter.score_finding(
            finding,
            corroborating_count=2,  # 2 other techniques confirmed this
        )
        finding.verdict_score = score.to_dict()
    """

    def __init__(self, context: Any | None = None) -> None:
        self._engine = vw.VerdictWeight()
        self._context = context or vw.ContextType.CYBERSECURITY_GENERAL
        # Track per-(target_surface, technique_family) corroboration counts
        self._corroboration: dict[tuple[str, str], int] = {}
        # Async lock to protect corroboration dict from concurrent agent updates
        self._lock = asyncio.Lock()

    def _technique_family(self, technique: str) -> str:
        """Group related techniques into a single family for corroboration counting.

        E.g., role_hijack_classic, role_hijack_lowercase, role_hijack_debug_mode
        all belong to the role_hijack family.
        """
        if not technique:
            return "unknown"
        # Strip variant suffixes — corpus:pi-direct-001:variant -> corpus:pi-direct-001
        family = technique.split(":variant")[0]
        # Strip "trigger:" prefix that Phase 2 agents emit on the second turn
        if family.startswith("trigger:"):
            family = family[len("trigger:") :]
        # Strip "identity_spoof:command_name" -> "identity_spoof"
        if family.startswith("identity_spoof:"):
            return "identity_spoof"
        # Strip role_hijack_X / memory_poison_X / Phase 3-4 suffixes
        for prefix in (
            "role_hijack",
            "prompt_extraction",
            "delimiter_escape",
            "guardrail_bypass",
            "tool_invocation",
            "indirect_doc",
            "indirect_web",
            "encoded",
            "multistep",
            "memory_poison",
            "identity_spoof",
            # Phase 3-4 technique families
            "early_authority",
            "conditional_trigger",
            "trust_accumulation",
            "context_pollution",
            "instruction_burial",
            "attention_manipulation",
            "session_boundary",
            "agent_relay",
            "shared_resource",
            "trust_chain",
            "covert_channel",
            "output_aggregation",
            "sequential_chain",
            "confused_deputy",
            "scope_creep",
            "ordering_exploitation",
            "parameter_boundary",
            "resource_exhaustion",
            "toctou",
            "parallel_session",
            "transaction_atomicity",
            "cache_poisoning",
            "quota_race",
            "system_prompt_extraction",
            "tool_inventory",
            "config_fingerprint",
            "behavior_boundary",
            "training_data",
            "user_data",
        ):
            if family.startswith(prefix):
                return prefix
        return family

    def get_source_reliability(self, agent_type: str) -> float:
        return AGENT_RELIABILITY_PRIORS.get(agent_type, DEFAULT_RELIABILITY_PRIOR)

    def get_historical_accuracy(self, technique: str) -> tuple[int, int]:
        # Try exact match first, then family match, then default
        if technique in TECHNIQUE_HISTORICAL_ACCURACY:
            return TECHNIQUE_HISTORICAL_ACCURACY[technique]
        family = self._technique_family(technique)
        if family in TECHNIQUE_HISTORICAL_ACCURACY:
            return TECHNIQUE_HISTORICAL_ACCURACY[family]
        # Default neutral prior
        return (50, 100)

    async def register_for_corroboration(
        self,
        target_surface: str,
        technique: str,
    ) -> int:
        """Increment corroboration count for this target/technique-family pair.

        Returns the new count (1 if this is the first observation).
        Lock-protected so concurrent agent updates produce correct counts.
        """
        family = self._technique_family(technique)
        key = (target_surface or "unknown", family)
        async with self._lock:
            self._corroboration[key] = self._corroboration.get(key, 0) + 1
            return self._corroboration[key]

    async def score_finding(
        self,
        finding: Finding,
        age_value: float = 0.0,
        n_corroborating_override: int | None = None,
    ) -> VerdictScore:
        """Score a finding via VERDICT WEIGHT and return a VerdictScore.

        Args:
            finding: the ARGUS finding to score
            age_value: corpus pattern age in domain-appropriate units (default 0 = fresh)
            n_corroborating_override: override the auto-tracked corroboration count
        """
        agent_type = finding.agent_type
        technique = finding.technique or ""
        target_surface = finding.target_surface or ""

        sr = self.get_source_reliability(agent_type)
        correct, total = self.get_historical_accuracy(technique)

        if n_corroborating_override is not None:
            n_corroborating = n_corroborating_override
        else:
            n_corroborating = await self.register_for_corroboration(target_surface, technique)

        # If the finding is already marked as direct evidence (canary observed,
        # zero-width chars present, etc.), bump SR upward — direct observation
        # is the strongest source.
        if finding.validation and finding.validation.validation_method == "direct_observation":
            sr = min(0.99, sr + 0.05)

        try:
            result = self._engine.score(
                source_reliability=sr,
                n_corroborating_sources=max(1, n_corroborating),
                age_value=age_value,
                correct_predictions=correct,
                total_predictions=total,
                context=self._context,
            )
        except Exception as exc:
            logger.warning("VERDICT WEIGHT scoring failed for finding %s: %s", finding.id[:8], exc)
            # Fail safe: return a neutral score
            return VerdictScore(
                consequence_weight=0.5,
                signal_strength=0.5,
                doubt_index=0.5,
                action_tier="UNKNOWN",
                interpretation="Scoring failed, default neutral score applied",
                streams={},
                source_reliability=sr,
                n_corroborating=n_corroborating,
                historical_accuracy=(correct, total),
            )

        return VerdictScore(
            consequence_weight=float(result.consequence_weight),
            signal_strength=float(result.signal_strength),
            doubt_index=float(result.doubt_index),
            action_tier=result.action_tier,
            interpretation=result.interpretation,
            streams=dict(result.streams),
            source_reliability=sr,
            n_corroborating=n_corroborating,
            historical_accuracy=(correct, total),
        )

    def reset_corroboration(self) -> None:
        """Reset corroboration tracking. Call between scans."""
        self._corroboration.clear()
