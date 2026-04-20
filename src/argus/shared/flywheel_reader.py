"""
shared/flywheel_reader.py
Intelligence Flywheel Reader

Reads flywheel.jsonl and turns accumulated scan history into ranked priors
that feed into L2 hypothesis synthesis. This is what makes ARGUS smarter
with every scan — the compounding moat.

What the flywheel knows after N scans:
  - Which attack classes fire most often in which framework types
  - Which fuzz modalities produce confirmed findings (not just findings)
  - Which chain patterns appear repeatedly (high-yield attack signatures)
  - Which entry point types produce critical findings
  - Effective vs ineffective technique combinations

How it feeds L2:
  - _synthesize_hypotheses() gets FlywheelPriors as extra context
  - Haiku re-ranks hypotheses using historical success rates
  - High-yield attack classes for this framework type get boosted likelihood
  - Ineffective attack classes get suppressed (saves cost, improves signal)

After 10 scans : basic pattern recognition
After 50 scans : framework-specific attack signatures
After 100 scans: proprietary zero-day discovery intelligence
"""
from __future__ import annotations

import json
import os
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class AttackClassStats:
    """Historical stats for a single attack class."""
    attack_class:        str
    total_occurrences:   int = 0
    critical_chain_count: int = 0
    high_chain_count:    int = 0
    effective_modalities: list[str] = field(default_factory=list)
    framework_types:     list[str] = field(default_factory=list)
    # Derived
    critical_rate:       float = 0.0   # critical_chains / total_occurrences
    yield_score:         float = 0.0   # composite score for hypothesis boosting


@dataclass
class FrameworkProfile:
    """Historical attack profile for a framework type."""
    framework_type:      str
    total_scans:         int = 0
    top_attack_classes:  list[str] = field(default_factory=list)   # ordered by yield
    top_modalities:      list[str] = field(default_factory=list)   # most effective
    common_entry_points: list[str] = field(default_factory=list)
    avg_critical_chains: float = 0.0


@dataclass
class FlywheelPriors:
    """
    Ranked attack priors derived from flywheel history.
    Fed into L2 hypothesis synthesis to pre-rank hypotheses.

    Empty priors = cold start (first scan).
    Rich priors = experienced attacker (50+ scans).
    """
    total_scans:          int = 0
    framework_profile:    Optional[FrameworkProfile] = None
    ranked_attack_classes: list[AttackClassStats] = field(default_factory=list)
    boosted_classes:      list[str] = field(default_factory=list)   # historical high yield
    suppressed_classes:   list[str] = field(default_factory=list)   # historically ineffective
    recommended_modalities: list[str] = field(default_factory=list)
    prior_summary:        str = ""   # human-readable summary for L2 prompt injection


@dataclass
class FlywheelStats:
    """Full aggregate statistics from all flywheel entries."""
    total_entries:        int = 0
    total_scans:          int = 0
    framework_types_seen: list[str] = field(default_factory=list)
    attack_class_stats:   dict[str, AttackClassStats] = field(default_factory=dict)
    framework_profiles:   dict[str, FrameworkProfile] = field(default_factory=dict)
    modality_effectiveness: dict[str, float] = field(default_factory=dict)
    entry_point_yield:    dict[str, float] = field(default_factory=dict)


# ── Reader ────────────────────────────────────────────────────────────────────

def read_flywheel(flywheel_path: str) -> FlywheelStats:
    """
    Load and aggregate all flywheel entries into FlywheelStats.
    Returns empty stats if file doesn't exist (cold start).
    """
    stats = FlywheelStats()

    if not os.path.exists(flywheel_path):
        return stats  # cold start — no history

    entries = []
    with open(flywheel_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not entries:
        return stats

    stats.total_entries = len(entries)

    # ── Aggregate by framework type ──────────────────────────────────────
    framework_data: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        ft = entry.get("framework_type", "unknown")
        framework_data[ft].append(entry)

    stats.framework_types_seen = list(framework_data.keys())

    # ── Aggregate attack class statistics ────────────────────────────────
    class_raw: dict[str, dict] = defaultdict(lambda: {
        "occurrences": 0, "critical": 0, "high": 0,
        "modalities": Counter(), "frameworks": Counter()
    })

    for entry in entries:
        for cls in entry.get("vuln_classes", []):
            class_raw[cls]["occurrences"] += 1
            br = entry.get("blast_radius", "LOW")
            if br == "CRITICAL":
                class_raw[cls]["critical"] += 1
            elif br == "HIGH":
                class_raw[cls]["high"] += 1
            for mod in entry.get("effective_modalities", []):
                class_raw[cls]["modalities"][mod] += 1
            ft = entry.get("framework_type", "unknown")
            class_raw[cls]["frameworks"][ft] += 1

    for cls, data in class_raw.items():
        occ = data["occurrences"]
        crit_rate = data["critical"] / occ if occ > 0 else 0.0
        high_rate = (data["critical"] + data["high"]) / occ if occ > 0 else 0.0
        yield_score = (crit_rate * 0.6) + (high_rate * 0.3) + min(occ / 10, 0.1)

        stats.attack_class_stats[cls] = AttackClassStats(
            attack_class=cls,
            total_occurrences=occ,
            critical_chain_count=data["critical"],
            high_chain_count=data["high"],
            effective_modalities=[m for m, _ in data["modalities"].most_common(3)],
            framework_types=[f for f, _ in data["frameworks"].most_common(3)],
            critical_rate=round(crit_rate, 3),
            yield_score=round(yield_score, 3)
        )

    # ── Build framework profiles ──────────────────────────────────────────
    for ft, ft_entries in framework_data.items():
        class_counter: Counter = Counter()
        mod_counter:   Counter = Counter()
        ep_counter:    Counter = Counter()
        crit_chains = 0

        for entry in ft_entries:
            for cls in entry.get("vuln_classes", []):
                class_counter[cls] += 1
                if entry.get("blast_radius") == "CRITICAL":
                    crit_chains += 1
            for mod in entry.get("effective_modalities", []):
                mod_counter[mod] += 1
            ep = entry.get("entry_point_type", "")
            if ep:
                ep_counter[ep] += 1

        stats.framework_profiles[ft] = FrameworkProfile(
            framework_type=ft,
            total_scans=len(ft_entries),
            top_attack_classes=[c for c, _ in class_counter.most_common(5)],
            top_modalities=[m for m, _ in mod_counter.most_common(3)],
            common_entry_points=[e for e, _ in ep_counter.most_common(3)],
            avg_critical_chains=round(crit_chains / max(len(ft_entries), 1), 2)
        )

    # ── Global modality effectiveness ─────────────────────────────────────
    mod_total:  Counter = Counter()
    mod_crit:   Counter = Counter()
    for entry in entries:
        br = entry.get("blast_radius", "LOW")
        for mod in entry.get("effective_modalities", []):
            mod_total[mod] += 1
            if br in ("CRITICAL", "HIGH"):
                mod_crit[mod] += 1

    for mod, total in mod_total.items():
        stats.modality_effectiveness[mod] = round(mod_crit[mod] / total, 3) if total > 0 else 0.0

    # ── Entry point yield ─────────────────────────────────────────────────
    ep_total: Counter = Counter()
    ep_crit:  Counter = Counter()
    for entry in entries:
        ep = entry.get("entry_point_type", "")
        if not ep:
            continue
        ep_total[ep] += 1
        if entry.get("blast_radius") in ("CRITICAL", "HIGH"):
            ep_crit[ep] += 1

    for ep, total in ep_total.items():
        stats.entry_point_yield[ep] = round(ep_crit[ep] / total, 3) if total > 0 else 0.0

    stats.total_scans = len(set(
        entry.get("scan_date", "")[:10] + entry.get("framework_type", "")
        for entry in entries
    ))

    return stats


# ── Prior Generator ───────────────────────────────────────────────────────────

def generate_priors(
    stats: FlywheelStats,
    target_framework_type: str,
    verbose: bool = False
) -> FlywheelPriors:
    """
    Convert FlywheelStats into actionable priors for a specific target.
    Boosts attack classes that historically yield CRITICAL findings.
    Suppresses classes that rarely produce anything.
    """
    priors = FlywheelPriors(total_scans=stats.total_scans)

    if stats.total_entries == 0:
        priors.prior_summary = "No prior scan history (cold start)."
        return priors

    # Framework-specific profile
    profile = stats.framework_profiles.get(
        target_framework_type,
        stats.framework_profiles.get("agentic_ai")  # fallback
    )
    priors.framework_profile = profile

    # Rank attack classes by yield score
    ranked = sorted(
        stats.attack_class_stats.values(),
        key=lambda x: x.yield_score,
        reverse=True
    )
    priors.ranked_attack_classes = ranked

    # Boost: yield_score > 0.5 AND seen in this framework type
    # Suppress: yield_score < 0.1 AND seen 3+ times (not just rare)
    for cls_stats in ranked:
        is_relevant_framework = (
            target_framework_type in cls_stats.framework_types or
            not cls_stats.framework_types  # seen in all types
        )
        if cls_stats.yield_score > 0.5 and is_relevant_framework:
            priors.boosted_classes.append(cls_stats.attack_class)
        elif cls_stats.yield_score < 0.1 and cls_stats.total_occurrences >= 3:
            priors.suppressed_classes.append(cls_stats.attack_class)

    # Recommended modalities — highest effectiveness for this framework
    if profile:
        priors.recommended_modalities = profile.top_modalities
    else:
        # Global best modalities
        priors.recommended_modalities = sorted(
            stats.modality_effectiveness.keys(),
            key=lambda m: stats.modality_effectiveness[m],
            reverse=True
        )[:3]

    # Build human-readable summary for L2 prompt injection
    priors.prior_summary = _build_prior_summary(priors, stats, target_framework_type)

    if verbose:
        print(f"\n[FLYWHEEL] Loaded {stats.total_entries} entries from {stats.total_scans} scans")
        print(f"  Framework: {target_framework_type}")
        print(f"  Boosted  : {priors.boosted_classes}")
        print(f"  Suppressed: {priors.suppressed_classes}")
        print(f"  Best modalities: {priors.recommended_modalities}")

    return priors


def _build_prior_summary(
    priors: FlywheelPriors,
    stats: FlywheelStats,
    framework_type: str
) -> str:
    """Build the prior summary injected into the L2 hypothesis prompt."""
    if stats.total_entries == 0:
        return ""

    lines = [
        f"FLYWHEEL INTELLIGENCE ({stats.total_entries} historical findings across {stats.total_scans} scans):",
        f"Framework type: {framework_type}",
    ]

    if priors.framework_profile:
        fp = priors.framework_profile
        lines.append(
            f"This framework type has been scanned {fp.total_scans} times. "
            f"Average CRITICAL chains per scan: {fp.avg_critical_chains}."
        )
        if fp.top_attack_classes:
            lines.append(
                f"Highest-yield attack classes for {framework_type}: "
                f"{', '.join(fp.top_attack_classes[:3])}."
            )

    if priors.boosted_classes:
        lines.append(
            f"PRIORITIZE these attack classes (historically produced CRITICAL findings): "
            f"{', '.join(priors.boosted_classes[:5])}."
        )

    if priors.suppressed_classes:
        lines.append(
            f"DEPRIORITIZE these attack classes (rarely produced findings after multiple scans): "
            f"{', '.join(priors.suppressed_classes[:3])}."
        )

    if priors.recommended_modalities:
        lines.append(
            f"Most effective fuzzing modalities for this framework: "
            f"{', '.join(priors.recommended_modalities)}."
        )

    # Top individual attack class insights
    for cls_stats in priors.ranked_attack_classes[:3]:
        if cls_stats.critical_chain_count > 0:
            lines.append(
                f"{cls_stats.attack_class}: {cls_stats.critical_chain_count} critical chains "
                f"from {cls_stats.total_occurrences} scans "
                f"({cls_stats.critical_rate:.0%} critical rate). "
                f"Best entry: {cls_stats.effective_modalities[0] if cls_stats.effective_modalities else 'any'}."
            )

    return "\n".join(lines)


# ── Utilities ─────────────────────────────────────────────────────────────────

def find_flywheel(output_dir: str) -> str:
    """Walk up from output_dir to find flywheel.jsonl."""
    path = Path(output_dir).resolve()
    for _ in range(4):  # max 4 levels up
        candidate = path / "flywheel.jsonl"
        if candidate.exists():
            return str(candidate)
        path = path.parent
    # Default: one level above output_dir
    return str(Path(output_dir).parent / "flywheel.jsonl")


def print_flywheel_report(stats: FlywheelStats) -> None:
    """Print a summary of flywheel state — useful for `argus_zd.py --flywheel-report`."""
    print(f"\n{'━'*62}")
    print(f"\033[1m  INTELLIGENCE FLYWHEEL REPORT\033[0m")
    print(f"{'━'*62}")
    print(f"  Total entries : {stats.total_entries}")
    print(f"  Total scans   : {stats.total_scans}")
    print(f"  Framework types: {', '.join(stats.framework_types_seen) or 'none'}")

    if stats.attack_class_stats:
        print(f"\n  Attack class yield scores:")
        ranked = sorted(
            stats.attack_class_stats.values(),
            key=lambda x: x.yield_score, reverse=True
        )
        for cls in ranked:
            bar_len = int(cls.yield_score * 20)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            print(f"  {cls.attack_class:<25} {bar} {cls.yield_score:.2f} "
                  f"({cls.critical_chain_count}c/{cls.high_chain_count}h "
                  f"from {cls.total_occurrences} scans)")

    if stats.modality_effectiveness:
        print(f"\n  Modality effectiveness (CRITICAL+HIGH yield rate):")
        for mod, rate in sorted(stats.modality_effectiveness.items(),
                                key=lambda x: x[1], reverse=True):
            print(f"  {mod:<12} {rate:.0%}")

    if stats.framework_profiles:
        print(f"\n  Framework profiles:")
        for ft, fp in stats.framework_profiles.items():
            print(f"  {ft:<20} {fp.total_scans} scans | "
                  f"avg {fp.avg_critical_chains} critical chains | "
                  f"top: {', '.join(fp.top_attack_classes[:3])}")
    print(f"{'━'*62}")
