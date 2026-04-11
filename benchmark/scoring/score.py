"""ARGUS Gauntlet — Scoring Engine.

Reads a tool's findings JSON file and produces a deterministic score
against the benchmark rubric. No human judgment required.

Usage:
    python score.py --findings findings.json
    python score.py --findings findings.json --scenario 01-poisoned-mcp
    python score.py --findings findings.json --output score-report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

RUBRIC_PATH = Path(__file__).parent / "rubric.json"


def load_rubric() -> dict[str, Any]:
    return json.loads(RUBRIC_PATH.read_text())


def load_findings(findings_path: Path) -> dict[str, Any]:
    """Load findings JSON. Accepts either ARGUS report format or generic format.

    ARGUS format:
        {"findings": [{"agent_type": ..., "title": ..., "technique": ..., ...}]}

    Generic format:
        {"findings": [{"scenario": "01", "vulnerability": "...", "validated": bool}]}
    """
    return json.loads(findings_path.read_text())


def _finding_text(finding: dict[str, Any]) -> str:
    """Concatenate all text fields of a finding for indicator matching."""
    parts = [
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("technique", ""),
        finding.get("target_surface", ""),
        finding.get("agent_type", ""),
        str(finding.get("raw_request", "")),
        str(finding.get("raw_response", "")),
    ]
    # Include attack chain steps
    for step in finding.get("attack_chain", []) or []:
        parts.append(step.get("description", "") if isinstance(step, dict) else "")
        parts.append(step.get("technique", "") if isinstance(step, dict) else "")
    return " ".join(parts).lower()


def _matches_indicators(text: str, indicators: list[str]) -> bool:
    """Check if any indicator from the list appears in the text."""
    return any(ind.lower() in text for ind in indicators)


def _is_validated(finding: dict[str, Any]) -> bool:
    """Check if a finding is validated."""
    if finding.get("status") == "validated":
        return True
    validation = finding.get("validation")
    if isinstance(validation, dict) and validation.get("validated"):
        return True
    return False


def _finding_cw(finding: dict[str, Any]) -> float:
    """Extract the Consequence Weight from a finding's verdict_score."""
    vs = finding.get("verdict_score") or {}
    if isinstance(vs, dict):
        cw = vs.get("consequence_weight")
        if isinstance(cw, int | float):
            return float(cw)
    return 0.0


def score_scenario(
    scenario_id: str,
    scenario_rubric: dict[str, Any],
    findings: list[dict[str, Any]],
    compound_paths: list[dict[str, Any]] | None = None,
    all_scenarios: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Score a single scenario against findings using VERDICT WEIGHT.

    Tier mapping:
      Detection (1pt) — at least 1 finding with CW >= detection threshold
                        AND content matching this scenario's indicators
      Validation (2pt) — at least N findings with CW >= validation threshold
                        AND content matching this scenario's indicators
      Chaining   (3pt) — at least 1 compound attack path matching this
                        scenario's chain indicators
    """
    result = {
        "scenario_id": scenario_id,
        "name": scenario_rubric.get("name", scenario_id),
        "difficulty": scenario_rubric.get("difficulty", "unknown"),
        "phase": scenario_rubric.get("phase"),
        "max_score": scenario_rubric.get("max_score", 6),
        "score": 0,
        "tiers": {
            "detection": {"earned": 0, "max": 1, "evidence": []},
            "validation": {"earned": 0, "max": 2, "evidence": []},
            "chaining": {"earned": 0, "max": 3, "evidence": []},
        },
        "matched_findings": [],
    }

    indicators = scenario_rubric.get("indicators", [])
    if not indicators:
        result["note"] = "Scenario has no indicators defined yet"
        return result

    thresholds = scenario_rubric.get("tier_thresholds", {})
    det_cw = thresholds.get("detection", {}).get("min_findings_above_cw", 0.40)
    det_count = thresholds.get("detection", {}).get("min_count", 1)
    val_cw = thresholds.get("validation", {}).get("min_findings_above_cw", 0.70)
    val_count = thresholds.get("validation", {}).get("min_count", 1)

    # Match findings to this scenario by indicator overlap
    matched: list[dict[str, Any]] = []
    for finding in findings:
        text = _finding_text(finding)
        if _matches_indicators(text, indicators):
            cw = _finding_cw(finding)
            matched.append(
                {
                    "title": finding.get("title", ""),
                    "agent_type": finding.get("agent_type", ""),
                    "technique": finding.get("technique", ""),
                    "cw": cw,
                    "validated": _is_validated(finding),
                }
            )

    result["matched_findings"] = matched[:20]

    # Detection tier
    above_det = [m for m in matched if m["cw"] >= det_cw]
    if len(above_det) >= det_count:
        result["tiers"]["detection"]["earned"] = 1
        result["tiers"]["detection"]["evidence"] = [m["title"] for m in above_det[:5]]

    # Validation tier (only if detection passed)
    if result["tiers"]["detection"]["earned"]:
        above_val = [m for m in matched if m["cw"] >= val_cw]
        if len(above_val) >= val_count:
            result["tiers"]["validation"]["earned"] = 2
            result["tiers"]["validation"]["evidence"] = [m["title"] for m in above_val[:5]]

    # Chaining tier — requires a compound path (Correlation Agent v1+)
    if result["tiers"]["validation"]["earned"]:
        chain_indicators = scenario_rubric.get("compound_chain_indicators", [])
        compound_paths = compound_paths or []
        for cp in compound_paths:
            cp_text = " ".join(
                str(v)
                for v in [
                    cp.get("title", ""),
                    cp.get("description", ""),
                    cp.get("compound_impact", ""),
                ]
            ).lower()
            if _matches_indicators(cp_text, chain_indicators):
                result["tiers"]["chaining"]["earned"] = 3
                result["tiers"]["chaining"]["evidence"] = [cp.get("title", "compound")]
                break

    result["score"] = (
        result["tiers"]["detection"]["earned"]
        + result["tiers"]["validation"]["earned"]
        + result["tiers"]["chaining"]["earned"]
    )
    result["matched_count"] = len(matched)
    result["above_validation_cw"] = len([m for m in matched if m["cw"] >= val_cw])
    return result


def score_all(rubric: dict[str, Any], findings_doc: dict[str, Any]) -> dict[str, Any]:
    """Score all scenarios. Returns full report."""
    findings = findings_doc.get("findings", [])
    compound_paths = findings_doc.get("compound_attack_paths", [])

    scenarios = rubric.get("scenarios", {})
    scenario_results = {}
    total_earned = 0
    total_max = 0

    for scenario_id, scenario_rubric in scenarios.items():
        result = score_scenario(
            scenario_id,
            scenario_rubric,
            findings,
            compound_paths=compound_paths,
            all_scenarios=scenarios,
        )
        scenario_results[scenario_id] = result
        total_earned += result["score"]
        total_max += result["max_score"]

    return {
        "benchmark": rubric.get("benchmark", "ARGUS Gauntlet"),
        "version": rubric.get("version", "1.0.0"),
        "total_score": total_earned,
        "total_max": total_max,
        "percentage": round(100 * total_earned / total_max, 2) if total_max else 0,
        "scenarios": scenario_results,
    }


def render_text_report(report: dict[str, Any]) -> str:
    """Render a human-readable text report."""
    lines = [
        "=" * 70,
        f"  {report['benchmark']} — Score Report",
        "=" * 70,
        f"  Total Score: {report['total_score']}/{report['total_max']} ({report['percentage']}%)",
        "=" * 70,
        "",
    ]

    for scenario_id, result in report["scenarios"].items():
        phase = result.get("phase")
        phase_tag = f" (Phase {phase})" if phase else ""
        diff = result.get("difficulty", "?").upper()
        lines.append(f"  [{diff}] {scenario_id} — {result['name']}{phase_tag}")
        lines.append(f"    Score: {result['score']}/{result['max_score']}")
        if result.get("note"):
            lines.append(f"    Note: {result['note']}")
        else:
            for tier_name, tier_data in result["tiers"].items():
                status = "PASS" if tier_data["earned"] == tier_data["max"] else "FAIL"
                lines.append(f"    {tier_name.title():12s}: {tier_data['earned']}/{tier_data['max']}  [{status}]")
            matched = result.get("matched_count", 0)
            above_val = result.get("above_validation_cw", 0)
            if matched:
                lines.append(f"    Findings matched: {matched}  (above val CW: {above_val})")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="ARGUS Gauntlet — Scoring Engine")
    parser.add_argument("--findings", type=Path, required=True, help="Path to findings JSON file")
    parser.add_argument("--scenario", type=str, help="Score only a specific scenario (e.g., 01-poisoned-mcp)")
    parser.add_argument("--output", type=Path, help="Write JSON report to file")
    parser.add_argument("--json", action="store_true", help="Output JSON to stdout instead of text")
    args = parser.parse_args()

    if not args.findings.exists():
        print(f"ERROR: findings file not found: {args.findings}", file=sys.stderr)
        return 1

    rubric = load_rubric()
    findings_doc = load_findings(args.findings)

    report = score_all(rubric, findings_doc)

    if args.scenario:
        if args.scenario not in report["scenarios"]:
            print(f"ERROR: scenario {args.scenario} not in rubric", file=sys.stderr)
            return 1
        report = {
            "benchmark": report["benchmark"],
            "scenarios": {args.scenario: report["scenarios"][args.scenario]},
        }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_text_report(report))

    if args.output:
        args.output.write_text(json.dumps(report, indent=2))
        print(f"\nReport written to: {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
