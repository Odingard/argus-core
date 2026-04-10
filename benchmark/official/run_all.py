#!/usr/bin/env python3
"""
ARGUS AI Agent Security Benchmark — Master Test Runner
Runs all scenarios and aggregates results.

Usage:
    python3 run_all.py
    python3 run_all.py --tool-report findings.json
    python3 run_all.py --score-only findings.json
"""
import subprocess, sys, argparse, json
from pathlib import Path

SCENARIOS = [
    ("01-tool-poisoning",    8001, 8002),
    ("02-memory-poisoning",  8003, None),
    ("03-identity-spoof",    8005, None),
    ("04-privilege-chain",   8007, None),
    ("05-injection-gauntlet",8009, None),
    ("06-supply-chain",      8011, None),
    ("07-race-condition",    8013, None),
]

ROOT = Path(__file__).parent


def score_report(report_path: str):
    """Score a tool's findings report against all scenarios."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "scoring" / "score.py"),
         "--report", report_path,
         "--scenario", "all",
         "--verbose"],
        capture_output=False
    )
    return result.returncode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool-report", help="Score a tool findings report")
    parser.add_argument("--score-only", help="Score only, no docker startup")
    parser.add_argument("--scenario", help="Run specific scenario only")
    args = parser.parse_args()

    if args.score_only:
        sys.exit(score_report(args.score_only))

    print(f"\n{'='*65}")
    print(f"  ARGUS AI Agent Security Benchmark")
    print(f"  Odingard Security / Six Sense Enterprise Services")
    print(f"{'='*65}\n")
    print(f"  7 scenarios | 42 maximum points")
    print(f"  Attack classes: tool_poisoning, memory_poisoning, identity_spoofing,")
    print(f"                  privilege_escalation, prompt_injection,")
    print(f"                  supply_chain, race_condition\n")

    for scenario_id, port1, port2 in SCENARIOS:
        if args.scenario and args.scenario != scenario_id:
            continue
        scenario_dir = ROOT / "scenarios" / scenario_id
        print(f"  [{scenario_id}]")
        print(f"    Directory: {scenario_dir}")
        print(f"    Port(s): {port1}{f', {port2}' if port2 else ''}")
        print(f"    Start: cd {scenario_dir} && docker-compose up -d")
        print(f"    Test:  cd {scenario_dir} && python3 run_scenario.py")
        print()

    print(f"  To start ALL scenarios:")
    for scenario_id, _, _ in SCENARIOS:
        print(f"    docker-compose -f scenarios/{scenario_id}/docker-compose.yml up -d")

    if args.tool_report:
        print(f"\n  Scoring tool report: {args.tool_report}")
        score_report(args.tool_report)


if __name__ == "__main__":
    main()
