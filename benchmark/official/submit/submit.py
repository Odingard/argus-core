#!/usr/bin/env python3
"""
ARGUS AI Agent Security Benchmark — Score Submission Tool
Verifies findings report and prepares a LEADERBOARD.md entry.

Usage:
    python3 submit.py --report findings.json --tool-name "MyTool" --tool-version "1.0"
"""
import json, argparse, subprocess, sys, hashlib, datetime, os, tempfile
from pathlib import Path

SCORER = Path(__file__).parent.parent / "scoring" / "score.py"


def hash_report(report_path: str) -> str:
    with open(report_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]


def run_scorer(report_path: str) -> dict:
    output_file = tempfile.mktemp(suffix=".json")
    result = subprocess.run(
        [sys.executable, str(SCORER),
         "--report", report_path,
         "--scenario", "all",
         "--output", output_file],
        capture_output=True, text=True
    )
    print(result.stdout)
    try:
        with open(output_file) as f:
            data = json.load(f)
        os.unlink(output_file)
        return data
    except Exception:
        return {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--tool-name")
    parser.add_argument("--tool-version")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  ARGUS Benchmark Score Submission")
    print(f"{'='*60}\n")

    with open(args.report) as f:
        report = json.load(f)
    if args.tool_name:
        report["tool_name"] = args.tool_name
    if args.tool_version:
        report["tool_version"] = args.tool_version

    tmp = args.report + ".tmp.json"
    with open(tmp, "w") as f:
        json.dump(report, f)

    score_data = run_scorer(tmp)
    os.unlink(tmp)

    if not score_data:
        print("[-] Scoring failed. Check your report format.")
        sys.exit(1)

    tool = score_data.get("tool_name", "Unknown")
    version = score_data.get("tool_version", "?")
    total = score_data.get("total_points", 0)
    max_pts = score_data.get("total_max", 42)
    pct = score_data.get("percentage", 0)
    date = datetime.date.today().isoformat()
    report_hash = hash_report(args.report)
    entry = f"| — | {tool} | {total}/{max_pts} ({pct:.1f}%) | {version} | {date} | {report_hash} |"

    print(f"\n{'='*60}")
    print(f"  LEADERBOARD ENTRY — add this to LEADERBOARD.md:")
    print(f"{'='*60}")
    print(f"\n  {entry}\n")
    print(f"  Then open a PR at: https://github.com/odingard/argus-benchmark\n")

    with open("submission_entry.txt", "w") as f:
        f.write(entry + "\n")
    print(f"  Saved to: submission_entry.txt\n")


if __name__ == "__main__":
    main()
