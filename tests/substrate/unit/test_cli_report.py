"""End-to-end tests for the ``argus-engine report`` CLI subcommand.

Exercises the full path: JSONL on disk → ``CliRunner`` → HTML + MD
artefacts on disk. Same JSONL must always produce the same bytes.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from argus.engine.cli import main


def _write_jsonl(path: Path) -> None:
    events = [
        {
            "type": "engagement_started",
            "target": "gpt-4o",
            "transport": "openai",
            "layer": "layer1_tool_poisoning",
            "seed": 7,
        },
        {
            "type": "fire",
            "variant_id": "tp-x:0",
            "attack_class": "tp-x",
            "lethality": 0.8,
            "verdict": "IRREFUTABLE",
            "landed": True,
            "phase": "probing",
        },
        {
            "type": "finding",
            "variant_id": "tp-x:0",
            "attack_class": "tp-x",
            "lethality": 0.8,
            "confidence": "IRREFUTABLE",
            "phase": "probing",
            "generation": 0,
            "evidence": {"trigger": "canary"},
        },
        {"type": "done", "duration_seconds": 1.2, "fired": 1, "findings": 1},
    ]
    path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")


def test_report_writes_both_artefacts(tmp_path: Path) -> None:
    jsonl = tmp_path / "run.jsonl"
    _write_jsonl(jsonl)
    html_out = tmp_path / "report.html"
    md_out = tmp_path / "report.md"

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "report",
            "--in",
            str(jsonl),
            "--html",
            str(html_out),
            "--md",
            str(md_out),
        ],
    )
    assert result.exit_code == 0, result.output

    assert html_out.exists()
    html = html_out.read_text(encoding="utf-8")
    assert html.startswith("<!DOCTYPE html>")
    assert "tp-x" in html
    assert "IRREFUTABLE" in html

    assert md_out.exists()
    md = md_out.read_text(encoding="utf-8")
    assert md.startswith("# ARGUS-ENGINE Engagement Report")
    assert "tp-x" in md


def test_report_rejects_when_no_output_flag_given(tmp_path: Path) -> None:
    jsonl = tmp_path / "run.jsonl"
    _write_jsonl(jsonl)

    runner = CliRunner()
    result = runner.invoke(main, ["report", "--in", str(jsonl)])
    assert result.exit_code != 0
    assert "at least one of --html or --md" in result.output


def test_report_html_only(tmp_path: Path) -> None:
    jsonl = tmp_path / "run.jsonl"
    _write_jsonl(jsonl)
    html_out = tmp_path / "out.html"
    md_out = tmp_path / "out.md"  # must NOT be created

    runner = CliRunner()
    result = runner.invoke(main, ["report", "--in", str(jsonl), "--html", str(html_out)])
    assert result.exit_code == 0, result.output
    assert html_out.exists()
    assert not md_out.exists()


def test_report_md_only(tmp_path: Path) -> None:
    jsonl = tmp_path / "run.jsonl"
    _write_jsonl(jsonl)
    html_out = tmp_path / "out.html"  # must NOT be created
    md_out = tmp_path / "out.md"

    runner = CliRunner()
    result = runner.invoke(main, ["report", "--in", str(jsonl), "--md", str(md_out)])
    assert result.exit_code == 0, result.output
    assert md_out.exists()
    assert not html_out.exists()


def test_report_missing_jsonl_fails(tmp_path: Path) -> None:
    """Click's ``exists=True`` Path option must reject a non-existent input."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "report",
            "--in",
            str(tmp_path / "does-not-exist.jsonl"),
            "--html",
            str(tmp_path / "out.html"),
        ],
    )
    assert result.exit_code != 0


def test_report_creates_parent_directory(tmp_path: Path) -> None:
    """Renderer must mkdir-p the output directory (smoke test for CI)."""
    jsonl = tmp_path / "run.jsonl"
    _write_jsonl(jsonl)
    nested = tmp_path / "deep" / "nested" / "report.html"

    runner = CliRunner()
    result = runner.invoke(main, ["report", "--in", str(jsonl), "--html", str(nested)])
    assert result.exit_code == 0, result.output
    assert nested.exists()


def test_report_is_byte_deterministic(tmp_path: Path) -> None:
    """Rule #7 — identical JSONL produces identical Markdown bytes.

    HTML embeds a wall-clock timestamp so we only pin the Markdown
    output here (the HTML render has its own determinism test with
    a pinned ``generated_at``).
    """
    jsonl = tmp_path / "run.jsonl"
    _write_jsonl(jsonl)
    md_a = tmp_path / "a.md"
    md_b = tmp_path / "b.md"

    runner = CliRunner()
    for out in (md_a, md_b):
        result = runner.invoke(main, ["report", "--in", str(jsonl), "--md", str(out)])
        assert result.exit_code == 0, result.output

    assert md_a.read_bytes() == md_b.read_bytes()
