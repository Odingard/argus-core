"""Phase R — CLI flag wiring tests for `argus-engine engage`.

These tests only verify the flag plumbing (help output + flag
recognition + mutually-compatible flag combinations). The actual
engagement loop is exercised by integration tests; here we just pin
that ``--hud`` / ``--narrate`` / ``--demo-pace`` reach the parser
without breaking existing flags.
"""

from __future__ import annotations

from click.testing import CliRunner

from argus.engine.cli import main


def test_engage_help_lists_new_phase_r_flags() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["engage", "--help"])
    assert result.exit_code == 0
    assert "--hud" in result.output
    assert "--narrate" in result.output
    assert "--demo-pace" in result.output


def test_engage_help_documents_hud_panels() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["engage", "--help"])
    assert result.exit_code == 0
    # Help text should hint at what the HUD adds.
    assert "heatmap" in result.output.lower()


def test_engage_help_documents_demo_pace_purpose() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["engage", "--help"])
    assert result.exit_code == 0
    # The demo_pace flag exists for recordings.
    assert "recording" in result.output.lower() or "demo" in result.output.lower()


def test_engage_rejects_negative_demo_pace() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "engage",
            "--target",
            "https://t.example/chat",
            "--transport",
            "openai",
            "--demo-pace",
            "-1",
        ],
    )
    assert result.exit_code != 0
    assert "demo-pace" in result.output.lower() or "demo_pace" in result.output.lower()


def test_engage_rejects_absurd_demo_pace() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "engage",
            "--target",
            "https://t.example/chat",
            "--transport",
            "openai",
            "--demo-pace",
            "999",
        ],
    )
    assert result.exit_code != 0


def test_engage_html_md_out_still_listed() -> None:
    """Phase R must not regress Phase M's existing report-output flags."""
    runner = CliRunner()
    result = runner.invoke(main, ["engage", "--help"])
    assert result.exit_code == 0
    assert "--html-out" in result.output
    assert "--md-out" in result.output
    assert "--tui" in result.output
    assert "--json" in result.output
