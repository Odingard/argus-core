"""CLI sanity test: --session-mode is only valid with --transport=argt.

We don't exercise the full engage flow here — that needs a live target. The
goal is to lock in the early-fail so the user never silently passes
``--session-mode=multi-call`` to a transport that ignores it.
"""

from __future__ import annotations

from click.testing import CliRunner

from argus.engine.cli import main


def test_session_mode_multi_call_rejected_for_non_argt_transport() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "engage",
            "--target",
            "http://example.com",
            "--transport",
            "openai",
            "--session-mode",
            "multi-call",
            "--no-persist",
        ],
    )
    assert result.exit_code != 0
    assert "--session-mode" in result.output
    assert "argt" in result.output


def test_session_mode_single_call_is_default_and_accepts_any_transport() -> None:
    runner = CliRunner()
    # --help just to confirm the flag parses; we don't actually engage.
    result = runner.invoke(main, ["engage", "--help"])
    assert result.exit_code == 0
    assert "--session-mode" in result.output
    assert "single-call" in result.output
    assert "multi-call" in result.output
