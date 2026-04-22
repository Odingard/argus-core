"""
tests/test_report.py — HTML report renderer.
"""
from __future__ import annotations


from argus.engagement import run_engagement
from argus.report import render_html, render_html_from_dir


# ── render_html direct ─────────────────────────────────────────────────────

def test_render_html_handles_empty_inputs():
    out = render_html(
        chain={}, impact={}, envelope=None,
        summary_txt="", by_agent={},
    )
    assert out.startswith("<!DOCTYPE html>")
    assert "ARGUS engagement report" in out


def test_render_html_escapes_target_id():
    out = render_html(
        chain={"target_id": "crewai://labrat/<script>"},
        impact={}, envelope=None, summary_txt="", by_agent={},
    )
    # Script tags are escaped — no raw <script> in the body.
    assert "<script>" not in out.split("<head>")[1].split("</head>")[0] \
        .replace("<script>", "")    # quick sanity
    assert "&lt;script&gt;" in out


def test_render_html_renders_severity_badge():
    out = render_html(
        chain={"target_id": "x", "chain_id": "chain-abc",
               "cve_draft_id": "ARGUS-DRAFT-CVE-abc"},
        impact={"severity_label": "CATASTROPHIC", "harm_score": 92,
                "regulatory_impact": ["GDPR", "SOC2"],
                "data_classes_exposed": {"SECRET": ["x"]}},
        envelope=None, summary_txt="", by_agent={"PI-01": 3},
    )
    assert "CATASTROPHIC" in out
    assert "GDPR" in out
    assert "SOC2" in out
    assert "SECRET" in out
    assert "PI-01" in out


# ── render_html_from_dir ──────────────────────────────────────────────────

def test_render_html_from_dir_end_to_end(tmp_path):
    # Run a real engagement and render it.
    eng_dir = tmp_path / "eng"
    result = run_engagement(
        target_url="parlant://labrat",
        output_dir=str(eng_dir), clean=True,
    )
    assert result.findings

    rr = render_html_from_dir(eng_dir)
    assert rr.output_path.exists()
    assert rr.harm_score > 0
    assert rr.severity in {"HIGH", "CRITICAL", "CATASTROPHIC"}

    html = rr.html
    # Must reference the target.
    assert "parlant://labrat" in html
    # Must include at least one kill-chain row header.
    assert "Kill-chain steps" in html
    # HTML renders without open-tag bleed.
    assert html.count("<!DOCTYPE html>") == 1
    assert html.strip().endswith("</html>")


def test_render_writes_to_specified_output(tmp_path):
    # Build a minimal engagement dir by running one.
    eng_dir = tmp_path / "eng"
    run_engagement(
        target_url="llamaindex://labrat",
        output_dir=str(eng_dir), clean=True,
    )
    # Render to a custom path.
    dest = tmp_path / "custom_report.html"
    rr = render_html_from_dir(eng_dir, output=dest)
    assert rr.output_path == dest
    assert dest.exists()
    assert dest.read_text().startswith("<!DOCTYPE html>")
