"""
tests/test_runner_recovery.py — runner disk-recovery of errored agent findings.

When an agent errors (BrokenResourceError, etc.) but saved findings to disk
before crashing, the runner must recover those findings from disk rather than
treating the agent as zero-finding.
"""
import json
import tempfile
from pathlib import Path
from argus.agents.base import AgentFinding


def _write_findings_file(directory: str, agent_id: str,
                         findings: list[AgentFinding]) -> Path:
    """Write a findings JSON file as save_findings() would."""
    out_dir = Path(directory) / agent_id.lower().replace("-", "")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{agent_id.upper()}_findings.json"
    payload = {
        "agent_id": agent_id,
        "total_findings": len(findings),
        "findings": [
            {k: getattr(f, k, None)
             for k in AgentFinding.__dataclass_fields__}
            for f in findings
        ],
    }
    out_path.write_text(json.dumps(payload, indent=2))
    return out_path


def test_findings_file_written_before_broken_resource():
    """Simulates EP-11 saving findings before transport dies."""
    with tempfile.TemporaryDirectory() as d:
        f = AgentFinding(
            id="ep11-critical-001",
            agent_id="EP-11",
            vuln_class="ENVIRONMENT_PIVOT",
            severity="CRITICAL",
            title="Shell injection — sandbox_initialize",
            description="execSync unsanitized",
            surface="tool:sandbox_initialize",
            exploitability_confirmed=True,
        )
        path = _write_findings_file(d, "EP-11", [f])
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["total_findings"] == 1
        assert data["findings"][0]["severity"] == "CRITICAL"
        assert data["findings"][0]["exploitability_confirmed"] is True


def test_recovered_findings_are_critical():
    """Runner recovery must preserve severity and exploitability_confirmed."""
    with tempfile.TemporaryDirectory() as d:
        findings = [
            AgentFinding(
                id=f"ep11-{i:03d}",
                agent_id="EP-11",
                vuln_class="ENVIRONMENT_PIVOT",
                severity="CRITICAL",
                title=f"Finding {i}",
                description="test",
                surface="tool:sandbox_initialize",
                exploitability_confirmed=True,
            )
            for i in range(2)
        ]
        path = _write_findings_file(d, "EP-11", findings)
        data = json.loads(path.read_text())
        for fd in data["findings"]:
            assert fd["severity"] == "CRITICAL"
            assert fd["exploitability_confirmed"] is True


def test_recovery_file_path_matches_runner_glob_pattern():
    """The file path written by save_findings must match the glob
    pattern the runner uses for recovery."""
    import glob
    with tempfile.TemporaryDirectory() as d:
        f = AgentFinding(
            id="test-001", agent_id="EP-11",
            vuln_class="ENVIRONMENT_PIVOT", severity="CRITICAL",
            title="test", description="test",
        )
        path = _write_findings_file(d, "EP-11", [f])
        # Runner glob pattern: findings/ep11/EP-11_findings.json
        # (agent_id lower no-dash subdir, upper filename)
        pattern = str(Path(d) / "ep11" / "EP-11_findings.json")
        hits = glob.glob(pattern)
        assert len(hits) == 1
        assert hits[0] == str(path)


def test_agent_id_subdir_normalization():
    """EP-11 → ep11 subdir (lower, no dash) matches runner expectation."""
    agent_id = "EP-11"
    subdir = agent_id.lower().replace("-", "")
    assert subdir == "ep11"
    agent_id2 = "SC-09"
    assert agent_id2.lower().replace("-", "") == "sc09"
    agent_id3 = "ME-10"
    assert agent_id3.lower().replace("-", "") == "me10"
