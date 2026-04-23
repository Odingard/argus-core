"""
tests/test_agent_11_environment_pivot.py — Phase 8 Agent 11 acceptance.

Target simulates the OAuth-supply-chain-class chain: an exec tool that leaks AWS /
OAuth credentials when queried, a fetch tool that's SSRF-able to
IMDS, a catalog with an overscoped OAuth integration, a third-party
AI vendor with corp-scoped access.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.agents.agent_11_environment_pivot import (
    EnvironmentPivotAgent, TECHNIQUES,
)
from argus.corpus_attacks import EvolveCorpus


# ── OAuth-supply-chain target ───────────────────────────────────────────────────

class _OAuthSupplyChainTarget(BaseAdapter):
    """
    Simulates a target with three classes of weakness:
      • exec tool leaks env-var creds when asked to dump env
      • fetch tool is SSRF-able to IMDS
      • catalog has an overgranted OAuth integration AND a
        third-party AI-integration vendor tool with broad scope
    """
    def __init__(self):
        super().__init__(target_id="mcp://oauth-supply-chain-pattern")

    async def _connect(self): pass
    async def _disconnect(self): pass

    async def _enumerate(self):
        return [
            Surface(
                kind="tool", name="tool:run_command",
                description="Run a shell command on the host.",
                schema={"properties": {"command": {"type": "string"}}},
            ),
            Surface(
                kind="tool", name="tool:fetch_url",
                description="Fetch a URL and return the body.",
                schema={"properties": {"url": {"type": "string"}}},
            ),
            # OAuth integration with wildcard / Allow-All scope —
            # catches EP-T7-oauth-overgrant-audit.
            Surface(
                kind="tool", name="tool:google_workspace",
                description="Google Workspace integration — allow all",
                schema={
                    "properties": {"action": {"type": "string"}},
                    "meta": {"scopes": ["*"], "allow_all": True},
                },
            ),
            # OAuth-overgrant AI-integration tool — external AI vendor with corp
            # scope. Catches EP-T8-third-party-ai-integration.
            Surface(
                kind="tool", name="tool:context_assistant",
                description=(
                    "AI Office Suite integration via context.ai. "
                    "Processes documents in your workspace."
                ),
                schema={"meta": {"origin": "https://api.context.ai/v1",
                                 "scopes": ["drive.readonly", "mail.read"]}},
            ),
            # A read-only surface so we also exercise the
            # "ignore non-matching surface" path.
            Surface(
                kind="tool", name="tool:lookup_user",
                description="Look up a user by id.",
                schema={"meta": {"signed_by": "customer",
                                 "version":   "1.0"}},
            ),
        ]

    async def _interact(self, request: Request) -> AdapterObservation:
        payload = request.payload if isinstance(request.payload, dict) else {}

        # Exec surface: leak env when asked.
        if request.surface == "tool:run_command":
            cmd = str(payload.get("command") or payload.get("arg") or "")
            if payload.get("action") == "dump" or \
               payload.get("action") == "read_all_env" or \
               "env" in cmd.lower() or "printenv" in cmd.lower():
                body = (
                    "PATH=/usr/bin\n"
                    "AWS_ACCESS_KEY_ID=AKIAEXAMPLEEXAMPLE7Q\n"
                    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/"
                    "bPxRfiCYEXAMPLEKEY\n"
                    "GOOGLE_API_KEY=AIzaSyDexampleexampleexampleexamplex1X\n"
                    "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234\n"
                    "VERCEL_TOKEN=vc_abcdefghijklmnopqrstuvwxyz"
                )
            elif "id_rsa" in cmd or "~/.ssh" in cmd:
                body = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAB\n"
                        "-----END OPENSSH PRIVATE KEY-----")
            else:
                body = "ok"
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(status="ok", body=body),
            )

        # Fetch surface: SSRF-able to IMDS.
        if request.surface == "tool:fetch_url":
            url = str(payload.get("url") or "")
            if "169.254.169.254" in url or "metadata.google.internal" in url:
                body = (
                    '{"AccessKeyId":"ASIAEXAMPLEEXAMPLEAAA",'
                    '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG",'
                    '"Token":"IQoJb3JpZ2luX2VjE...",'
                    '"Expiration":"2026-01-01T00:00:00Z"}'
                )
            elif "tokeninfo" in url:
                body = ('{"scope":"https://www.googleapis.com/auth/drive "'
                        '"https://www.googleapis.com/auth/gmail",'
                        '"aud":"123.apps.googleusercontent.com",'
                        '"exp":999999999}')
            elif "googleapis.com/drive" in url:
                body = ('{"files":[{"mimeType":'
                        '"application/vnd.google.spreadsheet"}]}')
            elif "api.vercel.com" in url and "/env" in url:
                body = ('{"envs":[{"target":"production","env":'
                        '{"DATABASE_URL":"postgres://..."}}]}')
            else:
                body = "no response for that url"
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(status="ok", body=body),
            )

        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body="ok"),
        )


class _CleanTarget(BaseAdapter):
    """No leaks, no overgrants, no AI-vendor integrations."""
    def __init__(self):
        super().__init__(target_id="mcp://clean")

    async def _connect(self): pass
    async def _disconnect(self): pass

    async def _enumerate(self):
        return [
            Surface(kind="tool", name="tool:lookup_user",
                    description="Look up a user by id.",
                    schema={"meta": {"signed_by": "customer",
                                     "version":   "1.0"}}),
        ]

    async def _interact(self, request: Request) -> AdapterObservation:
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body="ok"),
        )


# ── Tests ────────────────────────────────────────────────────────────────────

def test_agent_11_lands_on_oauth_supply_chain_pattern(tmp_path):
    agent = EnvironmentPivotAgent(
        adapter_factory=lambda: _OAuthSupplyChainTarget(),
    )
    findings = asyncio.run(agent.run_async(
        target_id="mcp://oauth-supply-chain-pattern",
        output_dir=str(tmp_path),
    ))
    assert findings, "EP-11 produced no findings against OAuth-supply-chain target"
    techs = {f.attack_variant_id for f in findings}
    # At least one from each family.
    family_a = {"EP-T1-cred-surface-scan", "EP-T2-ssh-key-probe",
                "EP-T3-cloud-cred-probe", "EP-T4-imds-ssrf-probe"}
    family_b = {"EP-T5-oauth-token-discovery",
                "EP-T6-oauth-scope-enum", "EP-T7-oauth-overgrant-audit"}
    family_c = {"EP-T8-third-party-ai-integration"}
    family_d = {"EP-T9-workspace-pivot", "EP-T10-paas-envvar-pivot"}
    assert techs & family_a, f"no family-A (discovery) finding; got {techs}"
    assert techs & family_b, f"no family-B (OAuth) finding; got {techs}"
    assert techs & family_c, f"no family-C (third-party-AI) finding; got {techs}"
    assert techs & family_d, f"no family-D (pivot) finding; got {techs}"


def test_agent_11_cred_discovery_finds_aws_key(tmp_path):
    agent = EnvironmentPivotAgent(
        adapter_factory=lambda: _OAuthSupplyChainTarget(),
        techniques=["EP-T1-cred-surface-scan"],
    )
    findings = asyncio.run(agent.run_async(
        target_id="mcp://oauth-supply-chain-pattern",
        output_dir=str(tmp_path),
    ))
    evidence_blob = "\n".join(f.delta_evidence for f in findings)
    assert "aws_access_key" in evidence_blob or \
           "AKIA" in evidence_blob, (
        f"AWS access key not surfaced in EP-T1; got: {evidence_blob[:400]}"
    )


def test_agent_11_imds_probe_lands_through_ssrf(tmp_path):
    agent = EnvironmentPivotAgent(
        adapter_factory=lambda: _OAuthSupplyChainTarget(),
        techniques=["EP-T4-imds-ssrf-probe"],
    )
    findings = asyncio.run(agent.run_async(
        target_id="mcp://oauth-supply-chain-pattern",
        output_dir=str(tmp_path),
    ))
    assert findings, "IMDS-SSRF probe didn't land"
    blob = "\n".join(f.delta_evidence for f in findings)
    assert "imds_shape" in blob or "AccessKeyId" in blob or \
           "aws_session_token" in blob


def test_agent_11_catches_oauth_overgrant_via_catalog(tmp_path):
    agent = EnvironmentPivotAgent(
        adapter_factory=lambda: _OAuthSupplyChainTarget(),
        techniques=["EP-T7-oauth-overgrant-audit"],
    )
    findings = asyncio.run(agent.run_async(
        target_id="mcp://oauth-supply-chain-pattern",
        output_dir=str(tmp_path),
    ))
    assert findings
    assert all(f.evidence_kind == "environment_pivot_audit" for f in findings)
    assert any(f.surface == "tool:google_workspace" for f in findings)


def test_agent_11_catches_third_party_ai_integration(tmp_path):
    agent = EnvironmentPivotAgent(
        adapter_factory=lambda: _OAuthSupplyChainTarget(),
        techniques=["EP-T8-third-party-ai-integration"],
    )
    findings = asyncio.run(agent.run_async(
        target_id="mcp://oauth-supply-chain-pattern",
        output_dir=str(tmp_path),
    ))
    assert findings
    assert any(f.surface == "tool:context_assistant" for f in findings)


def test_agent_11_findings_have_full_provenance(tmp_path):
    agent = EnvironmentPivotAgent(
        adapter_factory=lambda: _OAuthSupplyChainTarget(),
    )
    findings = asyncio.run(agent.run_async(
        target_id="mcp://oauth-supply-chain-pattern",
        output_dir=str(tmp_path),
    ))
    for f in findings:
        assert f.agent_id == "EP-11"
        assert f.vuln_class == "ENVIRONMENT_PIVOT"
        assert f.attack_variant_id in TECHNIQUES
        assert f.surface
        assert f.baseline_ref
        assert f.severity in {"CRITICAL", "HIGH"}


def test_agent_11_zero_findings_on_clean_target(tmp_path):
    agent = EnvironmentPivotAgent(adapter_factory=lambda: _CleanTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://clean",
        output_dir=str(tmp_path),
    ))
    assert findings == [], (
        f"clean target produced {len(findings)} false-positive pivot findings"
    )


def test_agent_11_persists_findings(tmp_path):
    agent = EnvironmentPivotAgent(
        adapter_factory=lambda: _OAuthSupplyChainTarget(),
    )
    asyncio.run(agent.run_async(
        target_id="mcp://oauth-supply-chain-pattern",
        output_dir=str(tmp_path),
    ))
    out = Path(tmp_path) / "EP-11_findings.json"
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["agent_id"] == "EP-11"
    assert data["total_findings"] >= 4


def test_agent_11_evolves_corpus_on_landing(tmp_path):
    discovered = tmp_path / "discovered"
    ev = EvolveCorpus(discovered_dir=str(discovered))
    agent = EnvironmentPivotAgent(
        adapter_factory=lambda: _OAuthSupplyChainTarget(),
        evolve_corpus=ev,
    )
    asyncio.run(agent.run_async(
        target_id="mcp://oauth-supply-chain-pattern",
        output_dir=str(tmp_path),
    ))
    assert list(discovered.glob("disc_*.json"))


def test_agent_11_class_metadata():
    assert EnvironmentPivotAgent.AGENT_ID == "EP-11"
    assert EnvironmentPivotAgent.MAAC_PHASES == [8]
    assert EnvironmentPivotAgent.PERSONA == "pivoter"
    assert EnvironmentPivotAgent.VULN_CLASS == "ENVIRONMENT_PIVOT"
    assert len(EnvironmentPivotAgent.TECHNIQUES) == 11
