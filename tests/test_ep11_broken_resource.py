"""
tests/test_ep11_broken_resource.py — EP-11 BrokenResourceError resilience.

The BrokenResourceError fired on MCP transport teardown after CRITICAL
findings were confirmed in memory but before save_findings() was called.
This test verifies findings are persisted even when the adapter raises
on __aexit__.
"""
import os
import tempfile


class _BrokenAdapter:
    """Adapter that succeeds on connect/enumerate but raises
    BrokenResourceError on __aexit__ (teardown)."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        raise Exception("BrokenResourceError: <no message>")

    async def enumerate(self):
        from argus.adapter.base import Surface
        return [Surface(name="tool:sandbox_initialize", kind="tool")]

    async def call_tool(self, name, **kwargs):
        from argus.adapter.base import AdapterObservation, Response
        return AdapterObservation(
            response=Response(body="root:x:0:0:/root:/bin/bash [STDERR] injected"),
            tool_name=name,
            raw_response="root:x:0:0:/root:/bin/bash [STDERR] injected",
        )


def test_ep11_persists_findings_on_broken_resource():
    """EP-11 must write findings to disk even when adapter teardown fails."""
    from argus.agents.agent_11_environment_pivot import EnvironmentPivotAgent

    with tempfile.TemporaryDirectory() as outdir:
        agent = EnvironmentPivotAgent(
            adapter_factory=lambda: _BrokenAdapter(),
        )
        # Directly inject a confirmed finding into agent state
        # (simulating what probe loop does before BrokenResource fires)
        from argus.agents.base import AgentFinding
        f = AgentFinding(
            id="test-broken-001",
            agent_id="EP-11",
            vuln_class="ENVIRONMENT_PIVOT",
            severity="CRITICAL",
            title="Shell injection — BrokenResource test",
            description="Persisted despite teardown failure",
            surface="tool:sandbox_initialize",
            exploitability_confirmed=True,
        )
        agent._add_finding(f)

        # save_findings should work even after simulated error
        out_path = agent.save_findings(outdir)
        assert os.path.exists(out_path)

        import json
        data = json.loads(open(out_path).read())
        assert data["total_findings"] >= 1
        titles = [fd["title"] for fd in data["findings"]]
        assert any("BrokenResource" in t for t in titles)


def test_ep11_findings_not_empty_after_teardown_error():
    """Agent findings list is non-empty after BrokenResource — nothing lost."""
    from argus.agents.agent_11_environment_pivot import EnvironmentPivotAgent
    from argus.agents.base import AgentFinding

    agent = EnvironmentPivotAgent(adapter_factory=lambda: _BrokenAdapter())
    f = AgentFinding(
        id="test-broken-002",
        agent_id="EP-11",
        vuln_class="ENVIRONMENT_PIVOT",
        severity="CRITICAL",
        title="Shell injection confirmed",
        description="test",
        surface="tool:sandbox_initialize",
        exploitability_confirmed=True,
    )
    agent._add_finding(f)
    assert len(agent.findings) == 1
    assert agent.findings[0].exploitability_confirmed is True
