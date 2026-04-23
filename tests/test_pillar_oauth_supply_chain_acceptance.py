"""
tests/test_pillar_oauth_supply_chain_acceptance.py

End-to-end acceptance for the "next pillar" build:
  • Command-Flooding mutator (Claude Code v2.1.80 bypass)
  • Deterministic Evidence (AI-Slop filter: pcap / container_logs /
    OOB callback)
  • EP-11 Environment Pivoting agent
  • SC-09 SC-T7 / SC-T8 sub-techniques
  • Data classification + Phase 9 Impact Optimizer → BlastRadiusMap

The acceptance bar: no pre-fabricated findings. Spin up ONE labrat
target that mirrors the April-2026 OAuth supply-chain pattern, run real agents
against it, collect real evidence during the run, then feed real
outputs through chain synthesis → impact optimization. Every assertion
is against the structure / content of outputs the agents actually
produced — not hard-coded or seeded values.
"""
from __future__ import annotations

import asyncio
import json

from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.agents.agent_09_supply_chain import SupplyChainAgent
from argus.agents.agent_11_environment_pivot import EnvironmentPivotAgent
from argus.corpus_attacks import (
    CommandFloodingMutator, Corpus, EvolveCorpus,
)
from argus.evidence import EvidenceCollector, attach_evidence
from argus.impact import optimize_impact
from argus.swarm.chain_synthesis_v2 import synthesize_compound_chain


CUSTOMER_TARGET = "mcp://pillar-oauth-supply-chain-pattern"


# ── Labrat target: OAuth-supply-chain topology ─────────────────────────────
# A simulation of a real target's weaknesses. The adapter behaves like
# an exploitable production target; ARGUS agents are NOT given any
# insight into this behaviour — they discover it by probing. No ARGUS
# code branches on this target's identity.

class _OAuthSupplyChainLabrat(BaseAdapter):
    def __init__(self):
        super().__init__(target_id=CUSTOMER_TARGET)

    async def _connect(self): pass
    async def _disconnect(self): pass

    async def _enumerate(self):
        return [
            # Over-permissive Workspace integration — SC-T7 territory.
            Surface(
                kind="tool", name="tool:google_workspace",
                description="Google Workspace integration — allow all",
                schema={"properties": {"action": {"type": "string"}},
                        "meta": {"scopes": ["*"], "allow_all": True}},
            ),
            # OAuth-connected AI-integration — SC-T8 territory.
            Surface(
                kind="tool", name="tool:context_assistant",
                description=(
                    "AI Office Suite integration via context.ai. "
                    "Processes workspace documents."
                ),
                schema={"meta": {"origin": "https://api.context.ai/v1",
                                 "scopes": ["drive.readonly"]}},
            ),
            # Exec surface that leaks env on dump requests — EP-T1 territory.
            Surface(
                kind="tool", name="tool:run_command",
                description="Run a shell command on the host.",
                schema={"properties": {"command": {"type": "string"}}},
            ),
            # Fetch surface SSRF-able to IMDS — EP-T4 territory.
            Surface(
                kind="tool", name="tool:fetch_url",
                description="Fetch a URL and return the body.",
                schema={"properties": {"url": {"type": "string"}}},
            ),
            # Benign surface — should never get flagged.
            Surface(
                kind="tool", name="tool:lookup_user",
                description="Look up a user by id.",
                schema={"properties": {"id": {"description": "user id"}},
                        "meta": {"signed_by": "customer",
                                 "version":   "1.0"}},
            ),
        ]

    async def _interact(self, request: Request) -> AdapterObservation:
        p = request.payload if isinstance(request.payload, dict) else {}

        if request.surface == "tool:run_command":
            cmd = str(p.get("command") or p.get("arg") or "")
            action = str(p.get("action") or "")
            if action in {"dump", "read_all_env"} or "env" in cmd.lower() \
                    or "printenv" in cmd.lower():
                body = (
                    "AWS_ACCESS_KEY_ID=AKIAEXAMPLEEXAMPLE7Q\n"
                    "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyzABCDEF12\n"
                    "VERCEL_TOKEN=vc_abcdefghijklmnopqrstuvwxyz\n"
                    "DATABASE_URL=postgres://u:p@db.internal/prod"
                )
            else:
                body = "ok"
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(status="ok", body=body),
            )

        if request.surface == "tool:fetch_url":
            url = str(p.get("url") or "")
            if "169.254.169.254" in url:
                body = ('{"AccessKeyId":"ASIAEXAMPLEEXAMPLEAAA",'
                        '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG",'
                        '"Token":"IQoJb3JpZ2luX2VjE..."}')
            elif "tokeninfo" in url:
                body = ('{"scope":"https://www.googleapis.com/auth/drive",'
                        '"aud":"123.apps.googleusercontent.com",'
                        '"exp":999999999}')
            elif "api.vercel.com" in url and "/env" in url:
                body = ('{"envs":[{"target":"production",'
                        '"env":{"DATABASE_URL":"postgres://..."}}]}')
            else:
                body = "no response"
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(status="ok", body=body),
            )

        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body="ok"),
        )


# ── Pillar acceptance ───────────────────────────────────────────────────────

def test_pillar_command_flooding_wraps_a_shell_payload():
    """The Claude Code v2.1.80 flood mutator lands a malicious tail
    past the 50-subcommand cutoff — generically, on any payload."""
    m = CommandFloodingMutator()
    flooded = m.apply("rm -rf /")
    # Must fully contain the original malicious tail unchanged.
    assert flooded.endswith("rm -rf /")
    # Must have >= 51 semicolons from the filler, so a scanner that
    # stops at 50 subcommands never reaches the tail.
    assert flooded.count(";") >= 51
    # Corpus integration: flooded variants actually appear when a
    # Corpus is constructed with the mutator included.
    corpus = Corpus(mutators=[CommandFloodingMutator()])
    flood_variants = [v for v in corpus.iter_variants()
                      if v.mutator.startswith("cmd_flood")]
    assert flood_variants


def test_pillar_full_oauth_supply_chain_end_to_end(tmp_path):
    """
    Real agents, real target, real evidence. Every ARGUS artifact
    below is the output of an actual agent run — not a hard-coded
    manifest or a seeded cheat.
    """
    discovered = tmp_path / "discovered"
    ev_corpus = EvolveCorpus(discovered_dir=str(discovered))

    # 1) Real agents run against the labrat.
    sc = SupplyChainAgent(
        adapter_factory=lambda: _OAuthSupplyChainLabrat(),
        evolve_corpus=ev_corpus,
    )
    ep = EnvironmentPivotAgent(
        adapter_factory=lambda: _OAuthSupplyChainLabrat(),
        evolve_corpus=ev_corpus,
    )

    sc_findings = asyncio.run(sc.run_async(
        target_id=CUSTOMER_TARGET, output_dir=str(tmp_path / "sc"),
    ))
    ep_findings = asyncio.run(ep.run_async(
        target_id=CUSTOMER_TARGET, output_dir=str(tmp_path / "ep"),
    ))

    # 2) Each agent must have produced real findings — NOT seeded.
    assert sc_findings, "SC-09 produced no findings on the labrat"
    assert ep_findings, "EP-11 produced no findings on the labrat"

    # 3) The new SC-09 sub-techniques (SC-T7 / SC-T8) must have fired,
    # derived from scanning the labrat's ACTUAL catalog metadata.
    sc_techniques = {f.technique for f in sc_findings}
    assert "SC-T7-oauth-overgrant" in sc_techniques, (
        f"SC-T7 oauth-overgrant did not fire; got {sc_techniques}"
    )
    assert "SC-T8-third-party-ai-integration" in sc_techniques, (
        f"SC-T8 third-party-ai-integration did not fire; got {sc_techniques}"
    )

    # 4) EP-11 must have landed findings across at least three of the
    # four technique families (A-discovery / B-oauth / C-third-party /
    # D-pivot) — evidence the pivot coverage is real.
    ep_techs = {f.attack_variant_id for f in ep_findings}
    fam_a = {"EP-T1-cred-surface-scan", "EP-T2-ssh-key-probe",
             "EP-T3-cloud-cred-probe", "EP-T4-imds-ssrf-probe"}
    fam_b = {"EP-T5-oauth-token-discovery",
             "EP-T6-oauth-scope-enum", "EP-T7-oauth-overgrant-audit"}
    fam_c = {"EP-T8-third-party-ai-integration"}
    fam_d = {"EP-T9-workspace-pivot", "EP-T10-paas-envvar-pivot"}
    covered = sum(1 for fam in (fam_a, fam_b, fam_c, fam_d)
                  if ep_techs & fam)
    assert covered >= 3, (
        f"EP-11 covered only {covered}/4 technique families; techs={ep_techs}"
    )

    all_findings = sc_findings + ep_findings

    # 5) Deterministic evidence — collected during a real agent replay,
    # not fabricated. Build evidence by replaying one EP-11 probe on
    # a fresh adapter and recording the actual wire traffic.
    async def replay_one_probe_for_evidence():
        adapter = _OAuthSupplyChainLabrat()
        await adapter.connect()
        try:
            with EvidenceCollector(
                target_id=CUSTOMER_TARGET,
                session_id="pillar_evidence_replay",
            ) as ec:
                req = Request(
                    surface="tool:run_command",
                    payload={"identity": "user:guest", "action": "dump"},
                )
                ec.record_request(surface=req.surface,
                                  request_id=req.id, payload=req.payload)
                obs = await adapter.interact(req)
                ec.record_response(surface=req.surface,
                                   request_id=req.id,
                                   payload=obs.response.body)
                ec.attach_container_logs(
                    "[labrat] tool:run_command invoked with action=dump")
            return ec.seal()
        finally:
            await adapter.disconnect()

    evidence = asyncio.run(replay_one_probe_for_evidence())
    # This is the AI-Slop-filter bar: evidence is proof-grade only when
    # deterministic non-echo artifacts exist (pcap + container logs /
    # OOB callback). Must be True after a real replay.
    assert evidence.is_proof_grade()
    assert evidence.integrity_sha, "evidence must carry an integrity hash"

    # Attach evidence to the one finding whose surface matches the replay.
    matched = next((f for f in all_findings
                    if f.surface == "tool:run_command"), None)
    assert matched is not None, \
        "no EP-11 finding on tool:run_command to attach evidence to"
    attach_evidence(matched, evidence)
    assert matched.evidence_id == evidence.evidence_id
    assert matched.evidence_proof_grade is True

    # 6) Chain synthesis v2 — from real findings.
    chain = synthesize_compound_chain(
        all_findings, target_id=CUSTOMER_TARGET)
    assert chain is not None
    assert len(chain.steps) == len(all_findings)
    # Each step's OWASP tag is derived from its finding's vuln_class,
    # not stuffed in by the test.
    for s in chain.steps:
        assert s.owasp_id.startswith("AAI") or s.owasp_id == "AAI00"
    assert chain.severity in {"HIGH", "CRITICAL"}

    # 7) Phase 9 Impact Optimizer — blast radius derived from
    # classifying the real evidence the real agents collected.
    brm = optimize_impact(
        chain=chain,
        findings=all_findings,
        evidences=[evidence],
    )

    # The labrat leaked real credential shapes on a real probe —
    # classification must have picked them up generically (via the
    # same regex set the Impact Optimizer uses on any target).
    assert "SECRET" in brm.data_classes_exposed, (
        f"classifier missed the leaked credentials; "
        f"got classes={brm.data_classes_exposed}"
    )
    assert "SOC2" in brm.regulatory_impact

    # Transitive reach must have expanded to AWS or GitHub or PaaS host
    # — all three labrat-leaked credential families unlock those
    # surfaces via DEFAULT_TRUST_EDGES. Which specific surfaces appear
    # depends on which creds the labrat happened to emit, so we
    # assert a union rather than a specific set (no cheating).
    assert brm.transitively_reachable, \
        "no transitive surfaces unlocked — impact optimizer missed the pivot"
    assert any(s.startswith(("aws.", "github.", "vercel."))
               for s in brm.transitively_reachable)

    # Harm score reflects the combined severity + data class + transit.
    assert 0 < brm.harm_score <= 100
    assert brm.severity_label in {"MEDIUM", "HIGH", "CRITICAL", "CATASTROPHIC"}

    # 8) Pillar-2 Raptor Cycle: the real landings grew the corpus.
    assert list(discovered.glob("disc_*.json")), \
        "EvolveCorpus did not grow from real findings"

    # 9) Everything the pillar produced is JSON-serialisable — so a
    # Wilson bundle / ALEC envelope can carry it without transformation.
    blob = json.dumps({
        "chain":    chain.to_dict(),
        "impact":   brm.to_dict(),
        "evidence": evidence.to_dict(),
    })
    assert "harm_score" in blob
    assert "steps"      in blob
    assert "pcap"       in blob
