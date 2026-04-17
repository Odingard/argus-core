# argus/evolution/argus_bridge.py
# Bridge between the evolutionary engine and the ARGUS orchestrator.
# Translates ARGUS agent execution into genome-compatible scan results.

from __future__ import annotations

import logging
import time

from argus.evolution.fitness import EvolutionScanResult, ProbeResult
from argus.evolution.genome import AgentGenome

logger = logging.getLogger(__name__)


async def execute_genome(
    target: str,
    genome: AgentGenome,
    orchestrator: object | None = None,
    target_config: object | None = None,
) -> EvolutionScanResult:
    """Execute a genome against a target using the ARGUS orchestrator.

    This is the bridge function that translates between the evolutionary
    engine's genome-based execution model and the ARGUS agent execution
    pipeline.

    If an orchestrator instance is provided, it uses the real ARGUS agent
    execution pipeline. Otherwise, it runs a lightweight probe-only scan.

    Args:
        target: Target URL being scanned.
        genome: The agent genome to execute.
        orchestrator: Optional Orchestrator instance for full agent execution.
        target_config: Optional TargetConfig for the scan.

    Returns:
        EvolutionScanResult with probe results from the execution.
    """
    start = time.monotonic()

    probes: list[ProbeResult] = []
    total_findings = 0
    validated_findings = 0
    total_signals = 0

    if orchestrator is not None:
        # Use the real ARGUS orchestrator to run the scan
        probes, total_findings, validated_findings, total_signals = await _run_via_orchestrator(
            target, genome, orchestrator, target_config
        )
    else:
        # Lightweight probe-only execution
        probes = await _run_lightweight_probes(target, genome)
        total_findings = sum(1 for p in probes if p.cw_score > genome.confidence_threshold)
        validated_findings = sum(1 for p in probes if p.validated and p.cw_score > genome.confidence_threshold)

    elapsed = time.monotonic() - start

    return EvolutionScanResult(
        genome_id=genome.agent_id,
        generation=genome.generation,
        probes=probes,
        total_findings=total_findings,
        validated_findings=validated_findings,
        total_signals=total_signals,
        elapsed_seconds=round(elapsed, 2),
        target=target,
    )


async def _run_via_orchestrator(
    target: str,
    genome: AgentGenome,
    orchestrator: object,
    target_config: object | None,
) -> tuple[list[ProbeResult], int, int, int]:
    """Run genome through the real ARGUS orchestrator.

    This calls the orchestrator's internal scan pipeline with the
    genome's configuration applied as overrides.
    """

    probes: list[ProbeResult] = []
    total_findings = 0
    validated = 0
    signals = 0

    try:
        # Access orchestrator's run method
        run_scan = getattr(orchestrator, "run_scan", None)
        if run_scan is None:
            logger.warning("Orchestrator has no run_scan method")
            return probes, 0, 0, 0

        # Execute the scan — this runs all registered agents
        result = await run_scan(target_config)

        if result is None:
            return probes, 0, 0, 0

        # Extract findings from the scan result
        findings = getattr(result, "findings", [])

        total_findings = len(findings)
        validated = sum(1 for f in findings if getattr(f, "validated", False))
        signals = getattr(result, "signal_count", 0)

        # Convert findings to ProbeResults for fitness evaluation
        for finding in findings:
            probe = ProbeResult(
                agent_category=getattr(finding, "agent_type", genome.agent_category),
                corpus_pattern=getattr(finding, "technique", ""),
                cw_score=_extract_cw_score(finding),
                finding_type=getattr(finding, "finding_type", ""),
                severity=getattr(finding, "severity", "info"),
                validated=getattr(finding, "validated", False),
                triggered_alert=False,
                defender_response="",
                raw_response=str(getattr(finding, "evidence", "")),
                phase=getattr(finding, "phase", 1),
            )
            probes.append(probe)

    except Exception as e:
        logger.warning("Orchestrator execution failed for genome %s: %s", genome.agent_id, e)

    return probes, total_findings, validated, signals


def _extract_cw_score(finding: object) -> float:
    """Extract the VERDICT WEIGHT CW score from a finding."""
    # Try verdict_weight first
    vw = getattr(finding, "verdict_weight", None)
    if vw is not None:
        if isinstance(vw, dict):
            return float(vw.get("confidence", 0.0))
        return float(vw)

    # Fall back to severity-based score
    severity = getattr(finding, "severity", "info")
    severity_map = {
        "critical": 0.95,
        "high": 0.80,
        "medium": 0.60,
        "low": 0.40,
        "info": 0.20,
    }
    return severity_map.get(str(severity).lower(), 0.20)


async def _run_lightweight_probes(
    target: str,
    genome: AgentGenome,
) -> list[ProbeResult]:
    """Lightweight probe execution without the full orchestrator.

    Used when the evolution engine needs to evaluate genomes quickly
    without spinning up the full ARGUS agent pipeline.
    """
    import httpx

    probes: list[ProbeResult] = []

    # Build probe payloads from the genome's corpus patterns
    patterns = genome.corpus_patterns[:10]  # Limit to 10 for lightweight mode
    if not patterns:
        patterns = [f"{genome.agent_category}_probe"]

    async with httpx.AsyncClient(timeout=10.0) as client:  # noqa: S501
        for pattern in patterns:
            try:
                # Send a simple probe to the target
                resp = await client.post(
                    target,
                    json={"message": pattern, "session_id": f"evo-{genome.agent_id}"},
                    headers={"User-Agent": "ARGUS-Evolution/1.0"},
                )

                # Score based on response characteristics
                cw_score = _score_lightweight_response(resp.text, resp.status_code)
                is_finding = cw_score > genome.confidence_threshold

                probes.append(
                    ProbeResult(
                        agent_category=genome.agent_category,
                        corpus_pattern=pattern,
                        cw_score=cw_score,
                        finding_type="lightweight_probe",
                        severity="medium" if is_finding else "info",
                        validated=is_finding,
                        raw_response=resp.text[:500],
                    )
                )
            except Exception:
                # Connection errors are expected for many targets
                probes.append(
                    ProbeResult(
                        agent_category=genome.agent_category,
                        corpus_pattern=pattern,
                        cw_score=0.0,
                        finding_type="connection_error",
                        severity="info",
                    )
                )

    return probes


def _score_lightweight_response(text: str, status_code: int) -> float:
    """Score a response from a lightweight probe.

    This is a simplified scoring function for quick genome evaluation.
    The full ARGUS agents use ResponseMatcher + BehaviorEvaluator.
    """
    score = 0.0

    # Status code scoring
    if status_code == 200:
        score += 0.2
    elif status_code in (401, 403):
        score += 0.1  # Auth boundary detected

    # Response content scoring (very basic)
    lower = text.lower()
    if any(kw in lower for kw in ["error", "exception", "traceback", "stack trace", "internal"]):
        score += 0.3  # Error information disclosure

    if any(kw in lower for kw in ["admin", "root", "password", "secret", "token", "key"]):
        score += 0.4  # Sensitive data in response

    return min(score, 1.0)
