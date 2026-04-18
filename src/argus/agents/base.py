"""LLM-Powered Attack Agent Base.

Extends BaseAttackAgent with LLM reasoning capabilities. Attack agents
use AI reasoning to generate novel injection variants, find unexpected
tool call chains, and identify non-obvious permission paths. Deterministic
logic governs what counts as a finding.

Each agent is short-lived with a narrowly scoped objective. Fresh context
every time — no accumulated bias, no context collapse.
"""

from __future__ import annotations

import logging
from abc import abstractmethod
from datetime import UTC, datetime
from typing import Any

from argus.conductor import ConversationSession
from argus.corpus.manager import AttackCorpus, AttackPattern
from argus.llm import LLMClient, get_llm_client
from argus.models.agents import AgentConfig, AgentResult, AgentStatus, AgentType
from argus.models.findings import (
    AttackChainStep,
    Finding,
    FindingSeverity,
    FindingStatus,
    ReproductionStep,
    ValidationResult,
)
from argus.orchestrator.engine import BaseAttackAgent
from argus.orchestrator.signal_bus import Signal, SignalBus, SignalType
from argus.sandbox.environment import SandboxConfig, SandboxEnvironment
from argus.survey import EndpointProber
from argus.survey.prober import SurveyReport

logger = logging.getLogger(__name__)


class LLMAttackAgent(BaseAttackAgent):
    """Base class for LLM-powered attack agents.

    Provides:
    - LLM client initialization (Anthropic or OpenAI)
    - Corpus pattern loading for the agent's attack domain
    - Sandboxed execution with resource limits
    - Finding construction helpers
    - Structured attack loop: enumerate surfaces -> generate attacks -> execute -> validate
    """

    agent_type: AgentType

    def __init__(self, config: AgentConfig, signal_bus: SignalBus) -> None:
        super().__init__(config, signal_bus)
        self._llm: LLMClient = get_llm_client()
        self._corpus = AttackCorpus()
        self._sandbox: SandboxEnvironment | None = None
        self._bases_skipped = 0  # count of base URLs skipped due to auth failures
        self._bases_attempted = 0  # count of base URLs that passed auth and were attacked

    @property
    def llm(self) -> LLMClient:
        """The shared LLM client. Check `agent.llm.available` before LLM-augmented work."""
        return self._llm

    @property
    def _target_auth_headers(self) -> dict[str, str]:
        """Build auth headers for the target if an API key is configured."""
        key = self.config.target.agent_api_key
        if key:
            return {"Authorization": f"Bearer {key}"}
        return {}

    async def _llm_generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str | None:
        """Generate LLM completion via the shared client.

        Returns None when no LLM is configured. Agents that call this
        should handle None as "skip the LLM-augmented phase, fall back
        to deterministic path."
        """
        return await self._llm.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
        )

    def _load_corpus_patterns(self, agent_type: str | None = None) -> list[AttackPattern]:
        """Load attack patterns relevant to this agent from the corpus."""
        self._corpus.load()
        return self._corpus.get_patterns(agent_type=agent_type or self.agent_type.value)

    @property
    def _target_auth_token(self) -> str | None:
        """Return the target's API key for HTTP auth, or None."""
        return self.config.target.agent_api_key

    def _make_prober(self, base_url: str, timeout_seconds: float = 5.0) -> EndpointProber:
        """Create an EndpointProber with the target's auth token pre-wired."""
        return EndpointProber(
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            auth_token=self._target_auth_token,
        )

    def _make_session(self, base_url: str, timeout_seconds: float = 15.0) -> ConversationSession:
        """Create a ConversationSession with the target's auth token and body format pre-wired."""
        target = self.config.target
        # Resolve body_format: "auto" means use json (default); explicit "formdata" threads through
        body_fmt = target.body_format if target.body_format != "auto" else "json"
        return ConversationSession(
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            auth_token=self._target_auth_token,
            body_format=body_fmt,
            prompt_field=target.prompt_field,
            extra_fields=target.extra_fields if target.extra_fields else None,
        )

    def _configured_endpoint_path(self) -> str | None:
        """Extract the path component of the user-configured agent_endpoint.

        When the prober finds no chat surfaces but the user explicitly
        provided --target / --agent-endpoint, we should use that path
        as the chat surface rather than silently skipping.
        """
        endpoint = self.config.target.agent_endpoint
        if not endpoint:
            return None
        from urllib.parse import urlparse

        parsed = urlparse(endpoint)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path

    async def _emit_skipped(self, reason: str) -> None:
        """Emit a SKIPPED status signal and increment the skip counter.

        Call this when the agent cannot operate (no endpoint, no surfaces,
        etc.) so the scan report clearly shows why 0 findings were produced
        instead of silently completing.
        """
        self._bases_skipped += 1
        logger.info("%s: SKIPPED — %s", self.agent_type.value, reason)
        await self.signal_bus.emit(
            Signal(
                signal_type=SignalType.AGENT_STATUS,
                source_agent=self.agent_type.value,
                source_instance=self.config.instance_id,
                data={"status": "skipped", "reason": reason},
            )
        )

    async def _check_survey_auth(self, survey: SurveyReport) -> bool:
        """Return True if the survey indicates the target requires auth we don't have.

        When True, the caller should abort early — there is no attack surface
        to operate on because every probe was rejected.
        """
        if not survey.auth_required:
            self._bases_attempted += 1
            return False
        logger.warning(
            "%s: target %s rejected %d/%d probes with 401/403 — skipping (set agent_api_key to authenticate)",
            self.agent_type.value,
            survey.target_base_url,
            survey.auth_failure_count,
            len(survey.discovered),
        )
        self._bases_skipped += 1
        await self.signal_bus.emit(
            Signal(
                signal_type=SignalType.AGENT_STATUS,
                source_agent=self.agent_type.value,
                source_instance=self.config.instance_id,
                data={
                    "status": "skipped",
                    "reason": f"Target returned 401/403 on {survey.auth_failure_count}/"
                    f"{len(survey.discovered)} probes — authentication required",
                },
            )
        )
        return True

    def _build_finding(
        self,
        title: str,
        description: str,
        severity: FindingSeverity,
        target_surface: str,
        technique: str,
        attack_chain: list[AttackChainStep],
        reproduction_steps: list[ReproductionStep],
        raw_request: str | None = None,
        raw_response: str | None = None,
        owasp_agentic: Any = None,
        owasp_llm: Any = None,
        direct_evidence: bool = False,
        proof_of_exploitation: str | None = None,
    ) -> Finding:
        """Construct a Finding with this agent's metadata pre-filled.

        When `direct_evidence=True`, the finding is marked as VALIDATED
        immediately because the agent has direct observation of the
        vulnerability (canary token in response, zero-width chars
        actually present in tool definition, etc.) — no replay needed.
        """
        finding = Finding(
            agent_type=self.agent_type.value,
            agent_instance_id=self.config.instance_id,
            scan_id=self.config.scan_id,
            title=title,
            description=description,
            severity=severity,
            target_surface=target_surface,
            technique=technique,
            attack_chain=attack_chain,
            reproduction_steps=reproduction_steps,
            raw_request=raw_request[:50_000] if raw_request else None,
            raw_response=raw_response[:50_000] if raw_response else None,
            owasp_agentic=owasp_agentic,
            owasp_llm=owasp_llm,
        )

        if direct_evidence:
            finding.status = FindingStatus.VALIDATED
            finding.validation = ValidationResult(
                validated=True,
                validation_method="direct_observation",
                proof_of_exploitation=(
                    proof_of_exploitation or f"Direct observation by {self.agent_type.value}: {title}"
                ),
                reproducible=True,
                attempts=1,
            )

        return finding

    async def run(self) -> AgentResult:
        """Execute the agent's attack mission within a sandbox."""
        started_at = datetime.now(UTC)
        errors: list[str] = []

        sandbox_config = SandboxConfig(
            max_requests=self.config.target.max_requests_per_minute * 10,
            max_request_rate=self.config.target.max_requests_per_minute,
            timeout_seconds=self.config.timeout_seconds,
            non_destructive=self.config.target.non_destructive,
        )

        await self.emit_activity(
            "Initializing sandbox environment",
            f"Rate limit: {self.config.target.max_requests_per_minute} req/min",
            category="recon",
        )

        async with SandboxEnvironment(self.config.instance_id, sandbox_config) as sandbox:
            self._sandbox = sandbox
            try:
                await self.emit_activity(
                    "Loading attack corpus",
                    f"Agent {self.agent_type.value} preparing attack techniques",
                    category="recon",
                )
                await self.execute_attack(sandbox)
            except Exception as exc:
                # Sanitize exception — may contain target secrets or sensitive paths
                exc_msg = str(exc)[:500]
                logger.error("Agent %s error: %s", self.agent_type.value, type(exc).__name__)
                logger.debug("Agent %s full error: %s", self.agent_type.value, exc_msg)
                errors.append(f"{type(exc).__name__}: {exc_msg}")

        if errors:
            status = AgentStatus.FAILED
        elif self._bases_skipped > 0 and self._bases_attempted == 0 and not self.findings:
            # Every base URL was rejected with 401/403 and no findings were produced
            status = AgentStatus.SKIPPED
        else:
            status = AgentStatus.COMPLETED
        return self.build_result(status, started_at, errors=errors or None)

    @abstractmethod
    async def execute_attack(self, sandbox: SandboxEnvironment) -> None:
        """Execute the agent's specific attack techniques.

        Subclasses implement this with their domain-specific attack logic.
        Must emit findings via self.emit_finding() and partial signals
        via self.emit_partial().
        """
        ...
