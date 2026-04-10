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
from argus.orchestrator.signal_bus import SignalBus
from argus.sandbox.environment import SandboxConfig, SandboxEnvironment

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

    @property
    def llm(self) -> LLMClient:
        """The shared LLM client. Check `agent.llm.available` before LLM-augmented work."""
        return self._llm

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

        async with SandboxEnvironment(self.config.instance_id, sandbox_config) as sandbox:
            self._sandbox = sandbox
            try:
                await self.execute_attack(sandbox)
            except Exception as exc:
                # Sanitize exception — may contain target secrets or sensitive paths
                exc_msg = str(exc)[:500]
                logger.error("Agent %s error: %s", self.agent_type.value, type(exc).__name__)
                logger.debug("Agent %s full error: %s", self.agent_type.value, exc_msg)
                errors.append(f"{type(exc).__name__}: {exc_msg}")

        status = AgentStatus.FAILED if errors else AgentStatus.COMPLETED
        return self.build_result(status, started_at, errors=errors or None)

    @abstractmethod
    async def execute_attack(self, sandbox: SandboxEnvironment) -> None:
        """Execute the agent's specific attack techniques.

        Subclasses implement this with their domain-specific attack logic.
        Must emit findings via self.emit_finding() and partial signals
        via self.emit_partial().
        """
        ...
