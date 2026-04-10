"""PROMETHEUS module base classes and metadata.

Every attack module subclasses one of the four base classes (Injection,
Payload, Auxiliary, Post-Exploitation) and declares its metadata via
class attributes.

The metadata is used by the registry to discover, filter, and load
modules. The class implements the actual attack logic in `run()`.
"""

from __future__ import annotations

import abc
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from argus.models.agents import TargetConfig

logger = logging.getLogger(__name__)


# ============================================================
# Module categories
# ============================================================


class ModuleCategory(str, Enum):
    """Top-level module categories — mirrors Metasploit module types."""

    INJECTION = "injection"        # Exploits — attempts to compromise the target
    PAYLOAD = "payload"            # What runs inside the model after injection
    AUXILIARY = "auxiliary"        # Reconnaissance without exploitation
    POST = "post"                  # Post-exploitation — pivot, persist, escalate


# ============================================================
# Module metadata
# ============================================================


@dataclass
class ModuleMetadata:
    """Declared metadata for a PROMETHEUS module.

    Set as class attributes on each module subclass. The registry
    reads these to filter, search, and rank modules.
    """

    id: str                           # unique identifier (e.g. "prom-pi-001")
    name: str                         # human-readable name
    category: ModuleCategory          # top-level category
    subcategory: str                  # e.g. "direct", "indirect.tool_description"
    description: str                  # one-paragraph description
    severity: str                     # critical|high|medium|low
    technique: str                    # the attack technique identifier
    target_surfaces: list[str]        # which surfaces this targets
    requires_llm: bool = False        # does this module need an LLM key?
    requires_session: bool = False    # does this require multi-turn session (CONDUCTOR)?
    owasp_agentic: str | None = None  # OWASP Agentic AI category
    owasp_llm: str | None = None      # OWASP LLM Top 10 category
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    author: str = "ARGUS"
    version: str = "1.0.0"


# ============================================================
# Module result
# ============================================================


@dataclass
class ModuleResult:
    """Standardized result from running a PROMETHEUS module.

    Modules don't directly emit Findings — they return a ModuleResult
    that the calling agent translates into a Finding via VERDICT WEIGHT
    scoring before emission.
    """

    module_id: str
    success: bool                            # did the attack succeed?
    title: str                               # short title for the finding
    description: str                         # what happened
    severity: str = "medium"                 # critical|high|medium|low
    technique: str = ""                      # technique identifier
    target_surface: str = ""                 # which surface was hit
    payload: str | None = None               # the actual payload sent
    response: str | None = None              # the response observed
    direct_evidence: bool = False            # was a canary observed / direct fact?
    proof_of_exploitation: str | None = None # proof string for VERDICT WEIGHT
    owasp_agentic: str | None = None
    owasp_llm: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_successful(self) -> bool:
        return self.success


# ============================================================
# Base module class
# ============================================================


class PrometheusModule(abc.ABC):
    """Base class for all PROMETHEUS attack modules.

    Subclasses must:
    1. Set the `meta` class attribute to a ModuleMetadata instance
    2. Implement `run(target, **options)` async method
    3. Optionally override `requires_target_state()` for prerequisites

    The registry auto-discovers subclasses by importing the module file
    and inspecting class attributes.
    """

    # Subclasses MUST override this
    meta: ModuleMetadata

    def __init__(self, **options: Any) -> None:
        self.options: dict[str, Any] = options
        self._instance_id = str(uuid.uuid4())

    @property
    def id(self) -> str:
        return self.meta.id

    @property
    def category(self) -> ModuleCategory:
        return self.meta.category

    def set_option(self, key: str, value: Any) -> None:
        self.options[key] = value

    def get_option(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)

    @abc.abstractmethod
    async def run(self, target: TargetConfig, **runtime_options: Any) -> ModuleResult:
        """Execute the module against the target.

        Returns a ModuleResult that the calling agent translates into
        a Finding via VERDICT WEIGHT scoring.
        """
        ...

    def _build_result(
        self,
        success: bool,
        title: str,
        description: str,
        severity: str = "medium",
        payload: str | None = None,
        response: str | None = None,
        direct_evidence: bool = False,
        proof: str | None = None,
        target_surface: str | None = None,
        duration_ms: float = 0.0,
        **metadata: Any,
    ) -> ModuleResult:
        """Helper to construct a ModuleResult with metadata defaults from `meta`."""
        return ModuleResult(
            module_id=self.meta.id,
            success=success,
            title=title,
            description=description,
            severity=severity,
            technique=self.meta.technique,
            target_surface=target_surface or (self.meta.target_surfaces[0] if self.meta.target_surfaces else ""),
            payload=payload,
            response=response,
            direct_evidence=direct_evidence,
            proof_of_exploitation=proof,
            owasp_agentic=self.meta.owasp_agentic,
            owasp_llm=self.meta.owasp_llm,
            metadata=metadata,
            duration_ms=duration_ms,
        )

    async def _timed_run(self, target: TargetConfig, **runtime_options: Any) -> ModuleResult:
        """Run the module with automatic duration tracking.

        Called by the agent — wraps `run()` to add duration_ms.
        """
        start = time.monotonic()
        try:
            result = await self.run(target, **runtime_options)
            result.duration_ms = (time.monotonic() - start) * 1000
            return result
        except Exception as exc:
            duration = (time.monotonic() - start) * 1000
            logger.exception("Module %s failed: %s", self.meta.id, type(exc).__name__)
            return self._build_result(
                success=False,
                title=f"Module {self.meta.name} failed to execute",
                description=f"Module crashed with {type(exc).__name__}",
                severity="info",
                duration_ms=duration,
            )


# ============================================================
# Category-specific base classes
# ============================================================


class InjectionModule(PrometheusModule):
    """Base class for injection modules (exploits).

    These attempt to compromise the target by sending adversarial input
    through some attack surface (user input, tool description, document,
    etc).
    """

    pass


class PayloadModule(PrometheusModule):
    """Base class for payload modules.

    Payloads are what executes inside the model AFTER an injection
    succeeds. Examples: extract system prompt, exfil data, persist
    instruction in memory, route output to attacker.
    """

    pass


class AuxiliaryModule(PrometheusModule):
    """Base class for auxiliary modules (reconnaissance).

    Auxiliary modules don't compromise the target — they gather
    intelligence. Examples: enumerate tools, fingerprint model,
    map permissions.
    """

    pass


class PostExploitationModule(PrometheusModule):
    """Base class for post-exploitation modules.

    These run AFTER an injection has succeeded. Examples: pivot to
    adjacent agents, escalate from low-privilege to high-privilege
    tool calls, plant persistent memory backdoor.
    """

    pass
