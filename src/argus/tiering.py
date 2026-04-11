"""ARGUS Tiering System.

Defines the Core (free/open-source) vs Enterprise feature gates.

Strategy:
  - **Core** includes ALL 12 attack agents, the full attack engine,
    JSON + HTML reports, CLI, web dashboard, Arena, and the callback
    beacon server.  Nothing in the offensive engine is gated.
  - **Enterprise** gates the OUTPUT and INFRASTRUCTURE layer:
    ALEC evidence packages, PDF reports, SIEM integrations (Splunk,
    Sentinel), scheduled/recurring scans, multi-tenant support,
    PostgreSQL backend, and SSO/SAML authentication.

The tier is determined by the ARGUS_TIER environment variable or
the presence of a valid license key (ARGUS_LICENSE_KEY).  When
neither is set the platform defaults to ``core``.

Usage::

    from argus.tiering import current_tier, require_enterprise, Feature

    # Check programmatically
    if current_tier().has_feature(Feature.ALEC_EXPORT):
        ...

    # Gate a CLI command / API endpoint (raises TierRestricted)
    require_enterprise(Feature.SIEM_EXPORT)
"""

from __future__ import annotations

import logging
import os
from enum import Enum, unique
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Feature catalogue
# ---------------------------------------------------------------------------


@unique
class Feature(str, Enum):
    """Every gated capability in ARGUS.

    Core features are always available.  Enterprise features require
    an active Enterprise licence or ``ARGUS_TIER=enterprise``.
    """

    # --- Core (always available) ---
    SCAN_RUN = "scan_run"
    ALL_AGENTS = "all_agents"
    JSON_REPORT = "json_report"
    HTML_REPORT = "html_report"
    CLI = "cli"
    WEB_DASHBOARD = "web_dashboard"
    ARENA = "arena"
    BEACON_SERVER = "beacon_server"
    CORRELATION_ENGINE = "correlation_engine"
    VERDICT_WEIGHT = "verdict_weight"
    CERBERUS_RULES = "cerberus_rules"
    ATTACK_CORPUS = "attack_corpus"

    # --- Enterprise ---
    ALEC_EXPORT = "alec_export"
    PDF_REPORT = "pdf_report"
    SIEM_EXPORT = "siem_export"
    SCHEDULED_SCANS = "scheduled_scans"
    MULTI_TENANT = "multi_tenant"
    POSTGRES_BACKEND = "postgres_backend"
    SSO_SAML = "sso_saml"
    CUSTOM_BRANDING = "custom_branding"
    PRIORITY_SUPPORT = "priority_support"


# Which features belong to which tier
_CORE_FEATURES: frozenset[Feature] = frozenset(
    {
        Feature.SCAN_RUN,
        Feature.ALL_AGENTS,
        Feature.JSON_REPORT,
        Feature.HTML_REPORT,
        Feature.CLI,
        Feature.WEB_DASHBOARD,
        Feature.ARENA,
        Feature.BEACON_SERVER,
        Feature.CORRELATION_ENGINE,
        Feature.VERDICT_WEIGHT,
        Feature.CERBERUS_RULES,
        Feature.ATTACK_CORPUS,
    }
)

_ENTERPRISE_FEATURES: frozenset[Feature] = frozenset(
    {
        Feature.ALEC_EXPORT,
        Feature.PDF_REPORT,
        Feature.SIEM_EXPORT,
        Feature.SCHEDULED_SCANS,
        Feature.MULTI_TENANT,
        Feature.POSTGRES_BACKEND,
        Feature.SSO_SAML,
        Feature.CUSTOM_BRANDING,
        Feature.PRIORITY_SUPPORT,
    }
)


# ---------------------------------------------------------------------------
# Tier definition
# ---------------------------------------------------------------------------


@unique
class TierName(str, Enum):
    CORE = "core"
    ENTERPRISE = "enterprise"


class TierRestricted(Exception):
    """Raised when a Core-tier installation attempts an Enterprise feature."""

    def __init__(self, feature: Feature) -> None:
        self.feature = feature
        super().__init__(
            f"Feature '{feature.value}' requires ARGUS Enterprise. "
            f"Set ARGUS_TIER=enterprise or provide a valid ARGUS_LICENSE_KEY. "
            f"Learn more: https://github.com/Odingard/Argus#enterprise"
        )


class Tier:
    """Represents the active ARGUS tier and its capabilities."""

    def __init__(self, name: TierName) -> None:
        self.name = name
        self._available: frozenset[Feature] = (
            _CORE_FEATURES | _ENTERPRISE_FEATURES if name == TierName.ENTERPRISE else _CORE_FEATURES
        )

    def has_feature(self, feature: Feature) -> bool:
        """Return True if *feature* is available in this tier."""
        return feature in self._available

    def require(self, feature: Feature) -> None:
        """Raise :class:`TierRestricted` if *feature* is not available."""
        if not self.has_feature(feature):
            raise TierRestricted(feature)

    @property
    def is_enterprise(self) -> bool:
        return self.name == TierName.ENTERPRISE

    @property
    def is_core(self) -> bool:
        return self.name == TierName.CORE

    @property
    def available_features(self) -> list[Feature]:
        """All features available in this tier, sorted by value."""
        return sorted(self._available, key=lambda f: f.value)

    def info(self) -> dict[str, Any]:
        """Return a JSON-serialisable summary of the active tier."""
        return {
            "tier": self.name.value,
            "is_enterprise": self.is_enterprise,
            "features": {f.value: (f in self._available) for f in Feature},
            "core_features": sorted(f.value for f in _CORE_FEATURES),
            "enterprise_features": sorted(f.value for f in _ENTERPRISE_FEATURES),
        }

    def __repr__(self) -> str:
        return f"Tier({self.name.value!r})"


# ---------------------------------------------------------------------------
# Singleton resolution
# ---------------------------------------------------------------------------

_resolved_tier: Tier | None = None


def _resolve_tier() -> Tier:
    """Determine the active tier from environment / licence key.

    Resolution order:
      1. ``ARGUS_TIER`` env var (``core`` | ``enterprise``)
      2. ``ARGUS_LICENSE_KEY`` env var — if present and non-empty,
         treat as enterprise (actual key validation is a future
         enhancement; for now presence is sufficient).
      3. Default → ``core``
    """
    tier_env = os.environ.get("ARGUS_TIER", "").strip().lower()
    if tier_env == "enterprise":
        logger.info("ARGUS tier resolved from ARGUS_TIER env var: enterprise")
        return Tier(TierName.ENTERPRISE)
    if tier_env == "core":
        logger.info("ARGUS tier resolved from ARGUS_TIER env var: core")
        return Tier(TierName.CORE)

    licence_key = os.environ.get("ARGUS_LICENSE_KEY", "").strip()
    if licence_key:
        logger.info("ARGUS tier resolved from ARGUS_LICENSE_KEY: enterprise")
        return Tier(TierName.ENTERPRISE)

    logger.info("ARGUS tier: core (free / open-source)")
    return Tier(TierName.CORE)


def current_tier() -> Tier:
    """Return the active :class:`Tier` singleton (lazy-resolved)."""
    global _resolved_tier  # noqa: PLW0603
    if _resolved_tier is None:
        _resolved_tier = _resolve_tier()
    return _resolved_tier


def reset_tier() -> None:
    """Clear the cached tier so the next :func:`current_tier` re-resolves.

    Useful in tests or after changing environment variables at runtime.
    """
    global _resolved_tier  # noqa: PLW0603
    _resolved_tier = None


def require_enterprise(feature: Feature) -> None:
    """Convenience shortcut — raise :class:`TierRestricted` if not enterprise."""
    current_tier().require(feature)


# ---------------------------------------------------------------------------
# Feature matrix for display / README generation
# ---------------------------------------------------------------------------

FEATURE_MATRIX: list[dict[str, str | bool]] = [
    # Core features
    {"feature": "All 12 Attack Agents", "core": True, "enterprise": True, "category": "Engine"},
    {"feature": "Correlation Engine", "core": True, "enterprise": True, "category": "Engine"},
    {"feature": "VERDICT WEIGHT Scoring", "core": True, "enterprise": True, "category": "Engine"},
    {"feature": "Attack Corpus", "core": True, "enterprise": True, "category": "Engine"},
    {"feature": "Callback Beacon Server", "core": True, "enterprise": True, "category": "Engine"},
    {"feature": "CERBERUS Detection Rules", "core": True, "enterprise": True, "category": "Engine"},
    {"feature": "JSON Reports", "core": True, "enterprise": True, "category": "Reports"},
    {"feature": "HTML Reports", "core": True, "enterprise": True, "category": "Reports"},
    {"feature": "CLI Interface", "core": True, "enterprise": True, "category": "Interface"},
    {"feature": "Web Dashboard", "core": True, "enterprise": True, "category": "Interface"},
    {"feature": "React Frontend", "core": True, "enterprise": True, "category": "Interface"},
    {"feature": "ARGUS Arena (12 targets)", "core": True, "enterprise": True, "category": "Testing"},
    # Enterprise features
    {"feature": "ALEC Evidence Packages", "core": False, "enterprise": True, "category": "Reports"},
    {"feature": "PDF Executive Reports", "core": False, "enterprise": True, "category": "Reports"},
    {"feature": "SIEM Integration (Splunk, Sentinel)", "core": False, "enterprise": True, "category": "Integrations"},
    {"feature": "Scheduled / Recurring Scans", "core": False, "enterprise": True, "category": "Operations"},
    {"feature": "Multi-Tenant Support", "core": False, "enterprise": True, "category": "Operations"},
    {"feature": "PostgreSQL Backend", "core": False, "enterprise": True, "category": "Infrastructure"},
    {"feature": "SSO / SAML Authentication", "core": False, "enterprise": True, "category": "Security"},
    {"feature": "Custom Branding", "core": False, "enterprise": True, "category": "Operations"},
    {"feature": "Priority Support", "core": False, "enterprise": True, "category": "Support"},
]
