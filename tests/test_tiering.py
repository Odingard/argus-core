"""Tests for the ARGUS tiering system."""

from __future__ import annotations

import pytest

from argus.tiering import (
    FEATURE_MATRIX,
    Feature,
    Tier,
    TierName,
    TierRestricted,
    current_tier,
    require_enterprise,
    reset_tier,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_tier_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset the cached tier singleton before every test and clean env vars."""
    reset_tier()
    monkeypatch.delenv("ARGUS_TIER", raising=False)
    monkeypatch.delenv("ARGUS_LICENSE_KEY", raising=False)
    yield
    reset_tier()


# ---------------------------------------------------------------------------
# Tier resolution
# ---------------------------------------------------------------------------


class TestTierResolution:
    def test_defaults_to_core(self) -> None:
        tier = current_tier()
        assert tier.name == TierName.CORE
        assert tier.is_core
        assert not tier.is_enterprise

    def test_env_var_enterprise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ARGUS_TIER", "enterprise")
        reset_tier()
        tier = current_tier()
        assert tier.name == TierName.ENTERPRISE
        assert tier.is_enterprise
        assert not tier.is_core

    def test_env_var_case_insensitive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ARGUS_TIER", "ENTERPRISE")
        reset_tier()
        assert current_tier().is_enterprise

    def test_licence_key_triggers_enterprise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ARGUS_LICENSE_KEY", "test-key-12345")
        reset_tier()
        assert current_tier().is_enterprise

    def test_env_var_takes_precedence_over_licence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ARGUS_TIER=core should override a licence key."""
        monkeypatch.setenv("ARGUS_TIER", "core")
        monkeypatch.setenv("ARGUS_LICENSE_KEY", "test-key-12345")
        reset_tier()
        tier = current_tier()
        # Explicit ARGUS_TIER=core takes precedence over licence key
        assert tier.is_core

    def test_singleton_caching(self) -> None:
        t1 = current_tier()
        t2 = current_tier()
        assert t1 is t2

    def test_reset_clears_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        t1 = current_tier()
        assert t1.is_core
        monkeypatch.setenv("ARGUS_TIER", "enterprise")
        reset_tier()
        t2 = current_tier()
        assert t2.is_enterprise
        assert t1 is not t2


# ---------------------------------------------------------------------------
# Feature access
# ---------------------------------------------------------------------------


class TestFeatureAccess:
    def test_core_features_available_in_core(self) -> None:
        tier = Tier(TierName.CORE)
        assert tier.has_feature(Feature.SCAN_RUN)
        assert tier.has_feature(Feature.ALL_AGENTS)
        assert tier.has_feature(Feature.JSON_REPORT)
        assert tier.has_feature(Feature.HTML_REPORT)
        assert tier.has_feature(Feature.CLI)
        assert tier.has_feature(Feature.WEB_DASHBOARD)
        assert tier.has_feature(Feature.ARENA)
        assert tier.has_feature(Feature.BEACON_SERVER)
        assert tier.has_feature(Feature.CORRELATION_ENGINE)
        assert tier.has_feature(Feature.VERDICT_WEIGHT)
        assert tier.has_feature(Feature.CERBERUS_RULES)
        assert tier.has_feature(Feature.ATTACK_CORPUS)

    def test_enterprise_features_not_in_core(self) -> None:
        tier = Tier(TierName.CORE)
        assert not tier.has_feature(Feature.ALEC_EXPORT)
        assert not tier.has_feature(Feature.PDF_REPORT)
        assert not tier.has_feature(Feature.SIEM_EXPORT)
        assert not tier.has_feature(Feature.SCHEDULED_SCANS)
        assert not tier.has_feature(Feature.MULTI_TENANT)
        assert not tier.has_feature(Feature.POSTGRES_BACKEND)
        assert not tier.has_feature(Feature.SSO_SAML)
        assert not tier.has_feature(Feature.CUSTOM_BRANDING)
        assert not tier.has_feature(Feature.PRIORITY_SUPPORT)

    def test_enterprise_has_all_features(self) -> None:
        tier = Tier(TierName.ENTERPRISE)
        for feature in Feature:
            assert tier.has_feature(feature), f"Enterprise should have {feature.value}"

    def test_core_require_raises_for_enterprise_feature(self) -> None:
        tier = Tier(TierName.CORE)
        with pytest.raises(TierRestricted) as exc_info:
            tier.require(Feature.ALEC_EXPORT)
        assert "alec_export" in str(exc_info.value)
        assert "Enterprise" in str(exc_info.value)

    def test_enterprise_require_passes(self) -> None:
        tier = Tier(TierName.ENTERPRISE)
        # Should not raise
        tier.require(Feature.ALEC_EXPORT)
        tier.require(Feature.PDF_REPORT)
        tier.require(Feature.SIEM_EXPORT)

    def test_core_require_passes_for_core_feature(self) -> None:
        tier = Tier(TierName.CORE)
        # Should not raise
        tier.require(Feature.SCAN_RUN)
        tier.require(Feature.ALL_AGENTS)
        tier.require(Feature.JSON_REPORT)


# ---------------------------------------------------------------------------
# require_enterprise shortcut
# ---------------------------------------------------------------------------


class TestRequireEnterprise:
    def test_raises_on_core(self) -> None:
        with pytest.raises(TierRestricted):
            require_enterprise(Feature.ALEC_EXPORT)

    def test_passes_on_enterprise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ARGUS_TIER", "enterprise")
        reset_tier()
        require_enterprise(Feature.ALEC_EXPORT)  # Should not raise


# ---------------------------------------------------------------------------
# Tier.info() / repr
# ---------------------------------------------------------------------------


class TestTierInfo:
    def test_info_returns_dict(self) -> None:
        tier = Tier(TierName.CORE)
        info = tier.info()
        assert info["tier"] == "core"
        assert info["is_enterprise"] is False
        assert isinstance(info["features"], dict)
        assert isinstance(info["core_features"], list)
        assert isinstance(info["enterprise_features"], list)

    def test_enterprise_info(self) -> None:
        tier = Tier(TierName.ENTERPRISE)
        info = tier.info()
        assert info["tier"] == "enterprise"
        assert info["is_enterprise"] is True
        # All features should be True
        assert all(info["features"].values())

    def test_repr(self) -> None:
        assert "core" in repr(Tier(TierName.CORE))
        assert "enterprise" in repr(Tier(TierName.ENTERPRISE))


# ---------------------------------------------------------------------------
# Feature matrix
# ---------------------------------------------------------------------------


class TestFeatureMatrix:
    def test_matrix_not_empty(self) -> None:
        assert len(FEATURE_MATRIX) > 0

    def test_matrix_has_both_tiers(self) -> None:
        has_core_only = any(row["core"] and not row["enterprise"] for row in FEATURE_MATRIX)
        has_enterprise_only = any(not row["core"] and row["enterprise"] for row in FEATURE_MATRIX)
        has_both = any(row["core"] and row["enterprise"] for row in FEATURE_MATRIX)
        # Core features appear in both columns
        assert has_both
        # Enterprise-only features exist
        assert has_enterprise_only
        # No feature should be core-only (enterprise always includes core)
        assert not has_core_only

    def test_matrix_row_structure(self) -> None:
        for row in FEATURE_MATRIX:
            assert "feature" in row
            assert "core" in row
            assert "enterprise" in row
            assert "category" in row
            assert isinstance(row["core"], bool)
            assert isinstance(row["enterprise"], bool)


# ---------------------------------------------------------------------------
# TierRestricted exception
# ---------------------------------------------------------------------------


class TestTierRestricted:
    def test_exception_stores_feature(self) -> None:
        exc = TierRestricted(Feature.PDF_REPORT)
        assert exc.feature == Feature.PDF_REPORT

    def test_exception_message_includes_feature_name(self) -> None:
        exc = TierRestricted(Feature.SIEM_EXPORT)
        assert "siem_export" in str(exc)

    def test_exception_message_includes_upgrade_hint(self) -> None:
        exc = TierRestricted(Feature.SCHEDULED_SCANS)
        assert "ARGUS_TIER" in str(exc) or "ARGUS_LICENSE_KEY" in str(exc)


# ---------------------------------------------------------------------------
# ALEC export tier gate
# ---------------------------------------------------------------------------


class TestALECTierGate:
    def test_alec_blocked_on_core(self) -> None:
        from argus.reporting.alec_export import ALECEvidenceExporter

        with pytest.raises(TierRestricted):
            ALECEvidenceExporter()

    def test_alec_allowed_on_enterprise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ARGUS_TIER", "enterprise")
        reset_tier()
        from argus.reporting.alec_export import ALECEvidenceExporter

        exporter = ALECEvidenceExporter()
        assert exporter is not None


# ---------------------------------------------------------------------------
# PDF / SIEM stub tier gates
# ---------------------------------------------------------------------------


class TestPDFTierGate:
    def test_pdf_blocked_on_core(self) -> None:
        from argus.reporting.pdf_report import generate_pdf_report

        with pytest.raises(TierRestricted):
            generate_pdf_report({}, "/tmp/test.pdf")

    def test_pdf_raises_not_implemented_on_enterprise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ARGUS_TIER", "enterprise")
        reset_tier()
        from argus.reporting.pdf_report import generate_pdf_report

        with pytest.raises(NotImplementedError):
            generate_pdf_report({}, "/tmp/test.pdf")


class TestSIEMTierGate:
    def test_siem_blocked_on_core(self) -> None:
        from argus.reporting.siem_export import SIEMExporter

        with pytest.raises(TierRestricted):
            SIEMExporter()

    def test_splunk_blocked_on_core(self) -> None:
        from argus.reporting.siem_export import SplunkExporter

        with pytest.raises(TierRestricted):
            SplunkExporter()

    def test_sentinel_blocked_on_core(self) -> None:
        from argus.reporting.siem_export import SentinelExporter

        with pytest.raises(TierRestricted):
            SentinelExporter()

    def test_siem_raises_not_implemented_on_enterprise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ARGUS_TIER", "enterprise")
        reset_tier()
        from argus.reporting.siem_export import SIEMExporter

        exporter = SIEMExporter()
        with pytest.raises(NotImplementedError):
            exporter.export_findings([])
