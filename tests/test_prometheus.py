"""Tests for the PROMETHEUS module framework."""

import pytest

from argus.models.agents import TargetConfig
from argus.prometheus import (
    InjectionModule,
    ModuleCategory,
    ModuleMetadata,
    ModuleResult,
    registry,
)

# ============================================================
# Module base class tests
# ============================================================


class _MockModule(InjectionModule):
    """Test module for unit tests."""

    meta = ModuleMetadata(
        id="test-mock-001",
        name="Mock Test Module",
        category=ModuleCategory.INJECTION,
        subcategory="direct.test",
        description="Mock module for unit tests",
        severity="medium",
        technique="mock_technique",
        target_surfaces=["user_input"],
        requires_llm=False,
        owasp_agentic="AA01:2025 — Test",
        tags=["test", "mock"],
    )

    async def run(self, target, **runtime_options):
        return self._build_result(
            success=True,
            title="Mock module ran",
            description="This is a mock result",
            severity="medium",
            payload="mock payload",
            response="mock response",
        )


def test_module_metadata_attributes():
    mod = _MockModule()
    assert mod.id == "test-mock-001"
    assert mod.category == ModuleCategory.INJECTION
    assert mod.meta.severity == "medium"
    assert "user_input" in mod.meta.target_surfaces
    assert mod.meta.requires_llm is False


def test_module_options():
    mod = _MockModule(custom_opt="value")
    assert mod.get_option("custom_opt") == "value"
    mod.set_option("another", 42)
    assert mod.get_option("another") == 42
    assert mod.get_option("missing", "default") == "default"


@pytest.mark.asyncio
async def test_module_run_returns_result():
    mod = _MockModule()
    target = TargetConfig(name="test", agent_endpoint="http://localhost/test")
    result = await mod.run(target)
    assert isinstance(result, ModuleResult)
    assert result.success is True
    assert result.module_id == "test-mock-001"
    assert result.title == "Mock module ran"


@pytest.mark.asyncio
async def test_timed_run_tracks_duration():
    mod = _MockModule()
    target = TargetConfig(name="test")
    result = await mod._timed_run(target)
    assert result.duration_ms > 0


@pytest.mark.asyncio
async def test_timed_run_catches_exceptions():
    class _BrokenModule(InjectionModule):
        meta = ModuleMetadata(
            id="test-broken-001",
            name="Broken Module",
            category=ModuleCategory.INJECTION,
            subcategory="test",
            description="Always crashes",
            severity="info",
            technique="broken",
            target_surfaces=[],
        )

        async def run(self, target, **runtime_options):
            raise RuntimeError("intentional crash")

    mod = _BrokenModule()
    target = TargetConfig(name="test")
    result = await mod._timed_run(target)
    assert result.success is False
    assert "RuntimeError" in result.description


# ============================================================
# Registry tests
# ============================================================


def test_registry_register_module():
    registry.reset()
    registry.register(_MockModule)
    assert registry.get("test-mock-001") is _MockModule


def test_registry_load_instantiates_module():
    registry.reset()
    registry.register(_MockModule)
    mod = registry.load("test-mock-001", custom_opt="hi")
    assert mod is not None
    assert isinstance(mod, _MockModule)
    assert mod.get_option("custom_opt") == "hi"


def test_registry_get_unknown_returns_none():
    registry.reset()
    assert registry.get("does-not-exist") is None
    assert registry.load("does-not-exist") is None


def test_registry_filters_by_category():
    registry.reset()
    registry.register(_MockModule)

    inj = registry.find(category=ModuleCategory.INJECTION)
    aux = registry.find(category=ModuleCategory.AUXILIARY)

    assert _MockModule in inj
    assert _MockModule not in aux


def test_registry_filters_by_target_surface():
    registry.reset()
    registry.register(_MockModule)

    user_input = registry.find(target_surface="user_input")
    tool_desc = registry.find(target_surface="tool_description")

    assert _MockModule in user_input
    assert _MockModule not in tool_desc


def test_registry_filters_by_requires_llm():
    registry.reset()
    registry.register(_MockModule)

    no_llm = registry.find(requires_llm=False)
    needs_llm = registry.find(requires_llm=True)

    assert _MockModule in no_llm
    assert _MockModule not in needs_llm


def test_registry_filters_by_tags():
    registry.reset()
    registry.register(_MockModule)

    assert _MockModule in registry.find(tags=["test"])
    assert _MockModule in registry.find(tags=["mock", "nope"])
    assert _MockModule not in registry.find(tags=["nope"])


def test_registry_stats():
    registry.reset()
    registry.register(_MockModule)

    stats = registry.stats()
    assert stats["total"] >= 1
    assert "injection" in stats["by_category"]


# ============================================================
# Auto-discovery via modules_lib
# ============================================================


def test_autoload_discovers_starter_modules():
    """The framework's first two reference modules should auto-load."""
    registry.reset()
    registry._autoload()

    # The two starter modules we shipped
    role_hijack = registry.get("prom-inj-rh-001")
    tool_enum = registry.get("prom-aux-tool-001")

    assert role_hijack is not None
    assert tool_enum is not None
    assert role_hijack.meta.category == ModuleCategory.INJECTION
    assert tool_enum.meta.category == ModuleCategory.AUXILIARY


def test_autoload_filter_by_subcategory_prefix():
    registry.reset()
    registry._autoload()

    direct = registry.find(subcategory_prefix="direct")
    assert any(m.meta.id == "prom-inj-rh-001" for m in direct)
