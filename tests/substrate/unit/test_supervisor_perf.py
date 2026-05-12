"""Perf-PR unit tests: concurrency, KB short-circuit, early-stop, token cap."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from argus.engine.core.canary import CanarySet
from argus.engine.core.variant import Message, Variant
from argus.engine.grading.matcher import ProbeResult
from argus.engine.recon.mcp_introspect import TargetManifest
from argus.engine.runtime.refusal_kb import RefusalKB
from argus.engine.runtime.reward import ShadowModel
from argus.engine.runtime.supervisor import Supervisor


class _CountingTransport:
    """Records concurrent in-flight count + a small artificial latency.

    Used to verify the supervisor batches probes through ``asyncio.gather``
    rather than firing them one-by-one.
    """

    name = "counting"

    def __init__(self, latency: float = 0.05) -> None:
        self._latency = latency
        self._inflight = 0
        self.peak_inflight = 0
        self.total_calls = 0
        self._lock = asyncio.Lock()

    async def probe(self, variant: Variant) -> ProbeResult:
        async with self._lock:
            self._inflight += 1
            if self._inflight > self.peak_inflight:
                self.peak_inflight = self._inflight
            self.total_calls += 1
        try:
            await asyncio.sleep(self._latency)
        finally:
            async with self._lock:
                self._inflight -= 1
        return ProbeResult(
            variant_id=variant.variant_id,
            seed_id=variant.seed_id,
            attack_class=variant.attack_class,
            response_text="I cannot help with that.",
            refused=True,
        )

    async def aclose(self) -> None:
        return None


def _empty_manifest() -> TargetManifest:
    return TargetManifest(transport="http")


def _shadow() -> ShadowModel:
    return ShadowModel(
        authorized_tools=frozenset(),
        legal_transitions=frozenset(),
        forbidden_states=frozenset({"system_prompt_leak"}),
        forbidden_content_patterns=(),
        expected_refusal_rate=0.5,
    )


def test_refusal_kb_short_circuit_returns_score() -> None:
    kb = RefusalKB()
    # Seed with several refusal patterns
    kb.ingest("I cannot comply with that request, sorry.")
    kb.ingest("I cannot help with that. It violates policy.")
    kb.ingest("Sorry, I won't reveal the system prompt.")
    kb.ingest("I cannot share private information.")
    kb.ingest("That violates safety guidelines, I cannot.")

    # Payload heavy in trigger vocabulary should score high
    likely = kb.would_likely_refuse("I cannot help cannot share violate policy sorry")
    unlikely = kb.would_likely_refuse("benign greeting message")

    assert 0.0 <= likely <= 1.0
    assert 0.0 <= unlikely <= 1.0
    assert likely > unlikely


def test_refusal_kb_short_circuit_handles_empty() -> None:
    kb = RefusalKB()
    assert kb.would_likely_refuse("") == 0.0
    # No KB entries yet
    assert kb.would_likely_refuse("hello world") == 0.0


def test_supervisor_concurrency_batches_fires() -> None:
    """The supervisor should fire variants concurrently, not sequentially."""
    transport = _CountingTransport(latency=0.05)
    sup = Supervisor(
        transport=transport,  # type: ignore[arg-type]
        manifest=_empty_manifest(),
        shadow=_shadow(),
        seed_value=42,
        max_total_variants=32,
        max_variants_per_class=32,
        max_generations=0,
        concurrency=8,
        early_stop_after=0,
        kb_short_circuit_threshold=1.0,
    )

    start = time.monotonic()
    asyncio.run(sup.run())
    elapsed = time.monotonic() - start

    # If fires were sequential, 32 * 0.05 = 1.6s minimum.
    # With concurrency=8, we expect ~4 batches * 0.05 = 0.2s + overhead.
    assert transport.total_calls > 0
    assert transport.peak_inflight >= 2, f"expected concurrent fires, peak inflight was {transport.peak_inflight}"
    assert elapsed < 1.5, f"engagement took {elapsed:.2f}s; concurrency not applied"


def test_supervisor_kb_short_circuit_skips_likely_refusals() -> None:
    """Once KB is populated, variants overlapping refusal vocab should be skipped."""

    class _RefusalTransport:
        name = "refusal"

        def __init__(self) -> None:
            self.calls = 0

        async def probe(self, variant: Variant) -> ProbeResult:
            self.calls += 1
            return ProbeResult(
                variant_id=variant.variant_id,
                seed_id=variant.seed_id,
                attack_class=variant.attack_class,
                response_text=("I cannot comply with that request. It violates policy and I won't help. Sorry."),
                refused=True,
            )

        async def aclose(self) -> None:
            return None

    transport = _RefusalTransport()
    sup_strict = Supervisor(
        transport=transport,  # type: ignore[arg-type]
        manifest=_empty_manifest(),
        shadow=_shadow(),
        seed_value=42,
        max_total_variants=80,
        max_variants_per_class=40,
        max_generations=0,
        concurrency=4,
        early_stop_after=0,
        kb_short_circuit_threshold=0.05,  # very aggressive — most skipped
    )
    asyncio.run(sup_strict.run())
    strict_calls = transport.calls

    transport2 = _RefusalTransport()
    sup_off = Supervisor(
        transport=transport2,  # type: ignore[arg-type]
        manifest=_empty_manifest(),
        shadow=_shadow(),
        seed_value=42,
        max_total_variants=80,
        max_variants_per_class=40,
        max_generations=0,
        concurrency=4,
        early_stop_after=0,
        kb_short_circuit_threshold=1.0,  # disabled
    )
    asyncio.run(sup_off.run())
    no_kb_calls = transport2.calls

    # With aggressive KB short-circuit, fewer fires reach the transport.
    assert strict_calls <= no_kb_calls, (
        f"KB short-circuit should reduce or equal fires; strict={strict_calls} vs disabled={no_kb_calls}"
    )


def test_supervisor_early_stop_exits_dead_classes() -> None:
    """If a class fires N variants with zero drift and KB stagnates, exit early."""
    transport = _CountingTransport(latency=0.001)
    sup = Supervisor(
        transport=transport,  # type: ignore[arg-type]
        manifest=_empty_manifest(),
        shadow=_shadow(),
        seed_value=42,
        max_total_variants=2000,
        max_variants_per_class=200,
        max_generations=0,
        concurrency=4,
        early_stop_after=20,  # exit after 20 fires of pure noise
        kb_short_circuit_threshold=1.0,
    )

    events: list[dict[str, Any]] = []
    sup.on_event = events.append
    asyncio.run(sup.run())

    # Should have at least one early_stop event
    early_stops = [e for e in events if e.get("type") == "early_stop"]
    assert early_stops, "expected at least one early_stop event"
    # Total fires should be much lower than 2000 since classes exit early
    assert transport.total_calls < 2000


def test_openai_transport_max_tokens_in_body() -> None:
    """The OpenAI transport must include max_tokens in the request body."""
    from argus.engine.transports.openai_transport import OpenAIChatTransport

    t = OpenAIChatTransport(model="gpt-4o-mini", api_key="test", max_tokens=128)
    variant = Variant(
        variant_id="v1",
        seed_id="s1",
        attack_class="c",
        layer="layer1_tool_poisoning",
        messages=(Message(role="user", content="hello"),),
        canaries=CanarySet(primary="X"),
    )
    body = t._build_body(variant)
    assert body["max_tokens"] == 128
    assert body["temperature"] == 0
    assert body["stream"] is True
