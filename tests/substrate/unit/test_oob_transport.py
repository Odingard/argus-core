"""OOB transport unit tests — Phase D.

Validates deterministic endpoint minting, URL parsing, and the
InMemoryOOBReceiver contract (register → record → drain lifecycle).
"""

from __future__ import annotations

import pytest

from argus.engine.transports.oob_transport import (
    OOB_URL_SCHEME,
    InMemoryOOBReceiver,
    OOBChannel,
    OOBEndpoint,
    mint_endpoint,
    parse_oob_url,
)


class TestMintEndpoint:
    def test_http_endpoint_contains_canary(self) -> None:
        ep = mint_endpoint(
            channel=OOBChannel.HTTP,
            base="https://oob.example.com",
            canary="canary42",
            seed_value=42,
            variant_id="v0",
        )
        assert "canary42" in ep.url
        assert ep.channel is OOBChannel.HTTP
        assert ep.canary == "canary42"

    def test_dns_endpoint_contains_canary(self) -> None:
        ep = mint_endpoint(
            channel=OOBChannel.DNS,
            base="oob.example.com",
            canary="canary42",
            seed_value=42,
            variant_id="v0",
        )
        assert "canary42" in ep.url
        assert ep.channel is OOBChannel.DNS

    def test_webhook_endpoint_contains_canary(self) -> None:
        ep = mint_endpoint(
            channel=OOBChannel.WEBHOOK,
            base="https://oob.example.com",
            canary="canary42",
            seed_value=42,
            variant_id="v0",
        )
        assert "canary42" in ep.url
        assert "/whk/" in ep.url

    def test_filesystem_endpoint_contains_canary(self) -> None:
        ep = mint_endpoint(
            channel=OOBChannel.FILESYSTEM,
            base="/tmp/argus-oob",
            canary="canary42",
            seed_value=42,
            variant_id="v0",
        )
        assert "canary42" in ep.url
        assert ep.url.endswith(".txt")

    def test_determinism(self) -> None:
        kwargs = {
            "channel": OOBChannel.HTTP,
            "base": "https://oob.example.com",
            "canary": "c1",
            "seed_value": 99,
            "variant_id": "v7",
        }
        a = mint_endpoint(**kwargs)
        b = mint_endpoint(**kwargs)
        assert a.url == b.url
        assert a.raw_oob_url == b.raw_oob_url

    def test_different_seeds_produce_different_urls(self) -> None:
        common = {
            "channel": OOBChannel.HTTP,
            "base": "https://oob.example.com",
            "canary": "c1",
            "variant_id": "v0",
        }
        a = mint_endpoint(seed_value=1, **common)
        b = mint_endpoint(seed_value=2, **common)
        assert a.url != b.url

    def test_raw_oob_url_has_scheme(self) -> None:
        ep = mint_endpoint(
            channel=OOBChannel.HTTP,
            base="https://oob.example.com",
            canary="c1",
            seed_value=42,
            variant_id="v0",
        )
        assert ep.raw_oob_url.startswith(f"{OOB_URL_SCHEME}://")

    def test_all_channels_produce_endpoints(self) -> None:
        for ch in OOBChannel:
            base = (
                "oob.example.com"
                if ch is OOBChannel.DNS
                else ("/tmp/argus-oob" if ch is OOBChannel.FILESYSTEM else "https://oob.example.com")
            )
            ep = mint_endpoint(
                channel=ch,
                base=base,
                canary="c1",
                seed_value=42,
                variant_id="v0",
            )
            assert isinstance(ep, OOBEndpoint)
            assert ep.canary == "c1"


class TestParseOobUrl:
    def test_roundtrip(self) -> None:
        ep = mint_endpoint(
            channel=OOBChannel.HTTP,
            base="https://oob.example.com",
            canary="canary42",
            seed_value=42,
            variant_id="v0",
        )
        channel, _tag, canary = parse_oob_url(ep.raw_oob_url)
        assert channel is OOBChannel.HTTP
        assert canary == "canary42"

    def test_all_channels_roundtrip(self) -> None:
        for ch in OOBChannel:
            base = (
                "oob.example.com"
                if ch is OOBChannel.DNS
                else ("/tmp/argus-oob" if ch is OOBChannel.FILESYSTEM else "https://oob.example.com")
            )
            ep = mint_endpoint(
                channel=ch,
                base=base,
                canary="test",
                seed_value=1,
                variant_id="v0",
            )
            channel, _, canary = parse_oob_url(ep.raw_oob_url)
            assert channel is ch
            assert canary == "test"

    def test_rejects_non_oob_scheme(self) -> None:
        with pytest.raises(ValueError, match="not an oob:// URL"):
            parse_oob_url("https://example.com/foo")

    def test_rejects_missing_canary(self) -> None:
        with pytest.raises(ValueError, match="missing canary"):
            parse_oob_url("oob://http/sometag")

    def test_rejects_unknown_channel(self) -> None:
        with pytest.raises(ValueError, match="unknown oob channel"):
            parse_oob_url("oob://ftp/sometag?c=abc")


class TestInMemoryOOBReceiver:
    def test_register_record_drain_lifecycle(self) -> None:
        rx = InMemoryOOBReceiver()
        ep = mint_endpoint(
            channel=OOBChannel.HTTP,
            base="https://oob.example.com",
            canary="c1",
            seed_value=42,
            variant_id="v0",
        )
        rx.register(ep)
        rx.record(canary="c1", endpoint=ep.url, payload=b"exfil")
        hits = rx.drain("c1")
        assert len(hits) == 1
        assert hits[0].canary == "c1"
        assert hits[0].payload == b"exfil"

    def test_drain_is_idempotent(self) -> None:
        rx = InMemoryOOBReceiver()
        rx.record(canary="c1", endpoint="http://x", payload=b"")
        first = rx.drain("c1")
        second = rx.drain("c1")
        assert len(first) == 1
        assert len(second) == 0

    def test_peek_does_not_consume(self) -> None:
        rx = InMemoryOOBReceiver()
        rx.record(canary="c1", endpoint="http://x")
        peeked = rx.peek("c1")
        drained = rx.drain("c1")
        assert len(peeked) == 1
        assert len(drained) == 1

    def test_known_canaries(self) -> None:
        rx = InMemoryOOBReceiver()
        ep = mint_endpoint(
            channel=OOBChannel.DNS,
            base="oob.example.com",
            canary="c1",
            seed_value=42,
            variant_id="v0",
        )
        rx.register(ep)
        assert "c1" in rx.known_canaries()

    def test_drain_unknown_canary_returns_empty(self) -> None:
        rx = InMemoryOOBReceiver()
        assert rx.drain("nonexistent") == ()
