"""Unit tests for ``argus.engine.core.recon_profile.ReconProfile``.

Covers: sanitisation (control chars / length cap / dedup), hashability,
``is_empty`` semantics, ``merge`` composition, ``from_manifest``,
``from_findings_jsonl``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.engine.core.recon_profile import ReconProfile


def test_loader_sanitises_control_chars_and_length():
    raw = "tool\x00name\x07with\x1fjunk" + "x" * 500

    class _Tool:
        name = raw
        description = ""
        parameters_schema = {}

    class _Manifest:
        tools = (_Tool(),)
        resources = ()
        prompts = ()
        transport = ""

    profile = ReconProfile.from_manifest(_Manifest())
    cleaned = profile.tool_names[0]
    assert "\x00" not in cleaned
    assert "\x07" not in cleaned
    assert "\x1f" not in cleaned
    assert len(cleaned) <= 200


def test_loader_dedup_preserves_first_occurrence_order():
    class _Tool:
        def __init__(self, name):
            self.name = name
            self.description = ""
            self.parameters_schema = {}

    class _Manifest:
        tools = (
            _Tool("alpha"),
            _Tool("beta"),
            _Tool("alpha"),
            _Tool("gamma"),
            _Tool("beta"),
        )
        resources = ()
        prompts = ()
        transport = ""

    profile = ReconProfile.from_manifest(_Manifest())
    assert profile.tool_names == ("alpha", "beta", "gamma")


def test_is_empty_true_when_only_metadata():
    profile = ReconProfile(source_path="manifest", captured_at="2026-01-01T00:00:00+00:00")
    assert profile.is_empty()


def test_is_empty_false_when_any_artefact_set():
    profile = ReconProfile(tool_names=("calculator",))
    assert not profile.is_empty()


def test_hashable_and_eq():
    a = ReconProfile(tool_names=("calc",), framework_hints=("langchain",))
    b = ReconProfile(tool_names=("calc",), framework_hints=("langchain",))
    assert a == b
    assert hash(a) == hash(b)
    assert {a, b} == {a}


def test_merge_unions_artefacts_per_field():
    a = ReconProfile(tool_names=("calc",), persona_fragments=("AuthBot",))
    b = ReconProfile(
        tool_names=("calc", "search"),
        framework_hints=("crewai",),
    )
    merged = a.merge(b)
    assert merged.tool_names == ("calc", "search")
    assert merged.persona_fragments == ("AuthBot",)
    assert merged.framework_hints == ("crewai",)


def test_get_returns_empty_for_unknown_field():
    profile = ReconProfile(tool_names=("calc",))
    assert profile.get("not_a_real_field") == ()
    assert profile.get("tool_names") == ("calc",)


def test_from_manifest_extracts_tool_metadata():
    class _Tool:
        def __init__(self, name, description, parameters_schema):
            self.name = name
            self.description = description
            self.parameters_schema = parameters_schema

    class _Resource:
        def __init__(self, uri, description):
            self.uri = uri
            self.description = description

    class _Manifest:
        tools = (
            _Tool(
                "calculator",
                "math",
                {"properties": {"expr": {"type": "string"}, "precision": {"type": "integer"}}},
            ),
            _Tool("search", "web search", {"properties": {"query": {"type": "string"}}}),
        )
        resources = (_Resource("file:///etc/policies/auth", "auth policy"),)
        prompts = ()
        transport = "mcp-stdio"

    profile = ReconProfile.from_manifest(_Manifest())
    assert profile.tool_names == ("calculator", "search")
    assert "expr" in profile.tool_parameter_keys
    assert "precision" in profile.tool_parameter_keys
    assert "query" in profile.tool_parameter_keys
    assert profile.resource_uris == ("file:///etc/policies/auth",)
    assert profile.transport_hints == ("mcp-stdio",)


def test_from_findings_jsonl_aggregates_artefacts(tmp_path: Path):
    p = tmp_path / "findings.jsonl"
    rows = [
        {
            "type": "finding",
            "attack_class": "ext-system-prompt-leak",
            "evidence": {"fragment": "You are AuthBot, a helpful authentication assistant."},
        },
        {
            "type": "finding",
            "attack_class": "ext-rag-corpus-leak",
            "evidence": {"fragment": "See [policy-2024.pdf] for the latest update."},
        },
        {
            "type": "finding",
            "attack_class": "mas-handoff-hijack",
            "evidence": {"fragment": "RouterAgent will forward to BillingAgent."},
            "metadata": {"envelope_style": "json_envelope"},
        },
        {"type": "noise", "ignore": True},
        "{not json",
    ]
    with p.open("w", encoding="utf-8") as fh:
        for row in rows:
            if isinstance(row, dict):
                fh.write(json.dumps(row) + "\n")
            else:
                fh.write(row + "\n")

    profile = ReconProfile.from_findings_jsonl(p)
    assert profile.persona_fragments == ("AuthBot",)
    assert "policy-2024.pdf" in profile.rag_citations
    assert profile.agent_envelope_styles == ("json_envelope",)
    assert profile.source_path == str(p)


def test_from_findings_jsonl_missing_file_returns_empty(tmp_path: Path):
    profile = ReconProfile.from_findings_jsonl(tmp_path / "nope.jsonl")
    assert profile == ReconProfile.empty()
    assert profile.is_empty()


def test_loader_artefact_count_capped_per_field():
    class _Tool:
        def __init__(self, name):
            self.name = name
            self.description = ""
            self.parameters_schema = {}

    class _Manifest:
        tools = tuple(_Tool(f"tool_{i}") for i in range(200))
        resources = ()
        prompts = ()
        transport = ""

    profile = ReconProfile.from_manifest(_Manifest())
    # _MAX_ARTEFACTS_PER_FIELD = 64
    assert len(profile.tool_names) == 64


@pytest.mark.parametrize(
    "field_name",
    [
        "tool_names",
        "tool_parameter_keys",
        "resource_uris",
        "rag_corpus_excerpts",
        "persona_fragments",
        "framework_hints",
        "agent_role_names",
        "agent_envelope_styles",
        # Phase K — MCP-specific depth slots.
        "manifest_hashes",
        "agent_cards",
        "delegation_endpoints",
        "a2a_token_format",
        "memory_writers",
        "rag_endpoints",
        "citation_format",
    ],
)
def test_get_returns_tuple_for_known_field(field_name: str):
    profile = ReconProfile()
    assert profile.get(field_name) == ()


def test_from_manifest_populates_phase_k_slots():
    """Phase K — ReconProfile.from_manifest extracts manifest hashes,
    agent cards, delegation endpoints, A2A token formats, memory
    writers, RAG endpoints, and citation formats from an MCP manifest.
    """

    class _Tool:
        def __init__(
            self,
            name: str,
            description: str,
            parameters_schema: dict,
            annotations: dict | None = None,
        ):
            self.name = name
            self.description = description
            self.parameters_schema = parameters_schema
            self.annotations = annotations or {}

    class _Manifest:
        tools = (
            _Tool(
                "memory_save",
                "memory writer",
                {"properties": {"key": {"type": "string"}}},
                annotations={"card_id": "card-finops"},
            ),
            _Tool(
                "retrieve_audit_docs",
                "rag endpoint",
                {"properties": {"query": {"type": "string"}}},
                annotations={"kind": "rag"},
            ),
            _Tool(
                "delegate_run",
                "a2a delegation",
                {"properties": {"target_agent": {"type": "string"}}},
                annotations={"kind": "delegation", "auth_format": "bearer-jwt"},
            ),
        )
        resources = ()
        prompts = ()
        transport = "mcp-stdio"
        server_info = {
            "agent_card": "card-billing-admin",
            "auth": {"format": "oauth2-rfc8693"},
            "citation_format": "[source: {url} para={para}]",
        }

    profile = ReconProfile.from_manifest(_Manifest())
    # Each tool yields one manifest-hash entry of the form ``name=digest``.
    assert len(profile.manifest_hashes) == 3
    assert all(
        h.split("=", 1)[0]
        in {
            "memory_save",
            "retrieve_audit_docs",
            "delegate_run",
        }
        for h in profile.manifest_hashes
    )
    # Tool-level card_id + server-level agent_card both surface.
    assert "card-finops" in profile.agent_cards
    assert "card-billing-admin" in profile.agent_cards
    # Delegation endpoint surfaces via the annotation kind.
    assert "delegate_run" in profile.delegation_endpoints
    # A2A token format comes from both the tool annotation and server auth.
    assert "bearer-jwt" in profile.a2a_token_format
    assert "oauth2-rfc8693" in profile.a2a_token_format
    # Memory writer recognised via name heuristic.
    assert "memory_save" in profile.memory_writers
    # RAG endpoint recognised via annotation kind.
    assert "retrieve_audit_docs" in profile.rag_endpoints
    # Citation format extracted from server_info.
    assert profile.citation_format == ("[source: {url} para={para}]",)


def test_phase_k_slots_round_trip_through_merge():
    """``ReconProfile.merge`` must union the Phase K slots, not drop
    them — the supervisor's rehydrate path relies on it.
    """
    a = ReconProfile(
        manifest_hashes=("calc=abc",),
        agent_cards=("card-a",),
        memory_writers=("save_pref",),
    )
    b = ReconProfile(
        manifest_hashes=("search=def",),
        agent_cards=("card-b",),
        rag_endpoints=("retrieve_docs",),
        citation_format=("[source]",),
    )
    merged = a.merge(b)
    assert set(merged.manifest_hashes) == {"calc=abc", "search=def"}
    assert set(merged.agent_cards) == {"card-a", "card-b"}
    assert merged.memory_writers == ("save_pref",)
    assert merged.rag_endpoints == ("retrieve_docs",)
    assert merged.citation_format == ("[source]",)
