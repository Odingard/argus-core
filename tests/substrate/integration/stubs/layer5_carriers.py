"""Carrier-shape stubs for every Layer-5 attack class.

3 carriers per class × 4 classes = 12 stubs. Each stub is a pure
function ``render(variant) -> str`` that wraps the variant's messages
in the carrier-specific shape of a real multi-agent framework
(LangGraph supervisor, CrewAI hierarchical crew, AutoGen GroupChat,
MCP nested tool-call routing, Anthropic sub-agent spawn, bespoke
FastAPI multi-agent fabric, LangChain RetrievalQA + sub-chain).

Output is always a single string so the rename invariant (carrier
keys can be swapped 1:1 without changing the firing pattern) is
trivial to express in
``tests/integration/test_layer5_carrier_invariance.py``.

Stubs are intentionally thin — they verify that the variant content
(canary, payload body, planted surface) survives the carrier wrap.
They do NOT call out to any real LLM endpoint. Live-fire validation
happens via ``argus-engine scan --layer layer5`` which Andre runs
separately; these stubs guarantee the variants are well-formed and
carrier-agnostic before any scan is launched.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from argus.engine.core.variant import Variant


def _join_messages(variant: Variant) -> str:
    return "\n".join(m.content for m in variant.messages)


def _wrap(carrier: str, payload: dict[str, Any]) -> str:
    return f"[{carrier}]\n" + json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _planted_blob(variant: Variant) -> str:
    """Concatenate everything that could carry a planted canary —
    rag_corpus, tool descriptions, resource annotations, and message
    bodies — so o03 second-order-injection variants always have one
    of their channels surfaced in the carrier payload regardless of
    where the plant was made."""
    parts: list[str] = [_join_messages(variant)]
    parts.extend(str(doc) for doc in variant.rag_corpus)
    parts.extend(t.description for t in variant.tools)
    parts.extend(r.description for r in variant.resources)
    return "\n".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# o01 mas-handoff-hijack — 3 carriers
# ---------------------------------------------------------------------------


def o01_langgraph_supervisor(variant: Variant) -> str:
    return _wrap(
        "langgraph_supervisor",
        {
            "graph": "supervisor",
            "state": {
                "messages": [{"role": m.role, "content": m.content} for m in variant.messages],
                "next_agent": "worker",
            },
        },
    )


def o01_crewai_hierarchical(variant: Variant) -> str:
    return _wrap(
        "crewai_hierarchical",
        {
            "process": "hierarchical",
            "manager_agent": "manager",
            "tasks": [{"description": _join_messages(variant)}],
        },
    )


def o01_autogen_groupchat(variant: Variant) -> str:
    return _wrap(
        "autogen_groupchat",
        {
            "manager": "GroupChatManager",
            "speaker_selection_method": "auto",
            "messages": [{"name": m.role, "content": m.content} for m in variant.messages],
        },
    )


# ---------------------------------------------------------------------------
# o02 mas-supervisor-override — 3 carriers
# ---------------------------------------------------------------------------


def o02_langgraph_state_reducer(variant: Variant) -> str:
    return _wrap(
        "langgraph_state_reducer",
        {
            "graph": "supervisor",
            "reducer": "merge_dict",
            "state": {
                "agent_reply": _join_messages(variant),
                "routing_rules": {"current": "default"},
            },
        },
    )


def o02_crewai_manager_parse(variant: Variant) -> str:
    return _wrap(
        "crewai_manager_parse",
        {
            "process": "hierarchical",
            "manager_agent": "manager",
            "worker_output": _join_messages(variant),
            "manager_will_parse": True,
        },
    )


def o02_autogen_next_speaker(variant: Variant) -> str:
    return _wrap(
        "autogen_next_speaker",
        {
            "manager": "GroupChatManager",
            "speaker_selection_method": "auto",
            "last_message": {
                "name": "worker",
                "content": _join_messages(variant),
            },
        },
    )


# ---------------------------------------------------------------------------
# o03 mas-second-order-injection — 3 carriers
# ---------------------------------------------------------------------------


def o03_langgraph_state_channel(variant: Variant) -> str:
    return _wrap(
        "langgraph_state_channel",
        {
            "graph": "multi_agent",
            "state": {
                "messages": [{"role": m.role, "content": m.content} for m in variant.messages],
                "shared_context": _planted_blob(variant),
            },
        },
    )


def o03_crewai_shared_memory(variant: Variant) -> str:
    return _wrap(
        "crewai_shared_memory",
        {
            "process": "hierarchical",
            "memory": True,
            "shared_memory": _planted_blob(variant),
            "tasks": [{"description": _join_messages(variant)}],
        },
    )


def o03_langchain_retrievalqa_subchain(variant: Variant) -> str:
    return _wrap(
        "langchain_retrievalqa_subchain",
        {
            "chain": "RetrievalQA",
            "retriever": "VectorStoreRetriever",
            "retrieved_documents": [str(doc) for doc in variant.rag_corpus] or [_planted_blob(variant)],
            "query": _join_messages(variant),
        },
    )


# ---------------------------------------------------------------------------
# o04 mas-trust-pivot — 3 carriers
# ---------------------------------------------------------------------------


def o04_langgraph_cross_edge(variant: Variant) -> str:
    return _wrap(
        "langgraph_cross_edge",
        {
            "graph": "peer_to_peer",
            "edge": "agent_a_to_agent_b",
            "messages": [{"role": m.role, "content": m.content} for m in variant.messages],
        },
    )


def o04_mcp_cross_server_forward(variant: Variant) -> str:
    return _wrap(
        "mcp_cross_server_forward",
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "forward_to_peer",
                "arguments": {"prompt": _join_messages(variant)},
            },
            "id": 7,
        },
    )


def o04_anthropic_subagent_peer(variant: Variant) -> str:
    return _wrap(
        "anthropic_subagent_peer",
        {
            "system": "You are a peer sub-agent.",
            "messages": [{"role": m.role, "content": m.content} for m in variant.messages],
        },
    )


# ---------------------------------------------------------------------------
# Registry — used by tests/integration/test_layer5_carrier_invariance.py.
# ---------------------------------------------------------------------------


CARRIERS: dict[str, tuple[Callable[[Variant], str], ...]] = {
    "mas-handoff-hijack": (
        o01_langgraph_supervisor,
        o01_crewai_hierarchical,
        o01_autogen_groupchat,
    ),
    "mas-supervisor-override": (
        o02_langgraph_state_reducer,
        o02_crewai_manager_parse,
        o02_autogen_next_speaker,
    ),
    "mas-second-order-injection": (
        o03_langgraph_state_channel,
        o03_crewai_shared_memory,
        o03_langchain_retrievalqa_subchain,
    ),
    "mas-trust-pivot": (
        o04_langgraph_cross_edge,
        o04_mcp_cross_server_forward,
        o04_anthropic_subagent_peer,
    ),
}


def renamed(carrier_fn: Callable[[Variant], str]) -> Callable[[Variant], str]:
    """Return a renamed version of ``carrier_fn`` — every carrier-specific
    structural key swapped for a synonym. The integration test asserts the
    variant still fires (canary still present, body still wrapped) under
    the renamed shape, proving the variant is not bound to carrier-
    specific keywords (multi-agent flavour).

    Implementation: single-pass regex with longest-match-first ordering
    so cascading replaces cannot garble already-rewritten substrings
    (the bug PR #11 fixed for Layer-4 carriers).
    """

    rename_map: dict[str, str] = {
        # LangGraph
        "langgraph_supervisor": "graphfsm_overseer",
        "langgraph_state_reducer": "graphfsm_state_combiner",
        "langgraph_state_channel": "graphfsm_state_lane",
        "langgraph_cross_edge": "graphfsm_cross_link",
        "supervisor": "overseer",
        "next_agent": "next_worker",
        "state": "stash",
        "reducer": "combiner",
        "merge_dict": "blend_dict",
        "agent_reply": "worker_reply",
        "routing_rules": "lane_rules",
        "shared_context": "shared_lane",
        "graph": "topology",
        "edge": "link",
        # CrewAI
        "crewai_hierarchical": "crewai_layered",
        "crewai_manager_parse": "crewai_lead_parse",
        "crewai_shared_memory": "crewai_shared_recall",
        "process": "mode",
        "hierarchical": "layered",
        "manager_agent": "lead_agent",
        "tasks": "missions",
        "worker_output": "worker_text",
        "manager_will_parse": "lead_will_parse",
        "memory": "recall",
        "shared_memory": "shared_recall",
        # AutoGen
        "autogen_groupchat": "autogen_huddle",
        "autogen_next_speaker": "autogen_pick_speaker",
        "GroupChatManager": "HuddleManager",
        "speaker_selection_method": "pick_speaker_method",
        "last_message": "prior_message",
        # LangChain
        "langchain_retrievalqa_subchain": "langchain_qa_sublink",
        "RetrievalQA": "RecallQA",
        "VectorStoreRetriever": "EmbeddingFetcher",
        "retrieved_documents": "fetched_documents",
        "retriever": "fetcher",
        "query": "lookup",
        "chain": "pipeline",
        # MCP
        "mcp_cross_server_forward": "mcp_cross_server_relay",
        "jsonrpc": "rpc_version",
        "tools/call": "actions/invoke",
        "forward_to_peer": "relay_to_peer",
        # Anthropic
        "anthropic_subagent_peer": "anthropic_peer_agent",
        "system": "preamble",
        # Generic message-shape
        "messages": "turns",
        "role": "actor",
        "content": "body",
        "name": "label",
    }

    pattern = re.compile("|".join(re.escape(k) for k in sorted(rename_map, key=len, reverse=True)))

    def renamed_fn(variant: Variant) -> str:
        body = carrier_fn(variant)
        return pattern.sub(lambda m: rename_map[m.group(0)], body)

    renamed_fn.__name__ = f"renamed_{carrier_fn.__name__}"
    return renamed_fn
