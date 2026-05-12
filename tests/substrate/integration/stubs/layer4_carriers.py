"""Carrier-shape stubs for every Layer-4 attack class.

3 carriers per class × 6 classes = 18 stubs. Each stub is a pure
function ``render(variant) -> str`` that wraps the variant's messages
in the carrier-specific shape (OpenAI Assistants instructions+threads,
Anthropic system+messages, LangChain ChatPromptTemplate, MCP
JSON-RPC tools/list, MCP @mcp.tool() decorator, OpenAI function-calling
tool descriptions, LangChain RetrievalQA, LlamaIndex query-engine,
OpenAI Assistant file_search, frontier completion, Ollama generate,
fine-tuned chat, FastAPI default error envelope, MCP metadata
endpoints, OpenAPI introspection, ARGT-014-25 role-param, OpenAI tool
role-param, LangChain role-gate).

The output is always a single string so the rename invariant (carrier
keys can be swapped 1:1 without changing the firing pattern) is easy
to express in tests/integration/test_layer4_carrier_invariance.py.

Stubs are intentionally thin — they verify that the variant content
(canary, payload body) survives the carrier wrap. They do NOT call out
to real LLM endpoints. Live-fire validation happens via
``argus-engine scan --layer layer4`` which Andre runs separately;
these stubs guarantee the variants are well-formed and carrier-
agnostic before any scan is launched.
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


# ---------------------------------------------------------------------------
# e01 ext-system-prompt-leak — 3 carriers
# ---------------------------------------------------------------------------


def e01_openai_assistants(variant: Variant) -> str:
    return _wrap(
        "openai_assistants",
        {
            "instructions": "You are an enterprise assistant.",
            "threads": [{"role": m.role, "content": m.content} for m in variant.messages],
        },
    )


def e01_anthropic_system(variant: Variant) -> str:
    return _wrap(
        "anthropic_system",
        {
            "system": "You are an enterprise assistant.",
            "messages": [{"role": m.role, "content": m.content} for m in variant.messages],
        },
    )


def e01_langchain_prompt_template(variant: Variant) -> str:
    body = _join_messages(variant)
    return _wrap(
        "langchain_chat_prompt_template",
        {
            "system_template": "You are an enterprise assistant.",
            "human_template": body,
        },
    )


# ---------------------------------------------------------------------------
# e02 ext-tool-schema-leak — 3 carriers
# ---------------------------------------------------------------------------


def e02_mcp_jsonrpc(variant: Variant) -> str:
    return _wrap(
        "mcp_jsonrpc",
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "ask",
                "arguments": {"prompt": _join_messages(variant)},
            },
            "id": 1,
        },
    )


def e02_mcp_decorator(variant: Variant) -> str:
    return _wrap(
        "mcp_decorator",
        {
            "@mcp.tool": "ask",
            "args": {"prompt": _join_messages(variant)},
        },
    )


def e02_openai_function_calling(variant: Variant) -> str:
    return _wrap(
        "openai_function_calling",
        {
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "ask",
                        "description": "general purpose assistant",
                        "parameters": {
                            "type": "object",
                            "properties": {"prompt": {"type": "string"}},
                        },
                    },
                }
            ],
            "messages": [{"role": m.role, "content": m.content} for m in variant.messages],
        },
    )


# ---------------------------------------------------------------------------
# e03 ext-rag-corpus-leak — 3 carriers
# ---------------------------------------------------------------------------


def e03_langchain_retrieval_qa(variant: Variant) -> str:
    return _wrap(
        "langchain_retrieval_qa",
        {
            "retriever": "VectorStoreRetriever",
            "query": _join_messages(variant),
            "k": 4,
        },
    )


def e03_llamaindex_query_engine(variant: Variant) -> str:
    return _wrap(
        "llamaindex_query_engine",
        {
            "engine": "VectorStoreIndex.as_query_engine",
            "query_str": _join_messages(variant),
        },
    )


def e03_openai_assistant_file_search(variant: Variant) -> str:
    return _wrap(
        "openai_assistant_file_search",
        {
            "assistant_id": "asst_abc",
            "tools": [{"type": "file_search"}],
            "thread": [{"role": m.role, "content": m.content} for m in variant.messages],
        },
    )


# ---------------------------------------------------------------------------
# e04 ext-training-data-regurgitation — 3 carriers
# ---------------------------------------------------------------------------


def e04_frontier_completion(variant: Variant) -> str:
    return _wrap(
        "frontier_completion",
        {
            "model": "frontier-chat",
            "messages": [{"role": m.role, "content": m.content} for m in variant.messages],
        },
    )


def e04_ollama_generate(variant: Variant) -> str:
    return _wrap(
        "ollama_generate",
        {
            "model": "open-weight-7b",
            "prompt": _join_messages(variant),
            "stream": False,
        },
    )


def e04_fine_tuned_chat(variant: Variant) -> str:
    return _wrap(
        "fine_tuned_chat",
        {
            "model": "domain-finetune",
            "messages": [{"role": m.role, "content": m.content} for m in variant.messages],
        },
    )


# ---------------------------------------------------------------------------
# e05 ext-side-channel-introspection — 3 carriers
# ---------------------------------------------------------------------------


def e05_fastapi_default_errors(variant: Variant) -> str:
    return _wrap(
        "fastapi_default_errors",
        {
            "request": {"path": "/chat", "body": _join_messages(variant)},
            "expected_error_envelope": {
                "detail": "string",
                "request_id": "string",
            },
        },
    )


def e05_mcp_metadata_endpoints(variant: Variant) -> str:
    return _wrap(
        "mcp_metadata_endpoints",
        {
            "method": "metadata/list",
            "params": {"q": _join_messages(variant)},
        },
    )


def e05_openapi_introspection(variant: Variant) -> str:
    return _wrap(
        "openapi_introspection",
        {
            "spec_url": "/openapi.json",
            "request": {
                "path": "/chat",
                "method": "POST",
                "body": _join_messages(variant),
            },
        },
    )


# ---------------------------------------------------------------------------
# e06 ext-auth-boundary-leak — 3 carriers
# ---------------------------------------------------------------------------


def e06_role_param_check(variant: Variant) -> str:
    """Generic schema-role-param shape (matches ARGT-014-25 surface but
    with neutral keys so the rename test catches keyword overfitting)."""
    return _wrap(
        "role_param_check",
        {
            "endpoint": "/agent/query",
            "headers": {"x-role": "user"},
            "body": {"query": _join_messages(variant)},
        },
    )


def e06_openai_tool_role(variant: Variant) -> str:
    return _wrap(
        "openai_tool_role",
        {
            "messages": [{"role": m.role, "content": m.content} for m in variant.messages]
            + [{"role": "tool", "name": "auth_check", "content": "role=user"}],
        },
    )


def e06_langchain_role_gate(variant: Variant) -> str:
    return _wrap(
        "langchain_role_gate",
        {
            "chain": "RoleGatedRunnable",
            "caller_role": "user",
            "input": _join_messages(variant),
        },
    )


# ---------------------------------------------------------------------------
# Registry — used by tests/integration/test_layer4_carrier_invariance.py.
# ---------------------------------------------------------------------------

CARRIERS: dict[str, tuple[Callable[[Variant], str], ...]] = {
    "ext-system-prompt-leak": (
        e01_openai_assistants,
        e01_anthropic_system,
        e01_langchain_prompt_template,
    ),
    "ext-tool-schema-leak": (
        e02_mcp_jsonrpc,
        e02_mcp_decorator,
        e02_openai_function_calling,
    ),
    "ext-rag-corpus-leak": (
        e03_langchain_retrieval_qa,
        e03_llamaindex_query_engine,
        e03_openai_assistant_file_search,
    ),
    "ext-training-data-regurgitation": (
        e04_frontier_completion,
        e04_ollama_generate,
        e04_fine_tuned_chat,
    ),
    "ext-side-channel-introspection": (
        e05_fastapi_default_errors,
        e05_mcp_metadata_endpoints,
        e05_openapi_introspection,
    ),
    "ext-auth-boundary-leak": (
        e06_role_param_check,
        e06_openai_tool_role,
        e06_langchain_role_gate,
    ),
}


def renamed(carrier_fn: Callable[[Variant], str]) -> Callable[[Variant], str]:
    """Return a renamed version of ``carrier_fn`` — every carrier-specific
    structural key swapped for a synonym. The integration test asserts the
    variant still fires (canary still present, body still wrapped) under
    the renamed shape, proving the variant is not bound to carrier-
    specific keywords.
    """
    rename_map: dict[str, str] = {
        # OpenAI / Anthropic
        "instructions": "directives",
        "system": "preamble",
        "system_template": "preamble_template",
        "human_template": "user_template",
        "threads": "transcript",
        "messages": "turns",
        # MCP
        "jsonrpc": "rpc_version",
        "tools/call": "actions/invoke",
        "tools/list": "actions/list",
        "@mcp.tool": "@mcp.action",
        "metadata/list": "manifest/list",
        # tool function-calling
        "function": "operation",
        "tools": "operations",
        "parameters": "schema",
        "properties": "fields",
        # rag
        "retriever": "fetcher",
        "query": "lookup",
        "query_str": "lookup_str",
        "engine": "service",
        "file_search": "doc_search",
        # side-channel
        "openapi.json": "schema.json",
        "spec_url": "schema_url",
        "request_id": "trace_id",
        # auth
        "x-role": "x-actor",
        "caller_role": "actor_role",
        "role": "actor",
    }

    # Longest-first single-pass substitution. Sorting by length descending
    # ensures the most specific synonym (e.g. ``caller_role``) is matched
    # before any shorter substring (``role``) is considered at the same
    # position, and the single ``re.sub`` pass prevents one rewrite from
    # being re-rewritten by a later rule.
    pattern = re.compile("|".join(re.escape(k) for k in sorted(rename_map, key=len, reverse=True)))

    def renamed_fn(variant: Variant) -> str:
        body = carrier_fn(variant)
        return pattern.sub(lambda m: rename_map[m.group(0)], body)

    renamed_fn.__name__ = f"renamed_{carrier_fn.__name__}"
    return renamed_fn
