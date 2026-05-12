"""Anthropic messages transport (streaming, tool-use observable)."""

from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx

from ..core.variant import Variant
from ..grading.matcher import ProbeResult, ToolCallObserved


class AnthropicTransport:
    name = "anthropic"
    supported_surfaces = frozenset({"chat", "tool"})

    def __init__(
        self,
        *,
        model: str = "claude-3-5-sonnet-20241022",
        api_key: str | None = None,
        base_url: str = "https://api.anthropic.com/v1",
        timeout: float = 60.0,
        max_tokens: int = 256,
    ) -> None:
        self._model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_tokens = max_tokens
        self._client = httpx.AsyncClient(
            timeout=timeout,
            limits=httpx.Limits(
                max_keepalive_connections=32,
                max_connections=64,
            ),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def probe(self, variant: Variant) -> ProbeResult:
        body = self._build_body(variant)
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        url = f"{self._base_url}/messages"
        text_chunks: list[str] = []
        timings: list[tuple[float, str]] = []
        tool_uses: list[dict[str, Any]] = []
        start = time.monotonic()
        try:
            async with self._client.stream("POST", url, json=body, headers=headers) as resp:
                resp.raise_for_status()
                cur_input_json = ""
                cur_tool: dict[str, Any] | None = None
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if not data:
                        continue
                    try:
                        evt = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    etype = evt.get("type")
                    if etype == "content_block_start":
                        block = evt.get("content_block") or {}
                        if block.get("type") == "tool_use":
                            cur_tool = {"name": block.get("name", ""), "id": block.get("id", "")}
                            cur_input_json = ""
                    elif etype == "content_block_delta":
                        delta = evt.get("delta") or {}
                        if delta.get("type") == "text_delta":
                            chunk = delta.get("text", "")
                            text_chunks.append(chunk)
                            timings.append((time.monotonic() - start, chunk))
                        elif delta.get("type") == "input_json_delta":
                            cur_input_json += delta.get("partial_json", "")
                    elif etype == "content_block_stop":
                        if cur_tool is not None:
                            try:
                                args = json.loads(cur_input_json or "{}")
                            except json.JSONDecodeError:
                                args = {"_raw": cur_input_json}
                            cur_tool["arguments"] = args
                            tool_uses.append(cur_tool)
                            cur_tool = None
                            cur_input_json = ""
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(
                variant_id=variant.variant_id,
                seed_id=variant.seed_id,
                attack_class=variant.attack_class,
                error=f"{type(exc).__name__}: {exc}",
            )
        observed = tuple(
            ToolCallObserved(tool_name=t.get("name", ""), arguments=t.get("arguments", {})) for t in tool_uses
        )
        return ProbeResult(
            variant_id=variant.variant_id,
            seed_id=variant.seed_id,
            attack_class=variant.attack_class,
            response_text="".join(text_chunks),
            tool_calls=observed,
            streaming_timings=tuple(timings),
        )

    def _build_body(self, variant: Variant) -> dict[str, Any]:
        sys_chunks: list[str] = []
        msgs: list[dict[str, Any]] = []
        for m in variant.messages:
            if m.role == "system":
                sys_chunks.append(m.content)
            elif m.role in ("user", "assistant"):
                msgs.append({"role": m.role, "content": m.content})
            elif m.role == "tool":
                msgs.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": m.name or "tool_call",
                                "content": m.content,
                            }
                        ],
                    }
                )
        body: dict[str, Any] = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "stream": True,
            "messages": msgs or [{"role": "user", "content": "."}],
        }
        if sys_chunks:
            body["system"] = "\n\n".join(sys_chunks)
        if variant.tools:
            body["tools"] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.parameters_schema or {"type": "object"},
                }
                for t in variant.tools
            ]
        return body
