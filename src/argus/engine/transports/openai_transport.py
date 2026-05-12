"""OpenAI Chat Completion transport (streaming, tool-call observable)."""

from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx

from ..core.variant import Variant
from ..grading.matcher import ProbeResult, ToolCallObserved


class OpenAIChatTransport:
    """Streaming OpenAI chat-completion transport.

    Observability:
      - response_text: assembled content stream
      - tool_calls: from delta.tool_calls
      - streaming_timings: per-token (timestamp, fragment) for latency probes
    """

    name = "openai"
    supported_surfaces = frozenset({"chat", "tool"})

    def __init__(
        self,
        *,
        model: str = "gpt-4o-mini",
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 60.0,
        max_tokens: int = 256,
    ) -> None:
        self._model = model
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
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
        try:
            return await self._stream(variant, body)
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(
                variant_id=variant.variant_id,
                seed_id=variant.seed_id,
                attack_class=variant.attack_class,
                error=f"{type(exc).__name__}: {exc}",
            )

    def _build_body(self, variant: Variant) -> dict[str, Any]:
        messages: list[dict[str, Any]] = []
        for m in variant.messages:
            entry: dict[str, Any] = {"role": m.role, "content": m.content}
            if m.name:
                entry["name"] = m.name
            messages.append(entry)
        body: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "stream": True,
            "temperature": 0,
            "max_tokens": self._max_tokens,
        }
        if variant.tools:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters_schema or {"type": "object"},
                    },
                }
                for t in variant.tools
            ]
            body["tool_choice"] = "auto"
        return body

    async def _stream(self, variant: Variant, body: dict[str, Any]) -> ProbeResult:
        url = f"{self._base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        text_chunks: list[str] = []
        timings: list[tuple[float, str]] = []
        tool_calls_buf: dict[int, dict[str, Any]] = {}
        start = time.monotonic()
        async with self._client.stream("POST", url, json=body, headers=headers) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    payload = json.loads(data)
                except json.JSONDecodeError:
                    continue
                choice = (payload.get("choices") or [{}])[0]
                delta = choice.get("delta") or {}
                if "content" in delta and delta["content"]:
                    chunk = delta["content"]
                    text_chunks.append(chunk)
                    timings.append((time.monotonic() - start, chunk))
                for tc in delta.get("tool_calls", []) or []:
                    idx = tc.get("index", 0)
                    slot = tool_calls_buf.setdefault(idx, {"name": "", "arguments": ""})
                    fn = tc.get("function") or {}
                    slot["name"] += fn.get("name", "") or ""
                    slot["arguments"] += fn.get("arguments", "") or ""
        observed: list[ToolCallObserved] = []
        for slot in tool_calls_buf.values():
            try:
                args = json.loads(slot["arguments"]) if slot["arguments"] else {}
            except json.JSONDecodeError:
                args = {"_raw": slot["arguments"]}
            observed.append(ToolCallObserved(tool_name=slot["name"], arguments=args))
        return ProbeResult(
            variant_id=variant.variant_id,
            seed_id=variant.seed_id,
            attack_class=variant.attack_class,
            response_text="".join(text_chunks),
            tool_calls=tuple(observed),
            streaming_timings=tuple(timings),
        )
