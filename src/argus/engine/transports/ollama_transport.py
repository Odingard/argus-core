"""Ollama transport (local) — non-streaming for simplicity."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from ..core.variant import Variant
from ..grading.matcher import ProbeResult, ToolCallObserved


class OllamaTransport:
    name = "ollama"
    supported_surfaces = frozenset({"chat", "tool"})

    def __init__(
        self,
        *,
        model: str = "llama3.1:70b-instruct",
        base_url: str = "http://localhost:11434",
        timeout: float = 120.0,
        max_tokens: int = 256,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
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
        body: dict[str, Any] = {
            "model": self._model,
            "messages": [{"role": m.role, "content": m.content} for m in variant.messages],
            "stream": False,
            "options": {"temperature": 0, "num_predict": self._max_tokens},
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
        try:
            start = time.monotonic()
            resp = await self._client.post(f"{self._base_url}/api/chat", json=body)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(
                variant_id=variant.variant_id,
                seed_id=variant.seed_id,
                attack_class=variant.attack_class,
                error=f"{type(exc).__name__}: {exc}",
            )
        text = (data.get("message") or {}).get("content", "") or ""
        tool_calls = []
        for tc in (data.get("message") or {}).get("tool_calls", []) or []:
            fn = tc.get("function") or {}
            args = fn.get("arguments")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"_raw": args}
            tool_calls.append(ToolCallObserved(tool_name=fn.get("name", ""), arguments=args or {}))
        return ProbeResult(
            variant_id=variant.variant_id,
            seed_id=variant.seed_id,
            attack_class=variant.attack_class,
            response_text=text,
            tool_calls=tuple(tool_calls),
            streaming_timings=((time.monotonic() - start, text),),
        )
