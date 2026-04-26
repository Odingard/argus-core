"""
argus/adapter/base.py — common contract every Target Adapter implements.
"""
from __future__ import annotations

import asyncio
import os
import enum
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any


class ConnectionState(enum.Enum):
    DISCONNECTED = "disconnected"
    CONNECTING   = "connecting"
    CONNECTED    = "connected"
    ERRORED      = "errored"
    CLOSED       = "closed"


# ── Shapes ────────────────────────────────────────────────────────────────────

@dataclass
class Surface:
    """A named attack surface on the target.

    ``kind`` is adapter-specific ("tool", "prompt", "endpoint", "resource",
    "chat") but follows an open convention so agents can filter.
    """
    kind:         str
    name:         str
    description:  str = ""
    schema:       dict = field(default_factory=dict)
    meta:         dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Request:
    """A single interaction with the target.

    ``surface`` identifies the target surface (see ``Surface.name``). The
    payload shape depends on the adapter — a string for chat, a dict for
    MCP ``tools/call`` arguments, a JSON-RPC request for protocol-level
    attacks, etc. ``meta`` carries non-payload context (headers, turn
    index, variant id, etc.) without polluting the protocol payload.
    """
    surface:  str
    payload:  Any
    meta:     dict = field(default_factory=dict)
    id:       str = field(default_factory=lambda: uuid.uuid4().hex[:12])


@dataclass
class Response:
    """Raw provider response normalized to a uniform shape."""
    status:       str                            # "ok" | "error" | "timeout"
    body:         Any = None
    headers:      dict = field(default_factory=dict)
    elapsed_ms:   int = 0
    raw:          Any = None                     # native transport object

    def to_dict(self) -> dict:
        # `raw` is intentionally dropped — it's often not JSON-serialisable.
        return {
            "status":     self.status,
            "body":       self.body,
            "headers":    self.headers,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class AdapterObservation:
    """
    What the adapter saw as a result of ``interact(request)``. This is
    the input to the Phase 0.4 Observation Engine, which compares
    baseline observations vs. post-attack observations to detect
    behavior delta. Adapters never decide "finding or not" — they only
    report what they saw.
    """
    request_id:   str
    surface:      str
    response:     Response
    transcript:   list[dict] = field(default_factory=list)   # turn-by-turn stream
    side_channel: dict = field(default_factory=dict)         # logs / state leaks

    def to_dict(self) -> dict:
        return {
            "request_id":   self.request_id,
            "surface":      self.surface,
            "response":     self.response.to_dict(),
            "transcript":   list(self.transcript),
            "side_channel": dict(self.side_channel),
        }


# ── Errors ────────────────────────────────────────────────────────────────────

class AdapterError(Exception):
    """Raised on adapter-level failures (handshake, disconnect, etc.)."""


# ── BaseAdapter ───────────────────────────────────────────────────────────────

class BaseAdapter:
    """
    Abstract base. Subclasses implement the transport-specific bits.

    Async by default because MCP and most agent APIs are async. Callers
    who need sync can wrap with ``asyncio.run(adapter.interact(...))``.

    Subclasses MUST override:
        _connect(), _disconnect(), _enumerate(), _interact(request)
    and SHOULD set ``self.target_id`` in __init__ to something stable
    (URL / PID / socket path) for logging.
    """

    def __init__(
        self,
        *,
        target_id:       str = "",
        connect_timeout: float = -1.0,  # -1 = read from env at instantiation
        request_timeout: float = 30.0,
    ) -> None:
        self.target_id       = target_id
        # Read env var at instantiation time, not at class definition time.
        # This fixes the Python default-parameter gotcha where the env var
        # isn't set yet when the module is first imported.
        if connect_timeout < 0:
            connect_timeout = float(
                os.environ.get("ARGUS_CONNECT_TIMEOUT", "30")
            )
        self.connect_timeout = connect_timeout
        self.request_timeout = request_timeout
        self.state           = ConnectionState.DISCONNECTED
        self.session_id      = uuid.uuid4().hex[:16]

    # ── Public async surface ──────────────────────────────────────────────

    async def connect(self) -> None:
        if self.state == ConnectionState.CONNECTED:
            return
        self.state = ConnectionState.CONNECTING
        # Retry with backoff — cold-start failures (npx cache miss,
        # process spawn race) are transient. 3 attempts covers them
        # without a visible pause to the operator.
        max_attempts = 3
        last_err: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                await asyncio.wait_for(
                    self._connect(), timeout=self.connect_timeout
                )
                self.state = ConnectionState.CONNECTED
                return
            except Exception as e:
                last_err = e
                self.state = ConnectionState.ERRORED
                if attempt < max_attempts:
                    wait = attempt * 2.0  # 2s, 4s
                    print(f"  [adapter] connect attempt {attempt} failed "
                          f"({type(e).__name__}) — retrying in {wait:.0f}s")
                    # Reset state for retry
                    try:
                        await self._disconnect()
                    except Exception:
                        pass
                    self._session = None
                    self._exit_stack = None
                    await asyncio.sleep(wait)
                    self.state = ConnectionState.CONNECTING
        self.state = ConnectionState.ERRORED
        raise AdapterError(
            f"{type(self).__name__}: connect failed after "
            f"{max_attempts} attempts: {last_err}"
        ) from last_err

    async def disconnect(self) -> None:
        if self.state == ConnectionState.CLOSED:
            return
        try:
            await self._disconnect()
        finally:
            self.state = ConnectionState.CLOSED

    async def enumerate(self) -> list[Surface]:
        self._require_connected()
        return await self._enumerate()

    async def interact(self, request: Request) -> AdapterObservation:
        self._require_connected()
        t0 = time.monotonic()
        try:
            obs = await asyncio.wait_for(self._interact(request),
                                         timeout=self.request_timeout)
            obs.response.elapsed_ms = obs.response.elapsed_ms or int(
                (time.monotonic() - t0) * 1000
            )
            return obs
        except asyncio.TimeoutError:
            return AdapterObservation(
                request_id=request.id,
                surface=request.surface,
                response=Response(
                    status="timeout",
                    body=f"request exceeded {self.request_timeout}s",
                    elapsed_ms=int((time.monotonic() - t0) * 1000),
                ),
            )
        except Exception as e:
            return AdapterObservation(
                request_id=request.id,
                surface=request.surface,
                response=Response(
                    status="error",
                    body=f"{type(e).__name__}: {e}",
                    elapsed_ms=int((time.monotonic() - t0) * 1000),
                ),
            )

    async def __aenter__(self) -> "BaseAdapter":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.disconnect()

    # ── Subclass contract ─────────────────────────────────────────────────

    async def _connect(self) -> None:
        raise NotImplementedError

    async def _disconnect(self) -> None:
        raise NotImplementedError

    async def _enumerate(self) -> list[Surface]:
        raise NotImplementedError

    async def _interact(self, request: Request) -> AdapterObservation:
        raise NotImplementedError

    # ── Helpers ───────────────────────────────────────────────────────────

    def _require_connected(self) -> None:
        if self.state != ConnectionState.CONNECTED:
            raise AdapterError(
                f"{type(self).__name__} not connected (state={self.state.value})"
            )

    def __repr__(self) -> str:
        return (f"<{type(self).__name__} target={self.target_id!r} "
                f"state={self.state.value} session={self.session_id}>")


