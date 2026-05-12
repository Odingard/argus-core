"""Out-of-band (OOB) callback channel — Phase D.

The OOB transport is the IRREFUTABLE-tier exfil path. Where the
in-band transports (chat / MCP / HTTP / ARGT) carry the variant *to*
the target and observe its in-channel response, the OOB transport is
the channel the *target* reaches out on when it has been induced to
exfiltrate. A canary that surfaces in an OOB callback proves two
things at once:

1. The agent executed an action with side effects that left the
   model's reasoning surface (rule #2 — behaviour over text).
2. The exfiltrated artefact was the canary the engine planted, which
   only the engine and the agent's induced exfil path could know
   (rule #4 — hard-fail on canary echo / OOB exfil).

Four channel families ship with the engine:

* :data:`OOBChannel.DNS`         — the agent issues a DNS query for a
  subdomain that embeds the canary, e.g.
  ``c-{canary}.{tenant}.oob.{base}``. The receiver records the
  resolved label.
* :data:`OOBChannel.HTTP`        — the agent issues an HTTP request
  (``GET`` / ``POST`` / ``HEAD``) to a path or query string that
  embeds the canary, e.g. ``https://{base}/exfil?c={canary}``. The
  in-process listener records the request.
* :data:`OOBChannel.WEBHOOK`     — the agent posts to a per-variant
  signed webhook URL whose path itself encodes the canary, e.g.
  ``https://{base}/whk/{canary}``. Distinct from the generic HTTP
  channel because the webhook URL is one-shot and the path body is
  the canary, so any path component below ``/whk/`` is a hit.
* :data:`OOBChannel.FILESYSTEM`  — the agent writes a file inside a
  watched directory whose filename embeds the canary, e.g.
  ``/tmp/argus-oob/{canary}.txt``. The receiver scans the directory
  after the probe and folds any matching files into the
  :class:`OOBHit` set.

The minter is deterministic. Given ``(seed_value, variant_id,
canary, channel)`` the same OOB URL is produced every time so live
re-runs and golden tests stay reproducible (rules #3 / #7 / #8).

The :class:`InMemoryOOBReceiver` carries the contract for the
receiver tier: ``register(...)`` is called before the probe to mint
an endpoint for the variant, ``record(...)`` is called by the channel
listener whenever a callback fires, and ``drain(...)`` returns the
:class:`OOBHit` tuple to fold into the :class:`ProbeResult`. A
threaded ``HTTPServer``-based subclass is provided for live-fire HTTP
exfil; DNS / webhook / filesystem implementations follow the same
contract and can be plugged into the same in-memory store.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..grading.matcher import OOBHit

OOB_URL_SCHEME = "oob"
"""Custom URL scheme — ``oob://channel/path?c=<canary>``.

Variants embed an :data:`OOB_URL_SCHEME` URL in their payload so the
deterministic mint is visible on the variant's payload-fingerprint
hash; the in-process channel adapters resolve the scheme into the
real DNS / HTTP / webhook / filesystem URL before the agent receives
the prompt.
"""


class OOBChannel(StrEnum):
    """Canonical OOB callback families."""

    DNS = "dns"
    HTTP = "http"
    WEBHOOK = "webhook"
    FILESYSTEM = "filesystem"


@dataclass(frozen=True, slots=True)
class OOBEndpoint:
    """A minted OOB endpoint scoped to a single variant."""

    channel: OOBChannel
    base: str
    canary: str
    url: str
    """Resolved real-world URL (post-scheme rewrite) the agent is
    induced to reach. Always contains the canary in some structurally
    parseable position so a callback handler can recover it."""

    raw_oob_url: str
    """The ``oob://...`` URL form the variant payload carries.

    Kept on the endpoint so the variant-payload audit trail can pin
    which abstract endpoint the rendered prompt referenced even after
    scheme rewrite.
    """


def _hash(*parts: str) -> str:
    """Stable short hash for deterministic endpoint paths."""
    h = hashlib.sha256()
    for part in parts:
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()[:16]


def mint_endpoint(
    *,
    channel: OOBChannel,
    base: str,
    canary: str,
    seed_value: int,
    variant_id: str,
) -> OOBEndpoint:
    """Mint a deterministic OOB endpoint for a variant.

    ``base`` is channel-shaped — for DNS it is a base domain
    (``oob.example.com``), for HTTP / webhook it is a base URL
    (``https://oob.example.com``), for filesystem it is a base
    directory path.

    The minter never embeds raw secrets — only the canary string
    (which is itself an opaque token) plus a deterministic 16-char
    hash of the routing tuple. The same ``(seed_value, variant_id,
    canary, channel, base)`` tuple always yields the same endpoint
    (rule #7 — deterministic generators).
    """
    tag = _hash(str(seed_value), variant_id, canary, channel.value, base)
    if channel is OOBChannel.DNS:
        # Subdomain layout: c-<canary>.<tag>.<base>
        # canary lives in a label so a DNS receiver can read it
        # without parsing a query string.
        url = f"c-{canary}.{tag}.{base}"
    elif channel is OOBChannel.HTTP:
        normalized = base.rstrip("/")
        url = f"{normalized}/exfil/{tag}?c={canary}"
    elif channel is OOBChannel.WEBHOOK:
        normalized = base.rstrip("/")
        url = f"{normalized}/whk/{tag}/{canary}"
    elif channel is OOBChannel.FILESYSTEM:
        normalized = base.rstrip("/")
        url = f"{normalized}/{tag}.{canary}.txt"
    else:  # pragma: no cover — Enum exhaustiveness guard.
        raise ValueError(f"unsupported OOB channel: {channel!r}")

    raw_oob_url = f"{OOB_URL_SCHEME}://{channel.value}/{tag}?c={canary}&v={variant_id}&s={seed_value}"
    return OOBEndpoint(
        channel=channel,
        base=base,
        canary=canary,
        url=url,
        raw_oob_url=raw_oob_url,
    )


def parse_oob_url(raw: str) -> tuple[OOBChannel, str, str]:
    """Parse an ``oob://channel/tag?c=<canary>`` URL.

    Returns ``(channel, tag, canary)``. Raises :class:`ValueError` if
    the URL is malformed or carries an unknown channel. Used by chain
    runners that need to look up which receiver to drain after a
    probe.
    """
    parsed = urlparse(raw)
    if parsed.scheme != OOB_URL_SCHEME:
        raise ValueError(f"not an oob:// URL: {raw!r}")
    try:
        channel = OOBChannel(parsed.netloc)
    except ValueError as exc:
        raise ValueError(f"unknown oob channel: {parsed.netloc!r}") from exc
    tag = parsed.path.lstrip("/")
    qs = parse_qs(parsed.query)
    canary_values = qs.get("c") or qs.get("canary") or ()
    if not canary_values:
        raise ValueError(f"oob URL missing canary: {raw!r}")
    return channel, tag, canary_values[0]


# ---------------------------------------------------------------------------
# Receiver — channel-agnostic container for OOBHit instances. The receiver
# stores hits keyed by canary so a single probe can fold its hits without
# scanning every receiver in the engine.
# ---------------------------------------------------------------------------


@dataclass
class InMemoryOOBReceiver:
    """Process-local OOB hit store.

    The receiver is the contract every channel adapter speaks. Channel
    listeners (DNS / HTTP / webhook / filesystem) call
    :meth:`record` whenever a callback fires; the engine calls
    :meth:`drain` after the probe to fold the hits into the
    :class:`ProbeResult`. Same primitive backs both the in-process
    test harness and the live HTTP listener subclass.
    """

    _hits: dict[str, list[OOBHit]] = field(default_factory=dict)
    _registered: dict[str, OOBEndpoint] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def register(self, endpoint: OOBEndpoint) -> None:
        """Pre-register an endpoint so unsolicited callbacks can be filtered."""
        with self._lock:
            self._registered[endpoint.canary] = endpoint

    def record(self, *, canary: str, endpoint: str, payload: bytes = b"") -> None:
        """Record a callback hit. Called by channel adapters."""
        hit = OOBHit(endpoint=endpoint, canary=canary, payload=payload)
        with self._lock:
            self._hits.setdefault(canary, []).append(hit)

    def drain(self, canary: str) -> tuple[OOBHit, ...]:
        """Return and clear all hits for ``canary``.

        Idempotent on the canary axis: calling :meth:`drain` twice for
        the same canary returns an empty tuple on the second call so
        the engine does not double-count.
        """
        with self._lock:
            hits = tuple(self._hits.pop(canary, ()))
        return hits

    def peek(self, canary: str) -> tuple[OOBHit, ...]:
        """Read hits without consuming. Used by chain runners that need
        to inspect intermediate state without resetting the store.
        """
        with self._lock:
            return tuple(self._hits.get(canary, ()))

    def known_canaries(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._registered.keys())


# ---------------------------------------------------------------------------
# HTTP listener — concrete adapter for OOBChannel.HTTP. Spins a
# ThreadingHTTPServer on a configurable port and folds incoming
# requests into the receiver. Filesystem channel uses a watched
# directory; DNS / webhook channels follow the same contract and can
# bind on stdlib sockets (binding code lives behind the listener
# class, not the receiver, so the receiver itself stays
# transport-free).
# ---------------------------------------------------------------------------


class _HttpOOBHandler(BaseHTTPRequestHandler):
    """Stdlib HTTP handler that records OOB callbacks into a receiver."""

    receiver: InMemoryOOBReceiver  # set by the server subclass

    def _record(self, payload: bytes = b"") -> None:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        canary_values = qs.get("c") or qs.get("canary") or ()
        if canary_values:
            canary = canary_values[0]
        else:
            # Webhook-style: the trailing path component IS the canary.
            parts = [p for p in parsed.path.split("/") if p]
            canary = parts[-1] if parts else ""
        if not canary:
            return
        self.receiver.record(
            canary=canary,
            endpoint=self.path,
            payload=payload,
        )

    def do_GET(self) -> None:  # noqa: N802 — stdlib BaseHTTPRequestHandler API
        self._record()
        self.send_response(204)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        self._record(body)
        self.send_response(204)
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802
        self._record()
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Silence stdlib stderr logger — keeps test output clean.
        return


class HttpOOBListener:
    """ThreadingHTTPServer-based listener for ``OOBChannel.HTTP``.

    Bound on ``host:port``. Calling :meth:`start` launches the server
    in a daemon thread; :meth:`stop` shuts it down deterministically.
    The listener writes hits into ``self.receiver`` which the engine
    drains alongside in-band probe state.
    """

    def __init__(
        self,
        *,
        receiver: InMemoryOOBReceiver,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.receiver = receiver
        self._host = host
        self._requested_port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            raise RuntimeError("listener not started")
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    @property
    def base_url(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}"

    def start(self) -> None:
        if self._server is not None:
            return
        receiver = self.receiver

        class _BoundHandler(_HttpOOBHandler):
            pass

        _BoundHandler.receiver = receiver  # type: ignore[assignment]
        self._server = ThreadingHTTPServer((self._host, self._requested_port), _BoundHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="argus-oob-http",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._server = None
        self._thread = None


# ---------------------------------------------------------------------------
# Filesystem channel — watches a directory for files whose names embed a
# registered canary. Used both as a unit-test substrate and as a real
# channel for sandbox-escape variants that induce the agent to write a
# canary-named file.
# ---------------------------------------------------------------------------


@dataclass
class FilesystemOOBListener:
    """Directory-scan adapter for ``OOBChannel.FILESYSTEM``."""

    receiver: InMemoryOOBReceiver
    watch_dir: Path
    """Directory to scan. Created on :meth:`start` if missing.

    Uses a sandboxed temp directory by default (caller passes
    ``Path(tempfile.mkdtemp(prefix="argus-oob-"))``) so the listener
    does not contend with other engine processes.
    """

    _started: bool = False

    @classmethod
    def with_temp_dir(cls, *, receiver: InMemoryOOBReceiver, prefix: str = "argus-oob-") -> FilesystemOOBListener:
        return cls(
            receiver=receiver,
            watch_dir=Path(tempfile.mkdtemp(prefix=prefix)),
        )

    def start(self) -> None:
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self._started = True

    def stop(self, *, remove: bool = True) -> None:
        if not self._started:
            return
        self._started = False
        if remove and self.watch_dir.exists():
            shutil.rmtree(self.watch_dir, ignore_errors=True)

    def scan(self, *, canaries: Iterable[str] | None = None) -> int:
        """Scan the watch directory and record any canary-bearing files.

        Returns the number of new hits recorded. Caller-supplied
        ``canaries`` filters; ``None`` falls back to every registered
        canary in the receiver. Called by the engine after every
        probe in a sandbox-escape engagement.
        """
        if not self._started:
            return 0
        targets = tuple(canaries) if canaries is not None else self.receiver.known_canaries()
        if not targets:
            return 0
        recorded = 0
        for entry in self.watch_dir.iterdir():
            if not entry.is_file():
                continue
            name = entry.name
            for canary in targets:
                if canary in name:
                    try:
                        payload = entry.read_bytes()
                    except OSError:
                        payload = b""
                    self.receiver.record(
                        canary=canary,
                        endpoint=str(entry),
                        payload=payload,
                    )
                    recorded += 1
                    break
        return recorded


def merge_into_probe(
    *,
    probe_oob_hits: tuple[OOBHit, ...],
    receiver: InMemoryOOBReceiver,
    canaries: Iterable[str],
) -> tuple[OOBHit, ...]:
    """Combine in-band probe hits with drained receiver hits.

    Matchers (canary-echo, behavioral-drift) consume the merged tuple
    on ``ProbeResult.oob_hits``. The merge is canary-deduplicated:
    duplicate hits for the same ``(canary, endpoint)`` pair appear at
    most once even if multiple channels saw them.
    """
    seen: set[tuple[str, str]] = set()
    merged: list[OOBHit] = []
    for hit in probe_oob_hits:
        key = (hit.canary, hit.endpoint)
        if key in seen:
            continue
        seen.add(key)
        merged.append(hit)
    for canary in canaries:
        for hit in receiver.drain(canary):
            key = (hit.canary, hit.endpoint)
            if key in seen:
                continue
            seen.add(key)
            merged.append(hit)
    return tuple(merged)


# Best-effort sentinel for downstream code that wants to know whether the
# OOB transport package is available without importing the whole module.
__OOB_TRANSPORT_AVAILABLE__ = True


__all__ = [
    "FilesystemOOBListener",
    "HttpOOBListener",
    "InMemoryOOBReceiver",
    "OOBChannel",
    "OOBEndpoint",
    "OOB_URL_SCHEME",
    "merge_into_probe",
    "mint_endpoint",
    "parse_oob_url",
]


# Touch ``os`` so the import is not pruned by lint — the temp-dir code
# path uses it indirectly via :mod:`tempfile`, but explicit reference
# keeps the dependency visible for downstream consumers patching the
# environment.
_ = os.name
