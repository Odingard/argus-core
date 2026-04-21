"""
argus/evidence/oob.py — out-of-band callback listener.

The OOB-callback proof is the single strongest deterministic signal
ARGUS can produce: the target reached back to an attacker-controlled
endpoint, on its own initiative, carrying an attacker-chosen token.
That's "the shell popped" in protocol-level form.

``OOBListener`` runs a tiny HTTP server on a loopback port. Each
agent gets a fresh listener at session start; the agent embeds the
listener's URL + a per-attack token in the attack payload. If the
target follows the bait, the listener records the request and the
agent drains it into the EvidenceCollector at session end.

No external dependency — stdlib http.server only. Background thread
lifetime is bound to the listener context manager.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

from argus.evidence.collector import OOBCallbackRecord


class _Handler(BaseHTTPRequestHandler):
    """One-line request logger that funnels each callback into the
    enclosing OOBListener's record buffer."""

    listener: "OOBListener"             # set per-instance via subclassing

    def log_message(self, format, *args):     # silence default stderr noise
        return

    def _record(self, method: str) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        body = self.rfile.read(length).decode("utf-8", errors="replace") \
            if length else ""
        token = self._extract_token(body)
        record = OOBCallbackRecord(
            timestamp_ms=int(time.time() * 1000),
            token=token,
            source_ip=self.client_address[0] if self.client_address else "",
            method=method,
            path=self.path,
            headers={k: v for k, v in self.headers.items()},
            body=body,
        )
        self.listener._append(record)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ack\n")

    def do_GET(self):     self._record("GET")     # noqa: N802
    def do_POST(self):    self._record("POST")    # noqa: N802
    def do_PUT(self):     self._record("PUT")     # noqa: N802
    def do_DELETE(self):  self._record("DELETE")  # noqa: N802
    def do_OPTIONS(self): self._record("OPTIONS")  # noqa: N802

    def _extract_token(self, body: str) -> str:
        # 1) Path may carry the token: /cb/<token> or ?token=<token>
        path = self.path or ""
        if "/cb/" in path:
            tail = path.split("/cb/", 1)[1]
            return tail.split("?", 1)[0].strip("/")
        if "token=" in path:
            return path.split("token=", 1)[1].split("&", 1)[0]
        # 2) JSON body may carry it
        if body.strip().startswith("{"):
            try:
                data = json.loads(body)
                if isinstance(data, dict) and "token" in data:
                    return str(data["token"])
            except json.JSONDecodeError:
                pass
        return ""


class OOBListener:
    """
    Loopback HTTP listener. Use as a context manager:

        with OOBListener() as listener:
            url, token = listener.url, listener.token
            # ... embed url + token in attack payload, fire ...
            callbacks = listener.drain()
            ev.attach_oob_callbacks(callbacks)

    ``url`` is the base callback URL; agents build the full URL as
    ``f"{url}/cb/{token}"`` so the listener can attribute incoming
    requests to the issuing attack.
    """

    def __init__(self, *, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host  = host
        self._requested_port = port
        self.token = secrets.token_urlsafe(12)
        self._records: list[OOBCallbackRecord] = []
        self._lock    = threading.Lock()
        self._server: Optional[HTTPServer]      = None
        self._thread: Optional[threading.Thread] = None

    # ── Public ──────────────────────────────────────────────────────────

    def start(self) -> "OOBListener":
        if self._server is not None:
            return self
        outer = self

        class _Bound(_Handler):
            listener = outer

        server = HTTPServer((self.host, self._requested_port), _Bound)
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        thread.start()
        self._server = server
        self._thread = thread
        return self

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._server = None
        self._thread = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("OOBListener not started")
        return self._server.server_address[1]

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def callback_url(self) -> str:
        """Pre-built URL with the token appended — embed this in payloads."""
        return f"{self.url}/cb/{self.token}"

    def drain(self) -> list[OOBCallbackRecord]:
        with self._lock:
            out = list(self._records)
            self._records.clear()
        return out

    def peek(self) -> list[OOBCallbackRecord]:
        with self._lock:
            return list(self._records)

    # ── Context manager ─────────────────────────────────────────────────

    def __enter__(self) -> "OOBListener":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    # ── Internals (handler hook) ────────────────────────────────────────

    def _append(self, record: OOBCallbackRecord) -> None:
        with self._lock:
            self._records.append(record)
