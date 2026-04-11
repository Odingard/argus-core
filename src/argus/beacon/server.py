"""Callback Beacon Server.

Provides an HTTP endpoint that records "phone-home" hits from target
AI agents. When ARGUS tricks a target into fetching a beacon URL, the
hit is recorded here — proving an exfiltration path exists.

The beacon is mounted as an APIRouter inside the main ARGUS FastAPI app.
No authentication is required on beacon endpoints (the target agent
won't have ARGUS credentials).

Usage from an attack agent::

    from argus.beacon import BeaconStore

    store = BeaconStore.get()
    canary = store.create_canary(scan_id)
    beacon_url = store.beacon_url(scan_id, canary)
    # ... send payload instructing target to fetch beacon_url ...
    hit = store.check(scan_id, canary)
    if hit is not None:
        # exfiltration confirmed!
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Request

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BeaconHit:
    """A single callback hit recorded by the beacon."""

    scan_id: str
    canary: str
    timestamp: float
    source_ip: str
    method: str
    path: str
    headers: dict[str, str]
    query_params: dict[str, str]
    body_preview: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "canary": self.canary,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "query_params": self.query_params,
            "body_preview": self.body_preview,
        }


class BeaconStore:
    """In-process store for beacon hits.

    Singleton — all agents in the same process share one store.
    Thread-safe via the GIL for dict reads/writes (sufficient for
    our single-event-loop async server).
    """

    _instance: BeaconStore | None = None

    def __init__(self) -> None:
        # Key: (scan_id, canary) -> list of BeaconHit
        self._hits: dict[tuple[str, str], list[BeaconHit]] = {}
        # Key: scan_id -> set of active canaries
        self._canaries: dict[str, set[str]] = {}
        self._counter = 0
        # Configurable base URL for the beacon.  Defaults to the ARGUS
        # backend itself; override via ARGUS_BEACON_URL for remote beacons.
        self._base_url = os.environ.get("ARGUS_BEACON_URL", "").rstrip("/")

    @classmethod
    def get(cls) -> BeaconStore:
        """Return the singleton BeaconStore instance."""
        if cls._instance is None:
            cls._instance = BeaconStore()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton (for testing)."""
        cls._instance = None

    @property
    def base_url(self) -> str:
        """The base URL where the beacon is reachable."""
        if self._base_url:
            return self._base_url
        # Default: ARGUS backend on localhost
        port = os.environ.get("ARGUS_WEB_PORT", "8765")
        return f"http://localhost:{port}"

    def create_canary(self, scan_id: str) -> str:
        """Generate a unique canary token for a scan."""
        self._counter += 1
        canary = f"ARGUS-BCN-{scan_id[:8]}-{self._counter:04d}-{int(time.time()) % 100000}"
        self._canaries.setdefault(scan_id, set()).add(canary)
        return canary

    def beacon_url(self, scan_id: str, canary: str) -> str:
        """Return the full callback URL for a canary."""
        return f"{self.base_url}/beacon/{scan_id}/{canary}"

    def record_hit(self, hit: BeaconHit) -> None:
        """Record a beacon hit."""
        key = (hit.scan_id, hit.canary)
        self._hits.setdefault(key, []).append(hit)
        logger.warning(
            "BEACON HIT: scan=%s canary=%s source=%s method=%s",
            hit.scan_id,
            hit.canary,
            hit.source_ip,
            hit.method,
        )

    def check(self, scan_id: str, canary: str) -> BeaconHit | None:
        """Check if a canary received a callback. Returns the first hit or None."""
        hits = self._hits.get((scan_id, canary), [])
        return hits[0] if hits else None

    def all_hits(self, scan_id: str) -> list[BeaconHit]:
        """Return all beacon hits for a scan."""
        result: list[BeaconHit] = []
        for (sid, _canary), hits in self._hits.items():
            if sid == scan_id:
                result.extend(hits)
        return result

    def scan_canaries(self, scan_id: str) -> set[str]:
        """Return all canaries registered for a scan."""
        return self._canaries.get(scan_id, set())

    def has_canary(self, scan_id: str, canary: str) -> bool:
        """Check whether a canary was registered for the given scan."""
        return canary in self._canaries.get(scan_id, set())

    def clear_scan(self, scan_id: str) -> None:
        """Clean up all canaries and hits for a completed scan."""
        for canary in list(self._canaries.get(scan_id, set())):
            self._hits.pop((scan_id, canary), None)
        self._canaries.pop(scan_id, None)


def create_beacon_router(auth_dependency: Any = None) -> APIRouter:
    """Create the beacon callback router.

    Endpoints accept ANY HTTP method (GET, POST, PUT, etc.) so that
    regardless of how the target agent makes the callback, we capture it.

    Args:
        auth_dependency: Optional FastAPI dependency for authenticated
            endpoints (e.g. ``require_token``).  The beacon callback
            itself stays unauthenticated; only the hits-listing
            endpoint requires auth.
    """
    router = APIRouter(tags=["beacon"])
    store = BeaconStore.get()

    # ---- Authenticated endpoint FIRST (more specific path) ----
    # Must be registered before the catch-all /beacon/{scan_id}/{canary}
    # route, otherwise Starlette's registration-order resolution would
    # match /beacon/hits/{scan_id} as scan_id="hits", canary="..."
    # and bypass authentication entirely.
    _hits_deps: list[Any] = [Depends(auth_dependency)] if auth_dependency else []

    @router.get("/beacon/hits/{scan_id}", dependencies=_hits_deps)
    async def list_beacon_hits(scan_id: str) -> dict[str, Any]:
        """List all beacon hits for a scan (requires authentication)."""
        hits = store.all_hits(scan_id)
        return {
            "scan_id": scan_id,
            "total_hits": len(hits),
            "hits": [h.to_dict() for h in hits],
        }

    # ---- Unauthenticated catch-all callback endpoint ----
    @router.api_route(
        "/beacon/{scan_id}/{canary}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    )
    async def beacon_callback(scan_id: str, canary: str, request: Request) -> dict[str, str]:
        """Record a beacon callback from a target agent.

        No authentication required — the target agent won't have
        ARGUS credentials. The canary token itself is the proof.
        """
        # Only record hits for canaries we actually registered
        if not store.has_canary(scan_id, canary):
            return {"status": "ok", "message": "Beacon received"}

        # Read body (up to 4KB preview)
        body = b""
        try:
            body = await request.body()
        except Exception:  # noqa: BLE001
            logger.debug("Failed to read beacon request body")

        hit = BeaconHit(
            scan_id=scan_id,
            canary=canary,
            timestamp=time.time(),
            source_ip=request.client.host if request.client else "unknown",
            method=request.method,
            path=str(request.url),
            headers={k: v for k, v in list(request.headers.items())[:20]},
            query_params=dict(request.query_params),
            body_preview=body[:4096].decode("utf-8", errors="replace"),
        )
        store.record_hit(hit)

        # Return a plausible response so the target agent doesn't error out
        return {"status": "ok", "message": "Beacon received"}

    return router
