"""ARGUS Callback Beacon Server.

Lightweight HTTP beacon that agents use to verify exfiltration paths.
When an agent tricks a target into calling back to a controlled URL,
the beacon records the hit — providing *external* proof that data left
the target's perimeter.

Design:
- Built into the ARGUS backend (Option 1) as an APIRouter.
- ``beacon_url`` is configurable so the same agent code works with a
  remote beacon service (Option 3) in production.
- Thread-safe hit store keyed by ``(scan_id, canary)``.
"""

from argus.beacon.server import BeaconHit, BeaconStore, create_beacon_router

__all__ = ["BeaconHit", "BeaconStore", "create_beacon_router"]
