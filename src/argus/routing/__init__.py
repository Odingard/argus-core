"""
argus.routing — job-level model routing with failovers.

Every expensive ARGUS call is associated with a JOB name (e.g.
``L1_POC``, ``L5_SYNTH``, ``CORRELATOR_JUDGE``, ``REASONING_AUDIT``)
rather than a hardcoded model string. At call time, the router picks
the first model in the failover chain whose provider key is set.

Usage:

    from argus.routing import route_call

    resp = route_call("L5_SYNTH", messages=[...], max_tokens=4000)
    # picks the right client automatically; fails over to next model on
    # rate-limit / capability errors.

Override the defaults via ``argus/routing/policy.json`` (project root)
or the ARGUS_ROUTING_POLICY env var pointing at a JSON file.
"""
from argus.routing.models import (
    JOBS, ModelRouter, default_router, route_call,
)

__all__ = [
    "JOBS", "ModelRouter", "default_router", "route_call",
]
