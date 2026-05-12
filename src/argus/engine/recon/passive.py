"""Passive recon orchestrator.

Walks every zone in the operator-supplied :class:`~.scope.Scope`,
fans out to every passive source in parallel, dedupes results across
sources, filters every host through the scope allowlist, and returns
a ranked attack-surface map. Hosts that fail the scope check are
recorded in ``out_of_scope`` for audit purposes but never probed,
fingerprinted, or returned to the supervisor.

The orchestrator is the single place that touches the network for
passive recon — sources only fetch, fingerprint only probes when
``--active`` is set. Scope enforcement lives here so it cannot be
bypassed by adding new sources downstream.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

from .fingerprint import Fingerprint, classify_active, classify_passive
from .scope import Scope
from .sources import Observation, crt_sh, hackertarget, wayback

DEFAULT_SOURCES = ("crt.sh", "hackertarget", "wayback")
_HEADERS = {"User-Agent": "argus-engine-recon/1.0"}


@dataclass(frozen=True, slots=True)
class SurfaceMap:
    """Result of a passive recon run."""

    scope_path: str
    zones: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    out_of_scope: tuple[str, ...] = ()
    observations: tuple[Observation, ...] = ()
    fingerprints: tuple[Fingerprint, ...] = ()
    source_errors: tuple[tuple[str, str, str], ...] = field(default_factory=tuple)

    def ranked(self) -> tuple[Fingerprint, ...]:
        return tuple(
            sorted(
                self.fingerprints,
                key=lambda f: (-f.score, -f.confidence, f.host),
            )
        )

    def to_json(self) -> dict[str, object]:
        return {
            "scope_path": self.scope_path,
            "zones": list(self.zones),
            "host_count": len(self.hosts),
            "out_of_scope_count": len(self.out_of_scope),
            "hosts": list(self.hosts),
            "out_of_scope": list(self.out_of_scope),
            "source_errors": [{"source": s, "zone": z, "error": e} for s, z, e in self.source_errors],
            "fingerprints": [
                {
                    "host": f.host,
                    "surface": f.surface,
                    "confidence": f.confidence,
                    "framework": f.framework,
                    "score": f.score,
                    "evidence": [{"key": k, "value": v} for k, v in f.evidence],
                }
                for f in self.ranked()
            ],
        }


_SOURCE_FETCHERS = {
    "crt.sh": crt_sh.fetch,
    "hackertarget": hackertarget.fetch,
    "wayback": wayback.fetch,
}


async def _gather_zone(
    zone: str, sources: tuple[str, ...], client: httpx.AsyncClient
) -> tuple[list[Observation], list[tuple[str, str, str]]]:
    fetchers = []
    for name in sources:
        fn = _SOURCE_FETCHERS.get(name)
        if fn is None:
            continue
        fetchers.append((name, fn(zone, client=client)))
    results = await asyncio.gather(*(coro for _, coro in fetchers), return_exceptions=True)
    obs: list[Observation] = []
    errors: list[tuple[str, str, str]] = []
    for (name, _), batch in zip(fetchers, results, strict=False):
        if isinstance(batch, BaseException):
            errors.append((name, zone, f"{type(batch).__name__}: {batch}"[:200]))
            continue
        for o in batch:
            if o.record_type == "error":
                err = next((v for k, v in o.extra if k == "error"), "")
                errors.append((o.source, zone, err[:200]))
                continue
            obs.append(o)
    return obs, errors


async def discover(
    scope: Scope,
    *,
    sources: tuple[str, ...] = DEFAULT_SOURCES,
    active: bool = False,
    concurrency: int = 8,
    client: httpx.AsyncClient | None = None,
) -> SurfaceMap:
    """Run passive recon and return a :class:`SurfaceMap`.

    ``active=True`` enables the fingerprinter's HEAD+path probe — the
    only step that touches the actual target hosts. The default is
    fully passive.
    """
    own = client is None
    cli = client or httpx.AsyncClient(timeout=30.0, headers=_HEADERS)
    try:
        zones = scope.zones()
        if not zones:
            return SurfaceMap(
                scope_path=str(scope.source_path) if scope.source_path else "",
            )
        all_obs: list[Observation] = []
        all_errors: list[tuple[str, str, str]] = []
        for batch in await asyncio.gather(*(_gather_zone(z, sources, cli) for z in zones), return_exceptions=False):
            obs, errs = batch
            all_obs.extend(obs)
            all_errors.extend(errs)

        seen: dict[str, Observation] = {}
        for o in all_obs:
            existing = seen.get(o.host)
            if existing is None:
                seen[o.host] = o
                continue
            # Prefer the earliest first_seen we have on record.
            if o.first_seen and (not existing.first_seen or o.first_seen < existing.first_seen):
                seen[o.host] = o

        in_scope, out_of_scope = scope.filter_hosts(sorted(seen.keys()))
        observations = tuple(seen[h] for h in in_scope)

        if active and in_scope:
            fps = await classify_active(in_scope, concurrency=concurrency, client=cli)
        else:
            fps = classify_passive(in_scope)

        return SurfaceMap(
            scope_path=str(scope.source_path) if scope.source_path else "",
            zones=zones,
            hosts=tuple(in_scope),
            out_of_scope=tuple(out_of_scope),
            observations=observations,
            fingerprints=tuple(fps),
            source_errors=tuple(all_errors),
        )
    finally:
        if own:
            await cli.aclose()
