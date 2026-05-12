"""HackerTarget passive DNS source.

Uses the free `hostsearch` endpoint at api.hackertarget.com which
returns CSV-formatted ``host,a_record`` pairs harvested from
HackerTarget's passive DNS aggregation. No API key required; the
free tier is rate-limited (~50 queries / day per source IP) but
sufficient for one engagement at a time.

Endpoint: ``https://api.hackertarget.com/hostsearch/?q=<zone>``

Response is plain text, one ``hostname,ip`` per line. When the daily
quota is exhausted the API returns a single line that begins with
``API count exceeded`` — this is treated as a soft failure (one error
observation, no crash), matching the AGENTS.md rule that empty results
must always be explainable.
"""

from __future__ import annotations

import httpx

from . import Observation

_HOSTSEARCH_URL = "https://api.hackertarget.com/hostsearch/?q={zone}"
_HEADERS = {"User-Agent": "argus-engine-recon/1.0"}

_QUOTA_MARKERS = (
    "api count exceeded",
    "error invalid host",
)


async def fetch(
    zone: str,
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = 20.0,
) -> list[Observation]:
    url = _HOSTSEARCH_URL.format(zone=zone.strip().lower().rstrip("."))
    own = client is None
    cli = client or httpx.AsyncClient(timeout=timeout, headers=_HEADERS)
    try:
        resp = await cli.get(url)
        resp.raise_for_status()
        body = resp.text
    except (TimeoutError, httpx.HTTPError) as exc:
        return [
            Observation(
                host=zone,
                source="hackertarget",
                record_type="error",
                extra=(("error", str(exc)[:200]),),
            )
        ]
    finally:
        if own:
            await cli.aclose()

    body_lower = body.lower().strip()
    if any(body_lower.startswith(marker) for marker in _QUOTA_MARKERS):
        return [
            Observation(
                host=zone,
                source="hackertarget",
                record_type="error",
                extra=(("error", body.strip()[:200]),),
            )
        ]

    seen: dict[str, Observation] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        host, _, ip = line.partition(",")
        host = host.strip().lower().rstrip(".")
        ip = ip.strip()
        if not host or "*" in host:
            continue
        existing = seen.get(host)
        if existing is not None:
            continue
        seen[host] = Observation(
            host=host,
            source="hackertarget",
            record_type="dns_a",
            extra=(("a_record", ip),) if ip else (),
        )
    return sorted(seen.values(), key=lambda o: o.host)
