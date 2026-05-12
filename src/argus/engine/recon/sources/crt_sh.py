"""Certificate Transparency source — crt.sh.

Queries the public crt.sh search index (no API key required) for every
certificate ever issued under a given zone. Each cert's SAN names
become subdomain observations. CT logs include staging / dev / internal
hostnames that operators rarely realise are publicly enumerable, which
is why this is the highest-leverage passive source.

Endpoint: ``https://crt.sh/?q=%25.<zone>&output=json``

The response is a JSON array of certificate records; the relevant field
is ``name_value`` which holds the SAN list (newline-separated). We
emit one :class:`Observation` per unique host. Wildcard SANs
(``*.example.com``) are stripped to the parent zone — the wildcard
itself is not a host.
"""

from __future__ import annotations

import httpx

from . import Observation

_CRTSH_URL = "https://crt.sh/?q=%25.{zone}&output=json"
_HEADERS = {"User-Agent": "argus-engine-recon/1.0"}


async def fetch(
    zone: str,
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = 30.0,
) -> list[Observation]:
    """Return CT-derived observations for ``zone``.

    Failing to reach crt.sh is treated as an empty result with a
    ``record_type='error'`` sentinel observation against the zone
    itself, so the orchestrator can record provenance without
    crashing the engagement. This honours the AGENTS.md "no silent
    failures" rule.
    """
    url = _CRTSH_URL.format(zone=zone.strip().lower().rstrip("."))
    own = client is None
    cli = client or httpx.AsyncClient(timeout=timeout, headers=_HEADERS)
    try:
        resp = await cli.get(url)
        resp.raise_for_status()
        data = resp.json()
    except (TimeoutError, httpx.HTTPError, ValueError) as exc:
        return [
            Observation(
                host=zone,
                source="crt.sh",
                record_type="error",
                extra=(("error", str(exc)[:200]),),
            )
        ]
    finally:
        if own:
            await cli.aclose()

    seen: dict[str, Observation] = {}
    for row in data:
        name_value = row.get("name_value", "")
        not_before = row.get("not_before", "") or ""
        for raw in name_value.splitlines():
            host = raw.strip().lower().rstrip(".")
            if not host or "*" in host:
                continue
            existing = seen.get(host)
            if existing is None or (not existing.first_seen) or (not_before and not_before < existing.first_seen):
                seen[host] = Observation(
                    host=host,
                    source="crt.sh",
                    first_seen=not_before,
                    record_type="cert_san",
                )
    return sorted(seen.values(), key=lambda o: o.host)
