"""Wayback Machine CDX source.

Queries the Internet Archive's CDX index for every URL ever crawled
under a zone and extracts unique hostnames. Useful for discovering
shut-down / forgotten AI surfaces that are no longer DNS-resolvable
but still appear in historical data.

Endpoint:
    https://web.archive.org/cdx/search/cdx
        ?url=*.<zone>&output=json
        &fl=original,timestamp&collapse=urlkey

Response is a JSON array of arrays — the first row is the header.
We dedupe by host and report the earliest crawl timestamp seen for
each host as ``first_seen``.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from . import Observation

_WAYBACK_URL = (
    "https://web.archive.org/cdx/search/cdx?url=*.{zone}&output=json&fl=original,timestamp&collapse=urlkey&limit=50000"
)
_HEADERS = {"User-Agent": "argus-engine-recon/1.0"}


async def fetch(
    zone: str,
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = 60.0,
) -> list[Observation]:
    url = _WAYBACK_URL.format(zone=zone.strip().lower().rstrip("."))
    own = client is None
    cli = client or httpx.AsyncClient(timeout=timeout, headers=_HEADERS)
    try:
        resp = await cli.get(url)
        resp.raise_for_status()
        rows = resp.json()
    except (TimeoutError, httpx.HTTPError, ValueError) as exc:
        return [
            Observation(
                host=zone,
                source="wayback",
                record_type="error",
                extra=(("error", str(exc)[:200]),),
            )
        ]
    finally:
        if own:
            await cli.aclose()

    if not isinstance(rows, list) or len(rows) <= 1:
        return []

    seen: dict[str, Observation] = {}
    for row in rows[1:]:
        if not isinstance(row, list) or len(row) < 2:
            continue
        original, timestamp = row[0], row[1]
        if not isinstance(original, str):
            continue
        parsed = urlsplit(original if "://" in original else f"http://{original}")
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or "*" in host:
            continue
        ts = str(timestamp) if timestamp is not None else ""
        existing = seen.get(host)
        if existing is None or (ts and (not existing.first_seen or ts < existing.first_seen)):
            seen[host] = Observation(
                host=host,
                source="wayback",
                first_seen=ts,
                record_type="historical_url",
            )
    return sorted(seen.values(), key=lambda o: o.host)
