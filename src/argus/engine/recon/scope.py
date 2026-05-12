"""Scope enforcement for passive recon.

A scope file is a strict allowlist of FQDNs and CIDR ranges that the
operator has authorisation to investigate. Every host returned by every
recon source is filtered against this allowlist before it is reported,
fingerprinted, or fed into engagement. Hosts outside the allowlist are
recorded in ``out_of_scope`` for audit but never probed or returned to
the supervisor.

This is the bright line between red-team reconnaissance and
reconnaissance-as-a-service. ARGUS will refuse to operate without a
scope file.

Scope file format (one entry per line, ``#`` comments allowed):

    # production AI surfaces
    odingard.com
    *.odingard.com
    api.example.com
    10.0.0.0/24

A bare FQDN (``odingard.com``) matches that exact host. A wildcard
prefix (``*.odingard.com``) matches every subdomain at depth >= 1
under the parent zone but NOT the parent itself — wildcards must be
listed alongside the bare FQDN if the parent is also in scope.
CIDR entries match any host whose A record falls inside the range.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ScopeRule:
    """A single allowlist entry."""

    raw: str
    fqdn: str | None = None
    wildcard_zone: str | None = None
    cidr: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None

    def matches_host(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if self.fqdn is not None and host == self.fqdn:
            return True
        return self.wildcard_zone is not None and host.endswith("." + self.wildcard_zone)

    def matches_ip(self, address: str) -> bool:
        if self.cidr is None:
            return False
        try:
            return ipaddress.ip_address(address) in self.cidr
        except ValueError:
            return False


@dataclass(frozen=True, slots=True)
class Scope:
    """Parsed scope file. Immutable allowlist."""

    rules: tuple[ScopeRule, ...] = ()
    source_path: Path | None = None
    out_of_scope: tuple[str, ...] = field(default_factory=tuple)

    def host_in_scope(self, host: str) -> bool:
        if not host:
            return False
        return any(r.matches_host(host) for r in self.rules)

    def ip_in_scope(self, address: str) -> bool:
        if not address:
            return False
        return any(r.matches_ip(address) for r in self.rules)

    def filter_hosts(self, hosts: list[str]) -> tuple[list[str], list[str]]:
        """Partition ``hosts`` into ``(in_scope, out_of_scope)``."""
        keep: list[str] = []
        drop: list[str] = []
        for h in hosts:
            (keep if self.host_in_scope(h) else drop).append(h)
        return keep, drop

    def zones(self) -> tuple[str, ...]:
        """Top-level zones the scope file references.

        Used by recon sources that need a base domain to query
        (Certificate Transparency, Wayback). De-duplicated and sorted.
        """
        zones: set[str] = set()
        for r in self.rules:
            if r.wildcard_zone:
                zones.add(r.wildcard_zone)
            if r.fqdn:
                # Use the FQDN itself as a zone — sources will issue
                # wildcard-style queries (`%.<zone>`) so a bare FQDN
                # will surface its own subdomain history too.
                zones.add(r.fqdn)
        return tuple(sorted(zones))

    def cidrs(self) -> tuple[str, ...]:
        return tuple(sorted({str(r.cidr) for r in self.rules if r.cidr is not None}))


def _parse_rule(raw: str) -> ScopeRule:
    raw = raw.strip()
    # CIDR: contains "/" and is parseable as an IP network.
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR in scope: {raw!r}") from exc
        return ScopeRule(raw=raw, cidr=net)
    # Wildcard: "*.zone".
    if raw.startswith("*."):
        zone = raw[2:].lower().rstrip(".")
        if not zone or "*" in zone:
            raise ValueError(f"invalid wildcard scope entry: {raw!r}")
        return ScopeRule(raw=raw, wildcard_zone=zone)
    # Bare FQDN.
    fqdn = raw.lower().rstrip(".")
    if not fqdn or " " in fqdn or "*" in fqdn:
        raise ValueError(f"invalid scope entry: {raw!r}")
    return ScopeRule(raw=raw, fqdn=fqdn)


def load(path: Path | str) -> Scope:
    """Parse ``path`` into a :class:`Scope`.

    Raises ``FileNotFoundError`` if the path does not exist (scope
    enforcement is non-negotiable; we refuse to operate without it).
    Raises ``ValueError`` for malformed entries — failing closed is
    safer than parsing partially.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"scope file not found: {p}")
    rules: list[ScopeRule] = []
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        try:
            rules.append(_parse_rule(stripped))
        except ValueError as exc:
            raise ValueError(f"{p}:{lineno}: {exc}") from exc
    if not rules:
        raise ValueError(f"scope file {p} contains no rules")
    return Scope(rules=tuple(rules), source_path=p)
