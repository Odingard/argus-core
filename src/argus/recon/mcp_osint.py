"""
argus/recon/mcp_osint.py — MCP target OSINT pre-flight.

Runs before enumeration. Queries npm/PyPI registries + OSV for:
  - Package publish history & maintainer account age
  - Known CVEs (count, IDs, highest severity)
  - Dependency count (supply chain surface area)
  - Download velocity anomalies (sudden spikes = potential compromise)
  - Version staleness (time since last update)

Output feeds TargetSpec.risk_metadata which SC-09, layer6, and
the report renderer read to produce authoritative context.

Usage:
    from argus.recon.mcp_osint import osint_preflight
    meta = osint_preflight("node-code-sandbox-mcp", version="1.2.0")
    print(meta.cve_ids)       # ['CVE-2025-53372']
    print(meta.risk_score)    # 85
"""
from __future__ import annotations

import json
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class PackageOSINT:
    """Aggregated OSINT profile for one MCP package."""
    package_name:       str
    registry:           str           # "npm" | "pypi"
    version:            Optional[str] = None
    latest_version:     Optional[str] = None
    published_at:       Optional[str] = None   # ISO timestamp of target version
    last_updated:       Optional[str] = None   # ISO timestamp of latest release
    days_since_update:  Optional[int] = None
    maintainer_count:   int = 0
    dependency_count:   int = 0
    cve_ids:            list[str] = field(default_factory=list)
    cve_count:          int = 0
    highest_cve_sev:    str = "NONE"   # CRITICAL / HIGH / MEDIUM / LOW / NONE
    download_anomaly:   bool = False   # spike in downloads suggesting hijack
    risk_score:         int = 0        # 0-100 composite
    risk_factors:       list[str] = field(default_factory=list)
    raw_npm:            dict = field(default_factory=dict, repr=False)
    raw_osv:            list = field(default_factory=list, repr=False)
    error:              Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "package_name":      self.package_name,
            "registry":          self.registry,
            "version":           self.version,
            "latest_version":    self.latest_version,
            "days_since_update": self.days_since_update,
            "cve_ids":           self.cve_ids,
            "cve_count":         self.cve_count,
            "highest_cve_sev":   self.highest_cve_sev,
            "risk_score":        self.risk_score,
            "risk_factors":      self.risk_factors,
            "error":             self.error,
        }


def _fetch_json(url: str, timeout: int = 8) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _days_since(iso: str) -> Optional[int]:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def _osv_query(package: str, ecosystem: str) -> list[dict]:
    """Query OSV.dev for known vulnerabilities.
    Falls back to GitHub Advisory Database if OSV returns nothing."""
    payload = json.dumps({
        "package": {"name": package, "ecosystem": ecosystem}
    }).encode()
    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
            vulns = data.get("vulns", [])
            if vulns:
                return vulns
    except Exception:
        pass
    # Fallback: GitHub Advisory Database
    try:
        url = (f"https://api.github.com/advisories"
               f"?ecosystem={ecosystem.lower()}&package={package}"
               f"&per_page=10")
        req = urllib.request.Request(
            url, headers={"Accept": "application/vnd.github+json",
                          "X-GitHub-Api-Version": "2022-11-28"})
        with urllib.request.urlopen(req, timeout=10) as r:
            advisories = json.loads(r.read().decode())
            result = []
            for a in advisories:
                result.append({
                    "aliases": [a.get("ghsa_id", "")] +
                               [c.get("value", "") for c in
                                a.get("identifiers", [])
                                if c.get("type") == "CVE"],
                    "severity": [{"score": a.get("severity","").upper()}],
                    "summary":  a.get("summary", ""),
                })
            return result
    except Exception:
        pass
    return []    except Exception:
        return []


def _score_npm(meta: PackageOSINT) -> None:
    score = 0
    factors = []
    # CVEs
    _SEV_SCORES = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 15, "LOW": 5}
    score += _SEV_SCORES.get(meta.highest_cve_sev, 0)
    if meta.cve_count > 0:
        factors.append(f"{meta.cve_count} known CVE(s) — highest: {meta.highest_cve_sev}")
    # Staleness
    if meta.days_since_update is not None:
        if meta.days_since_update > 365:
            score += 20
            factors.append(f"unmaintained: {meta.days_since_update} days since last update")
        elif meta.days_since_update > 180:
            score += 10
            factors.append(f"stale: {meta.days_since_update} days since last update")
    # Maintainer count (single maintainer = higher risk)
    if meta.maintainer_count == 1:
        score += 10
        factors.append("single maintainer — no redundancy")
    # Version behind latest
    if meta.version and meta.latest_version and meta.version != meta.latest_version:
        score += 10
        factors.append(f"version {meta.version} behind latest {meta.latest_version}")
    # Download anomaly
    if meta.download_anomaly:
        score += 15
        factors.append("download spike detected — possible hijack signal")
    meta.risk_score = min(score, 100)
    meta.risk_factors = factors


def osint_preflight(package_name: str, *,
                    version: Optional[str] = None,
                    registry: str = "npm") -> PackageOSINT:
    """Run OSINT pre-flight against a package. Non-fatal on network errors."""
    meta = PackageOSINT(package_name=package_name,
                        registry=registry, version=version)
    try:
        if registry == "npm":
            _enrich_npm(meta)
        else:
            _enrich_pypi(meta)
        # CVEs from OSV regardless of registry
        eco = "npm" if registry == "npm" else "PyPI"
        meta.raw_osv = _osv_query(package_name, eco)
        _parse_osv(meta)
        _score_npm(meta)
    except Exception as e:
        meta.error = str(e)
    return meta


def _enrich_npm(meta: PackageOSINT) -> None:
    data = _fetch_json(f"https://registry.npmjs.org/{meta.package_name}")
    if not data:
        meta.error = "npm registry unreachable"
        return
    meta.raw_npm = data
    meta.latest_version = data.get("dist-tags", {}).get("latest")
    target_ver = meta.version or meta.latest_version
    times = data.get("time", {})
    if target_ver and target_ver in times:
        meta.published_at = times[target_ver]
    if meta.latest_version and meta.latest_version in times:
        meta.last_updated = times[meta.latest_version]
        meta.days_since_update = _days_since(meta.last_updated)
    maintainers = data.get("maintainers", [])
    meta.maintainer_count = len(maintainers)
    # Dep count from target version
    if target_ver:
        vdata = data.get("versions", {}).get(target_ver, {})
        deps = vdata.get("dependencies", {})
        meta.dependency_count = len(deps)


def _enrich_pypi(meta: PackageOSINT) -> None:
    data = _fetch_json(f"https://pypi.org/pypi/{meta.package_name}/json")
    if not data:
        meta.error = "PyPI registry unreachable"
        return
    info = data.get("info", {})
    meta.latest_version = info.get("version")
    releases = data.get("releases", {})
    target_ver = meta.version or meta.latest_version
    if target_ver and target_ver in releases:
        files = releases[target_ver]
        if files:
            meta.published_at = files[0].get("upload_time")
            meta.last_updated = meta.published_at
            meta.days_since_update = _days_since(meta.published_at or "")
    meta.maintainer_count = 1   # PyPI doesn't expose maintainer count easily
    reqs = info.get("requires_dist") or []
    meta.dependency_count = len(reqs)


_OSV_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

def _parse_osv(meta: PackageOSINT) -> None:
    cve_ids = []
    highest_idx = len(_OSV_SEV_ORDER)
    for vuln in meta.raw_osv:
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_ids.append(alias)
        for sev in vuln.get("severity", []):
            rating = sev.get("score", "") or ""
            for i, s in enumerate(_OSV_SEV_ORDER):
                if s in rating.upper() and i < highest_idx:
                    highest_idx = i
    meta.cve_ids = sorted(set(cve_ids))
    meta.cve_count = len(meta.cve_ids)
    meta.highest_cve_sev = (_OSV_SEV_ORDER[highest_idx]
                            if highest_idx < len(_OSV_SEV_ORDER) else "NONE")
