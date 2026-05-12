"""Scope-file parsing and enforcement tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.engine.recon.scope import Scope, load


def _write_scope(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "scope.txt"
    p.write_text(text, encoding="utf-8")
    return p


def test_scope_parses_fqdn_wildcard_and_cidr(tmp_path: Path) -> None:
    p = _write_scope(
        tmp_path,
        """
        # production AI surfaces
        odingard.com
        *.odingard.com
        api.example.com
        10.0.0.0/24
        """,
    )
    scope = load(p)
    assert scope.host_in_scope("odingard.com") is True
    assert scope.host_in_scope("chat.odingard.com") is True
    assert scope.host_in_scope("deeply.nested.odingard.com") is True
    assert scope.host_in_scope("api.example.com") is True
    # Bare FQDN does NOT auto-match its subdomains.
    assert scope.host_in_scope("v2.api.example.com") is False
    assert scope.host_in_scope("evil.com") is False
    assert scope.ip_in_scope("10.0.0.42") is True
    assert scope.ip_in_scope("192.168.1.1") is False
    # zones() de-duplicates and sorts.
    assert scope.zones() == ("api.example.com", "odingard.com")
    assert scope.cidrs() == ("10.0.0.0/24",)


def test_scope_filter_partitions_in_and_out(tmp_path: Path) -> None:
    scope = load(_write_scope(tmp_path, "*.odingard.com\nodingard.com\n"))
    keep, drop = scope.filter_hosts(
        [
            "chat.odingard.com",
            "api.odingard.com",
            "evil.com",
            "odingard.com",
            "leaked.partner.com",
        ]
    )
    assert sorted(keep) == ["api.odingard.com", "chat.odingard.com", "odingard.com"]
    assert sorted(drop) == ["evil.com", "leaked.partner.com"]


def test_scope_rejects_empty_file(tmp_path: Path) -> None:
    p = _write_scope(tmp_path, "# only comments\n\n")
    with pytest.raises(ValueError, match="no rules"):
        load(p)


def test_scope_rejects_invalid_entries(tmp_path: Path) -> None:
    p = _write_scope(tmp_path, "*.bad *.spaces.com\n")
    with pytest.raises(ValueError, match="invalid"):
        load(p)


def test_scope_missing_file_raises_filenotfound(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load(tmp_path / "does-not-exist.txt")


def test_scope_normalises_case_and_trailing_dot(tmp_path: Path) -> None:
    scope = load(_write_scope(tmp_path, "Odingard.COM\n"))
    assert scope.host_in_scope("odingard.com.") is True
    assert scope.host_in_scope("ODINGARD.COM") is True


def test_empty_scope_object_refuses_everything() -> None:
    scope = Scope(rules=())
    assert scope.host_in_scope("anything.com") is False
    assert scope.zones() == ()
