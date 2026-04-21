"""
tests/test_evidence.py — Deterministic Evidence (AI-Slop filter).
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest

from argus.agents.base import AgentFinding
from argus.evidence import (
    DeterministicEvidence, EvidenceCollector, EvidenceError,
    OOBListener, attach_evidence,
)


# ── EvidenceCollector ──────────────────────────────────────────────────────

def test_collector_records_pcap_in_order():
    with EvidenceCollector(target_id="mcp://x", session_id="s") as ev:
        ev.record_request(surface="chat", request_id="r1", payload="hello")
        ev.record_response(surface="chat", request_id="r1", payload="hi")
    sealed = ev.seal()
    assert len(sealed.pcap) == 2
    assert sealed.pcap[0].direction == "out"
    assert sealed.pcap[1].direction == "in"


def test_collector_seal_is_idempotent():
    ev = EvidenceCollector(target_id="mcp://x", session_id="s")
    ev.record_request(surface="chat", request_id="r1", payload="hi")
    a = ev.seal()
    b = ev.seal()
    assert a is b


def test_collector_post_seal_writes_raise():
    ev = EvidenceCollector(target_id="mcp://x", session_id="s")
    ev.seal()
    with pytest.raises(EvidenceError):
        ev.record_request(surface="chat", request_id="r2", payload="late")


def test_collector_requires_ids():
    with pytest.raises(EvidenceError):
        EvidenceCollector(target_id="", session_id="s")
    with pytest.raises(EvidenceError):
        EvidenceCollector(target_id="x", session_id="")


def test_evidence_integrity_changes_on_field_change():
    ev = EvidenceCollector(target_id="mcp://x", session_id="s")
    ev.record_request(surface="chat", request_id="r1", payload="a")
    sealed = ev.seal()
    original = sealed.integrity_sha
    sealed.notes = "tampered"
    from argus.evidence.collector import _integrity
    new = _integrity(sealed)
    # Note: notes isn't part of the integrity payload by design;
    # changing pcap MUST move the hash.
    sealed.pcap[0].payload = "MUTATED"
    mutated = _integrity(sealed)
    assert mutated != original


def test_proof_grade_requires_pcap_plus_one_other():
    ev = EvidenceCollector(target_id="mcp://x", session_id="s")
    ev.record_request(surface="chat", request_id="r1", payload="hi")
    sealed = ev.seal()
    assert not sealed.is_proof_grade(), (
        "pcap alone should NOT be proof-grade — that's just an echo log"
    )

    # Add container logs → proof-grade.
    ev2 = EvidenceCollector(target_id="mcp://x", session_id="s2")
    ev2.record_request(surface="chat", request_id="r1", payload="hi")
    ev2.attach_container_logs("[2025-01-01] target executed payload")
    assert ev2.seal().is_proof_grade()


def test_evidence_persistence_round_trip(tmp_path):
    ev = EvidenceCollector(target_id="mcp://x", session_id="s")
    ev.record_request(surface="chat", request_id="r1", payload="hi")
    sealed = ev.seal()
    path = sealed.write(tmp_path)
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["evidence_id"] == sealed.evidence_id
    assert data["integrity_sha"] == sealed.integrity_sha
    assert len(data["pcap"]) == 1


# ── attach_evidence ─────────────────────────────────────────────────────────

def test_attach_evidence_decorates_finding():
    ev = EvidenceCollector(target_id="mcp://x", session_id="s")
    ev.record_request(surface="chat", request_id="r1", payload="x")
    ev.attach_container_logs("evidence")
    sealed = ev.seal()

    f = AgentFinding(
        id="f", agent_id="PI-01", vuln_class="X",
        severity="HIGH", title="t", description="d",
    )
    attach_evidence(f, sealed)
    assert f.evidence_id == sealed.evidence_id
    assert f.evidence_integrity == sealed.integrity_sha
    assert f.evidence_proof_grade is True


def test_attach_evidence_rejects_unsealed():
    f = AgentFinding(
        id="f", agent_id="PI-01", vuln_class="X",
        severity="HIGH", title="t", description="d",
    )
    bare = DeterministicEvidence(
        evidence_id="ev-x", sealed_at="now",
        target_id="t", session_id="s",
    )
    with pytest.raises(EvidenceError):
        attach_evidence(f, bare)


# ── OOBListener (real localhost HTTP) ───────────────────────────────────────

def test_oob_listener_records_callback_via_path_token():
    with OOBListener() as listener:
        url = listener.callback_url
        urllib.request.urlopen(url, timeout=2.0).read()
        callbacks = listener.drain()
    assert len(callbacks) == 1
    assert callbacks[0].token == listener.token
    assert callbacks[0].method == "GET"


def test_oob_listener_records_post_with_json_body_token():
    with OOBListener() as listener:
        # Hit the bare URL (no token in path); put token in JSON body.
        body = json.dumps({"token": listener.token, "x": 1}).encode()
        req = urllib.request.Request(
            listener.url + "/anything", data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2.0).read()
        callbacks = listener.drain()
    assert len(callbacks) == 1
    assert callbacks[0].method == "POST"
    assert callbacks[0].token == listener.token


def test_oob_listener_drain_empties_buffer():
    with OOBListener() as listener:
        urllib.request.urlopen(listener.callback_url, timeout=2.0).read()
        first = listener.drain()
        second = listener.drain()
    assert len(first) == 1
    assert second == []


def test_oob_callbacks_become_proof_grade():
    """OOB callbacks alone (with pcap) make evidence proof-grade —
    even with no container logs available, the OOB ping is the
    'shell popped' signal."""
    with OOBListener() as listener:
        url = listener.callback_url
        urllib.request.urlopen(url, timeout=2.0).read()
        cbs = listener.drain()

    ev = EvidenceCollector(target_id="mcp://x", session_id="s")
    ev.record_request(surface="chat", request_id="r1",
                      payload=f"GET {url}")
    ev.attach_oob_callbacks(cbs)
    sealed = ev.seal()
    assert sealed.is_proof_grade()
    assert len(sealed.oob_callbacks) == 1
