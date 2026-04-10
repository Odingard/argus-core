"""Database repository — CRUD operations for all ARGUS entities.

Encapsulates all database access behind a clean interface.
All methods accept/return Pydantic models or plain dicts — the ORM
models are internal to this module.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc
from sqlalchemy.orm import Session

from argus.db.models import (
    DBAPIKey,
    DBCompoundPath,
    DBFinding,
    DBScan,
    DBScanAgent,
    DBTarget,
)
from argus.db.session import get_session

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_key(raw_key: str) -> str:
    """SHA-256 hash an API key for secure storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _to_dict(obj: Any) -> dict[str, Any]:
    """Convert a SQLAlchemy model instance to a plain dict."""
    return {c.name: getattr(obj, c.name) for c in obj.__table__.columns}


# ---------------------------------------------------------------------------
# Target CRUD
# ---------------------------------------------------------------------------


class TargetRepository:
    """CRUD operations for client targets."""

    def __init__(self, session: Session | None = None) -> None:
        self._session = session or get_session()

    def create(
        self,
        name: str,
        mcp_server_urls: list[str] | None = None,
        agent_endpoint: str | None = None,
        description: str = "",
        environment: str = "staging",
        non_destructive: bool = True,
        max_requests_per_minute: int = 60,
        client_name: str = "",
        client_contact: str = "",
        notes: str = "",
    ) -> dict[str, Any]:
        target = DBTarget(
            name=name,
            description=description,
            environment=environment,
            mcp_server_urls=json.dumps(mcp_server_urls or []),
            agent_endpoint=agent_endpoint,
            agent_endpoints=json.dumps([]),
            non_destructive=non_destructive,
            max_requests_per_minute=max_requests_per_minute,
            client_name=client_name,
            client_contact=client_contact,
            notes=notes,
        )
        self._session.add(target)
        self._session.commit()
        logger.info("Created target: %s (%s)", target.name, target.id)
        return self._serialize_target(target)

    def get(self, target_id: str) -> dict[str, Any] | None:
        target = self._session.get(DBTarget, target_id)
        if target is None or not target.is_active:
            return None
        return self._serialize_target(target)

    def list_all(self, active_only: bool = True) -> list[dict[str, Any]]:
        query = self._session.query(DBTarget)
        if active_only:
            query = query.filter(DBTarget.is_active.is_(True))
        query = query.order_by(desc(DBTarget.created_at))
        return [self._serialize_target(t) for t in query.all()]

    def update(self, target_id: str, **kwargs: Any) -> dict[str, Any] | None:
        target = self._session.get(DBTarget, target_id)
        if target is None or not target.is_active:
            return None
        for key, value in kwargs.items():
            if key == "mcp_server_urls":
                setattr(target, key, json.dumps(value))
            elif key == "agent_endpoints":
                setattr(target, key, json.dumps(value))
            elif hasattr(target, key):
                setattr(target, key, value)
        target.updated_at = datetime.now(UTC)
        self._session.commit()
        return self._serialize_target(target)

    def delete(self, target_id: str) -> bool:
        """Soft-delete a target."""
        target = self._session.get(DBTarget, target_id)
        if target is None:
            return False
        target.is_active = False
        target.updated_at = datetime.now(UTC)
        self._session.commit()
        return True

    def _serialize_target(self, target: DBTarget) -> dict[str, Any]:
        d = _to_dict(target)
        d["mcp_server_urls"] = json.loads(d["mcp_server_urls"] or "[]")
        d["agent_endpoints"] = json.loads(d["agent_endpoints"] or "[]")
        # Never expose encrypted credentials
        d.pop("agent_api_key_encrypted", None)
        return d

    def close(self) -> None:
        self._session.close()


# ---------------------------------------------------------------------------
# API Key CRUD
# ---------------------------------------------------------------------------


class APIKeyRepository:
    """CRUD operations for API keys with role-based access."""

    VALID_ROLES = frozenset({"admin", "operator", "viewer"})

    def __init__(self, session: Session | None = None) -> None:
        self._session = session or get_session()

    def create(self, name: str, role: str = "viewer") -> dict[str, Any]:
        """Create a new API key. Returns the raw key (shown only once)."""
        if role not in self.VALID_ROLES:
            raise ValueError(f"Invalid role: {role}. Must be one of: {', '.join(sorted(self.VALID_ROLES))}")

        raw_key = f"argus_{secrets.token_urlsafe(32)}"
        key_hash = _hash_key(raw_key)
        key_prefix = raw_key[:12]

        api_key = DBAPIKey(
            name=name,
            role=role,
            key_hash=key_hash,
            key_prefix=key_prefix,
        )
        self._session.add(api_key)
        self._session.commit()
        logger.info("Created API key: %s (role=%s, prefix=%s)", name, role, key_prefix)

        result = _to_dict(api_key)
        result["raw_key"] = raw_key  # Shown only once
        return result

    def authenticate(self, raw_key: str) -> dict[str, Any] | None:
        """Authenticate an API key. Returns key info if valid, None otherwise."""
        key_hash = _hash_key(raw_key)
        api_key = (
            self._session.query(DBAPIKey)
            .filter(
                DBAPIKey.key_hash == key_hash,
                DBAPIKey.is_active.is_(True),
            )
            .first()
        )

        if api_key is None:
            return None

        # Check expiry
        if api_key.expires_at and api_key.expires_at < datetime.now(UTC):
            return None

        # Update last used
        api_key.last_used_at = datetime.now(UTC)
        self._session.commit()

        result = _to_dict(api_key)
        result.pop("key_hash", None)
        return result

    def list_all(self, active_only: bool = True) -> list[dict[str, Any]]:
        query = self._session.query(DBAPIKey)
        if active_only:
            query = query.filter(DBAPIKey.is_active.is_(True))
        query = query.order_by(desc(DBAPIKey.created_at))
        results = []
        for k in query.all():
            d = _to_dict(k)
            d.pop("key_hash", None)
            results.append(d)
        return results

    def revoke(self, key_id: str) -> bool:
        api_key = self._session.get(DBAPIKey, key_id)
        if api_key is None:
            return False
        api_key.is_active = False
        self._session.commit()
        logger.info("Revoked API key: %s (%s)", api_key.name, api_key.key_prefix)
        return True

    def close(self) -> None:
        self._session.close()


# ---------------------------------------------------------------------------
# Scan persistence
# ---------------------------------------------------------------------------


class ScanRepository:
    """CRUD operations for scan records and their children."""

    def __init__(self, session: Session | None = None) -> None:
        self._session = session or get_session()

    def create_scan(
        self,
        scan_id: str,
        target_name: str,
        target_id: str | None = None,
        timeout_seconds: float = 600.0,
        non_destructive: bool = True,
        initiated_by: str = "cli",
        started_at: datetime | None = None,
    ) -> dict[str, Any]:
        scan = DBScan(
            id=scan_id,
            target_id=target_id,
            target_name=target_name,
            status="running",
            started_at=started_at or datetime.now(UTC),
            timeout_seconds=timeout_seconds,
            non_destructive=non_destructive,
            initiated_by=initiated_by,
        )
        self._session.add(scan)
        self._session.commit()
        return _to_dict(scan)

    def complete_scan(
        self,
        scan_id: str,
        status: str = "completed",
        agents_deployed: int = 0,
        agents_completed: int = 0,
        agents_failed: int = 0,
        total_findings: int = 0,
        validated_findings: int = 0,
        compound_paths_count: int = 0,
        signals_exchanged: int = 0,
        report_json: str | None = None,
        report_html: str | None = None,
        completed_at: datetime | None = None,
        duration_seconds: float | None = None,
    ) -> dict[str, Any] | None:
        scan = self._session.get(DBScan, scan_id)
        if scan is None:
            return None

        now = datetime.now(UTC)
        scan.status = status
        scan.completed_at = completed_at or now
        if duration_seconds is not None:
            scan.duration_seconds = duration_seconds
        elif scan.started_at:
            scan.duration_seconds = (scan.completed_at - scan.started_at).total_seconds()
        scan.agents_deployed = agents_deployed
        scan.agents_completed = agents_completed
        scan.agents_failed = agents_failed
        scan.total_findings = total_findings
        scan.validated_findings = validated_findings
        scan.compound_paths_count = compound_paths_count
        scan.signals_exchanged = signals_exchanged
        scan.report_json = report_json
        scan.report_html = report_html

        self._session.commit()
        return _to_dict(scan)

    def save_agent_result(
        self,
        scan_id: str,
        agent_type: str,
        instance_id: str,
        status: str,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        duration_seconds: float | None = None,
        findings_count: int = 0,
        validated_count: int = 0,
        techniques_attempted: int = 0,
        techniques_succeeded: int = 0,
        requests_made: int = 0,
        signals_emitted: int = 0,
        errors: list[str] | None = None,
    ) -> dict[str, Any]:
        agent = DBScanAgent(
            scan_id=scan_id,
            agent_type=agent_type,
            instance_id=instance_id,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration_seconds,
            findings_count=findings_count,
            validated_count=validated_count,
            techniques_attempted=techniques_attempted,
            techniques_succeeded=techniques_succeeded,
            requests_made=requests_made,
            signals_emitted=signals_emitted,
            errors=json.dumps(errors or []),
        )
        self._session.add(agent)
        self._session.commit()
        return _to_dict(agent)

    def save_finding(self, scan_id: str, finding_data: dict[str, Any]) -> dict[str, Any]:
        """Persist a Finding (from its model_dump()) to the database."""
        db_finding = DBFinding(
            id=finding_data.get("id", str(secrets.token_hex(16))),
            scan_id=scan_id,
            agent_type=finding_data.get("agent_type", "unknown"),
            agent_instance_id=finding_data.get("agent_instance_id", ""),
            title=finding_data.get("title", ""),
            description=finding_data.get("description", ""),
            severity=finding_data.get("severity", "info"),
            status=finding_data.get("status", "unvalidated"),
            target_surface=finding_data.get("target_surface", ""),
            technique=finding_data.get("technique", ""),
            attack_chain_json=json.dumps(finding_data.get("attack_chain", []), default=str),
            reproduction_steps_json=json.dumps(finding_data.get("reproduction_steps", []), default=str),
            validation_json=(
                json.dumps(finding_data.get("validation"), default=str) if finding_data.get("validation") else None
            ),
            remediation_json=(
                json.dumps(finding_data.get("remediation"), default=str) if finding_data.get("remediation") else None
            ),
            verdict_score_json=(
                json.dumps(finding_data.get("verdict_score"), default=str)
                if finding_data.get("verdict_score")
                else None
            ),
            owasp_agentic=finding_data.get("owasp_agentic"),
            owasp_llm=finding_data.get("owasp_llm"),
            raw_request=(finding_data.get("raw_request") or "")[:50000] or None,
            raw_response=(finding_data.get("raw_response") or "")[:50000] or None,
        )
        self._session.add(db_finding)
        self._session.commit()
        return _to_dict(db_finding)

    def save_compound_path(self, scan_id: str, path_data: dict[str, Any]) -> dict[str, Any]:
        """Persist a CompoundAttackPath to the database."""
        db_path = DBCompoundPath(
            id=path_data.get("id", str(secrets.token_hex(16))),
            scan_id=scan_id,
            title=path_data.get("title", ""),
            description=path_data.get("description", ""),
            severity=path_data.get("severity", "info"),
            compound_impact=path_data.get("compound_impact", ""),
            exploitability_score=path_data.get("exploitability_score", 0.0),
            detectability_score=path_data.get("detectability_score", 0.0),
            finding_ids_json=json.dumps(path_data.get("finding_ids", []), default=str),
            attack_path_steps_json=json.dumps(path_data.get("attack_path_steps", []), default=str),
            owasp_agentic_json=json.dumps(path_data.get("owasp_agentic", []), default=str),
            validation_json=(
                json.dumps(path_data.get("validation"), default=str) if path_data.get("validation") else None
            ),
            remediation_json=(
                json.dumps(path_data.get("remediation"), default=str) if path_data.get("remediation") else None
            ),
            cerberus_rules_json=json.dumps(path_data.get("cerberus_detection_rules", []), default=str),
        )
        self._session.add(db_path)
        self._session.commit()
        return _to_dict(db_path)

    # -----------------------------------------------------------------------
    # Query
    # -----------------------------------------------------------------------

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        scan = self._session.get(DBScan, scan_id)
        if scan is None:
            return None
        return _to_dict(scan)

    def list_scans(
        self,
        limit: int = 50,
        offset: int = 0,
        target_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        query = self._session.query(DBScan)
        if target_id:
            query = query.filter(DBScan.target_id == target_id)
        if status:
            query = query.filter(DBScan.status == status)
        query = query.order_by(desc(DBScan.created_at)).offset(offset).limit(limit)
        return [_to_dict(s) for s in query.all()]

    def get_scan_findings(self, scan_id: str, severity: str | None = None) -> list[dict[str, Any]]:
        query = self._session.query(DBFinding).filter(DBFinding.scan_id == scan_id)
        if severity:
            query = query.filter(DBFinding.severity == severity)
        query = query.order_by(desc(DBFinding.created_at))
        findings = []
        for f in query.all():
            d = _to_dict(f)
            # Deserialize JSON fields
            d["attack_chain"] = json.loads(d.pop("attack_chain_json", "[]"))
            d["reproduction_steps"] = json.loads(d.pop("reproduction_steps_json", "[]"))
            d["validation"] = json.loads(d.pop("validation_json") or "null")
            d["remediation"] = json.loads(d.pop("remediation_json") or "null")
            d["verdict_score"] = json.loads(d.pop("verdict_score_json") or "null")
            findings.append(d)
        return findings

    def get_scan_agents(self, scan_id: str) -> list[dict[str, Any]]:
        query = self._session.query(DBScanAgent).filter(DBScanAgent.scan_id == scan_id)
        agents = []
        for a in query.all():
            d = _to_dict(a)
            d["errors"] = json.loads(d.get("errors") or "[]")
            agents.append(d)
        return agents

    def get_scan_compound_paths(self, scan_id: str) -> list[dict[str, Any]]:
        query = self._session.query(DBCompoundPath).filter(DBCompoundPath.scan_id == scan_id)
        paths = []
        for p in query.all():
            d = _to_dict(p)
            d["finding_ids"] = json.loads(d.pop("finding_ids_json", "[]"))
            d["attack_path_steps"] = json.loads(d.pop("attack_path_steps_json", "[]"))
            d["owasp_agentic"] = json.loads(d.pop("owasp_agentic_json", "[]"))
            d["validation"] = json.loads(d.pop("validation_json") or "null")
            d["remediation"] = json.loads(d.pop("remediation_json") or "null")
            d["cerberus_detection_rules"] = json.loads(d.pop("cerberus_rules_json", "[]"))
            paths.append(d)
        return paths

    def get_scan_count(self, target_id: str | None = None, status: str | None = None) -> int:
        query = self._session.query(DBScan)
        if target_id:
            query = query.filter(DBScan.target_id == target_id)
        if status:
            query = query.filter(DBScan.status == status)
        return query.count()

    def close(self) -> None:
        self._session.close()
