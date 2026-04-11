"""SQLAlchemy ORM models for ARGUS persistent storage.

Tables:
- targets: Client target configurations (MCP servers, agent endpoints)
- api_keys: Authentication keys with role-based access control
- scans: Scan execution records linked to targets
- scan_agents: Per-agent results within a scan
- findings: Individual attack findings with full evidence
- compound_paths: Correlated multi-agent attack paths
- settings: Platform configuration key-value store
- scheduled_scans: Recurring scan configurations
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Base class for all ARGUS ORM models."""


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


class DBTarget(Base):
    """Persistent target configuration for client AI systems."""

    __tablename__ = "targets"

    id = Column(String(36), primary_key=True, default=_uuid)
    created_at = Column(DateTime, default=_now, nullable=False)
    updated_at = Column(DateTime, default=_now, onupdate=_now, nullable=False)

    # Identity
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, default="")
    environment = Column(String(50), default="staging")  # staging, production, development
    target_type = Column(
        String(50), default="generic", nullable=False, index=True
    )  # mcp_server, ai_agent, pipeline, memory_store, generic

    # MCP targets (JSON-encoded list of URLs)
    mcp_server_urls = Column(Text, default="[]")
    # Agent target
    agent_endpoint = Column(String(2000), default=None, nullable=True)
    agent_api_key_encrypted = Column(Text, default=None, nullable=True)
    # Multi-agent targets (JSON-encoded list)
    agent_endpoints = Column(Text, default="[]")

    # Constraints
    non_destructive = Column(Boolean, default=True, nullable=False)
    max_requests_per_minute = Column(Integer, default=60, nullable=False)

    # Client metadata
    client_name = Column(String(200), default="")
    client_contact = Column(String(200), default="")
    notes = Column(Text, default="")

    # Status
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    scans = relationship("DBScan", back_populates="target", lazy="dynamic")


class DBAPIKey(Base):
    """API key for authentication with role-based access control.

    Roles:
    - admin: Full access (create keys, manage targets, run scans, view results)
    - operator: Run scans, manage targets, view results
    - viewer: View results only
    """

    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=_uuid)
    created_at = Column(DateTime, default=_now, nullable=False)

    # Key (hashed — the raw key is shown once at creation)
    key_hash = Column(String(128), nullable=False, unique=True, index=True)
    key_prefix = Column(String(12), nullable=False)  # First 8 chars for identification

    # Identity
    name = Column(String(200), nullable=False)
    role = Column(String(20), nullable=False, default="viewer")  # admin, operator, viewer

    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)


class DBScan(Base):
    """Persistent record of an ARGUS scan execution."""

    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    created_at = Column(DateTime, default=_now, nullable=False)

    # Target link
    target_id = Column(String(36), ForeignKey("targets.id"), nullable=True)
    target_name = Column(String(200), nullable=False)

    # Execution
    status = Column(String(20), nullable=False, default="pending")  # pending, running, completed, failed, cancelled
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # Configuration
    timeout_seconds = Column(Float, default=600.0)
    demo_pace_seconds = Column(Float, default=0.0)
    non_destructive = Column(Boolean, default=True)

    # Aggregate stats
    agents_deployed = Column(Integer, default=0)
    agents_completed = Column(Integer, default=0)
    agents_failed = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    validated_findings = Column(Integer, default=0)
    compound_paths_count = Column(Integer, default=0)
    signals_exchanged = Column(Integer, default=0)

    # Report (JSON blob)
    report_json = Column(Text, nullable=True)
    # HTML report
    report_html = Column(Text, nullable=True)

    # Operator
    initiated_by = Column(String(200), default="cli")

    # Relationships
    target = relationship("DBTarget", back_populates="scans")
    agents = relationship("DBScanAgent", back_populates="scan", lazy="dynamic")
    findings = relationship("DBFinding", back_populates="scan", lazy="dynamic")
    compound_paths = relationship("DBCompoundPath", back_populates="scan", lazy="dynamic")


class DBScanAgent(Base):
    """Per-agent result within a scan."""

    __tablename__ = "scan_agents"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    # Agent identity
    agent_type = Column(String(50), nullable=False)
    instance_id = Column(String(36), nullable=False)

    # Execution
    status = Column(String(20), nullable=False, default="pending")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # Stats
    findings_count = Column(Integer, default=0)
    validated_count = Column(Integer, default=0)
    techniques_attempted = Column(Integer, default=0)
    techniques_succeeded = Column(Integer, default=0)
    requests_made = Column(Integer, default=0)
    signals_emitted = Column(Integer, default=0)

    # Errors (JSON list)
    errors = Column(Text, default="[]")

    # Relationship
    scan = relationship("DBScan", back_populates="agents")


class DBFinding(Base):
    """Persistent finding from an ARGUS attack agent."""

    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=_now, nullable=False)

    # Source
    agent_type = Column(String(50), nullable=False, index=True)
    agent_instance_id = Column(String(36), nullable=False)

    # Classification
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    status = Column(String(30), nullable=False, default="unvalidated")

    # Attack details
    target_surface = Column(String(200), nullable=False)
    technique = Column(String(200), nullable=False)

    # Full evidence (JSON blobs)
    attack_chain_json = Column(Text, default="[]")
    reproduction_steps_json = Column(Text, default="[]")
    validation_json = Column(Text, nullable=True)
    remediation_json = Column(Text, nullable=True)
    verdict_score_json = Column(Text, nullable=True)

    # OWASP mapping
    owasp_agentic = Column(String(200), nullable=True)
    owasp_llm = Column(String(200), nullable=True)

    # Raw evidence (bounded)
    raw_request = Column(Text, nullable=True)
    raw_response = Column(Text, nullable=True)

    # Relationship
    scan = relationship("DBScan", back_populates="findings")


class DBCompoundPath(Base):
    """Persistent compound attack path from the correlation engine."""

    __tablename__ = "compound_paths"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=_now, nullable=False)

    # Classification
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    compound_impact = Column(Text, nullable=False)

    # Scoring
    exploitability_score = Column(Float, default=0.0)
    detectability_score = Column(Float, default=0.0)

    # Evidence (JSON blobs)
    finding_ids_json = Column(Text, default="[]")
    attack_path_steps_json = Column(Text, default="[]")
    owasp_agentic_json = Column(Text, default="[]")
    validation_json = Column(Text, nullable=True)
    remediation_json = Column(Text, nullable=True)
    cerberus_rules_json = Column(Text, default="[]")

    # Relationship
    scan = relationship("DBScan", back_populates="compound_paths")


class DBSetting(Base):
    """Platform configuration key-value store.

    Sections: scan, llm, notifications, integrations, cerberus.
    Values are stored as JSON text.
    """

    __tablename__ = "settings"
    __table_args__ = (UniqueConstraint("section", "key", name="uq_settings_section_key"),)

    id = Column(String(36), primary_key=True, default=_uuid)
    section = Column(String(50), nullable=False, index=True)  # scan, llm, notifications, integrations, cerberus
    key = Column(String(200), nullable=False)
    value = Column(Text, nullable=False, default="")  # JSON-encoded value
    updated_at = Column(DateTime, default=_now, onupdate=_now, nullable=False)


class DBScheduledScan(Base):
    """Recurring scan configuration.

    Defines automated scans that run on a cron-like schedule.
    """

    __tablename__ = "scheduled_scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    created_at = Column(DateTime, default=_now, nullable=False)
    updated_at = Column(DateTime, default=_now, onupdate=_now, nullable=False)

    # Identity
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")

    # Target
    target_id = Column(String(36), ForeignKey("targets.id"), nullable=False)
    target_name = Column(String(200), nullable=False)

    # Schedule (cron-style)
    cron_expression = Column(String(100), nullable=False)  # e.g. "0 2 * * 1" (Mon 2am)
    timezone = Column(String(50), default="UTC")

    # Scan config
    scan_profile = Column(String(50), default="full")  # full, quick, stealth, phase5_only
    non_destructive = Column(Boolean, default=True)
    timeout_seconds = Column(Float, default=600.0)
    agents_json = Column(Text, default="[]")  # JSON list of agent types to include (empty = all)

    # State
    is_active = Column(Boolean, default=True, nullable=False)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    last_run_status = Column(String(20), nullable=True)  # completed, failed, cancelled
    run_count = Column(Integer, default=0)

    # Relationship
    target = relationship("DBTarget")
