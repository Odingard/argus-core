"""Production API routes for ARGUS.

Adds target management, scan history, auth management, and report
generation endpoints on top of the existing scan/status endpoints.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi import status as http_status
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field, field_validator

from argus.db.repository import APIKeyRepository, ScanRepository, TargetRepository, UserRepository, _to_dict
from argus.db.session import init_db
from argus.web.auth import AuthContext, require_role

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Request/response schemas
# ---------------------------------------------------------------------------


def _validate_target_urls(urls: list[str]) -> list[str]:
    """Validate URLs for SSRF protection, matching ScanRequest validators."""
    from argus.web.server import _validate_url_for_scan

    if len(urls) > 50:
        raise ValueError("Too many MCP URLs (max 50)")
    for url in urls:
        try:
            _validate_url_for_scan(url)
        except ValueError as exc:
            raise ValueError(f"Invalid MCP URL '{url}': {exc}") from exc
    return urls


def _validate_target_endpoint(v: str | None) -> str | None:
    """Validate a single endpoint URL for SSRF protection."""
    if v is None:
        return v
    from argus.web.server import _validate_url_for_scan

    try:
        _validate_url_for_scan(v)
    except ValueError as exc:
        raise ValueError(f"Invalid agent endpoint '{v}': {exc}") from exc
    return v


class TargetCreate(BaseModel):
    name: str = Field(..., max_length=200)
    description: str = ""
    environment: str = "staging"
    target_type: str = "generic"  # mcp_server, ai_agent, pipeline, memory_store, generic
    mcp_server_urls: list[str] = []
    agent_endpoint: str | None = None
    non_destructive: bool = True
    max_requests_per_minute: int = 60
    client_name: str = ""
    client_contact: str = ""
    notes: str = ""

    @field_validator("mcp_server_urls")
    @classmethod
    def _validate_mcp_urls(cls, v: list[str]) -> list[str]:
        return _validate_target_urls(v)

    @field_validator("agent_endpoint")
    @classmethod
    def _validate_agent_ep(cls, v: str | None) -> str | None:
        return _validate_target_endpoint(v)


class TargetUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    environment: str | None = None
    target_type: str | None = None
    mcp_server_urls: list[str] | None = None
    agent_endpoint: str | None = None
    non_destructive: bool | None = None
    max_requests_per_minute: int | None = None
    client_name: str | None = None
    client_contact: str | None = None
    notes: str | None = None

    @field_validator("mcp_server_urls")
    @classmethod
    def _validate_mcp_urls(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        return _validate_target_urls(v)

    @field_validator("agent_endpoint")
    @classmethod
    def _validate_agent_ep(cls, v: str | None) -> str | None:
        return _validate_target_endpoint(v)


class FindingStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(open|triaged|resolved|false_positive|unvalidated|validated)$")


class UserLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)


class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=6, max_length=200)
    email: str | None = Field(default=None, max_length=200)
    display_name: str | None = Field(default=None, max_length=200)
    role: str = Field(default="viewer", pattern="^(admin|operator|viewer)$")


class APIKeyCreate(BaseModel):
    name: str = Field(..., max_length=200)
    role: str = Field(default="viewer", pattern="^(admin|operator|viewer)$")


class LLMKeySet(BaseModel):
    provider: str = Field(..., pattern="^(anthropic|openai|google|custom)$")
    api_key: str = Field(..., min_length=1, max_length=2000)
    endpoint: str | None = Field(default=None, max_length=500)


class LLMKeyDelete(BaseModel):
    provider: str = Field(..., pattern="^(anthropic|openai|google|custom)$")


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def create_production_router() -> APIRouter:
    """Create the production API router with all CRUD endpoints."""
    router = APIRouter(prefix="/api")

    # Ensure database is initialized
    init_db()

    # ------------------------------------------------------------------
    # Target Management
    # ------------------------------------------------------------------

    @router.post("/targets", dependencies=[Depends(require_role("write"))])
    async def create_target(body: TargetCreate) -> dict[str, Any]:
        repo = TargetRepository()
        try:
            target = repo.create(
                name=body.name,
                description=body.description,
                environment=body.environment,
                target_type=body.target_type,
                mcp_server_urls=body.mcp_server_urls,
                agent_endpoint=body.agent_endpoint,
                non_destructive=body.non_destructive,
                max_requests_per_minute=body.max_requests_per_minute,
                client_name=body.client_name,
                client_contact=body.client_contact,
                notes=body.notes,
            )
            return {"target": target}
        finally:
            repo.close()

    @router.get("/targets", dependencies=[Depends(require_role("read"))])
    async def list_targets() -> dict[str, Any]:
        repo = TargetRepository()
        try:
            targets = repo.list_all()
            return {"targets": targets, "total": len(targets)}
        finally:
            repo.close()

    @router.get("/targets/{target_id}", dependencies=[Depends(require_role("read"))])
    async def get_target(target_id: str) -> dict[str, Any]:
        repo = TargetRepository()
        try:
            target = repo.get(target_id)
            if target is None:
                raise HTTPException(status_code=404, detail="Target not found")
            return {"target": target}
        finally:
            repo.close()

    @router.put("/targets/{target_id}", dependencies=[Depends(require_role("write"))])
    async def update_target(target_id: str, body: TargetUpdate) -> dict[str, Any]:
        repo = TargetRepository()
        try:
            updates = body.model_dump(exclude_unset=True)
            if not updates:
                raise HTTPException(status_code=400, detail="No fields to update")
            target = repo.update(target_id, **updates)
            if target is None:
                raise HTTPException(status_code=404, detail="Target not found")
            return {"target": target}
        finally:
            repo.close()

    @router.delete("/targets/{target_id}", dependencies=[Depends(require_role("write"))])
    async def delete_target(target_id: str) -> dict[str, str]:
        repo = TargetRepository()
        try:
            if not repo.delete(target_id):
                raise HTTPException(status_code=404, detail="Target not found")
            return {"status": "deleted", "target_id": target_id}
        finally:
            repo.close()

    # ------------------------------------------------------------------
    # Scan History
    # ------------------------------------------------------------------

    @router.get("/scans", dependencies=[Depends(require_role("read"))])
    async def list_scans(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        target_id: str | None = Query(default=None),
        status: str | None = Query(default=None),
    ) -> dict[str, Any]:
        repo = ScanRepository()
        try:
            scans = repo.list_scans(limit=limit, offset=offset, target_id=target_id, status=status)
            total = repo.get_scan_count(target_id=target_id, status=status)
            return {"scans": scans, "total": total, "limit": limit, "offset": offset}
        finally:
            repo.close()

    @router.get("/scans/pending", dependencies=[Depends(require_role("read"))])
    async def pending_scans() -> dict[str, Any]:
        """Return scans with status pending or running."""
        repo = ScanRepository()
        try:
            pending = repo.list_scans(limit=50, status="pending")
            running = repo.list_scans(limit=50, status="running")
            return {"scans": pending + running, "total": len(pending) + len(running)}
        finally:
            repo.close()

    @router.get("/scans/scheduled", dependencies=[Depends(require_role("read"))])
    async def scheduled_scans() -> dict[str, Any]:
        """Return scheduled scan configurations.

        Currently returns an empty list — scheduled scans are a future feature
        that will be stored in a dedicated table.
        """
        return {"schedules": [], "total": 0}

    @router.get("/scans/{scan_id}", dependencies=[Depends(require_role("read"))])
    async def get_scan(scan_id: str) -> dict[str, Any]:
        repo = ScanRepository()
        try:
            scan = repo.get_scan(scan_id)
            if scan is None:
                raise HTTPException(status_code=404, detail="Scan not found")
            # Include agent results
            agents = repo.get_scan_agents(scan_id)
            return {"scan": scan, "agents": agents}
        finally:
            repo.close()

    @router.get("/scans/{scan_id}/findings", dependencies=[Depends(require_role("read"))])
    async def get_scan_findings(
        scan_id: str,
        severity: str | None = Query(default=None),
    ) -> dict[str, Any]:
        repo = ScanRepository()
        try:
            scan = repo.get_scan(scan_id)
            if scan is None:
                raise HTTPException(status_code=404, detail="Scan not found")
            findings = repo.get_scan_findings(scan_id, severity=severity)
            return {"scan_id": scan_id, "findings": findings, "total": len(findings)}
        finally:
            repo.close()

    @router.delete("/scans/{scan_id}", dependencies=[Depends(require_role("write"))])
    async def delete_scan(scan_id: str) -> dict[str, str]:
        """Delete a scan and all its children (findings, agents, compound paths)."""
        repo = ScanRepository()
        try:
            if not repo.delete_scan(scan_id):
                raise HTTPException(status_code=404, detail="Scan not found")
            return {"status": "deleted", "scan_id": scan_id}
        finally:
            repo.close()

    @router.get("/scans/{scan_id}/compound-paths", dependencies=[Depends(require_role("read"))])
    async def get_scan_compound_paths(scan_id: str) -> dict[str, Any]:
        repo = ScanRepository()
        try:
            scan = repo.get_scan(scan_id)
            if scan is None:
                raise HTTPException(status_code=404, detail="Scan not found")
            paths = repo.get_scan_compound_paths(scan_id)
            return {"scan_id": scan_id, "compound_paths": paths, "total": len(paths)}
        finally:
            repo.close()

    @router.get("/scans/{scan_id}/report")
    async def get_scan_report(
        scan_id: str,
        format: str = Query(default="html", pattern="^(html|json)$"),
        auth: AuthContext = Depends(require_role("read")),
    ) -> Response:
        """Download the scan report in HTML or JSON format."""
        repo = ScanRepository()
        try:
            scan = repo.get_scan(scan_id)
            if scan is None:
                raise HTTPException(status_code=404, detail="Scan not found")

            if format == "html":
                if not scan.get("report_html"):
                    raise HTTPException(status_code=404, detail="HTML report not generated for this scan")
                return HTMLResponse(
                    content=scan["report_html"],
                    headers={"Content-Disposition": f'inline; filename="argus-report-{scan_id[:8]}.html"'},
                )
            else:
                if not scan.get("report_json"):
                    raise HTTPException(status_code=404, detail="JSON report not generated for this scan")
                return Response(
                    content=scan["report_json"],
                    media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="argus-report-{scan_id[:8]}.json"'},
                )
        finally:
            repo.close()

    # ------------------------------------------------------------------
    # Auth / API Key Management
    # ------------------------------------------------------------------

    @router.post("/auth/login")
    async def auth_login(
        auth: AuthContext = Depends(require_role("read")),
    ) -> dict[str, Any]:
        """Validate a bearer token and return auth context.

        The frontend calls this to verify the token is valid before
        storing it in localStorage.  The actual authentication happens
        in the ``require_role`` dependency — if the token is invalid,
        FastAPI returns 401 before this handler runs.
        """
        return {
            "status": "authenticated",
            "role": auth.role.value,
            "key_name": auth.key_name,
            "auth_method": auth.auth_method,
        }

    # ------------------------------------------------------------------
    # User Login (username/password)
    # ------------------------------------------------------------------

    @router.post("/auth/user-login")
    async def user_login(body: UserLogin, request: Request) -> dict[str, Any]:
        """Authenticate with username/password. Returns a session token."""
        repo = UserRepository()
        try:
            user = repo.authenticate(body.username, body.password)
            if user is None:
                raise HTTPException(
                    status_code=http_status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username or password",
                )
            session = repo.create_session(
                user_id=user["id"],
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("User-Agent"),
            )
            return {
                "status": "authenticated",
                "session_token": session["raw_token"],
                "user": {
                    "id": user["id"],
                    "username": user["username"],
                    "display_name": user.get("display_name", user["username"]),
                    "email": user.get("email"),
                    "role": user["role"],
                },
            }
        finally:
            repo.close()

    @router.post("/auth/user-logout")
    async def user_logout(
        request: Request,
        auth: AuthContext = Depends(require_role("read")),
    ) -> dict[str, str]:
        """Invalidate the current session token."""
        # Extract the raw token from the request
        alt_token = request.headers.get("X-Argus-Token", "").strip()
        if alt_token:
            token = alt_token
        else:
            auth_header = request.headers.get("Authorization", "")
            token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""

        if token.startswith("argus_sess_"):
            repo = UserRepository()
            try:
                repo.invalidate_session(token)
            finally:
                repo.close()
        return {"status": "logged_out"}

    @router.get("/auth/me")
    async def auth_me(
        auth: AuthContext = Depends(require_role("read")),
    ) -> dict[str, Any]:
        """Return current user info from session or API key."""
        result: dict[str, Any] = {
            "authenticated": True,
            "role": auth.role.value,
            "auth_method": auth.auth_method,
            "key_name": auth.key_name,
        }
        if auth.auth_method == "user_session" and auth.key_id:
            repo = UserRepository()
            try:
                user = repo.get_by_id(auth.key_id)
                if user:
                    result["user"] = {
                        "id": user["id"],
                        "username": user["username"],
                        "display_name": user.get("display_name", user["username"]),
                        "email": user.get("email"),
                        "role": user["role"],
                    }
            finally:
                repo.close()
        return result

    @router.post("/auth/register")
    async def register_user(
        body: UserRegister,
        auth: AuthContext = Depends(require_role("admin")),
    ) -> dict[str, Any]:
        """Register a new user (admin only)."""
        repo = UserRepository()
        try:
            user = repo.create(
                username=body.username,
                password=body.password,
                role=body.role,
                email=body.email,
                display_name=body.display_name,
            )
            return {"user": user}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            repo.close()

    @router.get("/auth/users", dependencies=[Depends(require_role("admin"))])
    async def list_users() -> dict[str, Any]:
        """List all users (admin only)."""
        repo = UserRepository()
        try:
            users = repo.list_all()
            return {"users": users, "total": len(users)}
        finally:
            repo.close()

    @router.post("/auth/keys")
    async def create_api_key(
        body: APIKeyCreate,
        auth: AuthContext = Depends(require_role("admin")),
    ) -> dict[str, Any]:
        repo = APIKeyRepository()
        try:
            key = repo.create(name=body.name, role=body.role)
            return {
                "api_key": {
                    "id": key["id"],
                    "name": key["name"],
                    "role": key["role"],
                    "key_prefix": key["key_prefix"],
                    "created_at": key["created_at"],
                    "raw_key": key["raw_key"],  # Shown only once
                },
                "warning": "Store this key securely — it cannot be retrieved again.",
            }
        finally:
            repo.close()

    @router.get("/auth/keys", dependencies=[Depends(require_role("admin"))])
    async def list_api_keys() -> dict[str, Any]:
        repo = APIKeyRepository()
        try:
            keys = repo.list_all()
            # Never return key hashes
            safe_keys = [
                {
                    "id": k["id"],
                    "name": k["name"],
                    "role": k["role"],
                    "key_prefix": k["key_prefix"],
                    "is_active": k["is_active"],
                    "created_at": k["created_at"],
                    "last_used_at": k["last_used_at"],
                }
                for k in keys
            ]
            return {"api_keys": safe_keys, "total": len(safe_keys)}
        finally:
            repo.close()

    @router.delete("/auth/keys/{key_id}")
    async def revoke_api_key(
        key_id: str,
        auth: AuthContext = Depends(require_role("admin")),
    ) -> dict[str, str]:
        repo = APIKeyRepository()
        try:
            if not repo.revoke(key_id):
                raise HTTPException(status_code=404, detail="API key not found")
            return {"status": "revoked", "key_id": key_id}
        finally:
            repo.close()

    # ------------------------------------------------------------------
    # Tier info
    # ------------------------------------------------------------------

    @router.get("/system/tier", dependencies=[Depends(require_role("read"))])
    async def tier_info() -> dict[str, Any]:
        """Return the active ARGUS tier and feature matrix."""
        from argus.tiering import FEATURE_MATRIX, current_tier

        t = current_tier()
        return {
            **t.info(),
            "feature_matrix": FEATURE_MATRIX,
        }

    # ------------------------------------------------------------------
    # System info
    # ------------------------------------------------------------------

    @router.get("/system/db-status", dependencies=[Depends(require_role("read"))])
    async def db_status() -> dict[str, Any]:
        """Database health check with table counts."""
        try:
            from argus.db.session import get_session

            session = get_session()
            try:
                from argus.db.models import DBAPIKey, DBFinding, DBScan, DBTarget

                target_count = session.query(DBTarget).filter(DBTarget.is_active.is_(True)).count()
                scan_count = session.query(DBScan).count()
                finding_count = session.query(DBFinding).count()
                key_count = session.query(DBAPIKey).filter(DBAPIKey.is_active.is_(True)).count()
            finally:
                session.close()
            return {
                "status": "healthy",
                "tables": {
                    "targets": target_count,
                    "scans": scan_count,
                    "findings": finding_count,
                    "api_keys": key_count,
                },
            }
        except Exception as exc:
            return {"status": "error", "error": str(type(exc).__name__)}

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    @router.get("/dashboard/stats", dependencies=[Depends(require_role("read"))])
    async def dashboard_stats() -> dict[str, Any]:
        """Aggregate dashboard statistics from the database."""
        from argus.db.models import DBCompoundPath, DBFinding, DBScan, DBTarget
        from argus.db.session import get_session

        session = get_session()
        try:
            total_findings = session.query(DBFinding).count()
            critical_findings = session.query(DBFinding).filter(DBFinding.severity == "critical").count()
            high_findings = session.query(DBFinding).filter(DBFinding.severity == "high").count()
            medium_findings = session.query(DBFinding).filter(DBFinding.severity == "medium").count()
            low_findings = session.query(DBFinding).filter(DBFinding.severity == "low").count()
            active_targets = session.query(DBTarget).filter(DBTarget.is_active.is_(True)).count()
            compound_chains = session.query(DBCompoundPath).count()
            total_scans = session.query(DBScan).count()
            completed_scans = session.query(DBScan).filter(DBScan.status == "completed").count()

            # Severity distribution for pie chart
            severity_dist = [
                {"name": "Critical", "value": critical_findings, "color": "#ef4444"},
                {"name": "High", "value": high_findings, "color": "#f97316"},
                {"name": "Medium", "value": medium_findings, "color": "#eab308"},
                {"name": "Low", "value": low_findings, "color": "#3b82f6"},
            ]

            # Trend data from recent scans (group findings by scan date)
            from sqlalchemy import func

            trend_rows = (
                session.query(
                    func.date(DBScan.created_at).label("scan_date"),
                    func.sum(DBScan.total_findings).label("total"),
                )
                .filter(DBScan.status == "completed")
                .group_by(func.date(DBScan.created_at))
                .order_by(func.date(DBScan.created_at).desc())
                .limit(7)
                .all()
            )
            trend = [{"date": str(r.scan_date), "findings": int(r.total or 0)} for r in reversed(trend_rows)]

            return {
                "total_findings": total_findings,
                "critical": critical_findings,
                "high": high_findings,
                "medium": medium_findings,
                "low": low_findings,
                "active_targets": active_targets,
                "compound_chains": compound_chains,
                "total_scans": total_scans,
                "completed_scans": completed_scans,
                "severity_distribution": severity_dist,
                "trend": trend,
            }
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Agents status
    # ------------------------------------------------------------------

    @router.get("/agents/status", dependencies=[Depends(require_role("read"))])
    async def agents_status() -> dict[str, Any]:
        """Return all 12 ARGUS agents with their current status."""
        from argus.db.models import DBScanAgent
        from argus.db.session import get_session

        agents_meta = [
            {"code": "PI-01", "name": "Prompt Injection Hunter", "type": "prompt_injection_hunter", "techniques": 7},
            {"code": "TP-02", "name": "Tool Poisoning Agent", "type": "tool_poisoning", "techniques": 5},
            {"code": "SC-09", "name": "Supply Chain Agent", "type": "supply_chain", "techniques": 4},
            {"code": "MP-03", "name": "Memory Poisoning Agent", "type": "memory_poisoning", "techniques": 5},
            {"code": "IS-04", "name": "Identity Spoof Agent", "type": "identity_spoof", "techniques": 5},
            {"code": "CW-05", "name": "Context Window Agent", "type": "context_window", "techniques": 7},
            {"code": "CX-06", "name": "Cross-Agent Exfil Agent", "type": "cross_agent_exfiltration", "techniques": 5},
            {"code": "PE-07", "name": "Privilege Escalation Agent", "type": "privilege_escalation", "techniques": 6},
            {"code": "RC-08", "name": "Race Condition Agent", "type": "race_condition", "techniques": 5},
            {"code": "ME-10", "name": "Model Extraction Agent", "type": "model_extraction", "techniques": 6},
            {"code": "PH-11", "name": "Persona Hijacking Agent", "type": "persona_hijacking", "techniques": 5},
            {"code": "MB-12", "name": "Memory Boundary Collapse", "type": "memory_boundary_collapse", "techniques": 5},
        ]

        session = get_session()
        try:
            results = []
            for meta in agents_meta:
                # Get the most recent agent run
                last_run = (
                    session.query(DBScanAgent)
                    .filter(DBScanAgent.agent_type == meta["type"])
                    .order_by(DBScanAgent.completed_at.desc().nullslast())
                    .first()
                )
                results.append(
                    {
                        "code": meta["code"],
                        "name": meta["name"],
                        "type": meta["type"],
                        "techniques": meta["techniques"],
                        "status": last_run.status if last_run else "idle",
                        "findings": last_run.findings_count if last_run else 0,
                        "last_run": str(last_run.completed_at) if last_run and last_run.completed_at else None,
                    }
                )
            return {"agents": results}
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Alerts (derived from recent findings)
    # ------------------------------------------------------------------

    @router.get("/alerts", dependencies=[Depends(require_role("read"))])
    async def get_alerts(
        limit: int = Query(default=20, ge=1, le=100),
    ) -> dict[str, Any]:
        """Return recent alerts derived from findings and scan events."""
        from argus.db.models import DBFinding, DBScan
        from argus.db.session import get_session

        session = get_session()
        try:
            alerts: list[dict[str, Any]] = []

            # Recent critical/high findings as alerts
            recent_findings = (
                session.query(DBFinding)
                .filter(DBFinding.severity.in_(["critical", "high"]))
                .order_by(DBFinding.created_at.desc())
                .limit(limit)
                .all()
            )
            for f in recent_findings:
                alerts.append(
                    {
                        "id": f.id,
                        "type": "new_critical" if f.severity == "critical" else "new_high",
                        "title": f"New {f.severity.title()}: {f.title}",
                        "time": str(f.created_at),
                        "severity": f.severity,
                        "source": "finding",
                    }
                )

            # Recent completed scans as info alerts
            recent_scans = (
                session.query(DBScan)
                .filter(DBScan.status == "completed")
                .order_by(DBScan.completed_at.desc())
                .limit(5)
                .all()
            )
            for s in recent_scans:
                alerts.append(
                    {
                        "id": s.id,
                        "type": "scan_complete",
                        "title": f"Scan completed: {s.target_name}",
                        "time": str(s.completed_at or s.created_at),
                        "severity": "info",
                        "source": "scan",
                    }
                )

            # Sort by time descending
            alerts.sort(key=lambda a: a["time"], reverse=True)
            return {"alerts": alerts[:limit]}
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Global findings (across all scans)
    # ------------------------------------------------------------------

    @router.get("/findings", dependencies=[Depends(require_role("read"))])
    async def list_all_findings(
        severity: str | None = Query(default=None),
        status: str | None = Query(default=None),
        agent_type: str | None = Query(default=None),
        search: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        """List findings across all scans with optional filters."""
        import json as json_mod

        from argus.db.models import DBFinding
        from argus.db.session import get_session

        session = get_session()
        try:
            query = session.query(DBFinding)
            if severity:
                query = query.filter(DBFinding.severity == severity)
            if status:
                query = query.filter(DBFinding.status == status)
            if agent_type:
                query = query.filter(DBFinding.agent_type == agent_type)
            if search:
                query = query.filter(DBFinding.title.ilike(f"%{search}%"))
            total = query.count()
            rows = query.order_by(DBFinding.created_at.desc()).offset(offset).limit(limit).all()
            findings = []
            for f in rows:
                d = _to_dict(f)
                d["attack_chain"] = json_mod.loads(d.pop("attack_chain_json", "[]"))
                d["reproduction_steps"] = json_mod.loads(d.pop("reproduction_steps_json", "[]"))
                d["validation"] = json_mod.loads(d.pop("validation_json") or "null")
                d["remediation"] = json_mod.loads(d.pop("remediation_json") or "null")
                d["verdict_score"] = json_mod.loads(d.pop("verdict_score_json") or "null")
                findings.append(d)
            return {"findings": findings, "total": total}
        finally:
            session.close()

    @router.get("/findings/{finding_id}", dependencies=[Depends(require_role("read"))])
    async def get_finding(finding_id: str) -> dict[str, Any]:
        """Get a single finding by ID."""
        import json as json_mod

        from argus.db.models import DBFinding
        from argus.db.session import get_session

        session = get_session()
        try:
            f = session.get(DBFinding, finding_id)
            if f is None:
                raise HTTPException(status_code=404, detail="Finding not found")
            d = _to_dict(f)
            d["attack_chain"] = json_mod.loads(d.pop("attack_chain_json", "[]"))
            d["reproduction_steps"] = json_mod.loads(d.pop("reproduction_steps_json", "[]"))
            d["validation"] = json_mod.loads(d.pop("validation_json") or "null")
            d["remediation"] = json_mod.loads(d.pop("remediation_json") or "null")
            d["verdict_score"] = json_mod.loads(d.pop("verdict_score_json") or "null")
            return {"finding": d}
        finally:
            session.close()

    @router.put("/findings/{finding_id}/status", dependencies=[Depends(require_role("write"))])
    async def update_finding_status(finding_id: str, body: FindingStatusUpdate) -> dict[str, Any]:
        """Update the triage status of a finding."""
        from argus.db.models import DBFinding
        from argus.db.session import get_session

        new_status = body.status

        session = get_session()
        try:
            f = session.get(DBFinding, finding_id)
            if f is None:
                raise HTTPException(status_code=404, detail="Finding not found")
            f.status = new_status  # type: ignore[assignment]
            session.commit()
            return {"status": "updated", "finding_id": finding_id, "new_status": new_status}
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Compound paths (global)
    # ------------------------------------------------------------------

    @router.get("/compound-paths", dependencies=[Depends(require_role("read"))])
    async def list_compound_paths(
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, Any]:
        """List all compound attack paths across all scans."""
        import json as json_mod

        from argus.db.models import DBCompoundPath
        from argus.db.session import get_session

        session = get_session()
        try:
            query = session.query(DBCompoundPath).order_by(DBCompoundPath.created_at.desc()).limit(limit)
            paths = []
            for p in query.all():
                d = _to_dict(p)
                d["finding_ids"] = json_mod.loads(d.pop("finding_ids_json", "[]"))
                d["attack_path_steps"] = json_mod.loads(d.pop("attack_path_steps_json", "[]"))
                d["owasp_agentic"] = json_mod.loads(d.pop("owasp_agentic_json", "[]"))
                d["validation"] = json_mod.loads(d.pop("validation_json") or "null")
                d["remediation"] = json_mod.loads(d.pop("remediation_json") or "null")
                d["cerberus_detection_rules"] = json_mod.loads(d.pop("cerberus_rules_json", "[]"))
                paths.append(d)
            return {"compound_paths": paths, "total": len(paths)}
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Monitoring metrics
    # ------------------------------------------------------------------

    @router.get("/monitoring/metrics", dependencies=[Depends(require_role("read"))])
    async def monitoring_metrics() -> dict[str, Any]:
        """Return platform monitoring metrics."""
        import platform
        import time

        from argus.db.models import DBFinding, DBScan, DBScanAgent
        from argus.db.session import get_session

        session = get_session()
        try:
            total_scans = session.query(DBScan).count()
            total_findings = session.query(DBFinding).count()

            # Agent health from most recent runs
            agents_meta = [
                {"code": "PI-01", "name": "Prompt Injection", "type": "prompt_injection_hunter"},
                {"code": "TP-02", "name": "Tool Poisoning", "type": "tool_poisoning"},
                {"code": "MP-03", "name": "Memory Poisoning", "type": "memory_poisoning"},
                {"code": "IS-04", "name": "Identity Spoof", "type": "identity_spoof"},
                {"code": "CW-05", "name": "Context Window", "type": "context_window"},
                {"code": "CX-06", "name": "Cross-Agent Exfil", "type": "cross_agent_exfiltration"},
                {"code": "PE-07", "name": "Privilege Escalation", "type": "privilege_escalation"},
                {"code": "RC-08", "name": "Race Condition", "type": "race_condition"},
                {"code": "SC-09", "name": "Supply Chain", "type": "supply_chain"},
                {"code": "ME-10", "name": "Model Extraction", "type": "model_extraction"},
                {"code": "PH-11", "name": "Persona Hijacking", "type": "persona_hijacking"},
                {"code": "MB-12", "name": "Memory Boundary", "type": "memory_boundary_collapse"},
            ]

            agents_health = []
            for meta in agents_meta:
                last_run = (
                    session.query(DBScanAgent)
                    .filter(DBScanAgent.agent_type == meta["type"])
                    .order_by(DBScanAgent.completed_at.desc().nullslast())
                    .first()
                )
                status = "healthy"
                if last_run and last_run.status == "failed":
                    status = "degraded"
                agents_health.append(
                    {
                        "code": meta["code"],
                        "name": meta["name"],
                        "status": status,
                        "last_run": str(last_run.completed_at) if last_run and last_run.completed_at else None,
                        "avg_duration": f"{last_run.duration_seconds:.0f}s"
                        if last_run and last_run.duration_seconds
                        else "N/A",
                    }
                )

            return {
                "platform_status": "operational",
                "total_scans": total_scans,
                "total_findings": total_findings,
                "agents_health": agents_health,
                "system": {
                    "python": platform.python_version(),
                    "platform": platform.platform(),
                    "uptime_check": time.time(),
                },
            }
        finally:
            session.close()

    # ------------------------------------------------------------------
    # OWASP coverage
    # ------------------------------------------------------------------

    @router.get("/owasp/coverage", dependencies=[Depends(require_role("read"))])
    async def owasp_coverage() -> dict[str, Any]:
        """Return OWASP Agentic AI category coverage based on actual findings."""
        from argus.db.models import DBFinding
        from argus.db.session import get_session

        # Static mapping of OWASP categories to ARGUS agents
        categories = [
            {
                "id": "AA01",
                "name": "Prompt Injection",
                "agents": ["PI-01", "CW-05"],
                "agent_types": ["prompt_injection_hunter", "context_window"],
            },
            {
                "id": "AA02",
                "name": "Sensitive Information Disclosure",
                "agents": ["ME-10", "IS-04"],
                "agent_types": ["model_extraction", "identity_spoof"],
            },
            {
                "id": "AA03",
                "name": "Supply Chain Vulnerabilities",
                "agents": ["SC-09"],
                "agent_types": ["supply_chain"],
            },
            {
                "id": "AA04",
                "name": "Excessive Agency",
                "agents": ["PE-07", "CX-06"],
                "agent_types": ["privilege_escalation", "cross_agent_exfiltration"],
            },
            {
                "id": "AA05",
                "name": "Improper Output Handling",
                "agents": ["MP-03", "PI-01"],
                "agent_types": ["memory_poisoning", "prompt_injection_hunter"],
            },
            {
                "id": "AA06",
                "name": "Tool Misuse",
                "agents": ["TP-02", "CW-05"],
                "agent_types": ["tool_poisoning", "context_window"],
            },
            {
                "id": "AA07",
                "name": "System Prompt Leakage",
                "agents": ["ME-10", "PI-01"],
                "agent_types": ["model_extraction", "prompt_injection_hunter"],
            },
            {
                "id": "AA08",
                "name": "Model Theft / Extraction",
                "agents": ["ME-10"],
                "agent_types": ["model_extraction"],
            },
            {"id": "AA09", "name": "Overreliance", "agents": [], "agent_types": []},
            {
                "id": "AA10",
                "name": "Insecure Plugin Design",
                "agents": ["TP-02", "SC-09"],
                "agent_types": ["tool_poisoning", "supply_chain"],
            },
            {
                "id": "AA11",
                "name": "Persona Hijacking (ARGUS)",
                "agents": ["PH-11"],
                "agent_types": ["persona_hijacking"],
            },
            {
                "id": "AA12",
                "name": "Memory Boundary Collapse (ARGUS)",
                "agents": ["MB-12"],
                "agent_types": ["memory_boundary_collapse"],
            },
        ]

        session = get_session()
        try:
            result = []
            for cat in categories:
                findings_count = 0
                critical_count = 0
                high_count = 0
                for agent_type in cat["agent_types"]:
                    findings_count += session.query(DBFinding).filter(DBFinding.agent_type == agent_type).count()
                    critical_count += (
                        session.query(DBFinding)
                        .filter(DBFinding.agent_type == agent_type, DBFinding.severity == "critical")
                        .count()
                    )
                    high_count += (
                        session.query(DBFinding)
                        .filter(DBFinding.agent_type == agent_type, DBFinding.severity == "high")
                        .count()
                    )

                if not cat["agents"]:
                    coverage = 0
                    status = "gap"
                elif findings_count > 0:
                    coverage = min(100, 60 + findings_count * 5)
                    status = "covered"
                else:
                    coverage = 50
                    status = "partial"

                result.append(
                    {
                        "id": cat["id"],
                        "name": cat["name"],
                        "coverage": coverage,
                        "findings": findings_count,
                        "critical": critical_count,
                        "high": high_count,
                        "agents": cat["agents"],
                        "status": status,
                    }
                )
            return {"categories": result}
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Gauntlet (benchmark)
    # ------------------------------------------------------------------

    @router.get("/gauntlet/scenarios", dependencies=[Depends(require_role("read"))])
    async def gauntlet_scenarios() -> dict[str, Any]:
        """Return benchmark scenario definitions with results from latest scans."""
        from argus.db.models import DBScanAgent
        from argus.db.session import get_session

        scenarios_meta = [
            {
                "id": "BM-01",
                "name": "Basic Prompt Injection",
                "agent": "PI-01",
                "agent_type": "prompt_injection_hunter",
                "category": "prompt_injection_hunter",
                "description": "Tests detection of standard injection patterns",
            },
            {
                "id": "BM-02",
                "name": "Unicode Hidden Instructions",
                "agent": "TP-02",
                "agent_type": "tool_poisoning",
                "category": "tool_poisoning",
                "description": "Tests detection of zero-width character hiding",
            },
            {
                "id": "BM-03",
                "name": "Memory Store Poisoning",
                "agent": "MP-03",
                "agent_type": "memory_poisoning",
                "category": "memory_poisoning",
                "description": "Tests adversarial content planting and retrieval",
            },
            {
                "id": "BM-04",
                "name": "Identity Header Forgery",
                "agent": "IS-04",
                "agent_type": "identity_spoof",
                "category": "identity_spoof",
                "description": "Tests A2A authentication bypass via header spoofing",
            },
            {
                "id": "BM-05",
                "name": "Context Window Overflow",
                "agent": "CW-05",
                "agent_type": "context_window",
                "category": "context_window",
                "description": "Tests long-con multi-turn context manipulation",
            },
            {
                "id": "BM-06",
                "name": "Cross-Agent Data Relay",
                "agent": "CX-06",
                "agent_type": "cross_agent_exfiltration",
                "category": "cross_agent_exfiltration",
                "description": "Tests data leakage between agent boundaries",
            },
            {
                "id": "BM-07",
                "name": "Confused Deputy Escalation",
                "agent": "PE-07",
                "agent_type": "privilege_escalation",
                "category": "privilege_escalation",
                "description": "Tests chained tool-call privilege escalation",
            },
            {
                "id": "BM-08",
                "name": "TOCTOU Race Condition",
                "agent": "RC-08",
                "agent_type": "race_condition",
                "category": "race_condition",
                "description": "Tests time-of-check/time-of-use exploitation",
            },
            {
                "id": "BM-09",
                "name": "Supply Chain Dependency",
                "agent": "SC-09",
                "agent_type": "supply_chain",
                "category": "supply_chain",
                "description": "Tests external dependency trust verification",
            },
            {
                "id": "BM-10",
                "name": "System Prompt Extraction",
                "agent": "ME-10",
                "agent_type": "model_extraction",
                "category": "model_extraction",
                "description": "Tests system prompt and config fingerprinting",
            },
            {
                "id": "BM-11",
                "name": "Persona Drift Induction",
                "agent": "PH-11",
                "agent_type": "persona_hijacking",
                "category": "persona_hijacking",
                "description": "Tests identity drift via multi-turn adversarial pressure",
            },
            {
                "id": "BM-12",
                "name": "Memory Boundary Bleed",
                "agent": "MB-12",
                "agent_type": "memory_boundary_collapse",
                "category": "memory_boundary",
                "description": "Tests cross-session memory boundary enforcement",
            },
        ]

        session = get_session()
        try:
            results = []
            for sc in scenarios_meta:
                last_agent = (
                    session.query(DBScanAgent)
                    .filter(DBScanAgent.agent_type == sc["agent_type"])
                    .order_by(DBScanAgent.completed_at.desc().nullslast())
                    .first()
                )
                if last_agent and last_agent.status == "completed":
                    attempted = last_agent.techniques_attempted or 1
                    succeeded = last_agent.techniques_succeeded or 0
                    score = min(100, int((succeeded / max(attempted, 1)) * 100))
                    status = "passed" if score >= 50 else "failed"
                elif last_agent:
                    score = 0
                    status = "failed"
                else:
                    score = 0
                    status = "pending"

                results.append(
                    {
                        "id": sc["id"],
                        "name": sc["name"],
                        "agent": sc["agent"],
                        "category": sc["category"],
                        "status": status,
                        "score": score,
                        "maxScore": 100,
                        "description": sc["description"],
                    }
                )
            return {"scenarios": results}
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Corpus (attack patterns)
    # ------------------------------------------------------------------

    @router.get("/corpus/patterns", dependencies=[Depends(require_role("read"))])
    async def corpus_patterns(
        search: str | None = Query(default=None),
    ) -> dict[str, Any]:
        """Return attack corpus patterns from the corpus data directory."""
        from argus.corpus.manager import AttackCorpus

        agent_code_map = {
            "prompt_injection_hunter": "PI-01",
            "tool_poisoning": "TP-02",
            "supply_chain": "SC-09",
            "memory_poisoning": "MP-03",
            "identity_spoof": "IS-04",
            "context_window": "CW-05",
            "cross_agent_exfiltration": "CX-06",
            "privilege_escalation": "PE-07",
            "race_condition": "RC-08",
            "model_extraction": "ME-10",
            "persona_hijacking": "PH-11",
            "memory_boundary_collapse": "MB-12",
        }

        corpus = AttackCorpus()
        corpus.load()
        all_patterns = corpus.get_patterns()

        patterns: list[dict[str, Any]] = []
        for p in all_patterns:
            # Determine agent code from the pattern's agent_types list
            agent_code = "—"
            category_key = p.category.value.split(".")[0]
            for agent_type in p.agent_types:
                if agent_type in agent_code_map:
                    agent_code = agent_code_map[agent_type]
                    break
            # Fallback: derive from category prefix
            if agent_code == "—":
                for key, code in agent_code_map.items():
                    if key.startswith(category_key):
                        agent_code = code
                        break

            effectiveness = round(p.success_rate * 100) if p.times_used > 0 else 0
            patterns.append(
                {
                    "id": p.id,
                    "name": p.name,
                    "category": p.category.value,
                    "agent": agent_code,
                    "effectiveness": effectiveness,
                    "timesUsed": p.times_used,
                    "lastUsed": None,
                    "description": p.description,
                }
            )

        if search:
            search_lower = search.lower()
            patterns = [
                pat
                for pat in patterns
                if search_lower in pat["name"].lower()
                or search_lower in pat["category"].lower()
                or search_lower in pat["agent"].lower()
                or search_lower in pat["description"].lower()
            ]

        return {"patterns": patterns, "total": len(patterns)}

    # ------------------------------------------------------------------
    # LLM API Key Management (stored in ~/.argusrc)
    # ------------------------------------------------------------------

    _PROVIDER_CONFIG_MAP = {
        "anthropic": "anthropic_api_key",
        "openai": "openai_api_key",
        "google": "google_api_key",
        "custom": "custom_api_key",
    }

    @router.get("/settings/llm-keys", dependencies=[Depends(require_role("read"))])
    async def list_llm_keys() -> dict[str, Any]:
        """List configured LLM providers with masked keys."""
        from argus.config import get, mask_key

        providers = []
        for provider, config_key in _PROVIDER_CONFIG_MAP.items():
            val = get(config_key)
            entry: dict[str, Any] = {
                "provider": provider,
                "configured": val is not None and len(val) > 0,
                "masked_key": mask_key(val) if val else None,
            }
            if provider == "custom":
                ep = get("custom_endpoint")
                entry["endpoint"] = ep
            providers.append(entry)
        return {"providers": providers}

    @router.post("/settings/llm-keys", dependencies=[Depends(require_role("admin"))])
    async def set_llm_key(body: LLMKeySet) -> dict[str, Any]:
        """Save an LLM API key to the persistent config."""
        from argus.config import _read_config, _write_config, mask_key

        config_key = _PROVIDER_CONFIG_MAP.get(body.provider)
        if not config_key:
            raise HTTPException(status_code=400, detail="Unknown provider")
        # Validate endpoint BEFORE persisting anything to avoid inconsistent state
        if body.provider == "custom" and body.endpoint:
            try:
                _validate_target_endpoint(body.endpoint)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        # Atomic write: read once, apply all changes, write once
        # Route API keys to [keys] section to match set_value() convention
        data = _read_config()
        data.setdefault("keys", {})[config_key] = body.api_key
        if body.provider == "custom" and body.endpoint:
            data["custom_endpoint"] = body.endpoint
        _write_config(data)
        return {
            "status": "saved",
            "provider": body.provider,
            "masked_key": mask_key(body.api_key),
        }

    @router.delete("/settings/llm-keys/{provider}", dependencies=[Depends(require_role("admin"))])
    async def delete_llm_key(provider: str) -> dict[str, Any]:
        """Remove an LLM API key from the persistent config."""
        from argus.config import _read_config, _write_config

        config_key = _PROVIDER_CONFIG_MAP.get(provider)
        if not config_key:
            raise HTTPException(status_code=400, detail="Unknown provider")
        # Atomic delete: read once, remove all related keys, write once
        data = _read_config()
        changed = False
        keys_section = data.get("keys", {})
        if config_key in keys_section:
            del keys_section[config_key]
            changed = True
        if provider == "custom" and "custom_endpoint" in data:
            del data["custom_endpoint"]
            changed = True
        if changed:
            _write_config(data)
        return {"status": "deleted" if changed else "not_found", "provider": provider}

    @router.post("/settings/llm-keys/{provider}/test", dependencies=[Depends(require_role("admin"))])
    async def test_llm_key(provider: str) -> dict[str, Any]:
        """Test an LLM API key by making a minimal API call."""
        import httpx

        from argus.config import get

        config_key = _PROVIDER_CONFIG_MAP.get(provider)
        if not config_key:
            raise HTTPException(status_code=400, detail="Unknown provider")
        key = get(config_key)
        if not key:
            return {"status": "error", "message": "No key configured for this provider"}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                if provider == "anthropic":
                    r = await client.post(
                        "https://api.anthropic.com/v1/messages",
                        headers={
                            "x-api-key": key,
                            "anthropic-version": "2023-06-01",
                            "content-type": "application/json",
                        },
                        json={
                            "model": "claude-sonnet-4-20250514",
                            "max_tokens": 1,
                            "messages": [{"role": "user", "content": "hi"}],
                        },
                    )
                    if r.status_code in (200, 201):
                        return {"status": "ok", "message": "Anthropic API key is valid"}
                    return {"status": "error", "message": f"Anthropic returned {r.status_code}"}
                elif provider == "openai":
                    r = await client.get(
                        "https://api.openai.com/v1/models",
                        headers={"Authorization": f"Bearer {key}"},
                    )
                    if r.status_code == 200:
                        return {"status": "ok", "message": "OpenAI API key is valid"}
                    return {"status": "error", "message": f"OpenAI returned {r.status_code}"}
                elif provider == "google":
                    r = await client.get(
                        "https://generativelanguage.googleapis.com/v1beta/models",
                        params={"key": key},
                    )
                    if r.status_code == 200:
                        return {"status": "ok", "message": "Google API key is valid"}
                    return {"status": "error", "message": f"Google returned {r.status_code}"}
                elif provider == "custom":
                    endpoint = get("custom_endpoint")
                    if not endpoint:
                        return {"status": "error", "message": "No custom endpoint configured"}
                    _validate_target_endpoint(endpoint)
                    r = await client.get(
                        endpoint.rstrip("/") + "/models",
                        headers={"Authorization": f"Bearer {key}"},
                    )
                    return {
                        "status": "ok" if r.status_code == 200 else "error",
                        "message": f"Endpoint returned {r.status_code}",
                    }
                else:
                    return {"status": "error", "message": "Unknown provider"}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            return {"status": "error", "message": str(type(exc).__name__) + ": " + str(exc)[:200]}

    return router
