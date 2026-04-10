"""Production API routes for ARGUS.

Adds target management, scan history, auth management, and report
generation endpoints on top of the existing scan/status endpoints.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from argus.db.repository import APIKeyRepository, ScanRepository, TargetRepository
from argus.db.session import init_db
from argus.web.auth import AuthContext, require_role

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Request/response schemas
# ---------------------------------------------------------------------------


class TargetCreate(BaseModel):
    name: str = Field(..., max_length=200)
    description: str = ""
    environment: str = "staging"
    mcp_server_urls: list[str] = []
    agent_endpoint: str | None = None
    non_destructive: bool = True
    max_requests_per_minute: int = 60
    client_name: str = ""
    client_contact: str = ""
    notes: str = ""


class TargetUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    environment: str | None = None
    mcp_server_urls: list[str] | None = None
    agent_endpoint: str | None = None
    non_destructive: bool | None = None
    max_requests_per_minute: int | None = None
    client_name: str | None = None
    client_contact: str | None = None
    notes: str | None = None


class APIKeyCreate(BaseModel):
    name: str = Field(..., max_length=200)
    role: str = Field(default="viewer", pattern="^(admin|operator|viewer)$")


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
            updates = {k: v for k, v in body.model_dump().items() if v is not None}
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

    return router
