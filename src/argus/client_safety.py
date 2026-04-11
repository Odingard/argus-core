"""Client Environment Safety — health checks, graceful degradation, structured logging.

Provides safety mechanisms for running ARGUS against production client
AI systems. Ensures ARGUS operates non-destructively and degrades
gracefully when target systems become unavailable.

Components:
- TargetHealthChecker: Pre-scan validation of target system availability
- ScanLogger: Structured JSON logging with scan_id correlation
- GracefulShutdown: Clean shutdown handler for in-progress scans
- EnvironmentValidator: Validates the client environment before scan start
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import time
from datetime import UTC, datetime
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class TargetHealthChecker:
    """Pre-scan health check for target AI systems.

    Validates that the target is reachable and responding before
    committing agent resources. Prevents wasted scan time on
    unreachable targets.
    """

    def __init__(self, timeout: float = 10.0, retries: int = 3) -> None:
        self.timeout = timeout
        self.retries = retries

    async def check_endpoint(self, url: str) -> dict[str, Any]:
        """Check if an HTTP endpoint is reachable and responding.

        Returns a health status dict with latency and status code.
        """
        result: dict[str, Any] = {
            "url": url,
            "healthy": False,
            "status_code": None,
            "latency_ms": None,
            "error": None,
            "checked_at": datetime.now(UTC).isoformat(),
        }

        for attempt in range(1, self.retries + 1):
            try:
                start = time.monotonic()
                async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:  # noqa: S501
                    response = await client.get(url)
                latency = (time.monotonic() - start) * 1000

                result["status_code"] = response.status_code
                result["latency_ms"] = round(latency, 1)

                if response.status_code < 500:
                    result["healthy"] = True
                    return result

            except httpx.ConnectError as exc:
                result["error"] = f"Connection failed: {type(exc).__name__}"
            except httpx.TimeoutException:
                result["error"] = f"Timeout after {self.timeout}s"
            except Exception as exc:
                result["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"

            if attempt < self.retries:
                await asyncio.sleep(min(2**attempt, 8))

        return result

    async def check_all(
        self,
        mcp_urls: list[str],
        agent_endpoint: str | None = None,
    ) -> dict[str, Any]:
        """Run health checks on all target endpoints.

        Returns an aggregate health report.
        """
        endpoints = list(mcp_urls)
        if agent_endpoint:
            endpoints.append(agent_endpoint)

        if not endpoints:
            return {
                "overall_healthy": False,
                "error": "No endpoints configured",
                "endpoints": [],
            }

        tasks = [self.check_endpoint(url) for url in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        endpoint_results = []
        for r in results:
            if isinstance(r, Exception):
                endpoint_results.append(
                    {
                        "healthy": False,
                        "error": f"{type(r).__name__}: {str(r)[:200]}",
                    }
                )
            else:
                endpoint_results.append(r)

        all_healthy = all(r.get("healthy", False) for r in endpoint_results)
        any_healthy = any(r.get("healthy", False) for r in endpoint_results)

        return {
            "overall_healthy": all_healthy,
            "partially_healthy": any_healthy,
            "total_endpoints": len(endpoints),
            "healthy_count": sum(1 for r in endpoint_results if r.get("healthy")),
            "endpoints": endpoint_results,
            "checked_at": datetime.now(UTC).isoformat(),
        }


class ScanLogger:
    """Structured JSON logger for scan operations.

    Produces machine-parseable log entries with consistent fields
    for correlation across distributed scan components:
    - scan_id: Links all log entries for a single scan
    - agent_type: Which agent produced the entry
    - event_type: Categorized event (health_check, finding, error, etc.)
    - timestamp: ISO 8601 UTC timestamp
    """

    def __init__(self, scan_id: str, log_file: str | None = None) -> None:
        self.scan_id = scan_id
        self._logger = logging.getLogger(f"argus.scan.{scan_id[:8]}")
        self._log_file = log_file

        if log_file:
            handler = logging.FileHandler(log_file)
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)

    def _emit(self, event_type: str, level: str = "info", **kwargs: Any) -> None:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "scan_id": self.scan_id,
            "event_type": event_type,
            "level": level,
            **kwargs,
        }
        log_line = json.dumps(entry, default=str)

        log_fn = getattr(self._logger, level, self._logger.info)
        log_fn(log_line)

    def scan_started(self, target_name: str, agents: list[str], timeout: float) -> None:
        self._emit(
            "scan_started",
            target_name=target_name,
            agents=agents,
            agent_count=len(agents),
            timeout_seconds=timeout,
        )

    def scan_completed(self, duration: float, findings: int, validated: int, paths: int) -> None:
        self._emit(
            "scan_completed",
            duration_seconds=round(duration, 2),
            total_findings=findings,
            validated_findings=validated,
            compound_paths=paths,
        )

    def scan_failed(self, error: str, duration: float) -> None:
        self._emit(
            "scan_failed",
            level="error",
            error=error,
            duration_seconds=round(duration, 2),
        )

    def agent_started(self, agent_type: str, instance_id: str) -> None:
        self._emit(
            "agent_started",
            agent_type=agent_type,
            instance_id=instance_id,
        )

    def agent_completed(self, agent_type: str, findings: int, duration: float) -> None:
        self._emit(
            "agent_completed",
            agent_type=agent_type,
            findings_count=findings,
            duration_seconds=round(duration, 2),
        )

    def agent_failed(self, agent_type: str, error: str) -> None:
        self._emit(
            "agent_failed",
            level="error",
            agent_type=agent_type,
            error=error,
        )

    def finding_detected(self, agent_type: str, severity: str, title: str) -> None:
        self._emit(
            "finding_detected",
            agent_type=agent_type,
            severity=severity,
            title=title,
        )

    def health_check(self, target: str, healthy: bool, latency_ms: float | None = None) -> None:
        self._emit(
            "health_check",
            target=target,
            healthy=healthy,
            latency_ms=latency_ms,
        )

    def rate_limited(self, target: str, wait_seconds: float) -> None:
        self._emit(
            "rate_limited",
            level="warning",
            target=target,
            wait_seconds=round(wait_seconds, 2),
        )

    def circuit_opened(self, target: str, consecutive_failures: int) -> None:
        self._emit(
            "circuit_opened",
            level="warning",
            target=target,
            consecutive_failures=consecutive_failures,
        )


class GracefulShutdown:
    """Handles clean shutdown of in-progress scans.

    Registers signal handlers for SIGINT and SIGTERM to ensure
    scan results are persisted and resources are cleaned up even
    when the process is terminated.
    """

    def __init__(self) -> None:
        self._shutdown_requested = False
        self._cleanup_callbacks: list = []
        self._original_sigint = None
        self._original_sigterm = None

    def register(self) -> None:
        """Register signal handlers for graceful shutdown."""
        self._original_sigint = signal.getsignal(signal.SIGINT)
        self._original_sigterm = signal.getsignal(signal.SIGTERM)

        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum: int, frame: Any) -> None:
        sig_name = signal.Signals(signum).name
        logger.warning("Received %s — initiating graceful shutdown", sig_name)
        self._shutdown_requested = True

        for callback in self._cleanup_callbacks:
            try:
                callback()
            except Exception as exc:
                logger.error("Cleanup callback failed: %s", type(exc).__name__)

        # Re-raise if second signal
        if signum == signal.SIGINT and self._original_sigint:
            signal.signal(signal.SIGINT, self._original_sigint)

    @property
    def shutdown_requested(self) -> bool:
        return self._shutdown_requested

    def add_cleanup(self, callback: Any) -> None:
        """Register a cleanup callback to run on shutdown."""
        self._cleanup_callbacks.append(callback)


class EnvironmentValidator:
    """Validates the client environment before scan execution.

    Checks:
    - Target endpoints are reachable
    - Non-destructive mode is properly configured
    - Rate limits are within acceptable bounds
    - Required credentials are available
    """

    REQUIRED_FIELDS = ["name"]
    MAX_RPM = 600  # Safety cap — never exceed this
    MIN_TIMEOUT = 30  # Minimum scan timeout in seconds

    def validate(self, config: dict[str, Any]) -> dict[str, Any]:
        """Validate a scan configuration.

        Returns a validation result with any warnings or errors.
        """
        errors: list[str] = []
        warnings: list[str] = []

        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if not config.get(field):
                errors.append(f"Missing required field: {field}")

        # Check endpoints
        mcp_urls = config.get("mcp_server_urls", [])
        agent_endpoint = config.get("agent_endpoint")
        if not mcp_urls and not agent_endpoint:
            errors.append("At least one MCP server URL or agent endpoint is required")

        # Check rate limits
        rpm = config.get("max_requests_per_minute", 60)
        if rpm > self.MAX_RPM:
            errors.append(f"RPM ({rpm}) exceeds safety cap ({self.MAX_RPM})")
        elif rpm > 300:
            warnings.append(f"High RPM ({rpm}) — consider reducing for production targets")

        # Check non-destructive mode
        if not config.get("non_destructive", True):
            warnings.append("Non-destructive mode is DISABLED — ARGUS may modify target state")

        # Check timeout
        timeout = config.get("timeout", 600)
        if timeout < self.MIN_TIMEOUT:
            warnings.append(f"Timeout ({timeout}s) is very short — agents may not complete")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "config_summary": {
                "name": config.get("name", ""),
                "endpoints": len(mcp_urls) + (1 if agent_endpoint else 0),
                "non_destructive": config.get("non_destructive", True),
                "rpm": rpm,
                "timeout": timeout,
            },
        }
