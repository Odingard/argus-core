"""
argus/platform/lifecycle.py — Process registry + graceful shutdown.

Every spawned process registers here. On SIGTERM/SIGINT/atexit the
registry kills everything cleanly so no orphans survive across runs.
"""
from __future__ import annotations

import atexit
import signal
import subprocess
import threading


class _ProcessRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._procs: dict[int, subprocess.Popen] = {}
        self._registered = False

    def register(self, proc: subprocess.Popen) -> None:
        with self._lock:
            self._procs[proc.pid] = proc
        self._ensure_handlers()

    def unregister(self, pid: int) -> None:
        with self._lock:
            self._procs.pop(pid, None)

    def kill_all(self, *, timeout: int = 5) -> None:
        with self._lock:
            procs = list(self._procs.values())
            self._procs.clear()
        for p in procs:
            try:
                if p.poll() is None:
                    p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=timeout)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    def _ensure_handlers(self) -> None:
        if self._registered:
            return
        self._registered = True
        atexit.register(self.kill_all)
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                old = signal.getsignal(sig)
                def _h(n, f, _o=old, _r=self):
                    _r.kill_all()
                    cleanup_docker()
                    if callable(_o):
                        _o(n, f)
                signal.signal(sig, _h)
            except (OSError, ValueError):
                pass


def cleanup_docker(label: str = "mcp-sandbox=true") -> int:
    """Remove all ARGUS sandbox containers. Non-fatal."""
    try:
        r = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"label={label}"],
            capture_output=True, text=True, timeout=10,
        )
        ids = [i for i in r.stdout.strip().split() if i]
        if not ids:
            return 0
        subprocess.run(["docker", "rm", "-f"] + ids,
                       capture_output=True, timeout=30)
        return len(ids)
    except Exception:
        return 0


def pre_engagement_cleanup() -> dict:
    """Call at the start of every engagement."""
    removed = cleanup_docker()
    return {"stale_containers_removed": removed}


_REGISTRY = _ProcessRegistry()


def register_process(proc: subprocess.Popen) -> None:
    _REGISTRY.register(proc)


def unregister_process(pid: int) -> None:
    _REGISTRY.unregister(pid)


def shutdown() -> None:
    _REGISTRY.kill_all()
    cleanup_docker()
