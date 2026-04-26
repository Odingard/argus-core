"""
argus/platform/event_loop.py — Thread-isolated event loop runner.

Permanent fix for anyio cancel scope + Python 3.14 incompatibility.

Root cause:
  anyio's stdio_client() uses create_task_group() which creates a cancel
  scope tied to the running asyncio Task at __enter__ time. Python 3.14
  changed task identity tracking — when asyncio.run() creates a new loop
  inside a ThreadPoolExecutor worker, the cancel scope's owner task check
  fails on __exit__ with:
    RuntimeError: Attempted to exit cancel scope in a different task

Fix:
  Each agent's coroutine runs in a completely isolated event loop that is
  set as the thread-local current event loop BEFORE anyio creates any
  cancel scopes. This ensures the task that enters the scope is the same
  task that exits it — satisfying Python 3.14's stricter checks.

Usage:
  Replace all asyncio.run(coro) in _run_agent() with run_isolated(coro).
"""
from __future__ import annotations

import asyncio
import threading
from typing import Any, Coroutine, TypeVar

T = TypeVar("T")


def run_isolated(coro: Coroutine[Any, Any, T]) -> T:
    """Run a coroutine in a completely isolated event loop.

    Creates a fresh event loop, sets it as the running loop for this
    thread, runs the coroutine to completion, and cleans up. Safe to
    call from any thread including ThreadPoolExecutor workers.

    This is the permanent replacement for asyncio.run() in ARGUS agent
    dispatch — it prevents the anyio cancel scope Python 3.14 error.
    """
    loop = asyncio.new_event_loop()
    # Set as the event loop for this thread so anyio can find it.
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            # Cancel any remaining tasks before closing.
            pending = asyncio.all_tasks(loop)
            if pending:
                for task in pending:
                    task.cancel()
                loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )
        finally:
            loop.close()
            asyncio.set_event_loop(None)
