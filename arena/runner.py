"""Arena runner — starts all 12 scenarios in a single process.

Usage::

    python -m arena.runner           # all 12 on ports 9001-9012
    python -m arena.runner --only 1  # just scenario 01
    python -m arena.runner --only 1,3,5  # specific scenarios

Each scenario runs in its own thread via uvicorn.
"""

from __future__ import annotations

import argparse
import sys
import threading
import time

import uvicorn

from arena import SCENARIO_PORTS

# Lazy import map — avoids importing every scenario at module level.
_SCENARIO_MODULE_MAP: dict[str, tuple[str, str]] = {
    "arena-01-prompt-leak": ("arena.scenarios.arena_01_prompt_leak", "create_app"),
    "arena-02-tool-poison": ("arena.scenarios.arena_02_tool_poison", "create_app"),
    "arena-03-supply-chain": ("arena.scenarios.arena_03_supply_chain", "create_app"),
    "arena-04-memory-poison": ("arena.scenarios.arena_04_memory_poison", "create_app"),
    "arena-05-identity-spoof": ("arena.scenarios.arena_05_identity_spoof", "create_app"),
    "arena-06-context-window": ("arena.scenarios.arena_06_context_window", "create_app"),
    "arena-07-exfil-relay": ("arena.scenarios.arena_07_exfil_relay", "create_app"),
    "arena-08-priv-escalation": ("arena.scenarios.arena_08_priv_escalation", "create_app"),
    "arena-09-race-condition": ("arena.scenarios.arena_09_race_condition", "create_app"),
    "arena-10-model-extraction": ("arena.scenarios.arena_10_model_extraction", "create_app"),
    "arena-11-persona-hijack": ("arena.scenarios.arena_11_persona_hijack", "create_app"),
    "arena-12-memory-boundary": ("arena.scenarios.arena_12_memory_boundary", "create_app"),
}


def _run_scenario(scenario_id: str, port: int, host: str = "0.0.0.0") -> None:
    """Run a single scenario in the current thread."""
    module_path, factory_name = _SCENARIO_MODULE_MAP[scenario_id]
    uvicorn.run(
        f"{module_path}:{factory_name}",
        host=host,
        port=port,
        log_level="warning",
        factory=True,
    )


def start_all(only: list[int] | None = None, host: str = "0.0.0.0") -> list[threading.Thread]:
    """Start scenarios as daemon threads.  Returns list of threads."""
    threads: list[threading.Thread] = []
    for scenario_id, port in SCENARIO_PORTS.items():
        num = int(scenario_id.split("-")[1])
        if only and num not in only:
            continue
        t = threading.Thread(
            target=_run_scenario,
            args=(scenario_id, port, host),
            name=f"arena-{num:02d}",
            daemon=True,
        )
        t.start()
        threads.append(t)
        print(f"  [{scenario_id}] started on port {port}")
    return threads


def main() -> None:
    parser = argparse.ArgumentParser(description="ARGUS Arena — run all 12 vulnerable AI targets")
    parser.add_argument("--only", type=str, default=None, help="Comma-separated scenario numbers (e.g. 1,3,5)")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    args = parser.parse_args()

    only = [int(x.strip()) for x in args.only.split(",")] if args.only else None

    print("\n  ╔════════════════════════════════════════╗")
    print("  ║       ARGUS Arena — 12 Targets         ║")
    print("  ║  Intentionally Vulnerable AI Agents     ║")
    print("  ║  DO NOT EXPOSE TO THE INTERNET          ║")
    print("  ╚════════════════════════════════════════╝\n")

    threads = start_all(only=only, host=args.host)
    count = len(threads)
    print(f"\n  {count} scenario(s) running.  Press Ctrl+C to stop.\n")

    # Wait for Ctrl+C
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  Shutting down Arena...")
        sys.exit(0)


if __name__ == "__main__":
    main()
