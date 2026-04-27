"""Legacy sequential vs SwarmProbeEngine benchmark.

Same probe_fn, same techniques, same surfaces — different orchestration.
This produces the side-by-side numbers that go in the sales deck and the
v0.5.0 release notes.

Usage:
    python -m benchmark.swarm_vs_legacy --simulated --trials 5

Real-target mode (live MCP servers) wires into the ARGUS engagement runner
on Day 3 — same orchestration, swap make_simulated_probe for the live agent
probe callable.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import statistics
import time
from dataclasses import asdict, dataclass
from itertools import product

from argus.swarm import (
    ProbeResult,
    ProbeStatus,
    Surface,
    SwarmConfig,
    SwarmProbeEngine,
    Technique,
    TunerConfig,
)


@dataclass
class BenchResult:
    label: str
    submitted: int
    requests_made: int
    confirmed: int
    elapsed_s: float
    requests_per_second: float

    def as_row(self) -> dict:
        return asdict(self)


def make_simulated_universe() -> tuple[list[Technique], list[Surface]]:
    """Mimics node-code-sandbox-mcp@1.2.0: 24 tools × ~130 payload variants."""
    techniques = [
        Technique(id=f"EP-T12.{i:03d}", family="shell-injection")
        for i in range(130)
    ]
    surfaces = [
        Surface(id=f"tool-{i:02d}", target="node-code-sandbox-mcp", transport="stdio")
        for i in range(24)
    ]
    return techniques, surfaces


def make_simulated_probe(confirm_at: tuple[str, str], rng_seed: int = 0):
    """A probe that confirms exactly once (technique, surface) — mimics a real CVE."""
    rng = random.Random(rng_seed)
    request_counter = {"n": 0}

    async def probe(t: Technique, s: Surface) -> ProbeResult:
        request_counter["n"] += 1
        await asyncio.sleep(rng.uniform(0.05, 0.15))
        is_target = (t.id, s.id) == confirm_at
        return ProbeResult(
            technique_id=t.id,
            surface_id=s.id,
            status=ProbeStatus.CONFIRMED if is_target else ProbeStatus.NEGATIVE,
            confirmed=is_target,
            response="exec output: uid=0(root)" if is_target else None,
        )

    probe.request_counter = request_counter  # type: ignore[attr-defined]
    return probe


# ----------------------------------------------------------------- legacy path
async def run_legacy(probe_fn, techniques, surfaces) -> BenchResult:
    submitted = len(techniques) * len(surfaces)
    confirmed = 0
    start = time.monotonic()
    for technique, surface in product(techniques, surfaces):
        result = await probe_fn(technique, surface)
        if result.confirmed:
            confirmed += 1
    elapsed = time.monotonic() - start
    requests = probe_fn.request_counter["n"]
    return BenchResult(
        label="legacy-sequential",
        submitted=submitted,
        requests_made=requests,
        confirmed=confirmed,
        elapsed_s=elapsed,
        requests_per_second=requests / elapsed if elapsed > 0 else 0,
    )


# ------------------------------------------------------------------ swarm path
async def run_swarm(probe_fn, techniques, surfaces) -> BenchResult:
    submitted = len(techniques) * len(surfaces)
    config = SwarmConfig(
        tuner=TunerConfig(initial=50, target_p95_ms=300, sample_window=20),
        stop_on_first_confirm=True,
    )
    engine = SwarmProbeEngine(probe_fn=probe_fn, config=config)
    confirmed = 0
    start = time.monotonic()
    async for r in engine.run(techniques, surfaces):
        if r.confirmed:
            confirmed += 1
    elapsed = time.monotonic() - start
    requests = probe_fn.request_counter["n"]
    return BenchResult(
        label="swarm-parallel",
        submitted=submitted,
        requests_made=requests,
        confirmed=confirmed,
        elapsed_s=elapsed,
        requests_per_second=requests / elapsed if elapsed > 0 else 0,
    )


# --------------------------------------------------------------------- driver
async def bench_simulated(trials: int = 5) -> dict:
    techniques, surfaces = make_simulated_universe()
    pairs = list(product(techniques, surfaces))

    legacy_runs: list[BenchResult] = []
    swarm_runs: list[BenchResult] = []

    for trial in range(trials):
        # Place the confirmation roughly halfway through legacy iteration order
        # so neither orchestration gets a free lunch.
        target = pairs[len(pairs) // 2 + trial * 7]
        confirm_at = (target[0].id, target[1].id)

        legacy_runs.append(await run_legacy(
            make_simulated_probe(confirm_at, rng_seed=trial),
            techniques, surfaces,
        ))
        swarm_runs.append(await run_swarm(
            make_simulated_probe(confirm_at, rng_seed=trial),
            techniques, surfaces,
        ))

    def summarize(runs: list[BenchResult]) -> dict:
        return {
            "trials": len(runs),
            "elapsed_s_median": statistics.median(r.elapsed_s for r in runs),
            "elapsed_s_p95": sorted(r.elapsed_s for r in runs)[
                max(0, int(len(runs) * 0.95) - 1)
            ],
            "requests_median": statistics.median(r.requests_made for r in runs),
            "confirmed_total": sum(r.confirmed for r in runs),
        }

    legacy_summary = summarize(legacy_runs)
    swarm_summary = summarize(swarm_runs)

    return {
        "universe": {
            "techniques": len(techniques),
            "surfaces": len(surfaces),
            "max_pairs": len(pairs),
        },
        "legacy": legacy_summary,
        "swarm": swarm_summary,
        "speedup_x": legacy_summary["elapsed_s_median"] / swarm_summary["elapsed_s_median"],
        "request_reduction_x": legacy_summary["requests_median"] / max(
            1, swarm_summary["requests_median"]
        ),
        "raw": {
            "legacy": [r.as_row() for r in legacy_runs],
            "swarm": [r.as_row() for r in swarm_runs],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--simulated", action="store_true",
        help="Run offline simulation against synthetic probes.",
    )
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument(
        "--out", type=str,
        default="results/swarm_smoke/bench_swarm_vs_legacy.json",
    )
    args = parser.parse_args()

    if not args.simulated:
        raise SystemExit(
            "--simulated required for now. Real-target mode wires "
            "into the ARGUS engagement runner in Day 3."
        )

    result = asyncio.run(bench_simulated(trials=args.trials))
    import os
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)

    print("\nBenchmark — node-code-sandbox-mcp@1.2.0 simulation")
    print(f"  universe:      {result['universe']['max_pairs']:,} possible probes")
    print(f"  legacy median: {result['legacy']['elapsed_s_median']:6.2f}s, "
          f"{int(result['legacy']['requests_median']):,} requests")
    print(f"  swarm  median: {result['swarm']['elapsed_s_median']:6.2f}s, "
          f"{int(result['swarm']['requests_median']):,} requests")
    print(f"  speedup:       {result['speedup_x']:.1f}x")
    print(f"  req reduction: {result['request_reduction_x']:.1f}x")
    print(f"\nFull results written to {args.out}")


if __name__ == "__main__":
    main()
