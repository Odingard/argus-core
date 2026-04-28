"""
argus/r2r/pipeline.py — Recon-to-Ready (R2R) Pipeline.

Layer 0. Runs before any agent fires.

Flow:
  resolve() → target context (repos, pid, ports, env)
  ↓
  enumerate tools via adapter
  ↓
  if hung/empty → LLM debugger → identify init tool
  ↓
  TIP auto-call → target ready
  ↓
  save "Requirement Signature" → cross-pollination
  ↓
  engagement proceeds autonomously
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from argus.r2r.target_resolver import TargetContext, resolve


@dataclass
class R2RResult:
    ctx:           TargetContext
    initialized:   bool
    init_tool:     str
    init_params:   dict
    surfaces_count: int
    debugger_used:  bool
    ready:          bool


async def run(target_url: str, adapter) -> R2RResult:
    """Full R2R pipeline. Call before engagement starts."""
    print("  [R2R] resolving target context...")

    # Step 1: Resolve local environment
    ctx = resolve(target_url)
    if ctx.working_dir:
        print(f"  [R2R] working_dir → {ctx.working_dir}")
    if ctx.process_pid:
        print(f"  [R2R] process PID {ctx.process_pid}"
              + (f" port {ctx.port}" if ctx.port else ""))

    # Step 2: Try enumeration with timeout
    surfaces = []
    tool_names = []
    try:
        surfaces = await asyncio.wait_for(adapter.enumerate(), timeout=8.0)
        tool_names = [
            s.name.split("tool:", 1)[1]
            for s in surfaces if s.name.startswith("tool:")
        ]
        print(f"  [R2R] enumerated {len(surfaces)} surfaces, "
              f"{len(tool_names)} tools")
    except asyncio.TimeoutError:
        print("  [R2R] enumeration hung (>8s) → LLM debugger activating")
    except Exception as e:
        print(f"  [R2R] enumeration error: {e}")

    # Step 3: If zero surfaces or timeout → LLM debugger
    debugger_used = False
    init_tool = ""
    init_params = {}
    initialized = False

    if len(surfaces) == 0:
        debugger_used = True
        from argus.r2r.llm_debugger import analyze

        # Collect stderr from adapter if available
        stderr = ""
        try:
            import glob
            import os
            files = glob.glob("/var/folders/**/*.argus_stderr",
                              recursive=True)
            if files:
                newest = max(files, key=os.path.getmtime)
                stderr = open(newest).read()[-500:]
        except Exception:
            pass

        rec = analyze(
            tool_names=tool_names,
            readme=ctx.readme_text,
            agents_md=ctx.agents_md,
            stderr=stderr,
            env_vars=ctx.env_vars,
            working_dir=ctx.working_dir or "",
        )
        print(f"  [R2R] debugger: needs_init={rec.needs_init} "
              f"confidence={rec.confidence:.0%} → {rec.reasoning}")

        if rec.needs_init and rec.confidence >= 0.70 and rec.init_tool:
            # Use resolver's safe working_dir or create a fresh disposable repo
            target_dir = ctx.working_dir
            if not target_dir:
                from argus.engagement.target_init import _make_temp_git_repo
                target_dir = _make_temp_git_repo()
                print(f"  [R2R] no safe repo found — created disposable: {target_dir}")

            # Build params using the safe target_dir
            params = dict(rec.init_params)
            for key in list(params.keys()):
                if params[key] in ("", None, "/path/to/repo"):
                    params[key] = target_dir
            if not params:
                params = {"path": target_dir}

            try:
                from argus.adapter.base import Request
                req = Request(
                    surface=f"tool:{rec.init_tool}",
                    payload=params,
                )
                obs = await adapter.interact(req)
                response = str(obs.response.body or "")
                initialized = "error" not in response.lower()
                init_tool = rec.init_tool
                init_params = params
                print(f"  [R2R] called {rec.init_tool!r} → "
                      f"{'ready' if initialized else 'failed'}")
                if initialized:
                    # Re-enumerate now that target is initialized
                    surfaces = await asyncio.wait_for(
                        adapter.enumerate(), timeout=10.0
                    )
                    print(f"  [R2R] post-init: {len(surfaces)} surfaces")
            except Exception as e:
                print(f"  [R2R] init call failed: {e}")

    # Step 4: Save requirement signature
    if initialized and init_tool:
        _save_requirement_signature(target_url, init_tool, init_params)

    return R2RResult(
        ctx=ctx,
        initialized=initialized,
        init_tool=init_tool,
        init_params=init_params,
        surfaces_count=len(surfaces),
        debugger_used=debugger_used,
        ready=(len(surfaces) > 0),
    )


def _save_requirement_signature(
    target_url: str, init_tool: str, init_params: dict
) -> None:
    """Persist what initialization this target class needs.
    Next run: TIP checks here first, no LLM call needed."""
    try:
        from pathlib import Path
        import json

        sig_path = (Path.home() / ".argus" / "evolve"
                    / "requirement_signatures.json")
        sig_path.parent.mkdir(parents=True, exist_ok=True)
        sigs = json.loads(sig_path.read_text()) if sig_path.exists() else {}

        # Key by package name
        name = target_url.split("/")[-1].split("@")[0].strip()
        sigs[name] = {
            "init_tool":   init_tool,
            "param_keys":  list(init_params.keys()),
            "param_types": {k: "git_repo" if "dir" in k or "path" in k
                            else "string" for k in init_params},
        }
        sig_path.write_text(json.dumps(sigs, indent=2))
        print(f"  [R2R] requirement signature saved for {name!r}")
    except Exception:
        pass
