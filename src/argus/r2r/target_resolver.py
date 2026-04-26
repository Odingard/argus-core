"""
argus/r2r/target_resolver.py — Semantic target resolution.

Input:  "git-mcp" or "npx://-y @cyanheads/git-mcp-server@2.1.4"
Output: TargetContext with everything ARGUS needs to engage

Harvests from the local environment:
  - Running processes (lsof, ps)
  - .git directories on disk
  - Environment variables (GIT_DIR, WORKSPACE, etc.)
  - Open file handles of the target process
  - Port bindings of the target process

Never asks the operator. Figures it out.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class TargetContext:
    target_url:   str
    git_repos:    list[str] = field(default_factory=list)   # local .git dirs
    working_dir:  Optional[str] = None                      # best repo pick
    env_vars:     dict[str, str] = field(default_factory=dict)
    open_files:   list[str] = field(default_factory=list)
    process_pid:  Optional[int] = None
    port:         Optional[int] = None
    readme_text:  str = ""
    agents_md:    str = ""
    init_hints:   list[str] = field(default_factory=list)   # TIP tool names


def _find_git_repos(search_roots: Optional[list[str]] = None,
                    max_depth: int = 5) -> list[str]:
    """Find .git directories under search roots."""
    roots = search_roots or [str(Path.home() / "dev"),
                              str(Path.home() / "prod"),
                              str(Path.home() / "projects"),
                              str(Path.home() / "src")]
    found = []
    for root in roots:
        if not os.path.exists(root):
            continue
        try:
            r = subprocess.run(
                ["find", root, "-name", ".git", "-type", "d",
                 "-maxdepth", str(max_depth)],
                capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.strip().splitlines():
                repo = str(Path(line).parent)
                if repo not in found:
                    found.append(repo)
        except Exception:
            pass
    return found


def _lsof_pid(pid: int) -> list[str]:
    """Get open files/dirs for a process via lsof."""
    try:
        r = subprocess.run(
            ["lsof", "-p", str(pid)],
            capture_output=True, text=True, timeout=5,
        )
        paths = []
        for line in r.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 9:
                path = parts[-1]
                if path.startswith("/") and not path.startswith("/dev"):
                    paths.append(path)
        return list(dict.fromkeys(paths))  # deduplicate, preserve order
    except Exception:
        return []


def _find_process(name_fragment: str) -> Optional[int]:
    """Find PID of a running process matching a name fragment."""
    try:
        r = subprocess.run(
            ["pgrep", "-f", name_fragment],
            capture_output=True, text=True, timeout=3,
        )
        pids = r.stdout.strip().splitlines()
        if pids:
            return int(pids[0])
    except Exception:
        pass
    return None


def _extract_port(pid: int) -> Optional[int]:
    """Find port a process is listening on."""
    try:
        r = subprocess.run(
            ["lsof", "-p", str(pid), "-i", "TCP", "-s", "TCP:LISTEN"],
            capture_output=True, text=True, timeout=3,
        )
        for line in r.stdout.splitlines():
            if "LISTEN" in line:
                # Format: proc PID ... TCP *:PORT (LISTEN)
                parts = line.split()
                for p in parts:
                    if ":" in p and p.split(":")[-1].isdigit():
                        return int(p.split(":")[-1])
    except Exception:
        pass
    return None


def _read_capability_files(repo_path: str) -> tuple[str, str]:
    """Read AGENTS.md, CLAUDE.md, README*, raptor.config from repo."""
    readme = ""
    agents = ""
    p = Path(repo_path)
    for name in ("AGENTS.md", "CLAUDE.md", "raptor.config", ".argus.json"):
        f = p / name
        if f.exists():
            try:
                agents += f"\n### {name}\n" + f.read_text(errors="replace")[:2000]
            except Exception:
                pass
    for pattern in ("README.md", "README.txt", "README"):
        f = p / pattern
        if f.exists():
            try:
                readme = f.read_text(errors="replace")[:3000]
                break
            except Exception:
                pass
    return readme, agents


def _best_repo(repos: list[str], target_name: str) -> Optional[str]:
    """Pick the most relevant repo for the target.

    SECURITY RULE: Never return a repo that looks like active development
    work (ARGUS itself, cerberus, OdinForge, etc.) — pointing a git
    injection attack at your own codebase is dangerous.

    If no safe match exists, return None and let TIP create a disposable
    temp repo instead.
    """
    name = target_name.lower().replace("-", "").replace("_", "")

    # Protected repos — never use these as attack targets
    _PROTECTED = {
        "argus", "cerberus", "odinforge", "odinforgeai", "nemesis",
        "wraith", "aegisprime", "alec", "verdictweight", "atlas"
    }

    safe_repos = [
        r for r in repos
        if Path(r).name.lower().replace("-", "").replace("_", "")
        not in _PROTECTED
    ]

    # Name match against safe repos only
    for repo in safe_repos:
        rname = Path(repo).name.lower().replace("-", "").replace("_", "")
        if name in rname or rname in name:
            return repo

    # Check for explicit argus-targets directory (safe sandbox repos)
    for repo in repos:
        if "argus-targets" in repo:
            return repo

    # No safe match — return None, TIP will create a temp repo
    return None


def resolve(target_url: str) -> TargetContext:
    """Full autonomous target resolution. No operator input needed."""
    ctx = TargetContext(target_url=target_url)

    # 1. Extract a name fragment from the URL
    name = target_url.split("/")[-1].split("@")[0].replace("npx://-y", "").strip()
    name = name.lstrip("-y").strip()

    # 2. Find running process
    ctx.process_pid = _find_process(name)
    if ctx.process_pid:
        ctx.open_files = _lsof_pid(ctx.process_pid)
        ctx.port = _extract_port(ctx.process_pid)
        # If process has open dirs — use them as repo candidates
        for f in ctx.open_files:
            p = Path(f)
            if (p / ".git").exists():
                ctx.git_repos.append(str(p))

    # 3. Harvest .git repos from filesystem
    if not ctx.git_repos:
        ctx.git_repos = _find_git_repos()

    # 4. Pick the best repo for this target
    ctx.working_dir = _best_repo(ctx.git_repos, name)

    # 5. Read capability files from best repo
    if ctx.working_dir:
        ctx.readme_text, ctx.agents_md = _read_capability_files(ctx.working_dir)

    # 6. Collect relevant environment variables
    env_keys = ("GIT_DIR", "GIT_WORK_TREE", "WORKSPACE", "HOME",
                "PWD", "REPO_PATH", "PROJECT_DIR")
    ctx.env_vars = {k: os.environ[k] for k in env_keys if k in os.environ}

    return ctx
