"""
argus/engagement/smart.py — one-input dispatcher.

The product UX commitment: ``argus <anything>`` just works. This
module is the detection layer that turns any single input into one
of three actions:

    engage URL          — hand to the EngagementRunner
    render DIR          — render report.html over a prior engagement
    fail-fast MESSAGE   — tell the operator clearly why we can't run

Inputs we recognise (detected in this order):

  1. Known URL schemes (``mcp://``, ``stdio-mcp://``, ``http[s]://``,
     ``crewai://``, etc.) — pass through to the registry.
  2. Existing directory containing ``chain.json`` — render report.
  3. ``github.com/<owner>/<repo>`` — clone shallow, scan for a
     runnable MCP/agent command, wrap in stdio-mcp://.
  4. Raw npm package (``@scope/name`` or ``name`` with no slashes) —
     wrap in ``npx -y`` and engage over stdio-mcp://. npm is the
     dominant MCP ecosystem; for PyPI targets pass the explicit
     ``uvx <pkg>`` command instead.
  5. Local file or directory — Python → ``python <path>``, Node →
     ``node <path>``, requirements.txt / pyproject.toml → pip path.

This module is deliberately NOT magic. When it can't identify a
target, it fails loud with a suggestion — no silent wrong-adapter
dispatch.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from argus.engagement.registry import target_for_url


# ── Public API ─────────────────────────────────────────────────────────────

@dataclass
class Dispatch:
    """Result of smart-dispatching an input."""
    action:    str               # "engage" | "report" | "fail"
    target:    str = ""          # engage URL or report dir
    reason:    str = ""          # free-form note (shown to operator)
    command:   Optional[list[str]] = None    # stdio command if derived

    def ok(self) -> bool:
        return self.action in ("engage", "report")


def dispatch(raw: str, *, workdir: Optional[Path] = None) -> Dispatch:
    """
    Resolve ``raw`` into a Dispatch. ``workdir`` is the root for
    any cloned / cached artefacts (default: ``~/.argus/targets``).
    """
    if not raw or not raw.strip():
        return Dispatch(action="fail", reason="empty input")

    arg = raw.strip()
    workdir = workdir or Path.home() / ".argus" / "targets"
    workdir.mkdir(parents=True, exist_ok=True)

    # 1) Known scheme → pass through if registered. ``http(s)://``
    # is special: the registry has a generic HTTPAgentAdapter factory
    # for chat endpoints, but we first inspect the PATH to see if the
    # URL is actually an MCP endpoint in disguise (/sse → MCP SSE,
    # /mcp → Streamable HTTP via mcp-remote). For every other scheme
    # the registry wins.
    if "://" in arg:
        parsed = urlparse(arg)
        if parsed.scheme in ("http", "https"):
            return _dispatch_http(arg)
        if target_for_url(arg) is not None:
            return Dispatch(action="engage", target=arg,
                            reason=f"registered scheme '{parsed.scheme}://'")
        return Dispatch(action="fail",
                        reason=f"unrecognised URL scheme '{parsed.scheme}://'. "
                               f"Try one of: mcp:// stdio-mcp:// http:// "
                               f"crewai:// autogen:// langgraph:// "
                               f"llamaindex:// parlant:// hermes:// "
                               f"generic-agent://")

    # 2) Directory with chain.json → render report.
    if _is_engagement_dir(arg):
        return Dispatch(action="report", target=str(Path(arg).resolve()),
                        reason="engagement dir (chain.json present)")

    # 3) GitHub URL forms.
    if gh := _looks_like_github(arg):
        return _dispatch_github(gh, workdir=workdir)

    # 4) npm package name (dominant MCP ecosystem; PyPI targets take
    # the explicit `uvx <pkg>` form).
    if _looks_like_npm_package(arg):
        return _dispatch_npm(arg)

    # 5) Local path.
    p = Path(arg).expanduser()
    if p.exists():
        return _dispatch_local(p)

    return Dispatch(
        action="fail",
        reason=(
            f"could not identify '{arg}' as a URL, GitHub repo, "
            f"npm/pip package, or local path. Explicit schemes "
            f"(mcp://, stdio-mcp://, crewai://, ...) always work — "
            f"run `argus --list-targets` to see them all."
        ),
    )


# ── Scheme-specific dispatchers ────────────────────────────────────────────

def _dispatch_http(url: str) -> Dispatch:
    """HTTP URL with no explicit MCP hint. Probe the path for known
    MCP-style endpoints; fall back to the generic http:// factory."""
    parsed = urlparse(url)
    path = (parsed.path or "").lower()

    # Common MCP-handler routes expose SSE at /sse or /mcp/sse.
    if path.endswith("/sse") or "/mcp/sse" in path or "/sse/" in path:
        # Re-route under mcp:// so the SSE MCPAdapter handles it.
        return Dispatch(
            action="engage",
            target="mcp://" + url[len(parsed.scheme) + 3:],
            reason="HTTP URL ends in /sse — routed through MCPAdapter",
        )
    # Streamable HTTP endpoints commonly live at /mcp. Bridge them
    # through mcp-remote (stdio) because ARGUS' SSE client can't
    # speak Streamable HTTP natively.
    if path.endswith("/mcp") or path.endswith("/mcp/"):
        return Dispatch(
            action="engage",
            target=f"stdio-mcp://npx+-y+mcp-remote+{url}",
            reason=("HTTP URL ends in /mcp — bridged through "
                    "mcp-remote over stdio"),
            command=["npx", "-y", "mcp-remote", url],
        )
    # Neither — treat as a generic chat endpoint.
    return Dispatch(
        action="engage", target=url,
        reason="generic HTTP endpoint (HTTPAgentAdapter)",
    )


def _dispatch_github(repo: dict, *, workdir: Path) -> Dispatch:
    """Route GitHub URLs through the ``repo-git://`` AutoDeploy
    scheme. The autodeploy module handles cloning, framework
    detection, isolated-env install, subprocess launch, and
    deployment teardown — a superset of the local detect-launch-
    command shim this function used to implement.

    The operator sees a single verb:

        argus engage https://github.com/owner/repo

    …and gets the full deploy + attack flow end-to-end. White-box
    agentic-AI engagements (client hands us their repo) land
    without any pre-engagement setup on the operator's part.

    ``workdir`` parameter kept in the signature so existing
    callers don't break; autodeploy manages its own staging root
    under ``$TMPDIR/argus-staging/``.
    """
    del workdir
    clone_url = repo.get("clone_url") or repo.get("html_url") or ""
    if not clone_url:
        return Dispatch(
            action="fail",
            reason=(
                f"could not derive clone URL from GitHub repo spec: "
                f"{repo}"
            ),
        )
    return Dispatch(
        action="engage",
        target=f"repo-git://{clone_url}",
        reason=(
            f"github:{repo.get('owner', '?')}/{repo.get('name', '?')} "
            f"→ autodeploy (clone + detect framework + launch)"
        ),
    )


def _dispatch_npm(pkg: str) -> Dispatch:
    encoded = "+".join(["npx", "-y", pkg])
    return Dispatch(
        action="engage", target=f"stdio-mcp://{encoded}",
        reason=f"npm package → npx -y {pkg}",
        command=["npx", "-y", pkg],
    )


def _dispatch_local(p: Path) -> Dispatch:
    """Local file / dir. Extension + shebang decide the launcher."""
    if p.is_dir():
        # A prior engagement directory is caught earlier; here the
        # directory might be a repo with a launchable server.
        detected = _detect_launch_command(p)
        if detected is None:
            return Dispatch(
                action="fail",
                reason=(f"local dir {p} has no recognisable MCP server "
                        f"entry. Pass the launch command directly: "
                        f"`argus mcp <cmd> <args...>`."),
            )
        encoded = "+".join(detected).replace(" ", "+")
        return Dispatch(
            action="engage", target=f"stdio-mcp://{encoded}",
            reason=f"local dir → detected launch: {' '.join(detected)}",
            command=detected,
        )

    # File.
    if p.suffix == ".py":
        command = ["python", str(p)]
    elif p.suffix in (".js", ".mjs", ".ts"):
        command = ["node", str(p)] if p.suffix != ".ts" else \
                  ["npx", "-y", "tsx", str(p)]
    elif p.suffix in ("", ".sh"):
        # Executable? Launch directly; else try bash.
        command = [str(p)] if os.access(str(p), os.X_OK) else ["bash", str(p)]
    else:
        return Dispatch(
            action="fail",
            reason=f"don't know how to launch '{p}' (extension {p.suffix!r})",
        )
    encoded = "+".join(command).replace(" ", "+")
    return Dispatch(
        action="engage", target=f"stdio-mcp://{encoded}",
        reason=f"local file → {' '.join(command)}",
        command=command,
    )


# ── Detection helpers ─────────────────────────────────────────────────────

_NPM_PACKAGE_RE = re.compile(
    r"^(@[a-z0-9][a-z0-9\-_.]*/)?[a-z0-9][a-z0-9\-_.]*$",
    re.IGNORECASE,
)


def _looks_like_npm_package(arg: str) -> bool:
    # Must not contain path separators in a way that implies a local
    # file. Scoped packages (@scope/name) are npm-style.
    if arg.startswith("@") and "/" in arg and arg.count("/") == 1:
        return bool(_NPM_PACKAGE_RE.match(arg))
    if "/" in arg or os.sep in arg:
        return False
    return bool(_NPM_PACKAGE_RE.match(arg))


_GITHUB_RE = re.compile(
    r"^"
    r"(?:"
    r"  (?:https?://)?(?:www\.)?github\.com/"      # github.com/owner/repo
    r"|"
    r"  github:"                                   # github:owner/repo (npm shorthand)
    r")"
    r"(?P<owner>[\w\-.]+)/(?P<name>[\w\-.]+?)"
    r"(?:\.git)?/?$",
    re.IGNORECASE | re.VERBOSE,
)


def _looks_like_github(arg: str) -> Optional[dict]:
    m = _GITHUB_RE.match(arg)
    if m is None:
        return None
    owner = m.group("owner")
    name  = m.group("name")
    return {
        "owner":     owner,
        "name":      name,
        "clone_url": f"https://github.com/{owner}/{name}.git",
    }


def _is_engagement_dir(arg: str) -> bool:
    p = Path(arg).expanduser()
    return p.is_dir() and (p / "chain.json").is_file()


def _detect_launch_command(repo_dir: Path) -> Optional[list[str]]:
    """
    Inspect a cloned repo for a runnable MCP server. Returns the
    argv or None. Ordered by confidence.
    """
    # 1) MCP manifest file (the canonical Anthropic spec).
    manifest = repo_dir / "mcp.json"
    if manifest.is_file():
        try:
            m = json.loads(manifest.read_text(encoding="utf-8"))
            if isinstance(m, dict) and m.get("command"):
                return [m["command"]] + list(m.get("args") or [])
        except json.JSONDecodeError:
            pass

    # 2) package.json — only dispatch via npx if the package declares
    # a runnable ``bin`` entry. A package with no bin (e.g. library
    # adapters like vercel/mcp-handler or openai/agents) can't be
    # launched standalone — npx -y against it will fail at startup
    # because the library expects to be imported into a host app.
    pkg_json = repo_dir / "package.json"
    if pkg_json.is_file():
        try:
            pj = json.loads(pkg_json.read_text(encoding="utf-8"))
            name = pj.get("name") or ""
            bin_section = pj.get("bin")
            if isinstance(bin_section, dict) and bin_section:
                first_bin = next(iter(bin_section))
                return ["npx", "-y", name or first_bin]
            if isinstance(bin_section, str) and name:
                return ["npx", "-y", name]
            # No bin — it's a library/framework, not a server.
            # Let the other detectors try (README hint, entrypoint
            # file); if they all fail, the dispatcher emits a
            # helpful framework-vs-server message.
        except json.JSONDecodeError:
            pass

    # 3) pyproject.toml — prefer [project.scripts] entries that look
    # like MCP servers (ending -server / containing "mcp") over the
    # bare package name. mcp-zettel e.g. has package name `mcp-zettel`
    # but the server entry is `mcp-zettel-server`.
    pyproj = repo_dir / "pyproject.toml"
    if pyproj.is_file():
        entry = _pick_pyproject_entry(pyproj)
        if entry is not None:
            return ["uvx", entry]

    # 4) README hint — first `npx`/`uvx`/`pipx` command in a fenced
    # code block.
    for name in ("README.md", "README.rst", "README.txt", "README"):
        readme = repo_dir / name
        if not readme.is_file():
            continue
        try:
            text = readme.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hint = _first_launch_hint(text)
        if hint is not None:
            return hint

    # 5) Entrypoint file (heuristic).
    for candidate in ("server.py", "main.py", "index.js", "src/server.py"):
        p = repo_dir / candidate
        if p.is_file():
            if candidate.endswith(".py"):
                return ["python", str(p)]
            return ["node", str(p)]

    return None


def _pick_pyproject_entry(pyproj: Path) -> Optional[str]:
    """Pick a runnable entry from a pyproject.toml. Prefer scripts
    that look like MCP servers; fall back to the package name.

    Returns None if the manifest doesn't advertise anything
    runnable that we can reasonably launch."""
    text = pyproj.read_text(encoding="utf-8", errors="replace")

    # Extract [project.scripts] block — tolerant to whitespace /
    # comments; we only need the LHS names.
    scripts_block = re.search(
        r"\[project\.scripts\]\s*\n"
        r"(?P<body>(?:[^\[]|\n)*?)"
        r"(?=\n\[|\Z)",
        text,
    )
    scripts: list[str] = []
    if scripts_block:
        for line in scripts_block.group("body").splitlines():
            m = re.match(r'^\s*([A-Za-z0-9_\-.]+)\s*=', line)
            if m:
                scripts.append(m.group(1))

    # Rank: explicit "*-server" > contains "server" > contains "mcp"
    # > first script > None.
    def _rank(name: str) -> int:
        low = name.lower()
        if low.endswith("-server") or low.endswith("_server"):
            return 0
        if "server" in low:
            return 1
        if "mcp" in low:
            return 2
        return 3

    if scripts:
        scripts.sort(key=_rank)
        # Only return a script if the best candidate looks like a
        # server — otherwise the package is a CLI or library, not an
        # MCP server, and we should let later detectors decide.
        if _rank(scripts[0]) <= 2:
            return scripts[0]

    # Fallback: package name heuristic (legacy behaviour).
    m = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if m:
        name = m.group(1)
        if "mcp" in name.lower() or "server" in name.lower():
            return name

    return None


_HINT_RE = re.compile(
    r"```(?:[a-z]*\n)?"
    r"((?:npx|uvx|pipx|python|node)\s+[^\n]+)\n",
    re.IGNORECASE,
)


def _framework_hint(repo_dir: Path) -> str:
    """Recognise common framework/library patterns and return a
    human-readable hint explaining why the target can't be launched
    standalone. Empty string when the repo isn't a known framework."""
    pkg_json = repo_dir / "package.json"
    if pkg_json.is_file():
        try:
            pj = json.loads(pkg_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return ""
        peer = pj.get("peerDependencies") or {}
        name = (pj.get("name") or "").lower()
        bin_section = pj.get("bin")
        has_bin = bool(bin_section)

        # Framework adapters declare peer deps on the host framework.
        host_peers = set(peer) & {
            "next", "nuxt", "@nestjs/core", "express", "fastify",
            "@sveltejs/kit", "react", "vue",
        }
        if host_peers and not has_bin:
            hosts = ", ".join(sorted(host_peers))
            return (f" This looks like a FRAMEWORK ADAPTER — it's "
                    f"imported into a host app ({hosts}), not run "
                    f"standalone.")

        # Name contains handler/adapter/sdk/client/lib → library shape.
        if not has_bin and any(s in name for s in (
            "handler", "adapter", "sdk", "-client", "-lib",
        )):
            return (" This looks like a LIBRARY (no bin entry in "
                    "package.json) — ARGUS can't launch it as a "
                    "standalone MCP server.")

    pyproj = repo_dir / "pyproject.toml"
    if pyproj.is_file():
        text = pyproj.read_text(encoding="utf-8", errors="replace")
        if "[project.scripts]" not in text and "entry_points" not in text:
            return (" This Python project declares no console scripts "
                    "or entry points — ARGUS can't launch it as a "
                    "standalone MCP server.")
    return ""


def _first_launch_hint(readme: str) -> Optional[list[str]]:
    for m in _HINT_RE.finditer(readme):
        line = m.group(1).strip().strip("`")
        # Filter out unrelated lines — must mention mcp OR run a
        # server-shaped binary.
        low = line.lower()
        if "mcp" in low or "server" in low:
            # Split respecting simple quoting.
            parts = [p for p in re.split(r"\s+", line) if p]
            return parts
    return None


# ── CLI integration helper ────────────────────────────────────────────────

def describe(d: Dispatch) -> str:
    """One-line summary for the CLI banner."""
    if d.action == "engage":
        return f"→ engage {d.target}\n   ({d.reason})"
    if d.action == "report":
        return f"→ render report from {d.target}\n   ({d.reason})"
    return f"✗ {d.reason}"
