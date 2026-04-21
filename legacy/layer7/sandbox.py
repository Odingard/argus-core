"""
layer7/sandbox.py
Execution Sandbox Module

Dynamically validates synthesized exploit chains against a live sandbox.
Prevents hallucinated exploits from reaching the final disclosure package.

Validation contract:
    A chain is marked validated ONLY when the PoC, when run inside an
    isolated container with the target code mounted read-only, produces
    observable evidence that the exploit landed. Exit code 0 alone is not
    sufficient — a benign `print()` also exits 0. We require one of:
      - stdout/stderr contains a recognised proof marker (OOB callback ID,
        sensitive-file content shape, RCE evidence), or
      - the PoC explicitly emits the line ``ARGUS_POC_LANDED:<chain_id>``.
    Everything else is reported as unvalidated with the observed output
    for human triage.
"""
import ast
import os
import re
import tempfile
import asyncio

from argus.shared.models import L5Chains, ExploitChain

VALIDATION_TIMEOUT_SECONDS = 15

# Evidence patterns that suggest a PoC actually touched the target.
# These are deliberately narrow — we would rather under-validate than
# falsely crown a print() statement as a "weaponised exploit".
_EVIDENCE_PATTERNS = [
    re.compile(r"ARGUS_POC_LANDED:\S+"),
    re.compile(r"root:[^:]*:0:0:"),                # /etc/passwd row
    re.compile(r"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY"),
    re.compile(r"AWS_SECRET_ACCESS_KEY\s*[:=]"),
    re.compile(r"sk-(?:ant-|proj-|svcacct-)[A-Za-z0-9_\-]{16,}"),
    re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+"),     # `id` output
]


def _has_evidence(output: str) -> bool:
    return any(p.search(output) for p in _EVIDENCE_PATTERNS)


def _target_packages(repo_path: str) -> list[str]:
    """
    Return the list of TOP-LEVEL installable Python packages that
    belong to the target repository. These are the names a PoC MUST
    import from to prove it actually exercises the shipping library.

    Resolution, in order:

      1. Walk UP from repo_path looking for a pyproject.toml /
         setup.py / setup.cfg. If found, extract the distribution
         name and use it as the package name (dash → underscore).
         This covers the common case where the user scopes a scan
         to a sub-directory (e.g. src/crewai/agents) — we still want
         to require imports from ``crewai`` not ``agents``.
      2. If the walk-up finds nothing, fall back to the name of the
         directory immediately containing the deepest ``__init__.py``
         at-or-above repo_path. This catches loose source trees.
      3. As an additional belt, if the package root has a ``src/``
         layout, include the names of top-level dirs under src/ that
         carry an __init__.py.

    Generic container names (src, lib, tests, test, docs, examples)
    are never returned — they would make the import gate useless.
    """
    from pathlib import Path as _P
    import re as _re
    candidates: set[str] = set()

    root = _P(repo_path).resolve()
    if not root.exists():
        return []

    # ── (1) Walk up for a packaging manifest ───────────────────────────
    manifest_dir: _P | None = None
    cur = root
    for _ in range(8):           # cap ascent to 8 levels
        for manifest in ("pyproject.toml", "setup.py", "setup.cfg"):
            if (cur / manifest).exists():
                manifest_dir = cur
                break
        if manifest_dir is not None:
            break
        if cur.parent == cur:
            break
        cur = cur.parent

    if manifest_dir is not None:
        # pyproject.toml — prefer [project].name / [tool.poetry].name
        pp = manifest_dir / "pyproject.toml"
        if pp.exists():
            try:
                text = pp.read_text(encoding="utf-8", errors="ignore")
                # Tolerant single-line name extraction that survives
                # without a TOML parser (pyproject specs differ and we
                # don't want to add tomllib handling here).
                for m in _re.finditer(r'(?mi)^\s*name\s*=\s*["\'`]([^"\'`]+)',
                                      text):
                    candidates.add(m.group(1).replace("-", "_").lower())
            except OSError:
                pass
        # setup.py — grep for name="..."
        sp = manifest_dir / "setup.py"
        if sp.exists():
            try:
                text = sp.read_text(encoding="utf-8", errors="ignore")
                for m in _re.finditer(r'name\s*=\s*["\']([^"\']+)', text):
                    candidates.add(m.group(1).replace("-", "_").lower())
            except OSError:
                pass
        # setup.cfg — grep for name = ...
        sc = manifest_dir / "setup.cfg"
        if sc.exists():
            try:
                text = sc.read_text(encoding="utf-8", errors="ignore")
                for m in _re.finditer(r'(?mi)^\s*name\s*=\s*([A-Za-z0-9_\-\.]+)',
                                      text):
                    candidates.add(m.group(1).replace("-", "_").lower())
            except OSError:
                pass

        # If manifest_dir has a src/ layout, add top-level src/<pkg>/
        src_dir = manifest_dir / "src"
        if src_dir.exists():
            for child in src_dir.iterdir():
                if (child.is_dir() and (child / "__init__.py").exists()):
                    candidates.add(child.name.lower())
        # Or a flat layout: manifest_dir/<pkg>/__init__.py
        for child in manifest_dir.iterdir():
            if (child.is_dir() and (child / "__init__.py").exists()):
                candidates.add(child.name.lower())

    # ── (2) Fallback: walk UP from repo_path to the deepest package root ──
    if not candidates:
        cur = root
        last_pkg: str = ""
        for _ in range(8):
            if (cur / "__init__.py").exists():
                last_pkg = cur.name.lower()
            elif last_pkg:
                break
            if cur.parent == cur:
                break
            cur = cur.parent
        if last_pkg:
            candidates.add(last_pkg)

    # Strip generic container names that would let anything pass.
    for generic in ("src", "lib", "tests", "test", "docs", "examples",
                    "__pycache__", ""):
        candidates.discard(generic)

    return sorted(candidates)


# Public alias — prompts in other layers call this at format time so
# Opus is told the real installed-package namespace to import from.
def target_packages(repo_path: str) -> list[str]:
    return _target_packages(repo_path)


def _poc_calls_target(poc_code: str, target_packages: list[str]) -> tuple[bool, str]:
    """
    AST-verify that the PoC doesn't just import the target, it actually
    USES a symbol it imported. Defeats PoCs of the shape:

        from crewai import X      # import present (passes import gate)
        if 'command' in s:        # but nothing ever touches X
            print('ARGUS_POC_LANDED:...')

    Returns (ok, reason). If the PoC imports `crewai` (module) we
    require either a call like ``crewai.something(...)`` or a call to
    a symbol imported via ``from crewai ... import Sym`` (e.g.
    ``Sym(...)`` or ``x.Sym(...)``).

    Degrades open when ``target_packages`` is empty so unusual repo
    shapes aren't blocked.
    """
    if not target_packages:
        return True, "target package set empty; skipping call check"

    try:
        tree = ast.parse(poc_code)
    except SyntaxError as e:
        return False, f"PoC is not valid Python: {e}"

    target_set = {t.lower() for t in target_packages}
    imported_syms: set[str] = set()      # symbols imported FROM a target package
    imported_mods: set[str] = set()      # target packages imported as modules
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0].lower()
            if root in target_set:
                for alias in node.names:
                    imported_syms.add((alias.asname or alias.name).lower())
        elif isinstance(node, ast.Import):
            for alias in node.names:
                root = (alias.name or "").split(".")[0].lower()
                if root in target_set:
                    imported_mods.add((alias.asname or alias.name).split(".")[0].lower())

    if not imported_syms and not imported_mods:
        # Our import gate should have caught this earlier, but be safe.
        return False, "no symbols imported from target packages"

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # f(...) form — bare name
        if isinstance(func, ast.Name) and func.id.lower() in imported_syms:
            return True, f"calls imported symbol {func.id!r}"
        # obj.f(...) form — attribute on imported module or symbol
        if isinstance(func, ast.Attribute):
            # Walk down to the root name
            cur = func
            while isinstance(cur, ast.Attribute):
                cur = cur.value
            if isinstance(cur, ast.Name):
                root = cur.id.lower()
                if root in imported_syms or root in imported_mods:
                    return True, f"calls method on {root!r}"

    return False, (
        "PoC imports target but never calls anything from it. "
        "Refusing — this is a theoretical PoC disguised as a real one."
    )


def _poc_imports_target(poc_code: str, target_packages: list[str]) -> tuple[bool, str]:
    """
    Check that the PoC imports at least one top-level package from the
    target. Accepts:
        from <pkg>...           import ...
        from <pkg>              import ...
        import <pkg>[.<more>]   [as ...]

    Returns (ok, matched_package_or_reason). Rejects PoCs that declare
    their own version of the vulnerable class instead of importing it.
    """
    import re as _re
    if not target_packages:
        # If we can't determine a target package name, fall through —
        # this keeps the check from being a hard blocker on unusual
        # repo shapes. L7 will still require evidence markers for pass.
        return True, "target package set empty; skipping import check"

    pattern = _re.compile(
        r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)",
        _re.MULTILINE,
    )
    imported_roots = {m.group(1).lower() for m in pattern.finditer(poc_code)}

    for pkg in target_packages:
        if pkg in imported_roots:
            return True, pkg

    return False, (
        f"PoC does not import any of the target's top-level packages "
        f"{target_packages}. Imports detected: {sorted(imported_roots)}. "
        f"Reject: theoretical PoC that does not exercise the shipping library."
    )


def _summarize_network(output: str) -> str:
    """
    Best-effort extract of network activity from PoC stdout/stderr. We
    can't sniff the network on a --rm container after it exits, but most
    non-trivial network attempts leave tell-tale strings in the Python
    stack: 'getaddrinfo failed', 'ConnectionRefusedError', URL strings,
    etc. This gives the Wilson bundle something forensic to show even
    when full packet capture isn't available.
    """
    if not output:
        return "no output captured"
    hits: list[str] = []
    net_markers = [
        r"getaddrinfo", r"ConnectionRefused", r"ConnectionReset",
        r"https?://[\w\.\-:/]+",
        r"SSLError", r"CertificateError",
        r"socket\.",
    ]
    for pat in net_markers:
        for m in re.finditer(pat, output):
            snippet = output[max(0, m.start() - 20):m.end() + 40]
            hits.append(snippet.replace("\n", " "))
            if len(hits) >= 4:
                break
        if len(hits) >= 4:
            break
    if not hits:
        return ("no network-indicator strings in output (consistent with "
                "a host-only or network-none run)")
    return " | ".join(hits[:4])


async def _validate_chain_via_docker(chain: ExploitChain, repo_path: str) -> tuple[bool, str]:
    if not chain.poc_code:
        return False, "No PoC code available for validation."

    payload = chain.poc_code
    if payload.startswith("```python"):
        payload = payload[9:]
    elif payload.startswith("```"):
        payload = payload[3:]
    if payload.endswith("```"):
        payload = payload[:-3]
    payload = payload.strip()

    # ── Static PoC gate: reject theoretical PoCs BEFORE sandbox ───────────
    # Opus can otherwise slip past the prompt-level real-library contract
    # by declaring its own version of the vulnerable class and printing
    # ARGUS_POC_LANDED under a trivial guard. The sandbox would then
    # dutifully "validate" a PoC that never touched the shipping code —
    # exactly the Bugcrowd failure mode. Refuse up-front if the PoC does
    # not import at least one top-level package belonging to the target.
    tpkgs = _target_packages(repo_path)
    imports_ok, reason = _poc_imports_target(payload, tpkgs)
    if not imports_ok:
        return False, (
            f"[static-gate:import] {reason}\n"
            f"--- rejected PoC ---\n{payload[:600]}"
        )
    calls_ok, call_reason = _poc_calls_target(payload, tpkgs)
    if not calls_ok:
        return False, (
            f"[static-gate:call] {call_reason}\n"
            f"--- rejected PoC ---\n{payload[:600]}"
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        poc_path = os.path.join(tmpdir, "poc.py")
        with open(poc_path, "w") as f:
            f.write(payload)

        # Copy the (read-only mounted) target into a writable path inside the
        # container, then `pip install -e .` if it's a Python package so the
        # PoC can import the REAL library (e.g. `from crewai.xxx import ...`).
        # Fall back to PYTHONPATH manipulation for loose source trees.
        install_script = (
            "set -e; "
            "cp -r /src /target; "
            "cd /target; "
            "pip install -q requests websocket-client aiohttp 2>/dev/null || true; "
            "if [ -f pyproject.toml ] || [ -f setup.py ]; then "
            "  pip install -q -e . 2>/dev/null "
            "  || pip install -q . 2>/dev/null "
            "  || true; "
            "fi; "
            "export PYTHONPATH=/target:/target/src:${PYTHONPATH}; "
            "python /poc/poc.py"
        )
        # Sandbox hardening: drop Linux capabilities, block privilege
        # escalation, cap process count and memory. A malicious PoC
        # (hallucinated by Opus, or a supply-chain payload in a scanned
        # repo) should not be able to break out of the container or DoS
        # the host. Network is left on because `pip install -e .` needs
        # PyPI; a fully offline two-stage build is the follow-up.
        cmd = [
            "docker", "run", "--rm",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=128",
            "--memory=512m",
            "--memory-swap=512m",
            "-v", f"{os.path.abspath(repo_path)}:/src:ro",
            "-v", f"{poc_path}:/poc/poc.py:ro",
            "python:3.10-slim",
            "bash", "-c", install_script,
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            try:
                stdout, _ = await asyncio.wait_for(
                    process.communicate(), timeout=VALIDATION_TIMEOUT_SECONDS
                )
                output = stdout.decode("utf-8", errors="replace")

                if process.returncode != 0:
                    return False, f"Crash/Error (Code {process.returncode}):\n{output}"

                # Light network-trace summary so the Wilson bundle has a
                # forensic record of what talked to whom. We can't inspect
                # outbound traffic post-hoc on a --rm container, but we
                # surface any obvious network-error / hostname traces the
                # PoC itself emitted; and we tag whether the run had net on.
                net_summary = _summarize_network(output)

                if _has_evidence(output):
                    return True, output + "\n\n[net] " + net_summary

                return False, (
                    "Exit code 0 but no exploit evidence in output. "
                    "PoC must emit an ARGUS_POC_LANDED:<id> marker or leak "
                    "recognisable sensitive data to be considered validated.\n"
                    f"Output:\n{output}\n\n[net] {net_summary}"
                )

            except asyncio.TimeoutError:
                process.kill()
                return False, f"Validation Timeout ({VALIDATION_TIMEOUT_SECONDS}s): Exploit hung or failed to complete."

        except Exception as e:
            return False, f"Docker Execution Error: {str(e)}"

def validate_l5_chains(l5_chains: L5Chains, repo_path: str, verbose: bool = False) -> None:
    """
    Mutates the L5Chains objects in place, setting the is_validated flag
    by executing the PoCs in Docker.
    """
    print(f"\n[L7] Execution Sandbox Validation")
    print(f"     Target repo: {repo_path}")
    print(f"     Validating {len(l5_chains.chains)} chains...")

    # We run the async validations synchronously sequentially for clean logging
    async def run_all():
        for i, chain in enumerate(l5_chains.chains):
            if not chain.poc_code:
                if verbose:
                    print(f"  [{i+1}/{len(l5_chains.chains)}] {chain.chain_id} - SKIP (No PoC)")
                continue

            print(f"  [{i+1}/{len(l5_chains.chains)}] Executing {chain.chain_id} in Sandbox...")
            is_valid, out = await _validate_chain_via_docker(chain, repo_path)
            
            chain.is_validated = is_valid
            chain.validation_output = out[:1000] # store summary
            
            if is_valid:
                print(f"         ✓ Exploit evidence detected — chain validated")
            else:
                reason = out.strip().replace('\n', ' ')[:100]
                print(f"         ✗ Not validated: {reason}")
                if verbose:
                    for line in out.splitlines():
                        print(f"             | {line}")
                
    asyncio.run(run_all())
