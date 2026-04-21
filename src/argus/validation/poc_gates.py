"""
argus/validation/poc_gates.py

PoC structural gates. Every PoC-producing path in ARGUS must pass both
gates before the platform trusts its evidence. Promoted out of the
archived ``layer7/sandbox.py`` on 2026-04-21 because the gates are
relevant regardless of where/how the PoC is validated (Phase 0 labrat
will replace the old Docker-pip-install substrate; the gates stay).

    target_packages(repo_path) -> list[str]
        Top-level installable Python packages that belong to the target
        repository (walks up for pyproject.toml / setup.py / setup.cfg).

    poc_imports_target(poc_code, target_packages) -> (ok, reason)
        First leg of the gate: does the PoC import at least one top-
        level package of the target?

    poc_calls_target(poc_code, target_packages) -> (ok, reason)
        Second leg: does it ACTUALLY CALL an imported symbol? Defeats
        "imports X but never uses X" PoCs that slipped past the
        prompt-level contract pre-2026-04-21.

Both gates degrade open when the target-package list is empty so unusual
repo shapes aren't hard-blocked.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path


# ── target_packages ───────────────────────────────────────────────────────────

def target_packages(repo_path: str) -> list[str]:
    """
    Return the list of TOP-LEVEL installable Python packages that belong
    to the target repository.

    Resolution order:
      1. Walk UP from repo_path looking for pyproject.toml / setup.py /
         setup.cfg; extract distribution name (dash → underscore).
      2. Fallback: deepest `__init__.py` at-or-above repo_path.
      3. Belt: top-level dirs under manifest_dir/src/ carrying __init__.py.

    Generic container names (src, lib, tests, test, docs, examples) are
    never returned — they would make the gate useless.
    """
    candidates: set[str] = set()

    root = Path(repo_path).resolve()
    if not root.exists():
        return []

    manifest_dir: Path | None = None
    cur = root
    for _ in range(8):
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
        pp = manifest_dir / "pyproject.toml"
        if pp.exists():
            try:
                text = pp.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r'(?mi)^\s*name\s*=\s*["\'`]([^"\'`]+)',
                                     text):
                    candidates.add(m.group(1).replace("-", "_").lower())
            except OSError:
                pass
        sp = manifest_dir / "setup.py"
        if sp.exists():
            try:
                text = sp.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r'name\s*=\s*["\']([^"\']+)', text):
                    candidates.add(m.group(1).replace("-", "_").lower())
            except OSError:
                pass
        sc = manifest_dir / "setup.cfg"
        if sc.exists():
            try:
                text = sc.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r'(?mi)^\s*name\s*=\s*([A-Za-z0-9_\-\.]+)',
                                     text):
                    candidates.add(m.group(1).replace("-", "_").lower())
            except OSError:
                pass

        src_dir = manifest_dir / "src"
        if src_dir.exists():
            for child in src_dir.iterdir():
                if child.is_dir() and (child / "__init__.py").exists():
                    candidates.add(child.name.lower())
        for child in manifest_dir.iterdir():
            if child.is_dir() and (child / "__init__.py").exists():
                candidates.add(child.name.lower())

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

    for generic in ("src", "lib", "tests", "test", "docs", "examples",
                    "__pycache__", ""):
        candidates.discard(generic)

    return sorted(candidates)


# ── poc_imports_target ────────────────────────────────────────────────────────

def poc_imports_target(poc_code: str, target_pkgs: list[str]) -> tuple[bool, str]:
    """
    First leg of the static gate. Returns ``(ok, matched_package_or_reason)``.
    Rejects PoCs that never import a top-level target package.
    """
    if not target_pkgs:
        return True, "target package set empty; skipping import check"

    pattern = re.compile(
        r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)",
        re.MULTILINE,
    )
    imported_roots = {m.group(1).lower() for m in pattern.finditer(poc_code)}

    for pkg in target_pkgs:
        if pkg in imported_roots:
            return True, pkg

    return False, (
        f"PoC does not import any of the target's top-level packages "
        f"{target_pkgs}. Imports detected: {sorted(imported_roots)}. "
        f"Reject: theoretical PoC that does not exercise the shipping library."
    )


# ── poc_calls_target ──────────────────────────────────────────────────────────

def poc_calls_target(poc_code: str, target_pkgs: list[str]) -> tuple[bool, str]:
    """
    Second leg of the static gate. AST-verifies that the PoC actually
    USES a symbol it imported from a target package. Defeats the class:

        from crewai import X
        if 'command' in s:
            print('ARGUS_POC_LANDED:...')

    — import present, marker printed, ``X`` never referenced.
    """
    if not target_pkgs:
        return True, "target package set empty; skipping call check"

    try:
        tree = ast.parse(poc_code)
    except SyntaxError as e:
        return False, f"PoC is not valid Python: {e}"

    target_set = {t.lower() for t in target_pkgs}
    imported_syms: set[str] = set()
    imported_mods: set[str] = set()
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
                    imported_mods.add(
                        (alias.asname or alias.name).split(".")[0].lower()
                    )

    if not imported_syms and not imported_mods:
        return False, "no symbols imported from target packages"

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id.lower() in imported_syms:
            return True, f"calls imported symbol {func.id!r}"
        if isinstance(func, ast.Attribute):
            cur = func
            while isinstance(cur, ast.Attribute):
                cur = cur.value
            if isinstance(cur, ast.Name):
                root_name = cur.id.lower()
                if root_name in imported_syms or root_name in imported_mods:
                    return True, f"calls method on {root_name!r}"

    return False, (
        "PoC imports target but never calls anything from it. "
        "Refusing — this is a theoretical PoC disguised as a real one."
    )
