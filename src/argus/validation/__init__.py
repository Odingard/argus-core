"""
argus.validation — static checks that validate PoC structure.

Promoted from the archived ``layer7/sandbox.py`` because these helpers
stay relevant regardless of where the PoC runs (Phase 0 labrat will
replace the old Docker-pip-install substrate). Every PoC-producing path
in ARGUS must pass both gates before evidence can be trusted:

    poc_imports_target     the PoC imports the installed package
    poc_calls_target       the PoC actually invokes an imported symbol
                           (AST-verified — defeats "imports X but never
                           uses X" PoCs that slipped past the prompt
                           contract pre-2026-04-21)

    target_packages        resolve the installed-package names from a
                           repo path (walks up for pyproject.toml etc.)
"""
from argus.validation.poc_gates import (
    target_packages,
    poc_imports_target,
    poc_calls_target,
)

__all__ = ["target_packages", "poc_imports_target", "poc_calls_target"]
