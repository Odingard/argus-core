"""
argus/corpus_attacks/cve_mutator.py — CVE-aware payload generation.

When SC-09 identifies a vulnerable package with a known CVE,
this mutator queries OSV for the CVE description and PoC hints,
then generates payloads specifically tuned to that vulnerability class.

Instead of firing generic shell injection templates, ARGUS generates
payloads that mirror the actual PoC pattern for the specific CVE —
making exploitation confirmation faster and more precise.

Integration:
    Called automatically by the turn-fire bus when SC-09 produces
    a SUPPLY_CHAIN finding with a CVE ID attached.
    Also available standalone via corpus.add_mutator(CVEMutator(cve_id)).
"""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CVEContext:
    """Structured context extracted from OSV for payload generation."""
    cve_id:         str
    summary:        str = ""
    details:        str = ""
    affected_func:  str = ""   # function/method known vulnerable
    vuln_class:     str = ""   # injection type inferred from description
    references:     list[str] = field(default_factory=list)

    @property
    def prompt_context(self) -> str:
        return (
            f"CVE: {self.cve_id}\n"
            f"Summary: {self.summary[:300]}\n"
            f"Details: {self.details[:400]}\n"
            f"Vulnerable function: {self.affected_func or 'unknown'}\n"
            f"Vulnerability class: {self.vuln_class or 'unknown'}"
        )


def fetch_cve_context(cve_id: str) -> Optional[CVEContext]:
    """Query OSV.dev for a specific CVE and extract payload context."""
    try:
        url = f"https://api.osv.dev/v1/vulns/{cve_id}"
        req = urllib.request.Request(url,
              headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
    except Exception:
        return None

    ctx = CVEContext(cve_id=cve_id)
    ctx.summary = data.get("summary", "")
    ctx.details = data.get("details", "")
    ctx.references = [r.get("url", "") for r in data.get("references", [])]

    # Infer vulnerable function from details
    details_low = ctx.details.lower()
    for fn in ("execsync", "exec", "spawn", "eval", "shell",
               "subprocess", "popen", "system"):
        if fn in details_low:
            ctx.affected_func = fn
            break

    # Infer vulnerability class
    for kw, vc in [
        ("shell injection", "shell_injection"),
        ("command injection", "command_injection"),
        ("path traversal", "path_traversal"),
        ("prototype pollution", "prototype_pollution"),
        ("sql injection", "sql_injection"),
        ("ssrf", "ssrf"),
        ("rce", "rce"),
    ]:
        if kw in details_low or kw in ctx.summary.lower():
            ctx.vuln_class = vc
            break

    return ctx


@dataclass
class CVEMutator:
    """Mutator that generates CVE-specific payloads via LLM.

    Given a CVE ID, fetches the vulnerability description and PoC
    hints from OSV, then prompts the LLM to generate payloads that
    mirror the actual exploitation pattern.

    Falls back to returning the original text unchanged if:
      - OSV lookup fails
      - No provider key available
      - LLM call times out
    """
    cve_id:      str
    seed_index:  int = 0
    name:        str = ""
    _ctx:        Optional[CVEContext] = field(default=None,
                                              init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.name:
            self.name = f"cve_{self.cve_id.lower().replace('-','_')}"
        self._ctx = fetch_cve_context(self.cve_id)

    def apply(self, text: str) -> str:
        if self._ctx is None:
            return text
        try:
            return self._generate(text)
        except Exception:
            return text

    def _generate(self, text: str) -> str:
        from argus.routing.models import route_call
        prompt = (
            f"You are an offensive security researcher generating a "
            f"proof-of-concept payload for a specific CVE.\n\n"
            f"{self._ctx.prompt_context}\n\n"
            f"SEED: {self.seed_index}\n\n"
            f"ORIGINAL PAYLOAD:\n{text}\n\n"
            f"Generate ONE payload variant that is specifically optimized "
            f"for this CVE's vulnerability class ({self._ctx.vuln_class}). "
            f"The variant should trigger the same root cause as the CVE. "
            f"Return only the payload, no explanation."
        )
        resp = route_call(
            "rephrase_adversarial",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=400,
        )
        import anthropic as _anth
        if hasattr(resp, "content"):
            for block in resp.content:
                if hasattr(block, "text"):
                    return block.text.strip()
        return text
