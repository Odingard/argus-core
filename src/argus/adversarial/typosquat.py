"""
argus/adversarial/typosquat.py — npm + PyPI typosquat scanner.

For each legitimate MCP package name, we generate a set of
plausible typosquat candidates (homoglyphs, adjacent-key slips,
doubled/omitted letters, scope lookalikes, package-order tricks)
and query the target registry for each. Any candidate that
actually resolves — i.e. the squat package exists on npm or PyPI —
is a supply-chain finding.

No LLM in this path. Deterministic candidate generation +
HTTP-GET resolution + strict name-match filter.

The seeded legit-package list covers the Anthropic reference
servers and the most-installed community MCP packages. Callers
can extend it at runtime — every squat found joins the detection
corpus via the usual EvolveCorpus hook.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional
from urllib.parse import quote

import urllib.request


# ── Seeded legit-package lists ──────────────────────────────────────────────

KNOWN_NPM_MCP_PACKAGES: tuple[str, ...] = (
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-git",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-time",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/sdk",
    "mcp-handler",
    "mcp-remote",
    "fastmcp",
)

KNOWN_PYPI_MCP_PACKAGES: tuple[str, ...] = (
    "mcp",
    "mcp-server-fetch",
    "mcp-server-sqlite",
    "mcp-server-time",
    "mcp-server-sequential-thinking",
    "fastmcp",
    "llama-index",
    "llama-index-core",
    "crewai",
    "langchain",
    "langgraph",
)


# ── Candidate generators ────────────────────────────────────────────────────

_HOMOGLYPH_MAP: dict[str, tuple[str, ...]] = {
    "l": ("1", "I", "L", "|"),
    "i": ("1", "l", "I"),
    "o": ("0", "O"),
    "s": ("5", "S", "z"),
    "a": ("@", "4"),
    "e": ("3",),
    "t": ("7",),
    "m": ("rn",),
    "n": ("m", "h"),
    "c": ("k",),
    "k": ("c",),
}

# Keyboard-adjacent typos for "right next to the intended key" slips.
_ADJACENT_KEYS: dict[str, tuple[str, ...]] = {
    "q": ("w", "a"),      "w": ("q", "e", "s"),   "e": ("w", "r", "d"),
    "r": ("e", "t", "f"), "t": ("r", "y", "g"),   "y": ("t", "u", "h"),
    "u": ("y", "i", "j"), "i": ("u", "o", "k"),   "o": ("i", "p", "l"),
    "p": ("o", "l"),
    "a": ("q", "s", "z"), "s": ("a", "d", "w"),   "d": ("s", "f", "e"),
    "f": ("d", "g", "r"), "g": ("f", "h", "t"),   "h": ("g", "j", "y"),
    "j": ("h", "k", "u"), "k": ("j", "l", "i"),   "l": ("k", "o"),
    "z": ("a", "x"),       "x": ("z", "c"),        "c": ("x", "v"),
    "v": ("c", "b"),       "b": ("v", "n"),        "n": ("b", "m"),
    "m": ("n",),
}


def _generate_npm_candidates(legit: str) -> set[str]:
    """Produce plausible typosquat candidates for an npm package."""
    cands: set[str] = set()
    # Split scope (@org/name) from name.
    if legit.startswith("@") and "/" in legit:
        scope, name = legit.split("/", 1)
    else:
        scope, name = "", legit

    # 1) Homoglyph substitutions on BOTH the scope and the name.
    #    One substitution at a time — double-subs are paranoid.
    _apply_homoglyphs(name, scope, cands)
    if scope:
        _apply_homoglyphs_to_scope(scope, name, cands)

    # 2) Adjacent-key slips (single char) on the name only — scope
    #    is usually user-visible enough that keyboard slips are rare
    #    there.
    _apply_adjacent(name, scope, cands)

    # 3) Doubled or omitted letters.
    _apply_doubled_omitted(name, scope, cands)

    # 4) Hyphen / underscore / dash swaps + trailing-s.
    _apply_separator_and_plural(name, scope, cands)

    # 5) Name-order tricks — "server-x" vs "x-server", "mcp-server-x"
    #    vs "server-mcp-x". Popular across ecosystems.
    _apply_name_order(name, scope, cands)

    # 6) "official" / "mcp" / "ai" bolt-ons — common supply-chain trick.
    _apply_suffix_tricks(legit, cands)

    cands.discard(legit)          # never report the legit name itself
    return cands


def _generate_pypi_candidates(legit: str) -> set[str]:
    """PyPI names don't have scopes. Fewer vectors."""
    cands: set[str] = set()
    _apply_homoglyphs(legit, "", cands)
    _apply_adjacent(legit, "", cands)
    _apply_doubled_omitted(legit, "", cands)
    _apply_separator_and_plural(legit, "", cands)
    _apply_name_order(legit, "", cands)
    _apply_suffix_tricks(legit, cands)
    cands.discard(legit)
    return cands


def _apply_homoglyphs(name: str, scope: str, out: set[str]) -> None:
    for i, ch in enumerate(name):
        for sub in _HOMOGLYPH_MAP.get(ch.lower(), ()):
            sq = name[:i] + sub + name[i + 1:]
            out.add(f"{scope}/{sq}" if scope else sq)


def _apply_homoglyphs_to_scope(scope: str, name: str, out: set[str]) -> None:
    # scope starts with @
    core = scope[1:]
    for i, ch in enumerate(core):
        for sub in _HOMOGLYPH_MAP.get(ch.lower(), ()):
            sq_scope = "@" + core[:i] + sub + core[i + 1:]
            out.add(f"{sq_scope}/{name}")


def _apply_adjacent(name: str, scope: str, out: set[str]) -> None:
    for i, ch in enumerate(name):
        for nxt in _ADJACENT_KEYS.get(ch.lower(), ()):
            sq = name[:i] + nxt + name[i + 1:]
            out.add(f"{scope}/{sq}" if scope else sq)


def _apply_doubled_omitted(name: str, scope: str, out: set[str]) -> None:
    # Double every char; also drop every char (single-op variants).
    for i, ch in enumerate(name):
        doubled = name[:i] + ch + ch + name[i + 1:]
        out.add(f"{scope}/{doubled}" if scope else doubled)
        if len(name) > 3:
            dropped = name[:i] + name[i + 1:]
            out.add(f"{scope}/{dropped}" if scope else dropped)


def _apply_separator_and_plural(name: str, scope: str, out: set[str]) -> None:
    # swap hyphens and underscores, add trailing s.
    for src, dst in (("-", "_"), ("_", "-")):
        if src in name:
            sq = name.replace(src, dst)
            out.add(f"{scope}/{sq}" if scope else sq)
    for suffix in ("s", "-official", "-pkg", "2"):
        sq = name + suffix
        out.add(f"{scope}/{sq}" if scope else sq)


def _apply_name_order(name: str, scope: str, out: set[str]) -> None:
    parts = name.split("-")
    if len(parts) > 1:
        reversed_ = "-".join(reversed(parts))
        out.add(f"{scope}/{reversed_}" if scope else reversed_)
    # If prefix is "server-*", try "mcp-server-*".
    if name.startswith("server-"):
        sq = "mcp-" + name
        out.add(f"{scope}/{sq}" if scope else sq)
    if name.startswith("mcp-"):
        sq = name[len("mcp-"):]
        if sq:
            out.add(f"{scope}/{sq}" if scope else sq)


def _apply_suffix_tricks(legit: str, out: set[str]) -> None:
    # Scope-lookalike for @modelcontextprotocol: try alternate
    # capitalisation and common brand-hijack variants.
    if legit.startswith("@modelcontextprotocol/"):
        name = legit.split("/", 1)[1]
        for fake_scope in (
            "@modelcontextprotoco1",                # l → 1
            "@modelcontextprotocol-official",
            "@mcp-official",
            "@mcp",
        ):
            out.add(f"{fake_scope}/{name}")


# ── Registry resolvers ──────────────────────────────────────────────────────

Resolver = Callable[[str], Optional[dict]]
"""Given a package name, return a dict of registry metadata if the
package exists, None otherwise."""


def _safe_get_json(url: str, *, timeout: float) -> Optional[dict]:
    """HTTPS-only JSON fetch. Explicit scheme allow-list defends against
    any future refactor that accidentally feeds urlopen a file:/ or
    custom-scheme URL — urlopen honours whatever scheme it's given."""
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https registry URL: {url!r}")
    req = urllib.request.Request(
        url, headers={"Accept": "application/json",
                      "User-Agent": "argus-typosquat/1"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 — scheme gated above
        if r.status != 200:
            return None
        body = r.read().decode("utf-8", errors="replace")
    data = json.loads(body)
    return data if isinstance(data, dict) else None


def _npm_resolver(name: str, *, timeout: float = 4.0) -> Optional[dict]:
    url = f"https://registry.npmjs.org/{quote(name, safe='@/')}"
    try:
        data = _safe_get_json(url, timeout=timeout)
        if data is None:
            return None
        return {
            "name":        data.get("name", name),
            "description": (data.get("description") or "")[:240],
            "created":     (data.get("time") or {}).get("created", ""),
            "author":      _first(data.get("maintainers") or []),
        }
    except Exception:
        return None


def _pypi_resolver(name: str, *, timeout: float = 4.0) -> Optional[dict]:
    url = f"https://pypi.org/pypi/{quote(name)}/json"
    try:
        data = _safe_get_json(url, timeout=timeout)
        if data is None:
            return None
        info = data.get("info") or {}
        return {
            "name":        info.get("name", name),
            "description": (info.get("summary") or "")[:240],
            "author":      info.get("author") or "",
        }
    except Exception:
        return None


def _first(items: list) -> str:
    if not items:
        return ""
    x = items[0]
    if isinstance(x, dict):
        return x.get("name") or x.get("email") or ""
    return str(x)


# ── Output shapes ───────────────────────────────────────────────────────────

@dataclass
class Squat:
    """One discovered typosquat: a registered package whose name
    targets a legitimate MCP package."""
    registry:   str
    legit:      str
    squat:      str
    description: str = ""
    author:     str = ""
    created:    str = ""
    signals:    list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TyposquatResult:
    targets_scanned:    int
    candidates_checked: int
    squats_found:       list[Squat]
    generated_at:       str

    def to_dict(self) -> dict:
        return {
            "targets_scanned":    self.targets_scanned,
            "candidates_checked": self.candidates_checked,
            "squats_found":       [s.to_dict() for s in self.squats_found],
            "generated_at":       self.generated_at,
        }


# ── Scanner ─────────────────────────────────────────────────────────────────

@dataclass
class TyposquatScanner:
    """
    Configurable scanner. Injectable resolvers make it test-friendly
    (tests pass a stub resolver that returns fixture metadata).
    """
    registry:     str                        # "npm" | "pypi"
    resolver:     Optional[Resolver] = None
    max_per_pkg:  int = 120                  # cap candidates per legit

    def scan(
        self, targets: Iterable[str],
    ) -> TyposquatResult:
        registry = self.registry.lower()
        resolver = self.resolver or (
            _npm_resolver if registry == "npm" else _pypi_resolver
        )
        gen = (_generate_npm_candidates
               if registry == "npm"
               else _generate_pypi_candidates)

        squats: list[Squat] = []
        cands_checked = 0
        targets = list(targets)
        for legit in targets:
            # Rank candidates by likelihood before applying the cap,
            # so high-signal squats (separator-swap, name-order,
            # single-homoglyph) always get checked even with a small
            # max_per_pkg. Alphabetical-only would bury them behind
            # numeric-substitution variants that start with '0', '1'…
            cands = _prioritise(legit, gen(legit))[:self.max_per_pkg]
            for c in cands:
                cands_checked += 1
                meta = resolver(c)
                if meta is None:
                    continue
                if meta.get("name") != c:
                    # Not an exact-name match — registry maybe returned
                    # a search hit. We only care about EXACT squats.
                    continue
                squats.append(Squat(
                    registry=registry,
                    legit=legit,
                    squat=c,
                    description=meta.get("description", ""),
                    author=meta.get("author", ""),
                    created=meta.get("created", ""),
                    signals=_classify_signals(legit=legit, squat=c),
                ))

        return TyposquatResult(
            targets_scanned=len(targets),
            candidates_checked=cands_checked,
            squats_found=squats,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )


def _prioritise(legit: str, cands: Iterable[str]) -> list[str]:
    """Return candidates sorted high-signal-first. Tie-break
    alphabetically for deterministic test output."""
    cands = list(cands)

    def rank(c: str) -> tuple[int, str]:
        score = 0
        # Separator swap and trailing-s are the two most-observed
        # real-world squats — keep them right at the front.
        if legit.replace("-", "_") == c or legit.replace("_", "-") == c:
            score -= 100
        if len(c) - len(legit) == 1 and c[:len(legit)] == legit:
            score -= 80
        # Name-order reversal (split + reversed join).
        parts = legit.split("-")
        if len(parts) > 1 and "-".join(reversed(parts)) == c:
            score -= 60
        # Scope lookalike ("@scope_variant/name").
        if legit.startswith("@") and c.startswith("@") \
                and legit.split("/", 1)[0] != c.split("/", 1)[0]:
            score -= 50
        # "official" / "pkg" / "2" brand-hijack suffixes.
        low = c.lower()
        if ("official" in low or low.endswith("-pkg")
                or low.endswith("2")):
            score -= 40
        # Single-homoglyph edit (mcp-hand1er / mcp-hand|er).
        if _homoglyph_distance(legit, c) == 1:
            score -= 30
        # Everything else — alphabetical.
        return (score, c)

    return sorted(cands, key=rank)


def _classify_signals(*, legit: str, squat: str) -> list[str]:
    """Why is this squat suspicious? Short human-readable signals."""
    out: list[str] = []
    if _homoglyph_distance(legit, squat) == 1:
        out.append("homoglyph_1")
    if abs(len(legit) - len(squat)) == 1:
        out.append("length_delta_1")
    if legit.startswith("@") and squat.startswith("@"):
        if legit.split("/", 1)[0] != squat.split("/", 1)[0]:
            out.append("scope_lookalike")
    if "official" in squat.lower():
        out.append("official_suffix")
    if legit.replace("-", "_") == squat or legit.replace("_", "-") == squat:
        out.append("separator_swap")
    return out


def _homoglyph_distance(a: str, b: str) -> int:
    """Edit distance treating homoglyph pairs as same char. Crude
    but good enough for a signal tag."""
    # Normalise: lowercase + apply known homoglyph mappings.
    def norm(s: str) -> str:
        out = []
        for ch in s.lower():
            if ch in ("1", "i", "l"): out.append("i")
            elif ch in ("0", "o"):    out.append("o")
            elif ch == "5":           out.append("s")
            elif ch == "@":           out.append("a")
            elif ch == "3":           out.append("e")
            elif ch == "7":           out.append("t")
            else:                     out.append(ch)
        return "".join(out)
    an, bn = norm(a), norm(b)
    # Plain Levenshtein on the normalised strings.
    if an == bn:
        return 0
    if len(an) < len(bn):
        an, bn = bn, an
    if not bn:
        return len(an)
    prev = list(range(len(bn) + 1))
    for i, ca in enumerate(an):
        cur = [i + 1]
        for j, cb in enumerate(bn):
            ins  = prev[j + 1] + 1
            dele = cur[j] + 1
            sub  = prev[j] + (ca != cb)
            cur.append(min(ins, dele, sub))
        prev = cur
    return prev[-1]


# ── Convenience entry point ────────────────────────────────────────────────

def scan(
    targets:   Optional[Iterable[str]] = None,
    *,
    registry:  str = "npm",
    resolver:  Optional[Resolver] = None,
) -> TyposquatResult:
    """Scan ``targets`` (or the seed list) on ``registry``."""
    registry = registry.lower()
    if targets is None:
        targets = (KNOWN_NPM_MCP_PACKAGES
                   if registry == "npm"
                   else KNOWN_PYPI_MCP_PACKAGES)
    scanner = TyposquatScanner(registry=registry, resolver=resolver)
    return scanner.scan(targets)
