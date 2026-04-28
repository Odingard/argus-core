"""
argus/memory/attack_graph.py — Persistent target knowledge graph.

Accumulates confirmed attack paths across engagements. On the second
engagement against the same target class, ARGUS prioritizes surfaces
and techniques that confirmed in previous runs — converging faster
than any stateless scanner.

Storage: SQLite in ~/.argus/knowledge/{target_class}.db
No external database dependency. Thread-safe writes.

Graph model:
  Nodes: surfaces (tool:sandbox_initialize, chat:/api/ask, etc.)
  Edges: confirmed attack paths (surface → technique → vuln_class)
  Weights: confirmation count, last seen, severity

Usage:
    graph = AttackGraph.for_target("node-code-sandbox-mcp")
    graph.record_confirmed(surface="tool:sandbox_initialize",
                           technique="EP-T12", vuln_class="ENVIRONMENT_PIVOT",
                           severity="CRITICAL")
    # Next engagement:
    priority = graph.priority_surfaces()  # sorted by confirmed count
"""
from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


_LOCK = threading.Lock()
_DEFAULT_DIR = Path.home() / ".argus" / "knowledge"


@dataclass
class AttackPath:
    surface:      str
    technique:    str
    vuln_class:   str
    severity:     str
    confirmed:    int = 1
    first_seen:   str = ""
    last_seen:    str = ""

    @property
    def weight(self) -> float:
        sev_w = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
            self.severity, 1)
        return self.confirmed * sev_w


class AttackGraph:
    """Persistent knowledge graph for one target class."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS attack_paths (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        surface     TEXT NOT NULL,
        technique   TEXT NOT NULL,
        vuln_class  TEXT NOT NULL,
        severity    TEXT NOT NULL DEFAULT 'MEDIUM',
        confirmed   INTEGER NOT NULL DEFAULT 1,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        UNIQUE(surface, technique, vuln_class)
    );
    CREATE TABLE IF NOT EXISTS surface_stats (
        surface     TEXT PRIMARY KEY,
        total_hits  INTEGER DEFAULT 0,
        last_hit    TEXT
    );
    """

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = str(db_path)
        with sqlite3.connect(self._db) as con:
            con.executescript(self._SCHEMA)

    @classmethod
    def for_target(cls, target_class: str,
                   base_dir: Optional[Path] = None) -> "AttackGraph":
        """Load or create graph for a target class slug."""
        slug = target_class.replace("://", "_").replace("/", "_").replace(".", "_")
        d = base_dir or _DEFAULT_DIR
        return cls(d / f"{slug}.db")

    def record_confirmed(self, *, surface: str, technique: str,
                         vuln_class: str, severity: str = "MEDIUM") -> None:
        now = datetime.now(timezone.utc).isoformat()
        with _LOCK, sqlite3.connect(self._db) as con:
            con.execute("""
                INSERT INTO attack_paths
                    (surface, technique, vuln_class, severity,
                     confirmed, first_seen, last_seen)
                VALUES (?,?,?,?,1,?,?)
                ON CONFLICT(surface, technique, vuln_class) DO UPDATE SET
                    confirmed = confirmed + 1,
                    severity  = excluded.severity,
                    last_seen = excluded.last_seen
            """, (surface, technique, vuln_class, severity, now, now))
            con.execute("""
                INSERT INTO surface_stats (surface, total_hits, last_hit)
                VALUES (?,1,?)
                ON CONFLICT(surface) DO UPDATE SET
                    total_hits = total_hits + 1,
                    last_hit   = excluded.last_hit
            """, (surface, now))

    def priority_surfaces(self, top_n: int = 10) -> list[str]:
        """Return surfaces sorted by historical confirmation weight."""
        with sqlite3.connect(self._db) as con:
            rows = con.execute("""
                SELECT surface, total_hits FROM surface_stats
                ORDER BY total_hits DESC LIMIT ?
            """, (top_n,)).fetchall()
        return [r[0] for r in rows]

    def known_techniques_for(self, surface: str) -> list[AttackPath]:
        """Return previously confirmed attack paths for a surface."""
        with sqlite3.connect(self._db) as con:
            rows = con.execute("""
                SELECT surface, technique, vuln_class, severity,
                       confirmed, first_seen, last_seen
                FROM attack_paths WHERE surface=?
                ORDER BY confirmed DESC
            """, (surface,)).fetchall()
        return [AttackPath(*r) for r in rows]

    def all_paths(self) -> list[AttackPath]:
        with sqlite3.connect(self._db) as con:
            rows = con.execute("""
                SELECT surface, technique, vuln_class, severity,
                       confirmed, first_seen, last_seen
                FROM attack_paths ORDER BY confirmed DESC
            """).fetchall()
        return [AttackPath(*r) for r in rows]

    def summary(self) -> dict:
        paths = self.all_paths()
        return {
            "total_confirmed_paths": len(paths),
            "top_surfaces":   [p.surface for p in paths[:5]],
            "top_techniques": list({p.technique for p in paths}),
        }
