"""Database session management for ARGUS.

Provides engine creation, session factory, and table initialization.
Default: SQLite at ~/.argus/argus.db (configurable via ARGUS_DB_URL).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from argus.db.models import Base

logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = Path.home() / ".argus"
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "argus.db"

# Module-level singletons — lazily initialized
_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _get_db_url() -> str:
    """Resolve database URL from environment or default."""
    url = os.environ.get("ARGUS_DB_URL", "").strip()
    if url:
        return url
    # Default to SQLite in ~/.argus/
    _DEFAULT_DB_DIR.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{_DEFAULT_DB_PATH}"


@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):  # noqa: ARG001
    """Enable WAL mode and foreign keys for SQLite connections.

    WAL mode allows concurrent readers during writes — critical for
    the web dashboard reading scan results while a scan is running.
    """
    import sqlite3

    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def get_engine() -> Engine:
    """Get or create the SQLAlchemy engine (singleton)."""
    global _engine  # noqa: PLW0603
    if _engine is None:
        db_url = _get_db_url()
        logger.info("Initializing database: %s", db_url.split("///")[-1] if "sqlite" in db_url else db_url)
        _engine = create_engine(
            db_url,
            echo=False,
            pool_pre_ping=True,
        )
    return _engine


def get_session() -> Session:
    """Create a new database session."""
    global _session_factory  # noqa: PLW0603
    if _session_factory is None:
        _session_factory = sessionmaker(bind=get_engine())
    return _session_factory()


def init_db() -> None:
    """Create all tables if they don't exist.

    Safe to call multiple times — uses CREATE TABLE IF NOT EXISTS.
    """
    engine = get_engine()
    Base.metadata.create_all(engine)
    logger.info("Database tables initialized")


def reset_engine() -> None:
    """Reset the engine singleton (for testing)."""
    global _engine, _session_factory  # noqa: PLW0603
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None
