"""Database engine, session, and schema init (SQLAlchemy 2.0, sync)."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


_connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(settings.DATABASE_URL, connect_args=_connect_args,
                       pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    from . import models  # noqa: F401  (register mappers)
    Base.metadata.create_all(engine)
    _ensure_columns()


# Additive columns for tables that already exist in a deployed DB. create_all()
# creates missing *tables* but never alters existing ones, so new columns on the
# agents table are added here idempotently (SQLite + PostgreSQL).
_ADDED_COLUMNS = {
    "agents": {
        "ports": {"postgresql": "JSONB", "sqlite": "JSON"},
        "ports_at": {"postgresql": "TIMESTAMP", "sqlite": "DATETIME"},
        "disk": {"postgresql": "INTEGER DEFAULT 0", "sqlite": "INTEGER DEFAULT 0"},
        "disk_total": {"postgresql": "INTEGER DEFAULT 0", "sqlite": "INTEGER DEFAULT 0"},
    },
}


def _ensure_columns() -> None:
    from sqlalchemy import inspect, text
    insp = inspect(engine)
    dialect = engine.dialect.name
    tables = set(insp.get_table_names())
    with engine.begin() as conn:
        for table, cols in _ADDED_COLUMNS.items():
            if table not in tables:
                continue
            have = {c["name"] for c in insp.get_columns(table)}
            for col, types in cols.items():
                if col in have:
                    continue
                coltype = types.get(dialect, "TEXT")
                conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {col} {coltype}'))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
