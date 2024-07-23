"""
database.py — SQLAlchemy database setup and session management.
"""

from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# Allow override via environment variable; default to local SQLite
_DB_PATH = os.getenv("DATABASE_URL", "sqlite:///./llm_safety_auditor.db")

engine = create_engine(
    _DB_PATH,
    connect_args={"check_same_thread": False} if _DB_PATH.startswith("sqlite") else {},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency — yields a DB session and closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables. Call once at startup."""
    # Import models so Base discovers them
    from api import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
