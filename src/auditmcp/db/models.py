"""SQLAlchemy 2.x models (scaffold).

The schema — servers, server_versions, scan_runs, findings, evidence, scores,
score_history, and supporting tables — lands with the first Alembic migration.
Requires the `workers` extra.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for all auditmcp models."""
