"""Database initialization and seed data.

Idempotent: safe to call on every startup and from setup scripts.
"""
from __future__ import annotations

import logging

from app.core.config import get_settings
from app.db.session import Base, SessionLocal, engine

# Import models so metadata is populated before create_all.
from app.models import entities  # noqa: F401
from app.models.entities import ToolDefinition, User
from app.tools import registry

logger = logging.getLogger("agentshield.db")
settings = get_settings()


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        # Seed the fixed synthetic trusted user.
        if db.get(User, settings.demo_user_id) is None:
            db.add(User(id=settings.demo_user_id, display_name="Demo Analyst"))

        # Seed tool definitions from the registry (reference/inspection table).
        for spec in registry.all_tools():
            if db.get(ToolDefinition, spec.name) is None:
                db.add(
                    ToolDefinition(
                        name=spec.name,
                        operation=spec.operation,
                        description=spec.description,
                        is_sensitive=spec.is_sensitive,
                        arg_schema=spec.arg_schema,
                    )
                )
        db.commit()
    logger.info("database initialized")


if __name__ == "__main__":
    init_db()
    print("Database initialized and seeded.")
