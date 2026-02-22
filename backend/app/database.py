"""SQLAlchemy async database engine & session management."""

import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import StaticPool

from app.config import settings

logger = logging.getLogger(__name__)


def _resolve_async_url(url: str) -> str:
    """Ensure the database URL has an async-compatible driver.

    Handles the common case where a system env var provides a plain
    ``postgresql://`` URL without the async driver suffix.
    """
    if url.startswith("postgresql://") or url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
        logger.info("Auto-injected async driver: postgresql+psycopg://")
    elif url.startswith("postgresql+psycopg2://"):
        url = url.replace("postgresql+psycopg2://", "postgresql+psycopg://", 1)
        logger.info("Replaced psycopg2 with psycopg (async) driver")
    return url


_db_url = _resolve_async_url(settings.database_url)

# Build engine kwargs based on DB type
_engine_kwargs = {
    "echo": settings.debug,
}

if "sqlite" in _db_url:
    # SQLite needs special handling for async + in-memory / file
    _engine_kwargs.update({
        "connect_args": {"check_same_thread": False},
        "poolclass": StaticPool,
    })
else:
    # PostgreSQL
    _engine_kwargs["pool_pre_ping"] = True

engine = create_async_engine(_db_url, **_engine_kwargs)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


async def get_db():
    """FastAPI dependency that yields a database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Create all tables (development convenience — use Alembic in prod)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

