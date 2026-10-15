"""Database connection and session management."""
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator
from app.database.models import Base
from app.config import settings

logger = logging.getLogger(__name__)

# Use a file-based SQLite database stored under data/
DB_PATH = settings.raw_data_dir.parent / "cybersecurity.db"
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Create all tables."""
    settings.ensure_directories()
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created/verified at %s", DB_PATH)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for DB sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
