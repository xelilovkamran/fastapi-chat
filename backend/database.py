from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os
import logging

logger = logging.getLogger(__name__)

load_dotenv()

# You should create a .env file with your database URL
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./chat.db")

logger.info(f"Initializing database connection with URL: {DATABASE_URL}")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency


def get_db():
    db = SessionLocal()
    try:
        logger.debug("Creating new database session")
        yield db
    finally:
        logger.debug("Closing database session")
        db.close()
