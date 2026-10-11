"""Database interface for C1 URL and Domain Analyzer (MongoDB with offline fallback)."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional
from app.config import get_settings

logger = logging.getLogger(__name__)

_mongo_client = None
_db = None


def init_db() -> bool:
    """Attempt connection to MongoDB; return True if successful, False if offline."""
    global _mongo_client, _db
    settings = get_settings()
    try:
        from pymongo import MongoClient
        client = MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=2000)
        client.admin.command("ping")
        _mongo_client = client
        _db = client[settings.mongodb_database]
        logger.info("Connected to MongoDB database: %s", settings.mongodb_database)
        return True
    except Exception as exc:
        logger.warning("MongoDB not reachable (%s). Operating in standalone/in-memory mode.", exc)
        _mongo_client = None
        _db = None
        return False


def ping() -> bool:
    """Return True if MongoDB connection is active."""
    if _mongo_client is None:
        return False
    try:
        _mongo_client.admin.command("ping")
        return True
    except Exception:
        return False


def close_db() -> None:
    """Close MongoDB client connection."""
    global _mongo_client, _db
    if _mongo_client:
        _mongo_client.close()
        _mongo_client = None
        _db = None


def save_scan_result(scan_data: Dict[str, Any]) -> bool:
    """Save analysis record to database if active."""
    if _db is not None:
        try:
            _db.scans.insert_one(scan_data)
            return True
        except Exception as exc:
            logger.error("Failed to persist scan result: %s", exc)
    return False
