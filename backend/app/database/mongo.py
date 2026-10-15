"""
MongoDB connection and collection helpers.

Architecture: dual-write — every record written to SQLite is ALSO written
to MongoDB. SQLite remains the primary read source for existing API endpoints.
MongoDB provides NoSQL access, rich querying, and analytics capabilities.

Collections:
  security_logs       — raw ingested log records
  alerts              — ML + rule-based detections
  incidents           — correlated alert groups
  compliance_mappings — framework control associations
  reports             — generated report metadata
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pymongo import MongoClient, ASCENDING, DESCENDING, IndexModel
from pymongo.database import Database
from pymongo.collection import Collection
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from app.config import settings

logger = logging.getLogger(__name__)

_client: Optional[MongoClient] = None
_db: Optional[Database] = None


def get_mongo_client() -> Optional[MongoClient]:
    """Return the shared MongoClient, creating it on first call."""
    global _client
    if _client is None:
        try:
            _client = MongoClient(
                settings.MONGODB_URI,
                serverSelectionTimeoutMS=3000,
                connectTimeoutMS=3000,
            )
            # Ping to verify connection
            _client.admin.command("ping")
            logger.info("MongoDB connected: %s", settings.MONGODB_URI)
        except (ConnectionFailure, ServerSelectionTimeoutError) as exc:
            logger.warning("MongoDB unavailable (%s) — MongoDB writes disabled.", exc)
            _client = None
    return _client


def get_mongo_db() -> Optional[Database]:
    """Return the analytics database, or None if MongoDB is unavailable."""
    global _db
    client = get_mongo_client()
    if client is None:
        return None
    if _db is None:
        _db = client[settings.MONGODB_DB]
    return _db


def mongo_available() -> bool:
    """True if MongoDB is reachable."""
    return get_mongo_db() is not None


# ── Collection accessors ────────────────────────────────────────────

def col_logs() -> Optional[Collection]:
    db = get_mongo_db()
    return db["security_logs"] if db is not None else None

def col_alerts() -> Optional[Collection]:
    db = get_mongo_db()
    return db["alerts"] if db is not None else None

def col_incidents() -> Optional[Collection]:
    db = get_mongo_db()
    return db["incidents"] if db is not None else None

def col_compliance() -> Optional[Collection]:
    db = get_mongo_db()
    return db["compliance_mappings"] if db is not None else None

def col_reports() -> Optional[Collection]:
    db = get_mongo_db()
    return db["reports"] if db is not None else None


# ── Index creation ──────────────────────────────────────────────────

def ensure_indexes():
    """Create indexes on all collections for fast querying."""
    db = get_mongo_db()
    if db is None:
        logger.warning("MongoDB unavailable — skipping index creation.")
        return

    try:
        db["security_logs"].create_indexes([
            IndexModel([("log_id", ASCENDING)],   unique=True, name="log_id_uniq"),
            IndexModel([("timestamp", DESCENDING)], name="ts_desc"),
            IndexModel([("event_type", ASCENDING)], name="event_type"),
            IndexModel([("severity", ASCENDING)],   name="severity"),
            IndexModel([("source_ip", ASCENDING)],  name="source_ip"),
            IndexModel([("label", ASCENDING)],      name="label"),
        ])

        db["alerts"].create_indexes([
            IndexModel([("alert_id", ASCENDING)],   unique=True, name="alert_id_uniq"),
            IndexModel([("timestamp", DESCENDING)], name="ts_desc"),
            IndexModel([("severity", ASCENDING)],   name="severity"),
            IndexModel([("event_type", ASCENDING)], name="event_type"),
            IndexModel([("detection_method", ASCENDING)], name="method"),
            IndexModel([("source_ip", ASCENDING)],  name="source_ip"),
        ])

        db["incidents"].create_indexes([
            IndexModel([("incident_id", ASCENDING)], unique=True, name="incident_id_uniq"),
            IndexModel([("last_seen", DESCENDING)],  name="last_seen"),
            IndexModel([("severity", ASCENDING)],    name="severity"),
            IndexModel([("category", ASCENDING)],    name="category"),
            IndexModel([("status", ASCENDING)],      name="status"),
        ])

        db["compliance_mappings"].create_indexes([
            IndexModel([("mapping_id", ASCENDING)],  unique=True, name="mapping_id_uniq"),
            IndexModel([("control_id", ASCENDING)],  name="control_id"),
            IndexModel([("framework", ASCENDING)],   name="framework"),
            IndexModel([("risk_level", ASCENDING)],  name="risk_level"),
        ])

        db["reports"].create_indexes([
            IndexModel([("report_id", ASCENDING)],     unique=True, name="report_id_uniq"),
            IndexModel([("generated_at", DESCENDING)], name="generated_at"),
        ])

        logger.info("MongoDB indexes ensured on all collections.")
    except Exception as exc:
        logger.error("Failed to create MongoDB indexes: %s", exc)


# ── Safe upsert helpers — used by service layer ─────────────────────

def _safe_upsert(collection: Optional[Collection], filter_key: str,
                 doc: Dict[str, Any]) -> bool:
    """
    Upsert a single document. Returns True on success, False if MongoDB
    is unavailable or the operation fails (never raises).
    """
    if collection is None:
        return False
    try:
        collection.update_one(
            {filter_key: doc[filter_key]},
            {"$set": doc},
            upsert=True,
        )
        return True
    except Exception as exc:
        logger.debug("MongoDB upsert failed: %s", exc)
        return False


def _safe_insert_many(collection: Optional[Collection],
                      docs: List[Dict[str, Any]],
                      ordered: bool = False) -> int:
    """
    Bulk-insert documents, skipping duplicates via unordered mode.
    Returns number of inserted documents.
    """
    if collection is None or not docs:
        return 0
    try:
        result = collection.insert_many(docs, ordered=ordered)
        return len(result.inserted_ids)
    except Exception as exc:
        # BulkWriteError includes partial success info — ignore duplicate key errors
        inserted = getattr(getattr(exc, "details", {}), "get", lambda *a: 0)("nInserted", 0)
        logger.debug("MongoDB bulk insert partial: %s", exc)
        return inserted


# ── Public write functions ──────────────────────────────────────────

def write_log(log_doc: Dict[str, Any]) -> bool:
    """Write a single security log to MongoDB."""
    return _safe_upsert(col_logs(), "log_id", log_doc)


def write_logs_bulk(log_docs: List[Dict[str, Any]]) -> int:
    """Bulk-insert security logs. Returns count inserted."""
    return _safe_insert_many(col_logs(), log_docs)


def write_alert(alert_doc: Dict[str, Any]) -> bool:
    return _safe_upsert(col_alerts(), "alert_id", alert_doc)


def write_alerts_bulk(alert_docs: List[Dict[str, Any]]) -> int:
    return _safe_insert_many(col_alerts(), alert_docs)


def write_incident(incident_doc: Dict[str, Any]) -> bool:
    return _safe_upsert(col_incidents(), "incident_id", incident_doc)


def write_compliance(mapping_doc: Dict[str, Any]) -> bool:
    return _safe_upsert(col_compliance(), "mapping_id", mapping_doc)


def write_report(report_doc: Dict[str, Any]) -> bool:
    return _safe_upsert(col_reports(), "report_id", report_doc)


# ── Analytics helpers (MongoDB-only queries) ─────────────────────────

def get_mongo_stats() -> Dict[str, Any]:
    """Return record counts across all collections."""
    db = get_mongo_db()
    if db is None:
        return {"available": False}
    try:
        return {
            "available": True,
            "database": settings.MONGODB_DB,
            "collections": {
                "security_logs":       db["security_logs"].estimated_document_count(),
                "alerts":              db["alerts"].estimated_document_count(),
                "incidents":           db["incidents"].estimated_document_count(),
                "compliance_mappings": db["compliance_mappings"].estimated_document_count(),
                "reports":             db["reports"].estimated_document_count(),
            },
        }
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def aggregate_event_types(limit: int = 20) -> List[Dict]:
    """MongoDB aggregation: top N event types by count."""
    c = col_logs()
    if c is None:
        return []
    try:
        pipeline = [
            {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": limit},
            {"$project": {"_id": 0, "event_type": "$_id", "count": 1}},
        ]
        return list(c.aggregate(pipeline))
    except Exception:
        return []


def aggregate_severity_trend(days: int = 30) -> List[Dict]:
    """MongoDB aggregation: daily alert counts by severity over last N days."""
    c = col_alerts()
    if c is None:
        return []
    try:
        cutoff = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        from datetime import timedelta
        cutoff = cutoff.replace(tzinfo=None) - timedelta(days=days)
        pipeline = [
            {"$match": {"timestamp": {"$gte": cutoff.isoformat()}}},
            {"$group": {
                "_id": {
                    "date":     {"$dateToString": {"format": "%Y-%m-%d", "date": {"$dateFromString": {"dateString": "$timestamp"}}}},
                    "severity": "$severity",
                },
                "count": {"$sum": 1},
            }},
            {"$sort": {"_id.date": 1}},
            {"$project": {"_id": 0, "date": "$_id.date", "severity": "$_id.severity", "count": 1}},
        ]
        return list(c.aggregate(pipeline))
    except Exception:
        return []


def get_top_attackers(limit: int = 10) -> List[Dict]:
    """MongoDB aggregation: source IPs with the most alerts."""
    c = col_alerts()
    if c is None:
        return []
    try:
        pipeline = [
            {"$match": {"source_ip": {"$exists": True, "$ne": ""}}},
            {"$group": {"_id": "$source_ip", "alert_count": {"$sum": 1},
                        "severities": {"$addToSet": "$severity"}}},
            {"$sort": {"alert_count": -1}},
            {"$limit": limit},
            {"$project": {"_id": 0, "source_ip": "$_id",
                          "alert_count": 1, "severities": 1}},
        ]
        return list(c.aggregate(pipeline))
    except Exception:
        return []


def get_asset_risk_scores(limit: int = 15) -> List[Dict]:
    """MongoDB aggregation: affected assets ranked by weighted risk score."""
    c = col_alerts()
    if c is None:
        return []
    try:
        pipeline = [
            {"$match": {"affected_asset": {"$exists": True, "$ne": ""}}},
            {"$addFields": {
                "risk_weight": {"$switch": {
                    "branches": [
                        {"case": {"$eq": ["$severity", "critical"]}, "then": 4},
                        {"case": {"$eq": ["$severity", "high"]},     "then": 3},
                        {"case": {"$eq": ["$severity", "medium"]},   "then": 2},
                    ],
                    "default": 1,
                }},
            }},
            {"$group": {
                "_id": "$affected_asset",
                "alert_count": {"$sum": 1},
                "risk_score":  {"$sum": "$risk_weight"},
                "event_types": {"$addToSet": "$event_type"},
            }},
            {"$sort": {"risk_score": -1}},
            {"$limit": limit},
            {"$project": {"_id": 0, "asset": "$_id",
                          "alert_count": 1, "risk_score": 1,
                          "event_types": 1}},
        ]
        return list(c.aggregate(pipeline))
    except Exception:
        return []
