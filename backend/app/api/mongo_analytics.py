"""
MongoDB analytics endpoints.

These endpoints run aggregation pipelines directly on MongoDB collections,
providing fast analytics that would be expensive in SQLite.

All endpoints gracefully return empty data when MongoDB is unavailable
rather than returning 503 — the platform always works via SQLite.
"""
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query, HTTPException, status

from app.database.mongo import (
    get_mongo_stats,
    aggregate_event_types,
    aggregate_severity_trend,
    get_top_attackers,
    get_asset_risk_scores,
    mongo_available,
    col_logs,
    col_alerts,
    col_incidents,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/mongodb", tags=["MongoDB Analytics"])


@router.get("/status")
def mongodb_status():
    """
    MongoDB connection status and collection record counts.
    Always returns 200 — check 'available' field for connection state.
    """
    return get_mongo_stats()


@router.get("/event-types")
def top_event_types(limit: int = Query(20, ge=1, le=100)):
    """Top N event types by frequency (MongoDB aggregation)."""
    return aggregate_event_types(limit=limit)


@router.get("/severity-trend")
def severity_trend(days: int = Query(30, ge=1, le=365)):
    """Daily alert counts grouped by severity for the last N days."""
    return aggregate_severity_trend(days=days)


@router.get("/top-attackers")
def top_attackers(limit: int = Query(10, ge=1, le=50)):
    """Source IPs responsible for the most alerts, ranked by alert count."""
    return get_top_attackers(limit=limit)


@router.get("/asset-risk")
def asset_risk(limit: int = Query(15, ge=1, le=50)):
    """
    Assets ranked by weighted risk score.
    Score = sum of (critical×4, high×3, medium×2, low×1) across all alerts.
    """
    return get_asset_risk_scores(limit=limit)


@router.get("/logs/search")
def search_logs(
    event_type: Optional[str] = Query(None),
    severity:   Optional[str] = Query(None),
    source_ip:  Optional[str] = Query(None),
    label:      Optional[str] = Query(None),
    limit:      int           = Query(100, ge=1, le=1000),
    skip:       int           = Query(0,   ge=0),
):
    """
    Full MongoDB query on security_logs collection.
    Supports filtering by event_type, severity, source_ip, label.
    """
    c = col_logs()
    if c is None:
        return {"available": False, "results": []}

    filt: Dict[str, Any] = {}
    if event_type:
        filt["event_type"] = {"$regex": event_type, "$options": "i"}
    if severity:
        filt["severity"] = severity.lower()
    if source_ip:
        filt["source_ip"] = {"$regex": source_ip, "$options": "i"}
    if label:
        filt["label"] = label.lower()

    try:
        total = c.count_documents(filt)
        docs  = list(
            c.find(filt, {"_id": 0})
             .sort("timestamp", -1)
             .skip(skip)
             .limit(limit)
        )
        return {"available": True, "total": total, "returned": len(docs), "results": docs}
    except Exception as exc:
        logger.error("MongoDB logs search failed: %s", exc)
        return {"available": False, "error": str(exc), "results": []}


@router.get("/alerts/search")
def search_alerts(
    severity:         Optional[str] = Query(None),
    detection_method: Optional[str] = Query(None),
    source_ip:        Optional[str] = Query(None),
    limit:            int           = Query(100, ge=1, le=1000),
    skip:             int           = Query(0,   ge=0),
):
    """Full MongoDB query on alerts collection."""
    c = col_alerts()
    if c is None:
        return {"available": False, "results": []}

    filt: Dict[str, Any] = {}
    if severity:
        filt["severity"] = severity.lower()
    if detection_method:
        filt["detection_method"] = detection_method.lower()
    if source_ip:
        filt["source_ip"] = {"$regex": source_ip, "$options": "i"}

    try:
        total = c.count_documents(filt)
        docs  = list(
            c.find(filt, {"_id": 0})
             .sort("timestamp", -1)
             .skip(skip)
             .limit(limit)
        )
        return {"available": True, "total": total, "returned": len(docs), "results": docs}
    except Exception as exc:
        logger.error("MongoDB alerts search failed: %s", exc)
        return {"available": False, "error": str(exc), "results": []}


@router.get("/incidents/search")
def search_incidents(
    severity: Optional[str] = Query(None),
    status:   Optional[str] = Query(None),
    limit:    int           = Query(50, ge=1, le=500),
    skip:     int           = Query(0,  ge=0),
):
    """Full MongoDB query on incidents collection."""
    c = col_incidents()
    if c is None:
        return {"available": False, "results": []}

    filt: Dict[str, Any] = {}
    if severity:
        filt["severity"] = severity.lower()
    if status:
        filt["status"] = status.lower()

    try:
        total = c.count_documents(filt)
        docs  = list(
            c.find(filt, {"_id": 0})
             .sort("last_seen", -1)
             .skip(skip)
             .limit(limit)
        )
        return {"available": True, "total": total, "returned": len(docs), "results": docs}
    except Exception as exc:
        logger.error("MongoDB incidents search failed: %s", exc)
        return {"available": False, "error": str(exc), "results": []}
