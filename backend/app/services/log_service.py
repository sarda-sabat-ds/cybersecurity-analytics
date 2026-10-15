"""Service layer for log ingestion, retrieval, and management.

Every write goes to both SQLite (primary) and MongoDB (mirror/analytics).
MongoDB writes are fire-and-forget — a MongoDB failure never blocks ingestion.
"""
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from sqlalchemy.orm import Session

from app.database.models import SecurityLog
from app.database.mongo import write_logs_bulk

logger = logging.getLogger(__name__)

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _clean_row(row: Any, idx: int) -> Optional[Tuple[SecurityLog, Dict]]:
    """
    Parse a DataFrame row into a SecurityLog ORM object and a MongoDB dict.
    Returns None on error.
    """
    try:
        log_id = str(row.get("log_id", "") or "") or str(uuid.uuid4())

        ts_raw = row.get("timestamp")
        try:
            ts = pd.to_datetime(ts_raw).to_pydatetime() if pd.notna(ts_raw) else datetime.utcnow()
        except Exception:
            ts = datetime.utcnow()

        severity = str(row.get("severity", "low") or "low").lower().strip()
        if severity not in VALID_SEVERITIES:
            severity = "low"

        raw_label = row.get("label")
        label = str(raw_label) if pd.notna(raw_label) else None
        if label not in {None, "normal", "suspicious"}:
            label = None

        orm_obj = SecurityLog(
            log_id=log_id,
            timestamp=ts,
            source_ip=str(row.get("source_ip", "") or "") or None,
            destination_ip=str(row.get("destination_ip", "") or "") or None,
            event_type=str(row.get("event_type", "unknown")),
            severity=severity,
            failed_login_count=int(row.get("failed_login_count", 0) or 0),
            request_count=int(row.get("request_count", 0) or 0),
            port=int(row.get("port", 0) or 0) or None,
            affected_asset=str(row.get("affected_asset", "") or "") or None,
            label=label,
            raw_data=row.to_dict(),
        )

        # MongoDB document — richer than the SQLite row
        mongo_doc = {
            "log_id":             log_id,
            "timestamp":          ts.isoformat(),
            "source_ip":          orm_obj.source_ip,
            "destination_ip":     orm_obj.destination_ip,
            "event_type":         orm_obj.event_type,
            "severity":           severity,
            "failed_login_count": orm_obj.failed_login_count,
            "request_count":      orm_obj.request_count,
            "port":               orm_obj.port,
            "affected_asset":     orm_obj.affected_asset,
            "label":              label,
            # Extra fields from the expanded dataset
            "username":           str(row.get("username", "") or "") or None,
            "bytes_transferred":  int(row.get("bytes_transferred", 0) or 0),
            "user_agent":         str(row.get("user_agent", "") or "") or None,
            "process_name":       str(row.get("process_name", "") or "") or None,
        }
        return orm_obj, mongo_doc

    except Exception as exc:
        logger.debug("Row %s parse error: %s", idx, exc)
        return None


def ingest_dataframe(
    db: Session,
    df: pd.DataFrame,
    batch_size: int = 1000,
) -> Tuple[int, int, List[str]]:
    """
    Insert log records from a DataFrame into SQLite AND MongoDB.

    Returns (imported_count, skipped_count, warnings).
    Uses batched commits for efficiency on large datasets.
    """
    imported = 0
    skipped  = 0
    warnings: List[str] = []

    # Pre-fetch all existing log_ids to avoid per-row DB queries
    existing_ids = {
        row[0] for row in db.query(SecurityLog.log_id).all()
    }

    orm_batch:   List[SecurityLog] = []
    mongo_batch: List[Dict]        = []

    for idx, row in df.iterrows():
        parsed = _clean_row(row, idx)
        if parsed is None:
            skipped += 1
            warnings.append(f"Row {idx}: parse error")
            continue

        orm_obj, mongo_doc = parsed

        if orm_obj.log_id in existing_ids:
            skipped += 1
            continue

        existing_ids.add(orm_obj.log_id)
        orm_batch.append(orm_obj)
        mongo_batch.append(mongo_doc)

        if len(orm_batch) >= batch_size:
            db.add_all(orm_batch)
            db.commit()
            write_logs_bulk(mongo_batch)   # MongoDB dual-write
            imported += len(orm_batch)
            orm_batch.clear()
            mongo_batch.clear()

    # Final partial batch
    if orm_batch:
        db.add_all(orm_batch)
        db.commit()
        write_logs_bulk(mongo_batch)
        imported += len(orm_batch)

    logger.info("Ingested %d records, skipped %d", imported, skipped)
    return imported, skipped, warnings


def get_logs(
    db: Session,
    page: int = 1,
    page_size: int = 50,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
) -> Tuple[int, List[SecurityLog]]:
    """Retrieve logs from SQLite with pagination and optional filters."""
    query = db.query(SecurityLog)
    if event_type:
        query = query.filter(SecurityLog.event_type.ilike(f"%{event_type}%"))
    if severity:
        query = query.filter(SecurityLog.severity == severity.lower())
    if source_ip:
        query = query.filter(SecurityLog.source_ip.ilike(f"%{source_ip}%"))

    total = query.count()
    items = (
        query.order_by(SecurityLog.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return total, items
