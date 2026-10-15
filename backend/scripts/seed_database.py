"""
seed_database.py — Seeds SQLite + syncs to MongoDB.

Usage:
    cd backend
    python scripts/seed_database.py           # incremental
    python scripts/seed_database.py --reset   # wipe and reseed
"""
import argparse
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd

from app.config import settings
from app.database.connection import init_db, SessionLocal
from app.database.models import SecurityLog, Alert, Incident, ComplianceMapping
from app.database.mongo import (
    ensure_indexes, get_mongo_stats,
    write_logs_bulk, write_alerts_bulk, write_incident, write_compliance,
)
from app.ml.dataset_generator import generate_synthetic_dataset
from app.services.log_service import ingest_dataframe
from app.services.detection_service import (
    run_detection_on_logs, run_correlation, run_compliance_mapping,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── MongoDB sync (defined BEFORE seed() so it can be called from it) ──

def _sync_sqlite_to_mongo(db):
    """Bulk-sync all SQLite records to MongoDB (idempotent upserts)."""
    logger.info("Syncing SQLite → MongoDB (idempotent)...")
    CHUNK = 2000

    # Logs
    total_logs = db.query(SecurityLog).count()
    synced_logs = 0
    for offset in range(0, total_logs, CHUNK):
        rows = db.query(SecurityLog).order_by(SecurityLog.id).offset(offset).limit(CHUNK).all()
        docs = [{
            "log_id":             r.log_id,
            "timestamp":          r.timestamp.isoformat() if r.timestamp else None,
            "source_ip":          r.source_ip,
            "destination_ip":     r.destination_ip,
            "event_type":         r.event_type,
            "severity":           r.severity,
            "failed_login_count": r.failed_login_count,
            "request_count":      r.request_count,
            "port":               r.port,
            "affected_asset":     r.affected_asset,
            "label":              r.label,
            "username":           (r.raw_data or {}).get("username"),
            "bytes_transferred":  (r.raw_data or {}).get("bytes_transferred", 0),
            "user_agent":         (r.raw_data or {}).get("user_agent"),
            "process_name":       (r.raw_data or {}).get("process_name"),
        } for r in rows]
        write_logs_bulk(docs)
        synced_logs += len(docs)
    logger.info("  Synced %d logs", synced_logs)

    # Alerts
    total_alerts = db.query(Alert).count()
    synced_alerts = 0
    for offset in range(0, total_alerts, CHUNK):
        rows = db.query(Alert).order_by(Alert.id).offset(offset).limit(CHUNK).all()
        docs = [{
            "alert_id":           r.alert_id,
            "log_id":             r.log_id,
            "timestamp":          r.timestamp.isoformat() if r.timestamp else None,
            "event_type":         r.event_type or "",
            "source_ip":          r.source_ip or "",
            "affected_asset":     r.affected_asset or "",
            "severity":           r.severity or "medium",
            "ml_prediction":      r.ml_prediction,
            "confidence_score":   r.confidence_score,
            "detection_reason":   r.detection_reason or "",
            "evidence":           r.evidence or [],
            "recommended_action": r.recommended_action or "",
            "detection_method":   r.detection_method or "rule",
        } for r in rows]
        write_alerts_bulk(docs)
        synced_alerts += len(docs)
    logger.info("  Synced %d alerts", synced_alerts)

    # Incidents
    all_incidents = db.query(Incident).all()
    for r in all_incidents:
        write_incident({
            "incident_id":      r.incident_id,
            "category":         r.category,
            "first_seen":       r.first_seen.isoformat() if r.first_seen else None,
            "last_seen":        r.last_seen.isoformat()  if r.last_seen  else None,
            "affected_assets":  r.affected_assets or [],
            "severity":         r.severity,
            "alert_ids":        r.alert_ids or [],
            "alert_count":      len(r.alert_ids or []),
            "evidence_summary": r.evidence_summary or "",
            "remediation":      r.remediation or "",
            "status":           r.status or "open",
        })
    logger.info("  Synced %d incidents", len(all_incidents))

    # Compliance
    all_mappings = db.query(ComplianceMapping).all()
    for r in all_mappings:
        write_compliance({
            "mapping_id":          r.mapping_id,
            "alert_id":            r.alert_id,
            "framework":           r.framework,
            "framework_version":   r.framework_version,
            "control_id":          r.control_id,
            "control_title":       r.control_title or "",
            "finding_description": r.finding_description or "",
            "evidence":            r.evidence or "",
            "risk_level":          r.risk_level or "low",
            "remediation":         r.remediation or "",
            "disclaimer":          r.disclaimer or "",
        })
    logger.info("  Synced %d compliance mappings", len(all_mappings))
    logger.info("SQLite → MongoDB sync complete.")


# ── Main seed function ─────────────────────────────────────────────

def seed(reset: bool = False):
    settings.ensure_directories()
    init_db()

    mongo_stats = get_mongo_stats()
    if mongo_stats.get("available"):
        ensure_indexes()
        logger.info("MongoDB connected — db=%s", mongo_stats.get("database"))
    else:
        logger.warning("MongoDB unavailable — SQLite only. Error: %s",
                       mongo_stats.get("error", "connection failed"))

    db = SessionLocal()
    try:
        if reset:
            logger.info("--reset: wiping all existing data...")
            db.query(ComplianceMapping).delete()
            db.query(Alert).delete()
            db.query(Incident).delete()
            db.query(SecurityLog).delete()
            db.commit()
            logger.info("All tables cleared.")

        synthetic_path = settings.synthetic_data_dir / "synthetic_logs.csv"
        if not synthetic_path.exists():
            logger.info("Generating synthetic dataset...")
            df = generate_synthetic_dataset(
                n_normal=30_000, n_suspicious=10_000, n_campaigns=200,
                output_path=synthetic_path,
            )
        else:
            df = pd.read_csv(synthetic_path, low_memory=False)
            logger.info("Loaded synthetic dataset: %d records", len(df))

        logger.info("Ingesting logs...")
        imported, skipped, warnings = ingest_dataframe(db, df)
        logger.info("Imported: %d  Skipped: %d", imported, skipped)

        logger.info("Running detection...")
        batch_size = 5_000
        all_alerts = []
        records = df.to_dict(orient="records")
        for i in range(0, len(records), batch_size):
            batch_alerts = run_detection_on_logs(db, records[i:i + batch_size])
            all_alerts.extend(batch_alerts)
            logger.info("  %d/%d → %d alerts",
                        min(i + batch_size, len(records)), len(records), len(all_alerts))

        logger.info("Running correlation...")
        incidents = run_correlation(db)

        logger.info("Running compliance mapping...")
        mappings = run_compliance_mapping(db)

        # Sync everything to MongoDB
        if mongo_stats.get("available"):
            _sync_sqlite_to_mongo(db)

        print()
        print("=" * 55)
        print("  DATABASE SEEDED SUCCESSFULLY")
        print("=" * 55)
        print(f"  Logs imported : {imported:,}")
        print(f"  Logs skipped  : {skipped:,}")
        print(f"  Alerts        : {len(all_alerts):,}")
        print(f"  Incidents     : {len(incidents):,}")
        print(f"  Compliance    : {len(mappings):,}")
        print(f"  MongoDB       : {'synced' if mongo_stats.get('available') else 'unavailable'}")
        print("=" * 55)

    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true",
                        help="Wipe all existing data before seeding")
    args = parser.parse_args()
    seed(reset=args.reset)
