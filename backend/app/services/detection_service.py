"""Service layer for detection, correlation, and compliance operations.

Every write goes to both SQLite (primary) and MongoDB (mirror).
MongoDB writes are fire-and-forget — never block the main workflow.
"""
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import pandas as pd
from sqlalchemy.orm import Session

from app.database.models import Alert, Incident, ComplianceMapping
from app.database.mongo import (
    write_alerts_bulk, write_incident, write_compliance, write_report,
)
from app.ml.detector import get_detection_engine
from app.correlation.engine import correlate_alerts
from app.compliance.mappings import map_alerts_to_compliance

logger = logging.getLogger(__name__)


def run_detection_on_logs(db: Session, log_records: List[Dict]) -> List[Dict]:
    """Run detection engine on log records and persist alerts to SQLite + MongoDB."""
    if not log_records:
        return []

    engine = get_detection_engine()
    df = pd.DataFrame(log_records)
    alerts_data = engine.detect_batch(df)

    new_alerts: List[Alert]  = []
    mongo_docs: List[Dict]   = []
    all_persisted: List[Dict] = []

    for a in alerts_data:
        existing = db.query(Alert).filter(Alert.alert_id == a["alert_id"]).first()
        if existing:
            all_persisted.append(a)
            continue

        orm_row = Alert(
            alert_id         = a["alert_id"],
            log_id           = a.get("log_id"),
            timestamp        = _parse_ts(a.get("timestamp")),
            event_type       = a.get("event_type"),
            source_ip        = a.get("source_ip"),
            affected_asset   = a.get("affected_asset"),
            severity         = a.get("severity", "medium"),
            ml_prediction    = a.get("ml_prediction"),
            confidence_score = a.get("confidence_score"),
            detection_reason = a.get("detection_reason"),
            evidence         = a.get("evidence", []),
            recommended_action = a.get("recommended_action"),
            detection_method = a.get("detection_method"),
        )
        new_alerts.append(orm_row)

        # MongoDB document (same shape, no ORM mapping needed)
        mongo_docs.append({
            "alert_id":          a["alert_id"],
            "log_id":            a.get("log_id"),
            "timestamp":         str(a.get("timestamp", "")),
            "event_type":        a.get("event_type", ""),
            "source_ip":         a.get("source_ip", ""),
            "affected_asset":    a.get("affected_asset", ""),
            "severity":          a.get("severity", "medium"),
            "ml_prediction":     a.get("ml_prediction"),
            "confidence_score":  a.get("confidence_score"),
            "detection_reason":  a.get("detection_reason", ""),
            "evidence":          a.get("evidence", []),
            "recommended_action": a.get("recommended_action", ""),
            "detection_method":  a.get("detection_method", "rule"),
        })
        all_persisted.append(a)

    if new_alerts:
        db.add_all(new_alerts)
        db.commit()
        write_alerts_bulk(mongo_docs)   # MongoDB dual-write

    logger.info("Persisted %d alerts (%d new)", len(all_persisted), len(new_alerts))
    return all_persisted


def run_correlation(db: Session) -> List[Dict]:
    """Correlate all alerts and persist incidents to SQLite + MongoDB."""
    alert_rows = db.query(Alert).all()
    if not alert_rows:
        return []

    alerts = [_alert_to_dict(a) for a in alert_rows]
    incidents_data = correlate_alerts(alerts)

    persisted = []
    for inc in incidents_data:
        existing = db.query(Incident).filter(
            Incident.incident_id == inc["incident_id"]
        ).first()
        if existing:
            persisted.append(_incident_to_dict(existing))
            continue

        inc_row = Incident(
            incident_id    = inc["incident_id"],
            category       = inc["category"],
            first_seen     = _parse_ts(inc.get("first_seen")),
            last_seen      = _parse_ts(inc.get("last_seen")),
            affected_assets = inc.get("affected_assets", []),
            severity       = inc.get("severity", "medium"),
            alert_ids      = inc.get("alert_ids", []),
            evidence_summary = inc.get("evidence_summary"),
            remediation    = inc.get("remediation"),
            status         = "open",
        )
        db.add(inc_row)

        for aid in inc.get("alert_ids", []):
            ar = db.query(Alert).filter(Alert.alert_id == aid).first()
            if ar:
                ar.incident_id = inc["incident_id"]

        # MongoDB dual-write
        write_incident({
            "incident_id":     inc["incident_id"],
            "category":        inc["category"],
            "first_seen":      str(inc.get("first_seen", "")),
            "last_seen":       str(inc.get("last_seen", "")),
            "affected_assets": inc.get("affected_assets", []),
            "severity":        inc.get("severity", "medium"),
            "alert_ids":       inc.get("alert_ids", []),
            "alert_count":     len(inc.get("alert_ids", [])),
            "evidence_summary": inc.get("evidence_summary", ""),
            "remediation":     inc.get("remediation", ""),
            "status":          "open",
        })
        persisted.append(inc)

    db.commit()
    logger.info("Persisted %d incidents", len(persisted))
    return persisted


def run_compliance_mapping(db: Session) -> List[Dict]:
    """Map alerts to compliance controls and persist to SQLite + MongoDB."""
    alert_rows = db.query(Alert).all()
    if not alert_rows:
        return []

    alerts = [_alert_to_dict(a) for a in alert_rows]
    mappings_data = map_alerts_to_compliance(alerts)

    persisted = []
    for m in mappings_data:
        existing = db.query(ComplianceMapping).filter(
            ComplianceMapping.mapping_id == m["mapping_id"]
        ).first()
        if existing:
            persisted.append(m)
            continue

        db.add(ComplianceMapping(
            mapping_id        = m["mapping_id"],
            alert_id          = m["alert_id"],
            framework         = m["framework"],
            framework_version = m["framework_version"],
            control_id        = m["control_id"],
            control_title     = m["control_title"],
            finding_description = m["finding_description"],
            evidence          = m["evidence"],
            risk_level        = m["risk_level"],
            remediation       = m["remediation"],
            disclaimer        = m["disclaimer"],
        ))
        write_compliance(m)   # MongoDB dual-write
        persisted.append(m)

    db.commit()
    logger.info("Persisted %d compliance mappings", len(persisted))
    return persisted


def persist_report_to_mongo(report_data: Dict) -> None:
    """Write a generated report's metadata to MongoDB."""
    write_report({
        "report_id":    report_data.get("report_id", ""),
        "title":        report_data.get("title", ""),
        "generated_at": report_data.get("generated_at", ""),
        "file_path":    report_data.get("file_path", ""),
        "summary":      report_data.get("summary", {}),
        "status":       "completed",
    })


# ── helpers ────────────────────────────────────────────────────────────────

def _parse_ts(ts_str) -> datetime:
    if not ts_str:
        return datetime.utcnow()
    try:
        return pd.to_datetime(ts_str).to_pydatetime()
    except Exception:
        return datetime.utcnow()


def _alert_to_dict(a: Alert) -> Dict:
    return {
        "alert_id":         a.alert_id,
        "log_id":           a.log_id,
        "timestamp":        a.timestamp.isoformat() if a.timestamp else None,
        "event_type":       a.event_type or "",
        "source_ip":        a.source_ip or "",
        "affected_asset":   a.affected_asset or "",
        "severity":         a.severity or "medium",
        "ml_prediction":    a.ml_prediction,
        "confidence_score": a.confidence_score,
        "detection_reason": a.detection_reason or "",
        "evidence":         a.evidence or [],
        "recommended_action": a.recommended_action or "",
        "detection_method": a.detection_method or "rule",
    }


def _incident_to_dict(inc: Incident) -> Dict:
    return {
        "incident_id":    inc.incident_id,
        "category":       inc.category,
        "first_seen":     inc.first_seen.isoformat() if inc.first_seen else None,
        "last_seen":      inc.last_seen.isoformat()  if inc.last_seen  else None,
        "affected_assets": inc.affected_assets or [],
        "severity":       inc.severity,
        "alert_ids":      inc.alert_ids or [],
        "evidence_summary": inc.evidence_summary,
        "remediation":    inc.remediation,
        "status":         inc.status,
        "alert_count":    len(inc.alert_ids or []),
    }
