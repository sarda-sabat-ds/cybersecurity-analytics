"""Dashboard summary endpoint."""
import json
import logging
from collections import Counter
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import SecurityLog, Alert, Incident
from app.ml.detector import get_detection_engine
from app.schemas.reports import DashboardSummary
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


def _load_model_metrics() -> Optional[dict]:
    metrics_path = settings.models_path / "model_metrics.json"
    if metrics_path.exists():
        with open(metrics_path) as f:
            return json.load(f)
    return None


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(db: Session = Depends(get_db)):
    """
    Return dashboard statistics.
    All values are derived from real database records and model evaluation results.
    """
    engine = get_detection_engine()

    total_logs = db.query(SecurityLog).count()
    total_alerts = db.query(Alert).count()
    total_incidents = db.query(Incident).count()
    high_alerts = db.query(Alert).filter(Alert.severity == "high").count()
    critical_alerts = db.query(Alert).filter(Alert.severity == "critical").count()

    # Event type distribution (from logs)
    log_event_types = db.query(SecurityLog.event_type).all()
    event_type_dist = dict(Counter(r[0] for r in log_event_types if r[0]))

    # Severity distribution (from logs)
    log_severities = db.query(SecurityLog.severity).all()
    severity_dist = dict(Counter(r[0] for r in log_severities if r[0]))

    # Detection method distribution (from alerts)
    alert_methods = db.query(Alert.detection_method).all()
    method_dist = dict(Counter(r[0] for r in alert_methods if r[0]))

    # Recent alerts (last 10)
    recent_alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(10).all()
    recent_alert_list = [
        {
            "alert_id": a.alert_id,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "event_type": a.event_type,
            "severity": a.severity,
            "source_ip": a.source_ip,
            "affected_asset": a.affected_asset,
            "detection_method": a.detection_method,
        }
        for a in recent_alerts
    ]

    # Model metrics
    model_metrics = _load_model_metrics()
    simplified_metrics = None
    if model_metrics:
        best = model_metrics.get("best_model")
        bm_data = model_metrics.get("model_metrics", {}).get(best, {})
        simplified_metrics = {
            "best_model": best,
            "accuracy": bm_data.get("accuracy"),
            "f1_suspicious": bm_data.get("f1_suspicious"),
            "recall_suspicious": bm_data.get("recall_suspicious"),
            "precision_suspicious": bm_data.get("precision_suspicious"),
            "false_positive_rate": bm_data.get("false_positive_rate"),
            "trained_at": model_metrics.get("trained_at"),
            "all_models": {
                name: {
                    "accuracy": data.get("accuracy"),
                    "f1_suspicious": data.get("f1_suspicious"),
                    "recall_suspicious": data.get("recall_suspicious"),
                }
                for name, data in model_metrics.get("model_metrics", {}).items()
                if "accuracy" in data
            },
        }

    return DashboardSummary(
        total_logs=total_logs,
        total_alerts=total_alerts,
        total_incidents=total_incidents,
        high_severity_alerts=high_alerts,
        critical_alerts=critical_alerts,
        model_name=engine.model_name,
        model_loaded=engine.model_loaded,
        model_metrics=simplified_metrics,
        event_type_distribution=event_type_dist,
        severity_distribution=severity_dist,
        detection_method_distribution=method_dist,
        recent_alerts=recent_alert_list,
    )
