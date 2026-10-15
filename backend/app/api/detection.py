"""Detection, alert, and incident endpoints."""
import json
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import Alert, Incident
from app.schemas.alerts import DetectRequest, DetectResponse, AlertResponse, IncidentResponse
from app.services.detection_service import (
    run_detection_on_logs, run_correlation, run_compliance_mapping
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["Detection"])


@router.post("/detect", response_model=DetectResponse)
def detect_logs(
    request: DetectRequest,
    db: Session = Depends(get_db),
):
    """
    Analyze a submitted batch of log records.
    Runs ML + rule-based detection, persists alerts, correlates incidents,
    and maps to compliance controls.
    """
    if not request.records:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No records provided.",
        )
    if len(request.records) > 10000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Maximum 10,000 records per request.",
        )

    alerts = run_detection_on_logs(db, request.records)

    # Also trigger correlation and compliance mapping
    if alerts:
        run_correlation(db)
        run_compliance_mapping(db)

    return DetectResponse(
        alerts_generated=len(alerts),
        alerts=[AlertResponse(**a) for a in alerts],
    )


@router.get("/alerts", response_model=List[AlertResponse])
def get_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Retrieve detected alerts with optional filters."""
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity.lower())
    if event_type:
        query = query.filter(Alert.event_type.ilike(f"%{event_type}%"))

    items = (
        query.order_by(Alert.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return [
        AlertResponse(
            alert_id=a.alert_id,
            log_id=a.log_id,
            timestamp=a.timestamp.isoformat() if a.timestamp else None,
            event_type=a.event_type or "",
            source_ip=a.source_ip,
            affected_asset=a.affected_asset,
            severity=a.severity or "medium",
            ml_prediction=a.ml_prediction,
            confidence_score=a.confidence_score,
            detection_reason=a.detection_reason or "",
            evidence=a.evidence or [],
            recommended_action=a.recommended_action or "",
            detection_method=a.detection_method or "rule",
        )
        for a in items
    ]


@router.get("/incidents", response_model=List[IncidentResponse])
def get_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Retrieve correlated potential incidents."""
    items = (
        db.query(Incident)
        .order_by(Incident.last_seen.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return [
        IncidentResponse(
            incident_id=inc.incident_id,
            category=inc.category or "Unknown",
            first_seen=inc.first_seen.isoformat() if inc.first_seen else "",
            last_seen=inc.last_seen.isoformat() if inc.last_seen else "",
            affected_assets=inc.affected_assets or [],
            severity=inc.severity or "medium",
            alert_ids=inc.alert_ids or [],
            evidence_summary=inc.evidence_summary or "",
            remediation=inc.remediation or "",
            status=inc.status or "open",
            alert_count=len(inc.alert_ids or []),
        )
        for inc in items
    ]
