"""Report generation and download endpoints."""
import json
import logging
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import Alert, Incident, ComplianceMapping, Report, SecurityLog
from app.schemas.reports import ReportGenerateRequest, ReportResponse
from app.services.detection_service import _alert_to_dict, _incident_to_dict
from app.reporting.generator import generate_report
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["Reports"])


def _load_model_metrics() -> dict:
    """Load model metrics from the saved JSON file."""
    metrics_path = settings.models_path / "model_metrics.json"
    if metrics_path.exists():
        with open(metrics_path) as f:
            return json.load(f)
    return None


@router.get("", response_model=List[ReportResponse])
def list_reports(db: Session = Depends(get_db)):
    """List all generated reports."""
    items = db.query(Report).order_by(Report.generated_at.desc()).all()
    return [
        ReportResponse(
            report_id=r.report_id,
            title=r.title or "Security Report",
            generated_at=r.generated_at.isoformat() if r.generated_at else "",
            file_path=r.file_path or "",
            summary=r.summary or {},
            status=r.status or "completed",
        )
        for r in items
    ]


@router.post("/generate", response_model=ReportResponse)
def generate_security_report(
    request: ReportGenerateRequest,
    db: Session = Depends(get_db),
):
    """
    Generate a PDF security assessment report from current analysis data.
    Report is based only on actual analyzed records — no fabricated findings.
    """
    # Load all alerts and incidents from DB
    alert_rows = db.query(Alert).all()
    incident_rows = db.query(Incident).all()
    compliance_rows = db.query(ComplianceMapping).all()

    alerts = [_alert_to_dict(a) for a in alert_rows]
    incidents = [
        {
            "incident_id": i.incident_id,
            "category": i.category,
            "first_seen": i.first_seen.isoformat() if i.first_seen else "",
            "last_seen": i.last_seen.isoformat() if i.last_seen else "",
            "affected_assets": i.affected_assets or [],
            "severity": i.severity,
            "alert_ids": i.alert_ids or [],
            "evidence_summary": i.evidence_summary or "",
            "remediation": i.remediation or "",
            "alert_count": len(i.alert_ids or []),
        }
        for i in incident_rows
    ]
    compliance_mappings = [
        {
            "mapping_id": m.mapping_id,
            "alert_id": m.alert_id,
            "framework": m.framework,
            "control_id": m.control_id,
            "control_title": m.control_title or "",
            "finding_description": m.finding_description or "",
            "evidence": m.evidence or "",
            "risk_level": m.risk_level or "low",
            "remediation": m.remediation or "",
        }
        for m in compliance_rows
    ]

    # Dataset summary
    total_logs = db.query(SecurityLog).count()
    first_log = db.query(SecurityLog).order_by(SecurityLog.timestamp.asc()).first()
    last_log = db.query(SecurityLog).order_by(SecurityLog.timestamp.desc()).first()
    date_range = (
        f"{first_log.timestamp.date()} to {last_log.timestamp.date()}"
        if first_log and last_log else "N/A"
    )
    dataset_summary = {
        "total_logs": total_logs,
        "date_range": date_range,
        "log_sources": "Imported security event logs / synthetic dataset",
    }

    model_metrics = _load_model_metrics()

    try:
        result = generate_report(
            alerts=alerts,
            incidents=incidents,
            compliance_mappings=compliance_mappings,
            dataset_summary=dataset_summary,
            model_metrics=model_metrics,
            output_dir=settings.reports_path,
            report_title=request.title or "Security Assessment Report",
        )
    except Exception as e:
        logger.error("Report generation failed: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(e)[:200]}",
        )

    # Persist report record — SQLite + MongoDB
    report_row = Report(
        report_id=result["report_id"],
        title=request.title or "Security Assessment Report",
        file_path=result["file_path"],
        summary=result["summary"],
        status="completed",
    )
    db.add(report_row)
    db.commit()

    # MongoDB dual-write
    from app.services.detection_service import persist_report_to_mongo
    persist_report_to_mongo({
        "report_id":    result["report_id"],
        "title":        request.title or "Security Assessment Report",
        "generated_at": result["generated_at"],
        "file_path":    result["file_path"],
        "summary":      result["summary"],
    })

    return ReportResponse(
        report_id=result["report_id"],
        title=request.title or "Security Assessment Report",
        generated_at=result["generated_at"],
        file_path=result["file_path"],
        summary=result["summary"],
        status="completed",
    )


@router.get("/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    """Download a generated PDF report by report ID."""
    report = db.query(Report).filter(Report.report_id == report_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found.",
        )

    file_path = Path(report.file_path)
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file not found on disk.",
        )

    return FileResponse(
        path=str(file_path),
        media_type="application/pdf",
        filename=file_path.name,
    )
