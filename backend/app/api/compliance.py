"""Compliance mapping endpoints."""
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import ComplianceMapping
from app.schemas.compliance import ComplianceMappingResponse, PaginatedCompliance

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/compliance", tags=["Compliance"])


@router.get("", response_model=PaginatedCompliance)
def get_compliance_mappings(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    framework: Optional[str] = Query(None, description="Filter by framework name substring"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    db: Session = Depends(get_db),
):
    """
    Retrieve deduplicated compliance mappings with pagination.

    Returns one representative mapping per (framework, control_id) pair.
    DISCLAIMER: These are suggested associations, not formal audit findings.
    """
    # Subquery: pick the most recent mapping_id per (framework, control_id) group
    subq = (
        db.query(
            ComplianceMapping.framework,
            ComplianceMapping.control_id,
            func.max(ComplianceMapping.id).label("max_id"),
        )
        .group_by(ComplianceMapping.framework, ComplianceMapping.control_id)
        .subquery()
    )

    query = (
        db.query(ComplianceMapping)
        .join(subq, ComplianceMapping.id == subq.c.max_id)
    )

    if framework:
        query = query.filter(ComplianceMapping.framework.ilike(f"%{framework}%"))
    if risk_level:
        query = query.filter(ComplianceMapping.risk_level == risk_level.lower())

    # Order by risk severity
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    items_all = query.all()
    items_all.sort(key=lambda m: risk_order.get(m.risk_level or "low", 3))

    total = len(items_all)
    start = (page - 1) * page_size
    items = items_all[start: start + page_size]

    def _to_schema(m: ComplianceMapping) -> ComplianceMappingResponse:
        return ComplianceMappingResponse(
            mapping_id=m.mapping_id,
            alert_id=m.alert_id,
            framework=m.framework,
            framework_version=m.framework_version,
            control_id=m.control_id,
            control_title=m.control_title or "",
            finding_description=m.finding_description or "",
            evidence=m.evidence or "",
            risk_level=m.risk_level or "low",
            remediation=m.remediation or "",
            disclaimer=m.disclaimer or "",
        )

    return PaginatedCompliance(
        total=total,
        page=page,
        page_size=page_size,
        items=[_to_schema(m) for m in items],
    )


@router.get("/summary", tags=["Compliance"])
def compliance_summary(db: Session = Depends(get_db)):
    """Risk-level counts for dashboard use."""
    rows = (
        db.query(ComplianceMapping.risk_level, func.count(ComplianceMapping.id))
        .group_by(ComplianceMapping.risk_level)
        .all()
    )
    return {r: c for r, c in rows}
