"""Pydantic schemas for report generation."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict


class ReportGenerateRequest(BaseModel):
    title: Optional[str] = "Security Assessment Report"


class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    report_id: str
    title: str
    generated_at: str
    file_path: str
    summary: Dict[str, Any]
    status: str


class DashboardSummary(BaseModel):
    total_logs: int
    total_alerts: int
    total_incidents: int
    high_severity_alerts: int
    critical_alerts: int
    model_name: str
    model_loaded: bool
    model_metrics: Optional[Dict[str, Any]] = None
    event_type_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]
    detection_method_distribution: Dict[str, int]
    recent_alerts: List[Any]
