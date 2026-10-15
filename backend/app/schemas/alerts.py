"""Pydantic schemas for alerts, incidents, and detection endpoints."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict


class DetectRequest(BaseModel):
    records: List[Dict[str, Any]]


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    alert_id: str
    log_id: Optional[str] = None
    timestamp: Optional[str] = None
    event_type: str
    source_ip: Optional[str] = None
    affected_asset: Optional[str] = None
    severity: str
    ml_prediction: Optional[str] = None
    confidence_score: Optional[float] = None
    detection_reason: str
    evidence: List[Dict[str, Any]]
    recommended_action: str
    detection_method: str


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: str
    category: str
    first_seen: str
    last_seen: str
    affected_assets: List[str]
    severity: str
    alert_ids: List[str]
    evidence_summary: str
    remediation: str
    status: str
    alert_count: int


class DetectResponse(BaseModel):
    alerts_generated: int
    alerts: List[AlertResponse]
