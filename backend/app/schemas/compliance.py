"""Pydantic schemas for compliance mappings."""
from typing import List
from pydantic import BaseModel, ConfigDict


class ComplianceMappingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    mapping_id: str
    alert_id: str
    framework: str
    framework_version: str
    control_id: str
    control_title: str
    finding_description: str
    evidence: str
    risk_level: str
    remediation: str
    disclaimer: str


class PaginatedCompliance(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[ComplianceMappingResponse]
