"""Pydantic schemas for security log endpoints."""
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict


class LogRecord(BaseModel):
    log_id: Optional[str] = None
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    event_type: str
    severity: str
    failed_login_count: int = Field(default=0, ge=0)
    request_count: int = Field(default=0, ge=0)
    port: Optional[int] = Field(default=None, ge=0, le=65535)
    affected_asset: Optional[str] = None
    label: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = {"low", "medium", "high", "critical"}
        if v.lower() not in valid:
            raise ValueError(f"severity must be one of {valid}")
        return v.lower()


class LogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    log_id: str
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    event_type: str
    severity: str
    failed_login_count: int
    request_count: int
    port: Optional[int] = None
    affected_asset: Optional[str] = None
    label: Optional[str] = None


class PaginatedLogs(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[LogResponse]


class UploadResponse(BaseModel):
    message: str
    records_imported: int
    records_skipped: int
    warnings: List[str] = []
