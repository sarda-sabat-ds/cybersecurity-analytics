"""SQLAlchemy database models."""
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(String(64), unique=True, index=True)
    timestamp = Column(DateTime, index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45))
    event_type = Column(String(64), index=True)
    severity = Column(String(16), index=True)
    failed_login_count = Column(Integer, default=0)
    request_count = Column(Integer, default=0)
    port = Column(Integer)
    affected_asset = Column(String(128))
    label = Column(String(32))
    raw_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), unique=True, index=True)
    log_id = Column(String(64), index=True)
    timestamp = Column(DateTime, index=True)
    event_type = Column(String(64))
    source_ip = Column(String(45))
    affected_asset = Column(String(128))
    severity = Column(String(16))
    ml_prediction = Column(String(32))
    confidence_score = Column(Float)
    detection_reason = Column(Text)
    evidence = Column(JSON)
    recommended_action = Column(Text)
    detection_method = Column(String(32))  # 'ml', 'rule', 'combined'
    incident_id = Column(String(64), ForeignKey("incidents.incident_id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), unique=True, index=True)
    category = Column(String(64))
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    affected_assets = Column(JSON)
    severity = Column(String(16))
    alert_ids = Column(JSON)
    evidence_summary = Column(Text)
    remediation = Column(Text)
    status = Column(String(32), default="open")
    created_at = Column(DateTime, default=datetime.utcnow)


class ComplianceMapping(Base):
    __tablename__ = "compliance_mappings"

    id = Column(Integer, primary_key=True, index=True)
    mapping_id = Column(String(64), unique=True, index=True)
    alert_id = Column(String(64), index=True)
    framework = Column(String(64))
    framework_version = Column(String(32))
    control_id = Column(String(32))
    control_title = Column(Text)
    finding_description = Column(Text)
    evidence = Column(Text)
    risk_level = Column(String(16))
    remediation = Column(Text)
    disclaimer = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(String(64), unique=True, index=True)
    title = Column(String(256))
    generated_at = Column(DateTime, default=datetime.utcnow)
    file_path = Column(String(512))
    summary = Column(JSON)
    status = Column(String(32), default="completed")
