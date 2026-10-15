"""Tests for PDF report generation."""
import tempfile
from pathlib import Path
import pytest

from app.reporting.generator import generate_report


@pytest.fixture
def sample_alerts():
    return [
        {
            "alert_id": "alert-001", "log_id": "log-001",
            "timestamp": "2024-01-01T10:00:00",
            "event_type": "brute_force", "source_ip": "1.2.3.4",
            "affected_asset": "auth-server-01", "severity": "high",
            "ml_prediction": "suspicious", "confidence_score": 0.95,
            "detection_reason": "High failed login count",
            "evidence": [{"rule": "brute_force_logins", "value": 30}],
            "recommended_action": "Block IP and review auth logs.",
            "detection_method": "combined",
        }
    ]


@pytest.fixture
def sample_incidents():
    return [
        {
            "incident_id": "inc-001",
            "category": "Brute Force Attack",
            "first_seen": "2024-01-01T10:00:00",
            "last_seen": "2024-01-01T10:30:00",
            "affected_assets": ["auth-server-01"],
            "severity": "high",
            "alert_ids": ["alert-001"],
            "evidence_summary": "Multiple failed logins from 1.2.3.4",
            "remediation": "Block source IP, enforce MFA.",
            "alert_count": 1,
        }
    ]


def test_generate_pdf_creates_file(sample_alerts, sample_incidents):
    with tempfile.TemporaryDirectory() as tmpdir:
        result = generate_report(
            alerts=sample_alerts,
            incidents=sample_incidents,
            compliance_mappings=[],
            dataset_summary={"total_logs": 100, "date_range": "2024-01-01 to 2024-01-31"},
            model_metrics=None,
            output_dir=Path(tmpdir),
        )
        assert "file_path" in result
        path = Path(result["file_path"])
        assert path.exists()
        assert path.stat().st_size > 0


def test_generate_pdf_with_metrics(sample_alerts, sample_incidents):
    model_metrics = {
        "best_model": "RandomForest",
        "selection_criteria": "0.5*F1",
        "model_metrics": {
            "RandomForest": {
                "accuracy": 0.95,
                "f1_suspicious": 0.92,
                "recall_suspicious": 0.90,
                "precision_suspicious": 0.94,
                "false_positive_rate": 0.05,
                "false_positives": 5,
                "false_negatives": 8,
            }
        },
    }
    with tempfile.TemporaryDirectory() as tmpdir:
        result = generate_report(
            alerts=sample_alerts,
            incidents=sample_incidents,
            compliance_mappings=[],
            dataset_summary={"total_logs": 500, "date_range": "2024-01-01 to 2024-01-31"},
            model_metrics=model_metrics,
            output_dir=Path(tmpdir),
        )
        assert Path(result["file_path"]).exists()


def test_generate_returns_report_id(sample_alerts, sample_incidents):
    with tempfile.TemporaryDirectory() as tmpdir:
        result = generate_report(
            alerts=sample_alerts, incidents=sample_incidents,
            compliance_mappings=[], dataset_summary={"total_logs": 10},
            model_metrics=None, output_dir=Path(tmpdir),
        )
        assert "report_id" in result
        assert len(result["report_id"]) > 0


def test_generate_with_empty_alerts():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = generate_report(
            alerts=[], incidents=[], compliance_mappings=[],
            dataset_summary={"total_logs": 0},
            model_metrics=None, output_dir=Path(tmpdir),
        )
        assert Path(result["file_path"]).exists()
