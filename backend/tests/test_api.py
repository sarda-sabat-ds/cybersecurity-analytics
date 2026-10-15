"""Tests for FastAPI endpoints using TestClient."""
import sys
from pathlib import Path
import pytest
import tempfile
import io
import csv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database.connection import get_db
from app.database.models import Base

# Use in-memory SQLite for testing
TEST_DB_URL = "sqlite:///./test_temp.db"

engine_test = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine_test)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="module")
def client():
    Base.metadata.create_all(bind=engine_test)
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    Base.metadata.drop_all(bind=engine_test)
    engine_test.dispose()
    app.dependency_overrides.clear()
    import time
    time.sleep(0.5)
    test_db = Path("test_temp.db")
    if test_db.exists():
        try:
            test_db.unlink()
        except PermissionError:
            pass  # Windows may still hold file lock; non-critical cleanup


def make_csv_bytes(rows):
    """Helper to create a CSV in-memory."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8")


# ---- Health ----
def test_health_returns_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---- Dashboard ----
def test_dashboard_summary_shape(client):
    resp = client.get("/api/dashboard/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_logs" in data
    assert "total_alerts" in data
    assert "model_name" in data


# ---- Logs ----
def test_list_logs_empty(client):
    resp = client.get("/api/logs")
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "items" in data


def test_upload_valid_csv(client):
    rows = [
        {"event_type": "login_success", "severity": "low", "failed_login_count": 0,
         "request_count": 1, "port": 443, "label": "normal"},
        {"event_type": "brute_force", "severity": "high", "failed_login_count": 25,
         "request_count": 25, "port": 22, "label": "suspicious"},
    ]
    content = make_csv_bytes(rows)
    resp = client.post(
        "/api/logs/upload",
        files={"file": ("logs.csv", content, "text/csv")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["records_imported"] >= 0


def test_upload_non_csv_rejected(client):
    resp = client.post(
        "/api/logs/upload",
        files={"file": ("logs.txt", b"not a csv", "text/plain")},
    )
    assert resp.status_code == 400


def test_upload_missing_event_type_rejected(client):
    rows = [{"severity": "low", "failed_login_count": 0}]
    content = make_csv_bytes(rows)
    resp = client.post(
        "/api/logs/upload",
        files={"file": ("bad.csv", content, "text/csv")},
    )
    assert resp.status_code == 422


# ---- Detection ----
def test_detect_returns_alerts(client):
    records = [
        {"event_type": "brute_force", "severity": "high",
         "failed_login_count": 30, "request_count": 30,
         "port": 22, "source_ip": "1.2.3.4", "affected_asset": "auth-server-01"},
        {"event_type": "port_scan", "severity": "medium",
         "failed_login_count": 0, "request_count": 500,
         "port": 80, "source_ip": "1.2.3.4", "affected_asset": "firewall-01"},
    ]
    resp = client.post("/api/detect", json={"records": records})
    assert resp.status_code == 200
    data = resp.json()
    assert "alerts_generated" in data
    assert data["alerts_generated"] >= 2


def test_detect_empty_records_rejected(client):
    resp = client.post("/api/detect", json={"records": []})
    assert resp.status_code == 400


# ---- Alerts ----
def test_alerts_endpoint(client):
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---- Incidents ----
def test_incidents_endpoint(client):
    resp = client.get("/api/incidents")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---- Compliance ----
def test_compliance_endpoint(client):
    resp = client.get("/api/compliance")
    assert resp.status_code == 200
    data = resp.json()
    # Endpoint now returns a paginated envelope
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)


# ---- Reports ----
def test_reports_list_endpoint(client):
    resp = client.get("/api/reports")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_generate_report(client):
    resp = client.post("/api/reports/generate", json={"title": "Test Report"})
    assert resp.status_code == 200
    data = resp.json()
    assert "report_id" in data
    assert data["status"] == "completed"


def test_download_nonexistent_report(client):
    resp = client.get("/api/reports/nonexistent-id/download")
    assert resp.status_code == 404
