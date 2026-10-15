"""Pytest configuration and shared fixtures."""
import sys
from pathlib import Path
import pytest

# Make sure app is importable from tests/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(scope="session")
def sample_df():
    """Provide a small sample DataFrame for testing."""
    import pandas as pd
    return pd.DataFrame([
        {"log_id": "a1", "timestamp": "2024-01-01T10:00:00", "source_ip": "192.168.1.1",
         "destination_ip": "10.0.0.1", "event_type": "brute_force", "severity": "high",
         "failed_login_count": 20, "request_count": 20, "port": 22,
         "affected_asset": "auth-server-01", "label": "suspicious"},
        {"log_id": "a2", "timestamp": "2024-01-01T10:05:00", "source_ip": "192.168.1.2",
         "destination_ip": "10.0.0.2", "event_type": "login_success", "severity": "low",
         "failed_login_count": 0, "request_count": 3, "port": 443,
         "affected_asset": "web-server-01", "label": "normal"},
        {"log_id": "a3", "timestamp": "2024-01-01T10:10:00", "source_ip": "203.0.113.5",
         "destination_ip": "192.168.1.1", "event_type": "port_scan", "severity": "medium",
         "failed_login_count": 0, "request_count": 500, "port": 80,
         "affected_asset": "firewall-01", "label": "suspicious"},
        {"log_id": "a4", "timestamp": "2024-01-01T10:15:00", "source_ip": "192.168.2.1",
         "destination_ip": "10.0.0.3", "event_type": "file_access", "severity": "low",
         "failed_login_count": 0, "request_count": 5, "port": 443,
         "affected_asset": "file-server-01", "label": "normal"},
    ])
