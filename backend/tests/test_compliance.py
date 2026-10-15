"""Tests for compliance mapping module."""
import pytest
from app.compliance.mappings import map_alert_to_compliance, map_alerts_to_compliance


def make_alert(event_type, alert_id="test-alert-001"):
    return {
        "alert_id": alert_id,
        "event_type": event_type,
        "source_ip": "1.2.3.4",
        "affected_asset": "web-server-01",
        "detection_reason": "test detection",
    }


def test_brute_force_returns_mappings():
    mappings = map_alert_to_compliance(make_alert("brute_force"))
    assert len(mappings) > 0


def test_brute_force_includes_iso():
    mappings = map_alert_to_compliance(make_alert("brute_force"))
    frameworks = [m["framework"] for m in mappings]
    assert any("ISO" in f for f in frameworks)


def test_port_scan_includes_nist():
    mappings = map_alert_to_compliance(make_alert("port_scan"))
    frameworks = [m["framework"] for m in mappings]
    assert any("NIST" in f for f in frameworks)


def test_data_exfiltration_is_critical():
    mappings = map_alert_to_compliance(make_alert("data_exfiltration"))
    risk_levels = [m["risk_level"] for m in mappings]
    assert "critical" in risk_levels


def test_unknown_event_type_still_maps():
    mappings = map_alert_to_compliance(make_alert("totally_unknown_event"))
    assert len(mappings) > 0


def test_required_mapping_fields():
    mappings = map_alert_to_compliance(make_alert("malware_detected"))
    for m in mappings:
        for field in ["mapping_id", "alert_id", "framework", "control_id",
                      "control_title", "finding_description", "risk_level",
                      "remediation", "disclaimer"]:
            assert field in m, f"Missing field: {field}"


def test_disclaimer_always_present():
    mappings = map_alert_to_compliance(make_alert("privilege_escalation"))
    for m in mappings:
        assert len(m["disclaimer"]) > 0
        assert "suggested" in m["disclaimer"].lower() or "not" in m["disclaimer"].lower()


def test_batch_mapping():
    alerts = [make_alert(et, f"alert-{i}") for i, et in
              enumerate(["brute_force", "port_scan", "data_exfiltration"])]
    mappings = map_alerts_to_compliance(alerts)
    assert len(mappings) > 3  # each alert generates multiple mappings


def test_alert_id_preserved_in_mapping():
    alert = make_alert("malware_detected", alert_id="my-alert-xyz")
    mappings = map_alert_to_compliance(alert)
    assert all(m["alert_id"] == "my-alert-xyz" for m in mappings)
