"""
Alert correlation engine.

Groups related alerts into potential security incidents using configurable,
documented rules. Correlation considers:
- Timestamp proximity (temporal clustering)
- Source IP address (same attacker)
- Affected asset (same target)
- Event type patterns (attack chain indicators)
- Severity aggregation

LIMITATIONS:
- Correlation does not confirm that an attack occurred — it groups
  alerts that may be related based on observable patterns.
- Incidents are labelled 'potential' until investigated and confirmed.
- This is not a SIEM replacement; it provides a starting point for
  security analyst investigation.
"""
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# Correlation configuration (all values documented)
CORRELATION_CONFIG = {
    # Alerts within this window from the same source IP are grouped
    "time_window_minutes": 30,
    # Minimum number of alerts to form an incident
    "min_alerts_per_incident": 2,
    # Source IPs that appear in this many+ alerts are flagged as campaign IPs
    "campaign_ip_threshold": 3,
    # Event type chains that suggest multi-stage attacks
    "attack_chain_patterns": [
        {"stages": ["port_scan", "brute_force"], "category": "Reconnaissance + Brute Force"},
        {"stages": ["brute_force", "privilege_escalation"], "category": "Credential Attack + Escalation"},
        {"stages": ["login_failure", "data_exfiltration"], "category": "Potential Account Compromise + Exfiltration"},
        {"stages": ["malware_detected", "data_exfiltration"], "category": "Malware + Data Exfiltration"},
        {"stages": ["port_scan", "malware_detected"], "category": "Reconnaissance + Malware Delivery"},
    ],
    # Severity weights for incident severity calculation
    "severity_weights": {"critical": 4, "high": 3, "medium": 2, "low": 1},
}

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse ISO 8601 or common timestamp strings."""
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]:
        try:
            return datetime.strptime(ts_str[:26], fmt)
        except ValueError:
            continue
    return None


def _aggregate_severity(alerts: List[Dict]) -> str:
    """Return the highest severity found among the given alerts."""
    weights = CORRELATION_CONFIG["severity_weights"]
    max_w = 0
    max_sev = "low"
    for a in alerts:
        sev = a.get("severity", "low").lower()
        w = weights.get(sev, 1)
        if w > max_w:
            max_w = w
            max_sev = sev
    return max_sev


def _detect_attack_chain(event_types: List[str]) -> Optional[str]:
    """Check if a sequence of event types matches a known attack chain."""
    et_set = set(event_types)
    for pattern in CORRELATION_CONFIG["attack_chain_patterns"]:
        if all(s in et_set for s in pattern["stages"]):
            return pattern["category"]
    return None


def _build_incident(
    alerts: List[Dict],
    category: str,
    evidence_summary: str,
    remediation: str,
) -> Dict[str, Any]:
    """Construct an incident record from a group of alerts."""
    timestamps = []
    assets = set()
    for a in alerts:
        ts = _parse_timestamp(str(a.get("timestamp", "")))
        if ts:
            timestamps.append(ts)
        asset = a.get("affected_asset", "")
        if asset:
            assets.add(asset)

    first_seen = min(timestamps).isoformat() if timestamps else datetime.utcnow().isoformat()
    last_seen = max(timestamps).isoformat() if timestamps else datetime.utcnow().isoformat()
    severity = _aggregate_severity(alerts)

    return {
        "incident_id": str(uuid.uuid4()),
        "category": category,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "affected_assets": sorted(assets),
        "severity": severity,
        "alert_ids": [a["alert_id"] for a in alerts],
        "evidence_summary": evidence_summary,
        "remediation": remediation,
        "status": "open",
        "alert_count": len(alerts),
    }


def correlate_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Correlate a list of alert dicts into potential incidents.

    Algorithm:
    1. Group by source IP — alerts from the same IP within the time window
       are candidates for the same incident.
    2. Group by affected asset — alerts targeting the same asset in the
       same window may indicate a focused attack.
    3. Detect attack chain patterns (multi-stage attacks).
    4. Single high-severity alerts without a group become standalone incidents.
    5. All incidents are labelled 'potential' (not confirmed).

    Parameters
    ----------
    alerts : list of alert dicts (output from DetectionEngine)

    Returns
    -------
    List of incident dicts.
    """
    if not alerts:
        return []

    incidents: List[Dict] = []
    time_window = timedelta(minutes=CORRELATION_CONFIG["time_window_minutes"])
    min_alerts = CORRELATION_CONFIG["min_alerts_per_incident"]

    # Parse and sort alerts by timestamp
    parsed = []
    for a in alerts:
        ts = _parse_timestamp(str(a.get("timestamp", "")))
        parsed.append({**a, "_ts": ts or datetime.utcnow()})

    parsed.sort(key=lambda x: x["_ts"])

    used_alert_ids = set()

    # ----------------------------------------------------------------
    # Pass 1: Group by source IP within time window
    # ----------------------------------------------------------------
    ip_groups: Dict[str, List[Dict]] = defaultdict(list)
    for a in parsed:
        ip = a.get("source_ip", "")
        if ip:
            ip_groups[ip].append(a)

    for ip, ip_alerts in ip_groups.items():
        if len(ip_alerts) < min_alerts:
            continue

        # Sliding window clustering
        cluster: List[Dict] = [ip_alerts[0]]
        for i in range(1, len(ip_alerts)):
            prev_ts = cluster[-1]["_ts"]
            curr_ts = ip_alerts[i]["_ts"]
            if curr_ts - prev_ts <= time_window:
                cluster.append(ip_alerts[i])
            else:
                if len(cluster) >= min_alerts:
                    _create_ip_incident(cluster, ip, incidents, used_alert_ids)
                cluster = [ip_alerts[i]]
        if len(cluster) >= min_alerts:
            _create_ip_incident(cluster, ip, incidents, used_alert_ids)

    # ----------------------------------------------------------------
    # Pass 2: Group by affected asset (for remaining alerts)
    # ----------------------------------------------------------------
    remaining = [a for a in parsed if a["alert_id"] not in used_alert_ids]
    asset_groups: Dict[str, List[Dict]] = defaultdict(list)
    for a in remaining:
        asset = a.get("affected_asset", "")
        if asset:
            asset_groups[asset].append(a)

    for asset, asset_alerts in asset_groups.items():
        if len(asset_alerts) < min_alerts:
            continue

        cluster: List[Dict] = [asset_alerts[0]]
        for i in range(1, len(asset_alerts)):
            prev_ts = cluster[-1]["_ts"]
            curr_ts = asset_alerts[i]["_ts"]
            if curr_ts - prev_ts <= time_window:
                cluster.append(asset_alerts[i])
            else:
                if len(cluster) >= min_alerts:
                    _create_asset_incident(cluster, asset, incidents, used_alert_ids)
                cluster = [asset_alerts[i]]
        if len(cluster) >= min_alerts:
            _create_asset_incident(cluster, asset, incidents, used_alert_ids)

    # ----------------------------------------------------------------
    # Pass 3: Standalone high/critical single alerts
    # ----------------------------------------------------------------
    solo_alerts = [
        a for a in parsed
        if a["alert_id"] not in used_alert_ids
        and a.get("severity", "low") in ("high", "critical")
    ]
    for a in solo_alerts:
        et = a.get("event_type", "unknown")
        sev = a.get("severity", "high")
        incident = _build_incident(
            [a],
            category=f"Standalone {et.replace('_', ' ').title()} Alert",
            evidence_summary=(
                f"Single high-severity {sev} event ({et}) detected. "
                f"Source: {a.get('source_ip', 'unknown')}. "
                f"Asset: {a.get('affected_asset', 'unknown')}."
            ),
            remediation=a.get("recommended_action", "Investigate immediately."),
        )
        incidents.append(incident)
        used_alert_ids.add(a["alert_id"])

    logger.info(
        "Correlation complete: %d alerts → %d potential incidents",
        len(alerts), len(incidents),
    )
    return incidents


def _create_ip_incident(
    cluster: List[Dict],
    source_ip: str,
    incidents: List[Dict],
    used_ids: set,
):
    """Create an incident from a cluster of alerts with the same source IP."""
    event_types = [a.get("event_type", "") for a in cluster]
    chain_category = _detect_attack_chain(event_types)
    category = chain_category or f"Sustained Activity from {source_ip}"

    summary_parts = [
        f"{len(cluster)} alerts from source IP {source_ip}.",
        f"Event types: {', '.join(set(event_types))}.",
        f"Time span: {cluster[0]['_ts'].isoformat()} – {cluster[-1]['_ts'].isoformat()}.",
    ]
    if chain_category:
        summary_parts.append(f"Attack chain detected: {chain_category}.")

    remediation = _get_incident_remediation(category, event_types)

    incident = _build_incident(
        cluster,
        category=category,
        evidence_summary=" ".join(summary_parts),
        remediation=remediation,
    )
    incidents.append(incident)
    for a in cluster:
        used_ids.add(a["alert_id"])


def _create_asset_incident(
    cluster: List[Dict],
    asset: str,
    incidents: List[Dict],
    used_ids: set,
):
    """Create an incident from a cluster of alerts targeting the same asset."""
    event_types = [a.get("event_type", "") for a in cluster]
    chain_category = _detect_attack_chain(event_types)
    category = chain_category or f"Multiple Attacks on {asset}"

    source_ips = set(a.get("source_ip", "") for a in cluster if a.get("source_ip"))
    summary_parts = [
        f"{len(cluster)} alerts targeting asset '{asset}'.",
        f"Source IPs: {', '.join(source_ips) if source_ips else 'unknown'}.",
        f"Event types: {', '.join(set(event_types))}.",
    ]
    if chain_category:
        summary_parts.append(f"Attack chain detected: {chain_category}.")

    remediation = _get_incident_remediation(category, event_types)

    incident = _build_incident(
        cluster,
        category=category,
        evidence_summary=" ".join(summary_parts),
        remediation=remediation,
    )
    incidents.append(incident)
    for a in cluster:
        used_ids.add(a["alert_id"])


def _get_incident_remediation(category: str, event_types: List[str]) -> str:
    """Return a contextual remediation recommendation for an incident category."""
    et_set = set(event_types)

    if "data_exfiltration" in et_set:
        return (
            "URGENT: Isolate affected systems. Preserve forensic evidence. "
            "Notify data protection officer. Review data access logs. "
            "Initiate formal incident response procedure per IR plan."
        )
    if "malware_detected" in et_set:
        return (
            "Quarantine affected hosts immediately. Run full antivirus scan. "
            "Identify and remove malware artifacts. Patch vulnerabilities. "
            "Change passwords for all accounts on affected systems."
        )
    if "privilege_escalation" in et_set:
        return (
            "Revoke excessive privileges. Audit recent admin account activity. "
            "Review sudo/admin logs. Investigate lateral movement. "
            "Enable privileged access management (PAM) if not in place."
        )
    if "brute_force" in et_set or "account_lockout" in et_set:
        return (
            "Block attacking source IP(s) at the firewall. Enforce account lockout policy. "
            "Require MFA on all privileged accounts. Review authentication logs "
            "for any successful logins from suspicious IPs."
        )
    if "port_scan" in et_set:
        return (
            "Block source IP at the perimeter firewall. Review exposed services. "
            "Ensure unnecessary ports are closed. Monitor for follow-on exploitation attempts."
        )
    return (
        "Investigate all related alerts. Review system and network logs. "
        "Isolate affected assets if compromise is suspected. "
        "Escalate to the security team for deeper investigation."
    )
