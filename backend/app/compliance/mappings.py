"""
Compliance mapping module.

Maps detected security events to relevant ISO/IEC 27001:2022 Annex A
controls and NIST Cybersecurity Framework 2.0 subcategories.

IMPORTANT DISCLAIMER:
These are SUGGESTED associations between observed security events and
framework controls. They are NOT:
- Proof of compliance or non-compliance.
- The result of a formal audit.
- Certification claims.
- Definitive evidence that a specific control is violated.

Control IDs are sourced from publicly available framework documentation:
- ISO/IEC 27001:2022 Annex A (114 controls across 4 domains)
- NIST Cybersecurity Framework 2.0 (published February 2024)

A qualified security auditor must confirm applicability.
"""
from typing import Any, Dict, List, Optional

# -----------------------------------------------------------------------
# ISO/IEC 27001:2022 Annex A control reference table
# Source: ISO/IEC 27001:2022 standard, Annex A (publicly documented structure)
# -----------------------------------------------------------------------
ISO_CONTROLS = {
    "A.5.24": {
        "control_id": "A.5.24",
        "control_title": "Information security incident management planning and preparation",
        "description": "The organization shall plan and prepare for managing information security incidents.",
        "domain": "Organizational Controls",
    },
    "A.5.25": {
        "control_id": "A.5.25",
        "control_title": "Assessment and decision on information security events",
        "description": "The organization shall assess information security events and decide if they are to be categorized as incidents.",
        "domain": "Organizational Controls",
    },
    "A.5.26": {
        "control_id": "A.5.26",
        "control_title": "Response to information security incidents",
        "description": "The organization shall respond to information security incidents in accordance with documented procedures.",
        "domain": "Organizational Controls",
    },
    "A.8.2": {
        "control_id": "A.8.2",
        "control_title": "Privileged access rights",
        "description": "The allocation and use of privileged access rights shall be restricted and managed.",
        "domain": "Technological Controls",
    },
    "A.8.3": {
        "control_id": "A.8.3",
        "control_title": "Information access restriction",
        "description": "Access to information and other associated assets shall be restricted in accordance with the established topic-specific policy on access control.",
        "domain": "Technological Controls",
    },
    "A.8.5": {
        "control_id": "A.8.5",
        "control_title": "Secure authentication",
        "description": "Secure authentication technologies and procedures shall be implemented based on information access restrictions.",
        "domain": "Technological Controls",
    },
    "A.8.7": {
        "control_id": "A.8.7",
        "control_title": "Protection against malware",
        "description": "Protection against malware shall be implemented and supported by appropriate user awareness.",
        "domain": "Technological Controls",
    },
    "A.8.12": {
        "control_id": "A.8.12",
        "control_title": "Data leakage prevention",
        "description": "Data leakage prevention measures shall be applied to systems, networks and any other devices that process, store or transmit sensitive information.",
        "domain": "Technological Controls",
    },
    "A.8.15": {
        "control_id": "A.8.15",
        "control_title": "Logging",
        "description": "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.",
        "domain": "Technological Controls",
    },
    "A.8.16": {
        "control_id": "A.8.16",
        "control_title": "Monitoring activities",
        "description": "Networks, systems and applications shall be monitored for anomalous behaviour.",
        "domain": "Technological Controls",
    },
    "A.8.20": {
        "control_id": "A.8.20",
        "control_title": "Networks security",
        "description": "Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.",
        "domain": "Technological Controls",
    },
    "A.8.23": {
        "control_id": "A.8.23",
        "control_title": "Web filtering",
        "description": "Access to external websites shall be managed to reduce exposure to malicious content.",
        "domain": "Technological Controls",
    },
}

# -----------------------------------------------------------------------
# NIST CSF 2.0 subcategory reference table
# Source: NIST Cybersecurity Framework 2.0 (February 2024)
# -----------------------------------------------------------------------
NIST_CONTROLS = {
    "DE.AE-02": {
        "control_id": "DE.AE-02",
        "control_title": "Anomalies, indicators of compromise, and other potentially adverse events are analyzed to characterize the events and detect cybersecurity incidents",
        "function": "Detect",
        "category": "Adverse Event Analysis (DE.AE)",
    },
    "DE.AE-06": {
        "control_id": "DE.AE-06",
        "control_title": "Information on adverse events is provided to authorized staff and tools",
        "function": "Detect",
        "category": "Adverse Event Analysis (DE.AE)",
    },
    "DE.CM-01": {
        "control_id": "DE.CM-01",
        "control_title": "Networks and network services are monitored to find potentially adverse events",
        "function": "Detect",
        "category": "Continuous Monitoring (DE.CM)",
    },
    "DE.CM-03": {
        "control_id": "DE.CM-03",
        "control_title": "Personnel activity and technology usage are monitored to find potentially adverse events",
        "function": "Detect",
        "category": "Continuous Monitoring (DE.CM)",
    },
    "PR.AA-01": {
        "control_id": "PR.AA-01",
        "control_title": "Identities and credentials for authorized users, services, and hardware are managed by the organization",
        "function": "Protect",
        "category": "Identity Management, Authentication, and Access Control (PR.AA)",
    },
    "PR.AA-05": {
        "control_id": "PR.AA-05",
        "control_title": "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed",
        "function": "Protect",
        "category": "Identity Management, Authentication, and Access Control (PR.AA)",
    },
    "PR.DS-01": {
        "control_id": "PR.DS-01",
        "control_title": "The confidentiality, integrity, and availability of data-at-rest are protected",
        "function": "Protect",
        "category": "Data Security (PR.DS)",
    },
    "PR.DS-02": {
        "control_id": "PR.DS-02",
        "control_title": "The confidentiality, integrity, and availability of data-in-transit are protected",
        "function": "Protect",
        "category": "Data Security (PR.DS)",
    },
    "PR.PS-01": {
        "control_id": "PR.PS-01",
        "control_title": "Configuration management practices are established and applied",
        "function": "Protect",
        "category": "Platform Security (PR.PS)",
    },
    "RS.MA-01": {
        "control_id": "RS.MA-01",
        "control_title": "The incident response plan is executed in coordination with relevant third parties once an incident is declared",
        "function": "Respond",
        "category": "Incident Management (RS.MA)",
    },
    "RS.AN-03": {
        "control_id": "RS.AN-03",
        "control_title": "Analysis is performed to establish what has taken place during an incident and the root cause of the incident",
        "function": "Respond",
        "category": "Incident Analysis (RS.AN)",
    },
    "RC.RP-01": {
        "control_id": "RC.RP-01",
        "control_title": "The recovery portion of the incident response plan is executed once initiated from the incident response process",
        "function": "Recover",
        "category": "Incident Recovery Plan Execution (RC.RP)",
    },
}

# -----------------------------------------------------------------------
# Event-to-control mapping table
# Maps event_type → list of {framework, control_id, risk_level, finding, remediation}
# -----------------------------------------------------------------------
EVENT_MAPPINGS: Dict[str, List[Dict]] = {
    "brute_force": [
        {
            "framework": "ISO/IEC 27001:2022",
            "framework_version": "2022",
            "control_id": "A.8.5",
            "risk_level": "high",
            "finding_description": "Brute force attack detected against authentication endpoint. Repeated credential stuffing attempts indicate lack of or ineffective account lockout policy.",
            "remediation": "Implement account lockout after N failed attempts. Enable MFA. Review and enforce password policy. Block source IP(s) at perimeter firewall.",
        },
        {
            "framework": "NIST CSF 2.0",
            "framework_version": "2.0",
            "control_id": "DE.AE-02",
            "risk_level": "high",
            "finding_description": "Brute force pattern identified. This event should be analyzed as a potential indicator of compromise.",
            "remediation": "Correlate with other authentication events. Alert security operations. Review authentication failure patterns across systems.",
        },
        {
            "framework": "NIST CSF 2.0",
            "framework_version": "2.0",
            "control_id": "PR.AA-01",
            "risk_level": "high",
            "finding_description": "Identity and credential management may be insufficient if brute force attacks are not blocked.",
            "remediation": "Implement credential stuffing protection. Use adaptive authentication. Monitor for credential compromise.",
        },
    ],
    "port_scan": [
        {
            "framework": "ISO/IEC 27001:2022",
            "framework_version": "2022",
            "control_id": "A.8.20",
            "risk_level": "medium",
            "finding_description": "Port scanning activity detected. An attacker may be performing network reconnaissance to identify exposed services.",
            "remediation": "Review and close unnecessary open ports. Implement network segmentation. Update firewall rules to block unauthorized scanning.",
        },
        {
            "framework": "NIST CSF 2.0",
            "framework_version": "2.0",
            "control_id": "DE.CM-01",
            "risk_level": "medium",
            "finding_description": "Network scanning activity suggests external reconnaissance. This should trigger a monitoring alert.",
            "remediation": "Ensure network monitoring tools detect and alert on scanning activity in real time.",
        },
    ],
    "data_exfiltration": [
        {
            "framework": "ISO/IEC 27001:2022",
            "framework_version": "2022",
            "control_id": "A.8.12",
            "risk_level": "critical",
            "finding_description": "Potential data exfiltration detected. Large or unusual outbound data transfers may indicate a data breach.",
            "remediation": "URGENT: Isolate affected system. Preserve forensic evidence. Notify DPO. Review DLP controls and outbound traffic filtering.",
        },
        {
            "framework": "NIST CSF 2.0",
            "framework_version": "2.0",
            "control_id": "PR.DS-02",
            "risk_level": "critical",
            "finding_description": "Data in transit may be exfiltrated without authorization. Data protection controls may have failed.",
            "remediation": "Implement TLS inspection for outbound traffic. Deploy data loss prevention (DLP) solutions. Review data classification and access controls.",
        },
        {
            "framework": "ISO/IEC 27001:2022",
            "framework_version": "2022",
            "control_id": "A.5.26",
            "risk_level": "critical",
            "finding_description": "This event should trigger an incident response process if exfiltration is confirmed.",
            "remediation": "Activate incident response plan. Contain and eradicate threat. Notify relevant stakeholders and regulators if required.",
        },
    ],
    "privilege_escalation": [
        {
            "framework": "ISO/IEC 27001:2022",
            "framework_version": "2022",
            "control_id": "A.8.2",
            "risk_level": "high",
            "finding_description": "Privilege escalation attempt detected. An account may be attempting to gain unauthorized elevated access.",
            "remediation": "Review and restrict privileged access. Implement just-in-time (JIT) access. Audit recent privilege grants and remove excessive permissions.",
        },
        {
            "framework": "NIST CSF 2.0",
            "framework_version": "2.0",
            "control_id": "PR.AA-05",
            "risk_level": "high",
            "finding_description": "Access entitlements may not be properly enforced, allowing privilege escalation.",
            "remediation": "Implement PAM solution. Enforce principle of least privilege. Review access review cycle.",
        },
    ],
    "malware_detected": [
        {
            "framework": "ISO/IEC 27001:2022",
            "framework_version": "2022",
            "control_id": "A.8.7",
            "risk_level": "critical",
            "finding_description": "Malware detection event recorded. Malicious code may be present on affected systems.",
            "remediation": "Isolate affected host. Remove malware artifacts. Patch exploited vulnerabilities. Review endpoint protection configuration.",
        },
        {
            "framework": "NIST CSF 2.0",
            "framework_version": "2.0",
            "control_id": "RS.MA-01",
            "risk_level": "critical",
            "finding_description": "Malware event should trigger the incident response plan.",
            "remediation": "Activate IR plan. Coordinate response with IT and security teams. Document containment, eradication, and recovery steps.",
        },
    ],
    "account_lockout": [
        {
            "framework": "ISO/IEC 27001:2022",
            "framework_version": "2022",
            "control_id": "A.8.5",
            "risk_level": "high",
            "finding_description": "Account lockout triggered by repeated authentication failures. This may indicate a brute force or credential stuffing attack.",
            "remediation": "Investigate source of failed attempts. Verify account lockout thresholds are appropriate. Ensure MFA is enforced.",
        },
        {
            "framework": "NIST CSF 2.0",
            "framework_version": "2.0",
            "control_id": "DE.CM-03",
            "risk_level": "high",
            "finding_description": "User activity monitoring should have detected this anomaly.",
            "remediation": "Review authentication monitoring rules. Ensure SIEM or log analysis is alerting on multiple account lockouts.",
        },
    ],
    "login_failure": [
        {
            "framework": "ISO/IEC 27001:2022",
            "framework_version": "2022",
            "control_id": "A.8.5",
            "risk_level": "medium",
            "finding_description": "Elevated login failure count detected. May indicate unauthorized access attempts.",
            "remediation": "Monitor for continued failures. Verify lockout policy is functioning. Investigate if failures occur across multiple accounts.",
        },
    ],
    "login_success": [
        {
            "framework": "ISO/IEC 27001:2022",
            "framework_version": "2022",
            "control_id": "A.8.15",
            "risk_level": "low",
            "finding_description": "Login activity should be logged for audit purposes.",
            "remediation": "Ensure all authentication events are captured in security logs and retained per policy.",
        },
    ],
}


def map_alert_to_compliance(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Map a single alert to relevant compliance controls.

    Parameters
    ----------
    alert : dict with at least 'event_type', 'alert_id', 'evidence' fields.

    Returns
    -------
    List of compliance mapping dicts with disclaimer attached.
    """
    import uuid

    event_type = str(alert.get("event_type", "")).lower().strip()
    mappings_config = EVENT_MAPPINGS.get(event_type, [])

    if not mappings_config:
        # Generic mapping for unmapped event types
        mappings_config = [
            {
                "framework": "ISO/IEC 27001:2022",
                "framework_version": "2022",
                "control_id": "A.8.16",
                "risk_level": "low",
                "finding_description": f"Security event '{event_type}' was detected and requires monitoring review.",
                "remediation": "Investigate the event in context. Review logging and monitoring policies.",
            }
        ]

    result = []
    for m in mappings_config:
        # Get the full control details
        ctrl_db = ISO_CONTROLS if m["framework"].startswith("ISO") else NIST_CONTROLS
        ctrl_info = ctrl_db.get(m["control_id"], {})

        mapping = {
            "mapping_id": str(uuid.uuid4()),
            "alert_id": alert.get("alert_id", ""),
            "framework": m["framework"],
            "framework_version": m["framework_version"],
            "control_id": m["control_id"],
            "control_title": ctrl_info.get("control_title", m.get("control_title", "See control reference")),
            "finding_description": m["finding_description"],
            "evidence": (
                f"Alert ID: {alert.get('alert_id', 'N/A')}. "
                f"Event: {event_type}. "
                f"Source IP: {alert.get('source_ip', 'N/A')}. "
                f"Asset: {alert.get('affected_asset', 'N/A')}. "
                f"Detection reason: {alert.get('detection_reason', 'N/A')}."
            ),
            "risk_level": m["risk_level"],
            "remediation": m["remediation"],
            "disclaimer": (
                "This is a SUGGESTED association between an observed security event and a framework control. "
                "It does not constitute a formal audit finding, compliance certification, "
                "or confirmation that this control is violated. A qualified security auditor "
                "must assess applicability in context."
            ),
        }
        result.append(mapping)

    return result


def map_alerts_to_compliance(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Map a list of alerts to compliance controls."""
    all_mappings = []
    for alert in alerts:
        all_mappings.extend(map_alert_to_compliance(alert))
    return all_mappings
