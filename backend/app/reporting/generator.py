"""
PDF security assessment report generator using ReportLab.

Generates professional reports from actual analysis results.
Reports are based only on real analyzed data — no fabricated findings.
"""
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _safe_str(val: Any, max_len: int = 200) -> str:
    """Convert value to string safely."""
    s = str(val) if val is not None else "N/A"
    return s[:max_len] + "..." if len(s) > max_len else s


def generate_report(
    alerts: List[Dict],
    incidents: List[Dict],
    compliance_mappings: List[Dict],
    dataset_summary: Dict,
    model_metrics: Optional[Dict],
    output_dir: Path,
    report_title: str = "Security Assessment Report",
) -> Dict[str, Any]:
    """
    Generate a PDF security assessment report.

    Parameters
    ----------
    alerts : list of alert dicts from detection engine
    incidents : list of incident dicts from correlation engine
    compliance_mappings : list of compliance mapping dicts
    dataset_summary : dict with log count, date range, etc.
    model_metrics : dict with model evaluation results (or None)
    output_dir : directory to save the report PDF
    report_title : title for the report

    Returns
    -------
    dict with report_id, file_path, generated_at, summary
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable,
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report_id = str(uuid.uuid4())
    generated_at = datetime.utcnow()
    filename = f"security_report_{generated_at.strftime('%Y%m%d_%H%M%S')}.pdf"
    file_path = output_dir / filename

    # ----------------------------------------------------------------
    # Styles
    # ----------------------------------------------------------------
    styles = getSampleStyleSheet()
    style_title = ParagraphStyle(
        "ReportTitle", parent=styles["Title"],
        fontSize=22, spaceAfter=6, textColor=colors.HexColor("#1a365d")
    )
    style_h1 = ParagraphStyle(
        "H1", parent=styles["Heading1"],
        fontSize=14, spaceAfter=4, textColor=colors.HexColor("#1a365d"),
        spaceBefore=12
    )
    style_h2 = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontSize=11, spaceAfter=3, textColor=colors.HexColor("#2c5282"),
        spaceBefore=8
    )
    style_body = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=9, spaceAfter=3, leading=13
    )
    style_small = ParagraphStyle(
        "Small", parent=styles["Normal"],
        fontSize=8, spaceAfter=2, leading=11, textColor=colors.HexColor("#555555")
    )
    style_disclaimer = ParagraphStyle(
        "Disclaimer", parent=styles["Normal"],
        fontSize=8, spaceAfter=3, leading=11,
        textColor=colors.HexColor("#cc0000"),
        borderColor=colors.HexColor("#cc0000"),
        borderWidth=0.5, borderPadding=4
    )
    style_center = ParagraphStyle(
        "Center", parent=styles["Normal"],
        alignment=TA_CENTER, fontSize=9
    )

    # ----------------------------------------------------------------
    # Build document
    # ----------------------------------------------------------------
    doc = SimpleDocTemplate(
        str(file_path),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )
    story = []

    # ---- Title Page ----
    story.append(Paragraph(report_title, style_title))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a365d")))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(f"Generated: {generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}", style_body))
    story.append(Paragraph(f"Report ID: {report_id}", style_small))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(
        "<b>DISCLAIMER:</b> This report contains SUGGESTED security findings based on automated analysis. "
        "It is not a formal security audit. All findings require validation by a qualified security professional. "
        "Compliance mappings are suggested associations — not formal audit results.",
        style_disclaimer
    ))
    story.append(Spacer(1, 0.5 * cm))

    # ---- Section 1: Executive Summary ----
    story.append(Paragraph("1. Executive Summary", style_h1))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.2 * cm))

    total_logs = dataset_summary.get("total_logs", 0)
    total_alerts = len(alerts)
    total_incidents = len(incidents)
    critical_count = sum(1 for a in alerts if a.get("severity") == "critical")
    high_count = sum(1 for a in alerts if a.get("severity") == "high")

    summary_data = [
        ["Metric", "Value"],
        ["Total Logs Analyzed", str(total_logs)],
        ["Suspicious Alerts Detected", str(total_alerts)],
        ["Potential Incidents Correlated", str(total_incidents)],
        ["Critical Severity Alerts", str(critical_count)],
        ["High Severity Alerts", str(high_count)],
        ["Analysis Period", dataset_summary.get("date_range", "N/A")],
    ]
    t = Table(summary_data, colWidths=[9 * cm, 8 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a365d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f7fafc"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.4 * cm))

    # ---- Section 2: Dataset and Analysis Summary ----
    story.append(Paragraph("2. Dataset and Analysis Summary", style_h1))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        f"The analysis was performed on a dataset containing <b>{total_logs}</b> security log records. "
        f"The dataset covers the period <b>{dataset_summary.get('date_range', 'N/A')}</b>. "
        f"Log sources include: {dataset_summary.get('log_sources', 'Security event logs')}.",
        style_body
    ))
    story.append(Spacer(1, 0.3 * cm))

    # ---- Section 3: Model Information ----
    story.append(Paragraph("3. Machine Learning Model Information", style_h1))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.2 * cm))

    if model_metrics:
        best_model = model_metrics.get("best_model", "N/A")
        bm = model_metrics.get("model_metrics", {}).get(best_model, {})
        story.append(Paragraph(f"<b>Selected Model:</b> {best_model}", style_body))
        story.append(Paragraph(
            f"<b>Selection Criteria:</b> {model_metrics.get('selection_criteria', 'N/A')}",
            style_body
        ))
        story.append(Spacer(1, 0.2 * cm))

        if "accuracy" in bm:
            metric_data = [
                ["Metric", "Value", "Description"],
                ["Accuracy", f"{bm.get('accuracy', 0):.4f}", "Proportion of correctly classified records"],
                ["Precision (Suspicious)", f"{bm.get('precision_suspicious', 0):.4f}", "Of flagged events, how many are truly suspicious"],
                ["Recall (Suspicious)", f"{bm.get('recall_suspicious', 0):.4f}", "Of actual suspicious events, how many were caught"],
                ["F1-Score (Suspicious)", f"{bm.get('f1_suspicious', 0):.4f}", "Harmonic mean of precision and recall"],
                ["False Positive Rate", f"{bm.get('false_positive_rate', 0):.4f}", "Normal events incorrectly flagged as suspicious"],
                ["False Positives", str(bm.get("false_positives", "N/A")), "Count of normal events predicted as suspicious"],
                ["False Negatives", str(bm.get("false_negatives", "N/A")), "Count of suspicious events missed by the model"],
            ]
            t2 = Table(metric_data, colWidths=[5 * cm, 3 * cm, 9 * cm])
            t2.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c5282")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ebf8ff"), colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bee3f8")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t2)
        story.append(Spacer(1, 0.3 * cm))
    else:
        story.append(Paragraph(
            "No trained model metrics available. Run the training pipeline to generate model evaluation results.",
            style_body
        ))

    # ---- Section 4: Detected Suspicious Events ----
    story.append(PageBreak())
    story.append(Paragraph("4. Detected Suspicious Events", style_h1))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.2 * cm))

    if alerts:
        story.append(Paragraph(f"Total alerts detected: <b>{len(alerts)}</b>", style_body))
        story.append(Spacer(1, 0.2 * cm))

        alert_data = [["Alert ID (short)", "Timestamp", "Event Type", "Severity", "Source IP", "Method"]]
        for a in alerts[:50]:  # Limit to 50 for report length
            alert_data.append([
                _safe_str(a.get("alert_id", "")[:16], 16) + "...",
                _safe_str(a.get("timestamp", "")[:19], 19),
                _safe_str(a.get("event_type", ""), 30),
                _safe_str(a.get("severity", ""), 10),
                _safe_str(a.get("source_ip", ""), 20),
                _safe_str(a.get("detection_method", ""), 10),
            ])
        if len(alerts) > 50:
            alert_data.append(["...", f"({len(alerts) - 50} more)", "", "", "", ""])

        sev_colors = {"critical": "#FED7D7", "high": "#FEEBC8", "medium": "#FEFCBF", "low": "#F0FFF4"}

        t3 = Table(alert_data, colWidths=[2.5 * cm, 4 * cm, 4 * cm, 2 * cm, 3.5 * cm, 2 * cm])
        table_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a365d")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for i, a in enumerate(alerts[:50], start=1):
            sev = a.get("severity", "low")
            hex_col = sev_colors.get(sev, "#ffffff")
            table_style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor(hex_col)))
        t3.setStyle(TableStyle(table_style))
        story.append(t3)
    else:
        story.append(Paragraph("No suspicious events were detected in the analyzed dataset.", style_body))

    story.append(Spacer(1, 0.4 * cm))

    # ---- Section 5: Correlated Incidents ----
    story.append(Paragraph("5. Correlated Potential Incidents", style_h1))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.2 * cm))

    if incidents:
        for inc in incidents[:20]:  # limit
            story.append(Paragraph(f"<b>Incident: {inc.get('category', 'Unknown')}</b>", style_h2))
            inc_data = [
                ["Field", "Value"],
                ["Incident ID", _safe_str(inc.get("incident_id", ""), 40)],
                ["Category", _safe_str(inc.get("category", ""), 60)],
                ["Severity", _safe_str(inc.get("severity", ""), 20)],
                ["First Seen", _safe_str(inc.get("first_seen", ""), 30)],
                ["Last Seen", _safe_str(inc.get("last_seen", ""), 30)],
                ["Alert Count", str(inc.get("alert_count", len(inc.get("alert_ids", []))))],
                ["Affected Assets", _safe_str(", ".join(inc.get("affected_assets", [])), 80)],
            ]
            t4 = Table(inc_data, colWidths=[5 * cm, 12 * cm])
            t4.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c5282")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f7fafc"), colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t4)
            story.append(Spacer(1, 0.1 * cm))
            story.append(Paragraph(f"<b>Evidence:</b> {_safe_str(inc.get('evidence_summary', ''), 400)}", style_small))
            story.append(Paragraph(f"<b>Recommended Remediation:</b> {_safe_str(inc.get('remediation', ''), 400)}", style_small))
            story.append(Spacer(1, 0.3 * cm))
    else:
        story.append(Paragraph("No incidents were correlated from the detected alerts.", style_body))

    # ---- Section 6: Compliance Mappings ----
    story.append(PageBreak())
    story.append(Paragraph("6. Suggested Compliance Mappings", style_h1))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.1 * cm))
    story.append(Paragraph(
        "DISCLAIMER: The following are SUGGESTED associations only. They are not formal audit findings.",
        style_disclaimer
    ))
    story.append(Spacer(1, 0.2 * cm))

    # Deduplicate mappings by control_id for the report
    seen_controls = {}
    for m in compliance_mappings:
        key = (m.get("framework"), m.get("control_id"))
        if key not in seen_controls:
            seen_controls[key] = m

    if seen_controls:
        comp_data = [["Framework", "Control ID", "Risk Level", "Finding (summary)"]]
        for m in list(seen_controls.values())[:40]:
            comp_data.append([
                _safe_str(m.get("framework", ""), 20),
                _safe_str(m.get("control_id", ""), 15),
                _safe_str(m.get("risk_level", ""), 10),
                _safe_str(m.get("finding_description", ""), 80),
            ])
        t5 = Table(comp_data, colWidths=[5 * cm, 3 * cm, 2.5 * cm, 7.5 * cm])
        t5.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a365d")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f7fafc"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("WORDWRAP", (3, 1), (3, -1), 1),
        ]))
        story.append(t5)
    else:
        story.append(Paragraph("No compliance mappings generated.", style_body))

    # ---- Section 7: Limitations ----
    story.append(PageBreak())
    story.append(Paragraph("7. Known Limitations and Data Quality Notes", style_h1))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.2 * cm))

    limitations = [
        "The ML model was trained on synthetic data generated using rule-based labels. "
        "Performance on real-world logs may differ significantly.",
        "Alert correlation uses time-based and IP-based heuristics. "
        "It may produce false groupings if multiple unrelated events occur in the same window.",
        "Compliance mappings are suggested associations based on event types. "
        "They must be reviewed by a qualified security auditor.",
        "The system does not verify whether a detected suspicious event constitutes a confirmed attack.",
        "Confidence scores from ML models are probabilities, not certainties. "
        "High confidence does not guarantee the prediction is correct.",
        "This platform is intended as a demonstration/intern project tool, "
        "not a production security operations centre (SOC) replacement.",
    ]
    for i, lim in enumerate(limitations, 1):
        story.append(Paragraph(f"{i}. {lim}", style_body))
        story.append(Spacer(1, 0.1 * cm))

    # ---- Build PDF ----
    doc.build(story)
    logger.info("PDF report generated: %s (%d bytes)", file_path, file_path.stat().st_size)

    return {
        "report_id": report_id,
        "file_path": str(file_path),
        "filename": filename,
        "generated_at": generated_at.isoformat(),
        "summary": {
            "total_logs": total_logs,
            "total_alerts": total_alerts,
            "total_incidents": total_incidents,
            "critical_alerts": critical_count,
            "high_alerts": high_count,
            "compliance_mappings": len(compliance_mappings),
            "report_title": report_title,
        },
    }
