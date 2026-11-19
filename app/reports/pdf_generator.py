
import json
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


BASE_DIR = Path(__file__).resolve().parents[2]

INCIDENTS_FILE = BASE_DIR / "data" / "processed" / "incidents.json"
RECOMMENDATIONS_FILE = (
    BASE_DIR / "data" / "processed" / "response_recommendations.json"
)

REPORTS_DIR = BASE_DIR / "reports"


def load_json(file_path):
    if not file_path.exists():
        return []

    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def generate_incident_report():
    incidents = load_json(INCIDENTS_FILE)
    recommendations = load_json(RECOMMENDATIONS_FILE)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    report_path = REPORTS_DIR / "SOC_L2_Incident_Report.pdf"

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#12345A"),
        fontSize=20,
        spaceAfter=12
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#12345A"),
        spaceBefore=12,
        spaceAfter=8
    )

    body_style = styles["BodyText"]

    story = []

    story.append(Paragraph(
        "SOC L2 THREAT HUNTER",
        title_style
    ))

    story.append(Paragraph(
        "Security Incident Investigation Report",
        styles["Heading2"]
    ))

    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph(
        f"Report generated: {datetime.now(timezone.utc).isoformat()}",
        body_style
    ))

    story.append(Paragraph(
        "Project: SOC L2 Threat Hunter",
        body_style
    ))

    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph(
        "Executive Summary",
        heading_style
    ))

    high_count = sum(
        1 for incident in incidents
        if incident.get("severity") == "HIGH"
    )

    critical_count = sum(
        1 for incident in incidents
        if incident.get("severity") == "CRITICAL"
    )

    summary_data = [
        ["Metric", "Value"],
        ["Total incidents", str(len(incidents))],
        ["High severity", str(high_count)],
        ["Critical severity", str(critical_count)]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[75 * mm, 45 * mm]
    )

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12345A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8)
    ]))

    story.append(summary_table)

    story.append(Spacer(1, 10 * mm))

    for incident in incidents:
        incident_id = incident.get("incident_id", "Unknown")

        story.append(Paragraph(
            f"Incident: {incident_id}",
            heading_style
        ))

        details = [
            ["Field", "Details"],
            ["Alert", str(incident.get("alert_name", "N/A"))],
            ["Severity", str(incident.get("severity", "N/A"))],
            ["Status", str(incident.get("status", "N/A"))],
            ["Hostname", str(incident.get("hostname") or "N/A")],
            ["Source IP", str(incident.get("source_ip") or "N/A")],
            ["Destination IP", str(incident.get("destination_ip") or "N/A")],
            ["Destination Port", str(incident.get("destination_port") or "N/A")],
            ["Username", str(incident.get("username") or "N/A")],
            ["Process", str(incident.get("process_name") or "N/A")],
            ["MITRE ATT&CK", str(incident.get("mitre_attack") or "N/A")],
            ["Created", str(incident.get("created_at", "N/A"))],
            ["Analyst Notes", str(incident.get("analyst_notes", "N/A"))]
        ]

        details_table = Table(
            details,
            colWidths=[45 * mm, 125 * mm]
        )

        details_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12345A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))

        story.append(details_table)

        story.append(Spacer(1, 5 * mm))

        story.append(Paragraph(
            "Recommended Response Actions",
            styles["Heading3"]
        ))

        incident_recommendations = next(
            (
                item for item in recommendations
                if item.get("incident_id") == incident_id
            ),
            {}
        )

        actions = incident_recommendations.get(
            "response_recommendations", []
        )

        if actions:
            for action in actions:
                story.append(Paragraph(
                    f"&bull; {action}",
                    body_style
                ))
                story.append(Spacer(1, 3))
        else:
            story.append(Paragraph(
                "No recommendations available.",
                body_style
            ))

        story.append(Spacer(1, 10 * mm))

    story.append(PageBreak())

    story.append(Paragraph(
        "Investigation Disclaimer",
        heading_style
    ))

    story.append(Paragraph(
        "This report contains simulated security events generated "
        "for a cybersecurity laboratory demonstration. Detection "
        "alerts are indicators requiring analyst validation and "
        "do not independently confirm malicious compromise.",
        body_style
    ))

    document = SimpleDocTemplate(
        str(report_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    document.build(story)

    print("PDF incident report generated successfully.")
    print(f"Incidents included: {len(incidents)}")
    print(f"Report location: {report_path}")


if __name__ == "__main__":
    generate_incident_report()
