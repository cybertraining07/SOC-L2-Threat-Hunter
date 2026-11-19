import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "processed"
EVENTS_FILE = BASE_DIR / "data" / "raw" / "security_events.jsonl"
DASHBOARD_FILE = BASE_DIR / "dashboard" / "index.html"

app = FastAPI(
    title="SOC L2 Threat Hunter",
    description="Security monitoring and incident response dashboard",
    version="1.0.0"
)


def load_json(filename):
    file_path = DATA_DIR / filename

    if not file_path.exists():
        return []

    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_events():
    if not EVENTS_FILE.exists():
        return []

    events = []

    with EVENTS_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                events.append(json.loads(line))

    return events


@app.get("/")
def health_check():
    return {
        "status": "online",
        "application": "SOC L2 Threat Hunter"
    }


@app.get("/api/dashboard")
def dashboard_data():
    events = load_events()
    alerts = load_json("security_alerts.json")
    incidents = load_json("incidents.json")
    recommendations = load_json("response_recommendations.json")

    return {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "high_alerts": sum(
            1 for alert in alerts
            if alert.get("severity") == "HIGH"
        ),
        "critical_alerts": sum(
            1 for alert in alerts
            if alert.get("severity") == "CRITICAL"
        ),
        "total_incidents": len(incidents),
        "open_incidents": sum(
            1 for incident in incidents
            if incident.get("status") in [
                "OPEN", "UNDER_INVESTIGATION"
            ]
        ),
        "incidents": incidents,
        "alerts": alerts,
        "recommendations": recommendations
    }


@app.get("/dashboard", response_class=HTMLResponse)
def security_dashboard():
    if not DASHBOARD_FILE.exists():
        return HTMLResponse(
            "<h2>Dashboard HTML file not found.</h2>",
            status_code=404
        )

    return HTMLResponse(
        DASHBOARD_FILE.read_text(encoding="utf-8")
    )
