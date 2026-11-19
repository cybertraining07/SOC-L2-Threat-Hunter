
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "online"
    assert data["application"] == "SOC L2 Threat Hunter"


def test_dashboard_endpoint():
    response = client.get("/api/dashboard")

    assert response.status_code == 200

    data = response.json()

    assert "total_events" in data
    assert "total_alerts" in data
    assert "high_alerts" in data
    assert "critical_alerts" in data
    assert "total_incidents" in data
    assert "open_incidents" in data

    assert isinstance(data["events"] if "events" in data else [], list)
    assert isinstance(data["alerts"], list)
    assert isinstance(data["incidents"], list)
    assert isinstance(data["recommendations"], list)


def test_dashboard_counts():
    response = client.get("/api/dashboard")

    assert response.status_code == 200

    data = response.json()

    assert data["total_events"] >= 0
    assert data["total_alerts"] >= 0
    assert data["high_alerts"] >= 0
    assert data["critical_alerts"] >= 0
    assert data["total_incidents"] >= 0
    assert data["open_incidents"] >= 0


def test_dashboard_html():
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "SOC L2 Threat Hunter" in response.text
    assert "Security Alerts" in response.text
    assert "Incident Management" in response.text
