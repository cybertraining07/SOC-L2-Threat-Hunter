
import json
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]

ALERTS_FILE = BASE_DIR / "data" / "processed" / "security_alerts.json"
INCIDENTS_FILE = BASE_DIR / "data" / "processed" / "incidents.json"


def load_alerts():
    if not ALERTS_FILE.exists():
        return []

    with ALERTS_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def generate_analyst_notes(alert):
    alert_name = alert.get("alert_name", "")
    hostname = alert.get("hostname") or "Unknown host"
    source_ip = alert.get("source_ip") or "Unknown source"
    username = alert.get("username") or "Unknown user"

    if "Brute-Force" in alert_name:
        return (
            f"Initial assessment: {alert.get('failed_attempts', 0)} "
            f"failed login attempts targeting account {username} "
            f"from {source_ip} on host {hostname}. "
            "Review authentication logs, check for successful logins "
            "from the source IP, and determine whether the account "
            "was compromised. Investigation pending."
        )

    if "PowerShell" in alert_name:
        process = alert.get("process_name") or "Unknown process"
        patterns = ", ".join(
            alert.get("matched_patterns", [])
        ) or "None recorded"

        return (
            f"Initial assessment: suspicious PowerShell activity "
            f"detected on {hostname}, involving {process} under "
            f"account {username}. Matched indicators: {patterns}. "
            "Review the command line, parent process and related "
            "endpoint activity. Investigation pending."
        )

    if "Network Connection" in alert_name:
        destination_ip = (
            alert.get("destination_ip") or "Unknown destination"
        )
        destination_port = (
            alert.get("destination_port") or "Unknown port"
        )

        return (
            f"Initial assessment: suspicious outbound connection "
            f"from {source_ip} on host {hostname} to "
            f"{destination_ip}:{destination_port}. "
            "Review network traffic, destination reputation and "
            "the process responsible for the connection. "
            "Investigation pending."
        )

    return (
        f"Initial assessment: {alert_name} detected on {hostname}. "
        "Review the alert details and relevant security logs. "
        "Investigation pending."
    )


def create_incidents():
    alerts = load_alerts()
    incidents = []

    for index, alert in enumerate(alerts, start=1):
        incident = {
            "incident_id": f"INC-{index:04d}",
            "rule_id": alert.get("rule_id"),
            "alert_name": alert.get("alert_name"),
            "severity": alert.get("severity", "LOW"),
            "source_ip": alert.get("source_ip"),
            "destination_ip": alert.get("destination_ip"),
            "destination_port": alert.get("destination_port"),
            "hostname": alert.get("hostname"),
            "username": alert.get("username"),
            "process_name": alert.get("process_name"),
            "matched_patterns": alert.get("matched_patterns", []),
            "failed_attempts": alert.get("failed_attempts"),
            "mitre_attack": alert.get("mitre_attack"),
            "status": "UNDER_INVESTIGATION",
            "analyst_notes": generate_analyst_notes(alert),
            "alert_details": alert,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        incidents.append(incident)

    INCIDENTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    with INCIDENTS_FILE.open("w", encoding="utf-8") as file:
        json.dump(incidents, file, indent=4)

    print(f"Created {len(incidents)} incident records.")
    print(f"Output file: {INCIDENTS_FILE}")


if __name__ == "__main__":
    create_incidents()
