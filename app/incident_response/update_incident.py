import json
from pathlib import Path
from datetime import datetime, timezone


BASE_DIR = Path(__file__).resolve().parents[2]
INCIDENTS_FILE = BASE_DIR / "data" / "processed" / "incidents.json"


def update_incident(
    incident_id: str,
    new_status: str,
    analyst_notes: str
):
    if not INCIDENTS_FILE.exists():
        print("No incident records found.")
        return

    with INCIDENTS_FILE.open("r", encoding="utf-8") as file:
        incidents = json.load(file)

    valid_statuses = [
        "OPEN",
        "UNDER_INVESTIGATION",
        "CONTAINED",
        "RESOLVED",
        "CLOSED"
    ]

    if new_status not in valid_statuses:
        print("Invalid incident status.")
        return

    for incident in incidents:
        if incident["incident_id"] == incident_id:
            incident["status"] = new_status
            incident["analyst_notes"] = analyst_notes
            incident["updated_at"] = datetime.now(
                timezone.utc
            ).isoformat()

            with INCIDENTS_FILE.open("w", encoding="utf-8") as file:
                json.dump(incidents, file, indent=4)

            print(f"Incident {incident_id} updated successfully.")
            return

    print(f"Incident {incident_id} not found.")


if __name__ == "__main__":
    update_incident(
        incident_id="INC-0001",
        new_status="UNDER_INVESTIGATION",
        analyst_notes=(
            "Three failed SSH login attempts detected against "
            "the admin account from 192.168.1.105. "
            "Review authentication logs and investigate the source."
        )
    )
