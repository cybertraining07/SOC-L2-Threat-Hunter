
from collections import defaultdict
from datetime import datetime, timedelta


def detect_brute_force(
    events: list[dict],
    threshold: int = 3,
    window_minutes: int = 5
) -> list[dict]:
    """Detect repeated failed logins from the same IP and username."""

    grouped_events = defaultdict(list)

    for event in events:
        if event.get("event_type") != "FAILED_LOGIN":
            continue

        source_ip = event.get("source_ip")
        username = event.get("username")

        if not source_ip or not username:
            continue

        timestamp = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )

        key = (source_ip, username)
        grouped_events[key].append({
            "timestamp": timestamp,
            "event": event
        })

    alerts = []

    for (source_ip, username), records in grouped_events.items():
        records.sort(key=lambda record: record["timestamp"])

        for index, start_record in enumerate(records):
            start_time = start_record["timestamp"]
            end_time = start_time + timedelta(minutes=window_minutes)

            matching_records = [
                record
                for record in records[index:]
                if record["timestamp"] <= end_time
            ]

            if len(matching_records) >= threshold:
                hostname = next(
                    (
                        record["event"].get("hostname")
                        for record in matching_records
                        if record["event"].get("hostname")
                    ),
                    None
                )

                alerts.append({
                    "rule_id": "SOC-AUTH-001",
                    "alert_name": "Possible SSH Brute-Force Activity",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "username": username,
                    "hostname": hostname,
                    "failed_attempts": len(matching_records),
                    "time_window_minutes": window_minutes,
                    "mitre_attack": "T1110",
                    "status": "OPEN",
                    "description": (
                        f"{len(matching_records)} failed login attempts "
                        f"for {username} from {source_ip} "
                        f"within {window_minutes} minutes."
                    ),
                    "recommended_action": (
                        "Investigate the source IP, review authentication "
                        "logs and check whether the account was compromised."
                    )
                })
                break

    return alerts
