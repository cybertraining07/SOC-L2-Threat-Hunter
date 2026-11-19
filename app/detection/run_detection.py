
import json

from app.collectors.event_collector import load_events
from app.detection.brute_force_detector import detect_brute_force
from app.detection.powershell_detector import detect_suspicious_powershell
from app.detection.network_detector import detect_suspicious_network
from app.detection.alert_manager import save_alerts


def normalize_events(events: list[dict]) -> list[dict]:
    """Expose nested event fields for detection modules."""

    normalized_events = []

    for event in events:
        normalized = dict(event)
        raw_data = event.get("raw_data") or {}

        normalized["destination_port"] = (
            event.get("destination_port")
            or raw_data.get("destination_port")
        )

        normalized["destination_ip"] = (
            event.get("destination_ip")
            or raw_data.get("destination_ip")
        )

        normalized_events.append(normalized)

    return normalized_events


def main():
    # Load collected security events
    events = load_events()

    # Normalize nested event fields
    normalized_events = normalize_events(events)

    # Run SSH brute-force detection
    brute_force_alerts = detect_brute_force(
        normalized_events,
        threshold=3,
        window_minutes=5
    )

    # Run suspicious PowerShell detection
    powershell_alerts = detect_suspicious_powershell(
        normalized_events
    )

    # Run suspicious network detection
    network_alerts = detect_suspicious_network(
        normalized_events
    )

    # Combine all detection results
    alerts = (
        brute_force_alerts
        + powershell_alerts
        + network_alerts
    )

    # Save combined alerts
    save_alerts(alerts)

    # Display detection summary
    print("\n===== SOC L2 CENTRAL DETECTION ENGINE =====")

    print(f"Events analyzed: {len(events)}")
    print(f"Brute-force alerts: {len(brute_force_alerts)}")
    print(f"PowerShell alerts: {len(powershell_alerts)}")
    print(f"Network alerts: {len(network_alerts)}")
    print(f"Total alerts generated: {len(alerts)}")

    print("\n===== DETECTION RESULTS =====")

    for alert in alerts:
        print(json.dumps(alert, indent=4))


if __name__ == "__main__":
    main()
