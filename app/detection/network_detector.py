SUSPICIOUS_PORTS = {
    4444: "Potential reverse-shell communication",
    5555: "Unusual service communication",
    6667: "IRC communication",
    31337: "Unusual high-risk service port"
}


def detect_suspicious_network(events: list[dict]) -> list[dict]:
    """Detect simulated suspicious outbound network connections."""

    alerts = []

    for event in events:
        event_type = event.get("event_type", "").upper()

        if event_type not in [
            "NETWORK_CONNECTION",
            "OUTBOUND_CONNECTION"
        ]:
            continue

        raw_data = event.get("raw_data") or {}

        # Read network details from either the top level or raw_data
        destination_ip = (
            event.get("destination_ip")
            or raw_data.get("destination_ip")
        )

        destination_port = (
            event.get("destination_port")
            or raw_data.get("destination_port")
        )

        if destination_port is None:
            continue

        try:
            destination_port = int(destination_port)
        except (ValueError, TypeError):
            continue

        if destination_port not in SUSPICIOUS_PORTS:
            continue

        alerts.append({
            "rule_id": "SOC-NETWORK-001",
            "alert_name": "Suspicious Outbound Network Connection",
            "severity": "HIGH",
            "hostname": event.get("hostname"),
            "source_ip": event.get("source_ip"),
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "username": event.get("username"),
            "indicator": SUSPICIOUS_PORTS[destination_port],
            "mitre_attack": "T1571",
            "status": "OPEN",
            "description": (
                f"Outbound connection detected to "
                f"{destination_ip or 'unknown destination'} "
                f"on port {destination_port}."
            ),
            "recommended_action": (
                "Review network traffic, destination reputation, "
                "process ownership and endpoint activity."
            )
        })

    return alerts
