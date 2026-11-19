
from app.detection.network_detector import detect_suspicious_network


def create_network_event(
    destination_ip="203.0.113.50",
    destination_port=4444,
    event_type="NETWORK_CONNECTION"
):
    return {
        "event_id": "NET-001",
        "event_type": event_type,
        "hostname": "kali-lab",
        "source_ip": "192.168.1.20",
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "username": "admin"
    }


def test_detect_suspicious_port_4444():
    events = [create_network_event()]

    alerts = detect_suspicious_network(events)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["destination_port"] == 4444
    assert alerts[0]["mitre_attack"] == "T1571"


def test_detect_suspicious_port_5555():
    events = [
        create_network_event(destination_port=5555)
    ]

    alerts = detect_suspicious_network(events)

    assert len(alerts) == 1
    assert alerts[0]["destination_port"] == 5555


def test_normal_port_does_not_trigger_alert():
    events = [
        create_network_event(destination_port=443)
    ]

    alerts = detect_suspicious_network(events)

    assert len(alerts) == 0


def test_non_network_event_does_not_trigger_alert():
    events = [
        create_network_event(event_type="PROCESS_EXECUTION")
    ]

    alerts = detect_suspicious_network(events)

    assert len(alerts) == 0


def test_missing_destination_port_does_not_trigger_alert():
    event = create_network_event()
    event["destination_port"] = None

    alerts = detect_suspicious_network([event])

    assert len(alerts) == 0
