
from app.detection.brute_force_detector import detect_brute_force


def create_event(event_id, timestamp, source_ip="192.168.1.105",
                 username="admin", event_type="FAILED_LOGIN"):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "source_ip": source_ip,
        "username": username
    }


def test_detect_three_failed_logins():
    events = [
        create_event("1", "2026-11-19T10:00:00+00:00"),
        create_event("2", "2026-11-19T10:01:00+00:00"),
        create_event("3", "2026-11-19T10:02:00+00:00")
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["mitre_attack"] == "T1110"
    assert alerts[0]["failed_attempts"] == 3


def test_two_failed_logins_do_not_trigger_alert():
    events = [
        create_event("1", "2026-11-19T10:00:00+00:00"),
        create_event("2", "2026-11-19T10:01:00+00:00")
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0


def test_logins_outside_five_minute_window():
    events = [
        create_event("1", "2026-11-19T10:00:00+00:00"),
        create_event("2", "2026-11-19T10:06:00+00:00"),
        create_event("3", "2026-11-19T10:12:00+00:00")
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0


def test_successful_login_does_not_trigger_alert():
    events = [
        create_event(
            "1", "2026-11-19T10:00:00+00:00",
            event_type="SUCCESSFUL_LOGIN"
        ),
        create_event(
            "2", "2026-11-19T10:01:00+00:00",
            event_type="SUCCESSFUL_LOGIN"
        ),
        create_event(
            "3", "2026-11-19T10:02:00+00:00",
            event_type="SUCCESSFUL_LOGIN"
        )
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0
def test_brute_force_alert_includes_hostname():
    events = [
        create_event("1", "2026-11-19T10:00:00+00:00"),
        create_event("2", "2026-11-19T10:01:00+00:00"),
        create_event("3", "2026-11-19T10:02:00+00:00")
    ]

    for event in events:
        event["hostname"] = "kali-lab"

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["hostname"] == "kali-lab"
