
from app.detection.powershell_detector import detect_suspicious_powershell


def create_powershell_event(description="", command_line=""):
    return {
        "event_id": "PS-001",
        "event_type": "PROCESS_EXECUTION",
        "process_name": "powershell.exe",
        "hostname": "windows-lab",
        "username": "admin",
        "description": description,
        "raw_data": {
            "command_line": command_line
        }
    }


def test_detect_encoded_powershell():
    events = [
        create_powershell_event(
            command_line="powershell.exe -EncodedCommand ABC123"
        )
    ]

    alerts = detect_suspicious_powershell(events)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["mitre_attack"] == "T1059.001"


def test_detect_hidden_powershell():
    events = [
        create_powershell_event(
            command_line="powershell.exe -WindowStyle Hidden"
        )
    ]

    alerts = detect_suspicious_powershell(events)

    assert len(alerts) == 1
    assert "HIDDEN_EXECUTION" in alerts[0]["matched_patterns"]


def test_detect_download_activity():
    events = [
        create_powershell_event(
            command_line="powershell.exe Invoke-WebRequest"
        )
    ]

    alerts = detect_suspicious_powershell(events)

    assert len(alerts) == 1
    assert "DOWNLOAD_ACTIVITY" in alerts[0]["matched_patterns"]


def test_normal_powershell_does_not_trigger_alert():
    events = [
        create_powershell_event(
            command_line="powershell.exe Get-Process"
        )
    ]

    alerts = detect_suspicious_powershell(events)

    assert len(alerts) == 0


def test_non_powershell_process_does_not_trigger_alert():
    event = create_powershell_event(
        command_line="cmd.exe -EncodedCommand ABC123"
    )

    event["process_name"] = "cmd.exe"

    alerts = detect_suspicious_powershell([event])

    assert len(alerts) == 0
