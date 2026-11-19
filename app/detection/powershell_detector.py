
SUSPICIOUS_PATTERNS = {
    "ENCODED_COMMAND": [
        "-enc",
        "-encodedcommand"
    ],
    "HIDDEN_EXECUTION": [
        "-windowstyle hidden",
        "-w hidden"
    ],
    "DOWNLOAD_ACTIVITY": [
        "downloadstring",
        "invoke-webrequest",
        "start-bitstransfer"
    ],
    "SUSPICIOUS_SCRIPT_EXECUTION": [
        "invoke-expression",
        "iex ",
        "frombase64string"
    ]
}


def detect_suspicious_powershell(events: list[dict]) -> list[dict]:
    """Identify suspicious PowerShell command-line patterns."""

    alerts = []

    for event in events:
        process_name = (
            event.get("process_name") or ""
        ).lower()

        description = (
            event.get("description") or ""
        ).lower()

        command_line = (
            event.get("raw_data", {}).get("command_line") or ""
        ).lower()

        if "powershell" not in process_name:
            continue

        combined_data = f"{description} {command_line}"
        matched_patterns = []

        for category, patterns in SUSPICIOUS_PATTERNS.items():
            if any(pattern in combined_data for pattern in patterns):
                matched_patterns.append(category)

        if not matched_patterns:
            continue

        alerts.append({
            "rule_id": "SOC-ENDPOINT-001",
            "alert_name": "Suspicious PowerShell Execution",
            "severity": "HIGH",
            "hostname": event.get("hostname"),
            "username": event.get("username"),
            "process_name": event.get("process_name"),
            "matched_patterns": matched_patterns,
            "mitre_attack": "T1059.001",
            "status": "OPEN",
            "description": (
                "PowerShell execution contains suspicious "
                "command-line indicators."
            ),
            "recommended_action": (
                "Review the process command line, parent process, "
                "user account and related endpoint activity."
            )
        })

    return alerts
