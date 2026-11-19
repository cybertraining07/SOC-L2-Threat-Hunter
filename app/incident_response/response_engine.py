
def generate_response(incident: dict) -> dict:
    severity = incident.get("severity", "LOW")
    alert_name = incident.get("alert_name", "")

    recommendations = []

    if "Brute-Force" in alert_name:
        recommendations = [
            "Review SSH authentication logs.",
            "Verify whether the targeted account was compromised.",
            "Check for successful logins from the suspicious IP.",
            "Review source IP reputation and related activity.",
            "Consider blocking the source IP if malicious activity is confirmed.",
            "Review SSH access controls and disable password authentication where appropriate."
        ]

    elif "PowerShell" in alert_name:
        recommendations = [
            "Review the PowerShell command line and process execution logs.",
            "Investigate the parent process and initiating user account.",
            "Check for encoded commands, downloaded files and suspicious scripts.",
            "Review endpoint telemetry for related process and network activity.",
            "Isolate the endpoint if malicious activity is confirmed.",
            "Preserve relevant logs and evidence for investigation."
        ]

    elif "Network Connection" in alert_name:
        recommendations = [
            "Investigate the destination IP address and destination port.",
            "Review firewall and network traffic logs.",
            "Identify the process responsible for the outbound connection.",
            "Check whether other endpoints contacted the same destination.",
            "Consider blocking the destination if malicious activity is confirmed.",
            "Preserve relevant network and endpoint evidence."
        ]

    elif severity == "CRITICAL":
        recommendations = [
            "Escalate the incident immediately.",
            "Investigate affected systems and accounts.",
            "Contain confirmed compromised systems.",
            "Preserve evidence for forensic investigation."
        ]

    elif severity == "HIGH":
        recommendations = [
            "Investigate the affected account and system.",
            "Review related security logs.",
            "Identify suspicious activity.",
            "Document findings and escalate if compromise is confirmed."
        ]

    else:
        recommendations = [
            "Review the alert details.",
            "Check relevant system logs.",
            "Document investigation findings."
        ]

    return {
        "incident_id": incident.get("incident_id"),
        "severity": severity,
        "alert_name": alert_name,
        "response_recommendations": recommendations
    }
