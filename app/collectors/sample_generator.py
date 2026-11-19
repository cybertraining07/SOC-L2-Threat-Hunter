from app.collectors.event_model import SecurityEvent
from app.collectors.event_collector import collect_event


def generate_sample_events():
    samples = [
        {
            "event_id": "SOC-001",
            "source": "Linux Auth",
            "event_type": "FAILED_LOGIN",
            "severity": "MEDIUM",
            "username": "admin",
            "source_ip": "192.168.1.105",
            "hostname": "kali-lab",
            "description": "Failed SSH authentication attempt",
            "raw_data": {"service": "sshd"}
        },
        {
            "event_id": "SOC-002",
            "source": "Linux Auth",
            "event_type": "FAILED_LOGIN",
            "severity": "MEDIUM",
            "username": "admin",
            "source_ip": "192.168.1.105",
            "hostname": "kali-lab",
            "description": "Repeated failed SSH authentication",
            "raw_data": {"service": "sshd"}
        },
        {
            "event_id": "SOC-003",
            "source": "Linux Auth",
            "event_type": "SUCCESSFUL_LOGIN",
            "severity": "LOW",
            "username": "analyst",
            "source_ip": "192.168.1.20",
            "hostname": "kali-lab",
            "description": "Successful SSH authentication",
            "raw_data": {"service": "sshd"}
        },
        {
            "event_id": "SOC-004",
            "source": "Sysmon",
            "event_type": "PROCESS_EXECUTION",
            "severity": "HIGH",
            "username": "user1",
            "hostname": "windows-lab",
            "process_name": "powershell.exe",
            "description": "Simulated encoded PowerShell execution",
            "raw_data": {
                "event_id": 1,
                "command_line": "powershell.exe -EncodedCommand ABC123"
            }
        },
        {
            "event_id": "SOC-005",
            "source": "Suricata",
            "event_type": "NETWORK_CONNECTION",
            "severity": "HIGH",
            "source_ip": "192.168.1.20",
            "hostname": "kali-lab",
            "description": "Simulated suspicious outbound connection",
            "raw_data": {
                "destination_ip": "203.0.113.50",
                "destination_port": 4444
            }
        },
        {
            "event_id": "SOC-006",
            "source": "Linux Auth",
            "event_type": "FAILED_LOGIN",
            "severity": "MEDIUM",
            "username": "admin",
            "source_ip": "192.168.1.105",
            "hostname": "kali-lab",
            "description": "Third failed SSH authentication attempt",
            "raw_data": {"service": "sshd"}
        }
    ]

    for sample in samples:
        event = SecurityEvent(**sample)
        collect_event(event)

    print(f"Successfully collected {len(samples)} simulated events.")


if __name__ == "__main__":
    generate_sample_events()
