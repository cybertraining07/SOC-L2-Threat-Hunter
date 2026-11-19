
import re
from datetime import datetime
from pathlib import Path


AUTH_LOG = Path("/var/log/auth.log")

# Recognizes both sshd and sshd-session processes.
SSH_PATTERN = re.compile(
    r"(?P<service>sshd(?:-session)?)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)",
    re.IGNORECASE
)

# Failed SSH password authentication.
FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from (?P<ip>\S+)"
)

# Successful SSH password authentication.
ACCEPTED_PATTERN = re.compile(
    r"Accepted password for (?P<username>\S+) "
    r"from (?P<ip>\S+)"
)

# SSH attempts using an invalid username.
INVALID_PATTERN = re.compile(
    r"Invalid user (?P<username>\S+) from (?P<ip>\S+)"
)


def parse_auth_line(line: str) -> dict | None:
    """Parse an SSH authentication event from a syslog line."""

    ssh_match = SSH_PATTERN.search(line)

    if not ssh_match:
        return None

    message = ssh_match.group("message")

    event_type = None
    severity = "LOW"
    username = None
    source_ip = None

    failed = FAILED_PATTERN.search(message)
    accepted = ACCEPTED_PATTERN.search(message)
    invalid = INVALID_PATTERN.search(message)

    if failed:
        event_type = "FAILED_LOGIN"
        severity = "MEDIUM"
        username = failed.group("username")
        source_ip = failed.group("ip")

    elif accepted:
        event_type = "SUCCESSFUL_LOGIN"
        severity = "LOW"
        username = accepted.group("username")
        source_ip = accepted.group("ip")

    elif invalid:
        event_type = "INVALID_USER"
        severity = "MEDIUM"
        username = invalid.group("username")
        source_ip = invalid.group("ip")

    else:
        return None

    timestamp_match = re.match(
        r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
        line
    )

    if not timestamp_match:
        return None

    timestamp_text = timestamp_match.group(1)

    timestamp = datetime.strptime(
        f"{datetime.now().year} {timestamp_text}",
        "%Y %b %d %H:%M:%S"
    )

    return {
        "event_id": (
            f"LINUX-SSH-{timestamp.timestamp()}-"
            f"{source_ip}-{username}"
        ),
        "timestamp": timestamp.isoformat(),
        "source": "Linux Authentication Log",
        "event_type": event_type,
        "severity": severity,
        "username": username,
        "source_ip": source_ip,
        "hostname": "kali",
        "process_name": "sshd",
        "description": message,
        "raw_data": {
            "log_source": str(AUTH_LOG),
            "original_line": line.strip()
        }
    }


def collect_linux_auth_events(
    log_file: Path = AUTH_LOG
) -> list[dict]:
    """Read and parse SSH authentication events."""

    if not log_file.exists():
        raise FileNotFoundError(
            f"Authentication log not found: {log_file}"
        )

    events = []

    with log_file.open(
        "r",
        encoding="utf-8",
        errors="replace"
    ) as file:

        for line in file:
            event = parse_auth_line(line)

            if event:
                events.append(event)

    return events


if __name__ == "__main__":
    events = collect_linux_auth_events()

    print("===== LINUX SSH AUTHENTICATION COLLECTOR =====")
    print(f"Events collected: {len(events)}")

    for event in events:
        print(
            f"{event['event_type']} | "
            f"User: {event['username']} | "
            f"Source IP: {event['source_ip']} | "
            f"Severity: {event['severity']}"
        )
