import json
from pathlib import Path

from app.collectors.event_model import SecurityEvent


BASE_DIR = Path(__file__).resolve().parents[2]
EVENTS_FILE = BASE_DIR / "data" / "raw" / "security_events.jsonl"


def collect_event(event: SecurityEvent) -> dict:
    """Validate and save a security event as a JSON line."""

    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    event_data = event.model_dump(mode="json")

    with EVENTS_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event_data) + "\n")

    return event_data


def load_events() -> list[dict]:
    """Load previously collected security events."""

    if not EVENTS_FILE.exists():
        return []

    events = []

    with EVENTS_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                events.append(json.loads(line))

    return events
