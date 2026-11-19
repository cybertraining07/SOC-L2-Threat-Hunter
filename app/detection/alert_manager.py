import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
ALERTS_FILE = BASE_DIR / "data" / "processed" / "security_alerts.json"


def save_alerts(alerts: list[dict]) -> None:
    """Save detected security alerts to a JSON file."""

    ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    with ALERTS_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print(f"Saved {len(alerts)} alerts to {ALERTS_FILE}")


def load_alerts() -> list[dict]:
    """Load previously saved security alerts."""

    if not ALERTS_FILE.exists():
        return []

    with ALERTS_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)
