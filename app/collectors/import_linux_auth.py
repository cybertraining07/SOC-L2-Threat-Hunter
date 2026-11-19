
from app.collectors.event_collector import (
    collect_event,
    load_events
)
from app.collectors.event_model import SecurityEvent
from app.collectors.linux_auth_collector import (
    collect_linux_auth_events
)


def import_linux_auth_events():
    """Import new Linux SSH events without duplicating records."""

    live_events = collect_linux_auth_events()
    existing_events = load_events()

    # Track original log lines already imported.
    existing_lines = {
        event.get("raw_data", {}).get("original_line")
        for event in existing_events
        if event.get("raw_data")
    }

    imported = 0
    skipped = 0

    for event_data in live_events:

        original_line = event_data["raw_data"]["original_line"]

        if original_line in existing_lines:
            skipped += 1
            continue

        event = SecurityEvent(**event_data)

        collect_event(event)

        existing_lines.add(original_line)
        imported += 1

    print("===== LINUX AUTHENTICATION IMPORT =====")
    print(f"Live events discovered: {len(live_events)}")
    print(f"New events imported: {imported}")
    print(f"Duplicate events skipped: {skipped}")
    print(f"Total events in dataset: {len(load_events())}")


if __name__ == "__main__":
    import_linux_auth_events()
