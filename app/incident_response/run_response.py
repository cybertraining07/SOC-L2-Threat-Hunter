import json
from pathlib import Path

from app.incident_response.response_engine import generate_response


BASE_DIR = Path(__file__).resolve().parents[2]

INCIDENTS_FILE = BASE_DIR / "data" / "processed" / "incidents.json"
RESPONSES_FILE = BASE_DIR / "data" / "processed" / "response_recommendations.json"


def main():
    if not INCIDENTS_FILE.exists():
        print("No incident records found.")
        return

    with INCIDENTS_FILE.open("r", encoding="utf-8") as file:
        incidents = json.load(file)

    responses = []

    for incident in incidents:
        response = generate_response(incident)
        responses.append(response)

    RESPONSES_FILE.parent.mkdir(parents=True, exist_ok=True)

    with RESPONSES_FILE.open("w", encoding="utf-8") as file:
        json.dump(responses, file, indent=4)

    print(f"Incidents analyzed: {len(incidents)}")
    print(f"Recommendations saved: {len(responses)}")
    print(f"Output file: {RESPONSES_FILE}")

    print("\n===== INCIDENT RESPONSE RECOMMENDATIONS =====")

    for response in responses:
        print(json.dumps(response, indent=4))


if __name__ == "__main__":
    main()
