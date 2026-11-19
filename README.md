
# SOC L2 Threat Hunter

A Python-based Security Operations Center (SOC) Level 2 threat hunting and incident response laboratory.

## Project Overview

SOC L2 Threat Hunter is a lightweight security monitoring application designed to demonstrate security event collection, threat detection, incident investigation, response recommendations, and security reporting.

The project uses simulated security events and custom Python detection rules to identify suspicious activities.

## Key Features

- Security event collection and normalization
- SSH brute-force detection
- Suspicious PowerShell execution detection
- Suspicious outbound network connection detection
- MITRE ATT&CK technique mapping
- Automated security alert generation
- Incident creation and management
- Incident-specific investigation notes
- Automated response recommendations
- FastAPI REST API
- Interactive security dashboard
- PDF incident investigation reports
- Automated unit and API tests

## Technology Stack

- Python
- FastAPI
- Pydantic
- Uvicorn
- ReportLab
- HTML, CSS and JavaScript
- Pytest
- Git

## Detection Rules

| Detection | MITRE ATT&CK |
|---|---|
| SSH brute-force activity | T1110 |
| Suspicious PowerShell execution | T1059.001 |
| Suspicious outbound network connection | T1571 |

These mappings are contextual investigation references, not proof that an attack technique occurred.

## Project Structure

```text
SOC-L2-Threat-Hunter/
├── app/
│   ├── collectors/
│   ├── detection/
│   ├── incident_response/
│   ├── analyzers/
│   ├── reports/
│   └── main.py
├── dashboard/
│   └── index.html
├── data/
│   ├── raw/
│   └── processed/
├── reports/
├── rules/
├── tests/
├── docs/
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation

Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd SOC-L2-Threat-Hunter
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Running the Detection Engine

Run the detection engine:

```bash
python -m app.detection.run_detection
```

This analyzes the collected events and generates security alerts.

## Incident Management

Create incident records:

```bash
python -m app.incident_response.incident_manager
```

Generate response recommendations:

```bash
python -m app.incident_response.run_response
```

## Generate the PDF Report

Run:

```bash
python -m app.reports.pdf_generator
```

The report is generated at:

```text
reports/SOC_L2_Incident_Report.pdf
```

## Launch the Dashboard

Start the FastAPI application:

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8002
```

Open the dashboard:

http://127.0.0.1:8002/dashboard

API documentation:

http://127.0.0.1:8002/docs

Dashboard API:

http://127.0.0.1:8002/api/dashboard

## Running Tests

Run the complete test suite:

```bash
python -m pytest -v
```

Current project test result: 19 passing tests.

## Sample Security Scenarios

The laboratory includes simulated scenarios covering:

1. Multiple failed SSH authentication attempts.
2. PowerShell execution with an encoded command indicator.
3. An outbound network connection using port 4444.

The sample destination IP `203.0.113.50` is reserved for documentation and testing.

## Security Disclaimer

This project is an educational cybersecurity laboratory.

All included security events are simulated. Detection alerts are indicators that require analyst validation and do not independently establish malicious compromise.

Only perform security testing on systems for which you have explicit authorization.

## Project Status

Core event collection, detection, incident management, response recommendations, dashboard reporting, PDF generation, and automated tests are implemented.

Future improvements may include live Linux authentication log ingestion, Windows Sysmon integration, Suricata ingestion, threat intelligence enrichment, and SIEM integration.
