import json
from pathlib import Path

from agents.investigator_agent import investigate
from agents.rca_agent import analyze_incident
from agents.validation_agent import validate_analysis
from agents.remediation_agent import suggest_remediation
from agents.report_agent import generate_report


incident_path = (
    Path(__file__).resolve().parents[1]
    / "sample_incidents"
    / "oomkilled.json"
)

with incident_path.open("r", encoding="utf-8") as file:
    incident = json.load(file)

investigation = investigate(incident)

analysis = analyze_incident(incident)

validation = validate_analysis(
    incident,
    analysis,
)

remediation = suggest_remediation(
    incident,
    analysis,
)

report = generate_report(
    incident=incident,
    investigation=investigation,
    analysis=analysis,
    validation=validation,
    remediation=remediation,
)

print(report)