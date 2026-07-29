import json

from agents.rca_agent import analyze_incident
from agents.remediation_agent import suggest_remediation

with open(
    "sample_incidents/oomkilled.json"
) as f:

    incident = json.load(f)

analysis = analyze_incident(
    incident
)

result = suggest_remediation(
    incident,
    analysis
)

print(result)