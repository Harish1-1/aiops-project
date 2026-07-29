import json

from agents.rca_agent import analyze_incident
from agents.validation_agent import validate_analysis

with open(
    "sample_incidents/oomkilled.json"
) as f:

    incident = json.load(f)

analysis = analyze_incident(
    incident
)

result = validate_analysis(
    incident,
    analysis
)

print(result)