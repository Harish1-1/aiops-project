import json

from agents.rca_agent import analyze_incident

with open(
    "sample_incidents/oomkilled.json"
, "r") as f:

    incident = json.load(f)

result = analyze_incident(
    incident
)

print(result)