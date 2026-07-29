import json

from agents.investigator_agent import investigate

with open(
    "sample_incidents/oomkilled.json"
) as f:

    incident = json.load(f)

result = investigate(
    incident
)

print(result)