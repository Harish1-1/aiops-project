import json
from pathlib import Path

from agents.graph import aiops_workflow


incident_path = (
    Path(__file__).resolve().parents[1]
    / "sample_incidents"
    / "oomkilled.json"
)

with incident_path.open("r", encoding="utf-8") as file:
    incident = json.load(file)

result = aiops_workflow.invoke(
    {
        "incident": incident,
    }
)

print("\n" + "=" * 70)
print("INVESTIGATION")
print("=" * 70)
print(result["investigation"])

print("\n" + "=" * 70)
print("ROOT CAUSE ANALYSIS")
print("=" * 70)
print(result["analysis"])

print("\n" + "=" * 70)
print("VALIDATION")
print("=" * 70)
print(result["validation"])

print("\n" + "=" * 70)
print("REMEDIATION")
print("=" * 70)
print(result["remediation"])

print("\n" + "=" * 70)
print("FINAL REPORT")
print("=" * 70)
print(result["report"])