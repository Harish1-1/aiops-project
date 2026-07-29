from __future__ import annotations

from typing import Any

from agents.graph import aiops_workflow
from agents.workflow_tracker import (
    create_workflow_stages,
    workflow_summary,
)


def run_incident_workflow(
    incident: dict[str, Any],
) -> dict[str, Any]:
    """
    Run the complete Agentic AIOps workflow.

    A fresh stage-tracking structure is created for every incident.
    The returned LangGraph state contains both:

    - workflow_stages
    - workflow_summary

    These values are persisted inside the existing incident result JSON,
    so no SQLite schema migration is required.
    """

    stages = create_workflow_stages()

    result = aiops_workflow.invoke(
        {
            "incident": incident,
            "workflow_stages": stages,
            "workflow_summary": workflow_summary(
                stages
            ),
        }
    )

    if not isinstance(
        result,
        dict,
    ):
        raise RuntimeError(
            "The AIOps workflow returned an invalid result."
        )

    result_stages = result.get(
        "workflow_stages"
    )

    if not isinstance(
        result_stages,
        list,
    ):
        result_stages = stages
        result["workflow_stages"] = stages

    result["workflow_summary"] = (
        workflow_summary(
            result_stages
        )
    )

    return result