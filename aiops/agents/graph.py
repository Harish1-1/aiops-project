from __future__ import annotations

from typing import TypedDict

from langgraph.graph import (
    END,
    START,
    StateGraph,
)

from agents.alert_assessment import (
    assess_alert,
)
from agents.investigator_agent import (
    investigate,
)
from agents.rca_agent import (
    analyze_incident,
)
from agents.remediation_agent import (
    suggest_remediation,
)
from agents.report_agent import (
    generate_report,
)
from agents.validation_agent import (
    build_deterministic_validation,
)
from investigator.collector import (
    collect_live_incident_evidence,
)
from agents.workflow_tracker import (
    complete_stage,
    create_workflow_stages,
    fail_stage,
    start_stage,
    workflow_summary,
)


class IncidentState(
    TypedDict,
    total=False,
):
    incident: dict
    investigation: dict
    alert_assessment: dict
    analysis: str
    remediation: str
    validation: str
    validation_checks: dict
    policy_violations: list[str]
    validation_passed: bool
    retry_count: int
    approval_status: str
    report: str
    workflow_stages: list[dict]
    workflow_summary: dict


def investigator_node(
    state: IncidentState,
) -> dict:
    stages = state.get(
        "workflow_stages"
    )

    if not isinstance(
        stages,
        list,
    ):
        stages = create_workflow_stages()

    start_stage(
        stages,
        "investigation",
    )

    try:
        raw_incident = state[
            "incident"
        ]

        evidence_source = raw_incident.get(
            "evidence_source"
        )

        if (
            isinstance(
                evidence_source,
                str,
            )
            and evidence_source.startswith(
                "live-kubernetes"
            )
        ):
            enriched_incident = raw_incident

        else:
            enriched_incident = (
                collect_live_incident_evidence(
                    raw_incident
                )
            )

        investigation = investigate(
            enriched_incident
        )

        historical_metrics = (
            enriched_incident.get(
                "historical_metrics",
                {},
            )
        )

        historical_logs = (
            enriched_incident.get(
                "historical_logs",
                {},
            )
        )

        complete_stage(
            stages,
            "investigation",
            {
                "evidence_source": (
                    enriched_incident.get(
                        "evidence_source"
                    )
                ),
                "workload": (
                    f"{enriched_incident.get('workload_kind')}/"
                    f"{enriched_incident.get('workload_name')}"
                ),
                "prometheus_available": (
                    historical_metrics.get(
                        "available",
                        False,
                    )
                    if isinstance(
                        historical_metrics,
                        dict,
                    )
                    else False
                ),
                "loki_available": (
                    historical_logs.get(
                        "available",
                        False,
                    )
                    if isinstance(
                        historical_logs,
                        dict,
                    )
                    else False
                ),
            },
        )

        return {
            "incident": enriched_incident,
            "investigation": investigation,
            "workflow_stages": stages,
            "workflow_summary": (
                workflow_summary(stages)
            ),
            "retry_count": 0,
            "policy_violations": [],
        }

    except Exception as exc:
        fail_stage(
            stages,
            "investigation",
            str(exc),
        )

        raise


def alert_assessment_node(
    state: IncidentState,
) -> dict:
    stages = state[
        "workflow_stages"
    ]

    start_stage(
        stages,
        "alert_assessment",
    )

    try:
        assessment = assess_alert(
            state["incident"]
        )

        incident = dict(
            state["incident"]
        )

        incident[
            "alert_assessment"
        ] = assessment

        complete_stage(
            stages,
            "alert_assessment",
            {
                "status": assessment.get(
                    "status"
                ),
                "alert_confirmed": (
                    assessment.get(
                        "alert_confirmed",
                        False,
                    )
                ),
            },
        )

        return {
            "incident": incident,
            "alert_assessment": assessment,
            "workflow_stages": stages,
            "workflow_summary": (
                workflow_summary(stages)
            ),
        }

    except Exception as exc:
        fail_stage(
            stages,
            "alert_assessment",
            str(exc),
        )

        raise

def rca_node(
    state: IncidentState,
) -> dict:
    stages = state[
        "workflow_stages"
    ]

    start_stage(
        stages,
        "rca",
    )

    try:
        analysis = analyze_incident(
            state["incident"]
        )

        assessment = state.get(
            "alert_assessment",
            {},
        )

        deterministic_rca = not bool(
            assessment.get(
                "alert_confirmed",
                False,
            )
            if isinstance(
                assessment,
                dict,
            )
            else False
        )

        complete_stage(
            stages,
            "rca",
            {
                "mode": (
                    "deterministic"
                    if deterministic_rca
                    else "rag-assisted-llm"
                ),
                "output_length": len(
                    analysis
                ),
            },
        )

        return {
            "analysis": analysis,
            "workflow_stages": stages,
            "workflow_summary": (
                workflow_summary(stages)
            ),
        }

    except Exception as exc:
        fail_stage(
            stages,
            "rca",
            str(exc),
        )

        raise

def remediation_node(
    state: IncidentState,
) -> dict:
    stages = state[
        "workflow_stages"
    ]

    start_stage(
        stages,
        "remediation",
    )

    try:
        remediation = suggest_remediation(
            incident=state["incident"],
            analysis=state.get(
                "analysis",
                "",
            ),
        )

        complete_stage(
            stages,
            "remediation",
            {
                "mode": "deterministic",
                "output_length": len(
                    remediation
                ),
            },
        )

        return {
            "remediation": remediation,
            "retry_count": 0,
            "workflow_stages": stages,
            "workflow_summary": (
                workflow_summary(stages)
            ),
        }

    except Exception as exc:
        fail_stage(
            stages,
            "remediation",
            str(exc),
        )

        raise

def validation_node(
    state: IncidentState,
) -> dict:
    stages = state[
        "workflow_stages"
    ]

    start_stage(
        stages,
        "validation",
    )

    try:
        result = build_deterministic_validation(
            incident=state["incident"],
            analysis=state.get(
                "analysis",
                "",
            ),
            remediation=state.get(
                "remediation",
                "",
            ),
        )

        complete_stage(
            stages,
            "validation",
            {
                "passed": result[
                    "passed"
                ],
                "approval_status": result[
                    "approval_status"
                ],
                "policy_violation_count": len(
                    result[
                        "policy_violations"
                    ]
                ),
            },
        )

        return {
            "validation": result[
                "validation_text"
            ],
            "validation_checks": result[
                "checks"
            ],
            "policy_violations": result[
                "policy_violations"
            ],
            "validation_passed": result[
                "passed"
            ],
            "approval_status": result[
                "approval_status"
            ],
            "retry_count": 0,
            "workflow_stages": stages,
            "workflow_summary": (
                workflow_summary(stages)
            ),
        }

    except Exception as exc:
        fail_stage(
            stages,
            "validation",
            str(exc),
        )

        raise

def report_node(
    state: IncidentState,
) -> dict:
    stages = state[
        "workflow_stages"
    ]

    start_stage(
        stages,
        "report",
    )

    try:
        report = generate_report(
            incident=state["incident"],
            investigation=state.get(
                "investigation",
                {},
            ),
            analysis=state.get(
                "analysis",
                "",
            ),
            remediation=state.get(
                "remediation",
                "",
            ),
            validation=state.get(
                "validation",
                "",
            ),
            approval_status=state.get(
                "approval_status",
                "NOT APPROVED",
            ),
            retry_count=0,
        )

        complete_stage(
            stages,
            "report",
            {
                "output_length": len(
                    report
                ),
            },
        )

        return {
            "report": report,
            "workflow_stages": stages,
            "workflow_summary": (
                workflow_summary(stages)
            ),
        }

    except Exception as exc:
        fail_stage(
            stages,
            "report",
            str(exc),
        )

        raise

def build_workflow():
    """
    Build the core Agentic AIOps workflow.

    The workflow intentionally has no remediation retry loop because
    remediation and validation are deterministic.
    """

    workflow = StateGraph(
        IncidentState
    )

    workflow.add_node(
        "investigator",
        investigator_node,
    )

    workflow.add_node(
        "alert_assessment",
        alert_assessment_node,
    )

    workflow.add_node(
        "rca",
        rca_node,
    )

    workflow.add_node(
        "remediation",
        remediation_node,
    )

    workflow.add_node(
        "validation",
        validation_node,
    )

    workflow.add_node(
        "report",
        report_node,
    )

    workflow.add_edge(
        START,
        "investigator",
    )

    workflow.add_edge(
        "investigator",
        "alert_assessment",
    )

    workflow.add_edge(
        "alert_assessment",
        "rca",
    )

    workflow.add_edge(
        "rca",
        "remediation",
    )

    workflow.add_edge(
        "remediation",
        "validation",
    )

    workflow.add_edge(
        "validation",
        "report",
    )

    workflow.add_edge(
        "report",
        END,
    )

    return workflow.compile()


aiops_workflow = (
    build_workflow()
)