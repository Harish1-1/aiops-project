from __future__ import annotations
from investigator.collector import collect_live_incident_evidence

import logging

from fastapi import (
    BackgroundTasks,
    FastAPI,
    HTTPException,
    Query,
)
from fastapi.middleware.cors import CORSMiddleware

from sre_copilot.models import (
    IncidentRequest,
    WorkflowResponse,
)
from sre_copilot.service import run_incident_workflow
from storage.incident_store import (
    create_incident,
    get_incident,
    initialize_database,
    list_incidents,
    mark_completed,
    mark_failed,
    mark_running,
    update_incident_data,
    list_pending_approval,
    list_approval_history,
    record_approval_decision,
)
from webhook.alertmanager import convert_alert
from webhook.models import AlertManagerPayload
from agents.workflow_tracker import (
    create_workflow_stages,
    fail_stage,
    skip_remaining_stages,
    workflow_summary,
)
from sre_copilot.chat_models import (
    IncidentChatRequest,
    IncidentChatResponse,
)
from sre_copilot.chat_service import (
    ChatServiceError,
    answer_incident_question,
)
from sre_copilot.approval_models import (
    ApprovalDecisionRequest,
    ApprovalDecisionResponse,
)
from remediation.patch_generator import generate_gitops_plan
from remediation.github_pr import create_github_pr
from remediation.argocd_client import verify_argocd


logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

def _read_stored_incident(
    incident_id: int,
) -> dict:
    """
    Read one complete incident record from SQLite.

    The database layer must return the complete stored record,
    including:

    - id
    - incident
    - result
    - status
    - approval_status
    - timestamps
    """

    stored_incident = get_incident(
        incident_id
    )

    if stored_incident is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Incident {incident_id} was not found."
            ),
        )

    if not isinstance(
        stored_incident,
        dict,
    ):
        raise HTTPException(
            status_code=500,
            detail=(
                "The stored incident record has an invalid format."
            ),
        )

    return stored_incident

def _infer_failed_stage(
    exc: Exception,
) -> str:
    """
    Infer the most likely failed workflow stage from the traceback
    message.

    This is used only when LangGraph raises before its final state can
    be returned. Successful workflows use the exact stage tracker from
    LangGraph.
    """

    text = (
        f"{type(exc).__name__}: {exc}"
    ).lower()

    if any(
        token in text
        for token in (
            "kubernetes",
            "kubectl",
            "prometheus",
            "loki",
            "pod",
            "metrics api",
        )
    ):
        return "investigation"

    if any(
        token in text
        for token in (
            "alert assessment",
            "assess_alert",
            "quantity_pattern",
        )
    ):
        return "alert_assessment"

    if any(
        token in text
        for token in (
            "ollama",
            "llm",
            "qdrant",
            "runbook",
            "embedding",
            "rca",
        )
    ):
        return "rca"

    if any(
        token in text
        for token in (
            "remediation",
            "remediation_builder",
        )
    ):
        return "remediation"

    if any(
        token in text
        for token in (
            "validation",
            "evidence_guard",
            "safety_policy",
        )
    ):
        return "validation"

    if any(
        token in text
        for token in (
            "report",
            "generate_report",
        )
    ):
        return "report"

    return "investigation"


app = FastAPI(
    title="Agentic AIOps SRE Copilot",
    description=(
        "RAG-powered multi-agent Kubernetes incident analysis, "
        "validation, remediation planning, and reporting."
    ),
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event() -> None:
    initialize_database()


def process_alertmanager_incident(
    incident_id: int,
    incident: dict,
) -> None:
    fallback_stages = create_workflow_stages()
    try:
        mark_running(incident_id)

        logger.info(
            "Starting live Kubernetes investigation: "
            "id=%s alert=%s namespace=%s pod=%s",
            incident_id,
            incident.get("alert"),
            incident.get("namespace"),
            incident.get("pod"),
        )

        enriched_incident = collect_live_incident_evidence(
            incident
        )

        update_incident_data(
            incident_id,
            enriched_incident,
        )

        logger.info(
            "Starting Agentic AIOps workflow: "
            "id=%s logs=%s events=%s restarts=%s",
            incident_id,
            len(enriched_incident.get("logs", [])),
            len(enriched_incident.get("events", [])),
            enriched_incident.get("restart_count"),
        )

        result = run_incident_workflow(
            enriched_incident
        )

        workflow_stages = result.get(
            "workflow_stages",
            [],
        )

        workflow_summary_data = result.get(
            "workflow_summary",
            {},
        )

        logger.info(
            (
                "Agentic AIOps workflow completed: "
                "id=%s overall_status=%s "
                "completed_stages=%s failed_stages=%s "
                "duration_ms=%s"
            ),
            incident_id,
            workflow_summary_data.get(
                "overall_status",
                "UNKNOWN",
            ),
            workflow_summary_data.get(
                "completed_stages",
                0,
            ),
            workflow_summary_data.get(
                "failed_stages",
                0,
            ),
            workflow_summary_data.get(
                "total_duration_ms",
                0,
            ),
        )

        mark_completed(
            incident_id,
            result,
        )

        logger.info(
            "Incident workflow completed: "
            "id=%s alert=%s approval=%s retries=%s",
            incident_id,
            enriched_incident.get("alert"),
            result.get("approval_status"),
            result.get("retry_count"),
        )

    except Exception as exc:
        logger.exception(
            (
                "Background workflow failed: "
                "id=%s incident=%s"
            ),
            incident_id,
            incident,
        )

        failed_stage_name = (
            _infer_failed_stage(
                exc
            )
        )

        fail_stage(
            fallback_stages,
            failed_stage_name,
            str(exc),
        )

        skip_remaining_stages(
            fallback_stages,
            after_stage=failed_stage_name,
            reason=(
                "Skipped because an earlier "
                "workflow stage failed."
            ),
        )

        failure_result = {
            "incident": incident,
            "workflow_stages": (
                fallback_stages
            ),
            "workflow_summary": (
                workflow_summary(
                    fallback_stages
                )
            ),
            "approval_status": (
                "NOT APPROVED"
            ),
            "retry_count": 0,
            "policy_violations": [],
            "validation_passed": False,
            "error": str(exc),
        }

        mark_failed(
            incident_id=incident_id,
            error=str(exc),
            result=failure_result,
        )

@app.get("/")
def root() -> dict[str, str]:
    return {
        "service": "Agentic AIOps SRE Copilot",
        "status": "running",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "healthy",
    }


@app.post(
    "/analyze",
    response_model=WorkflowResponse,
)
def analyze_incident(
    request: IncidentRequest,
) -> WorkflowResponse:
    try:
        incident = request.model_dump()

        result = run_incident_workflow(incident)

        return WorkflowResponse(**result)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Workflow failed: {exc}",
        ) from exc


@app.post(
    "/alertmanager",
    status_code=202,
)
def receive_alertmanager_webhook(
    payload: AlertManagerPayload,
    background_tasks: BackgroundTasks,
) -> dict:
    if not payload.alerts:
        raise HTTPException(
            status_code=400,
            detail="Alertmanager payload contains no alerts.",
        )

    incident = convert_alert(payload)

    incident_id = create_incident(incident)

    background_tasks.add_task(
        process_alertmanager_incident,
        incident_id,
        incident,
    )

    return {
        "status": "accepted",
        "incident_id": incident_id,
        "message": (
            "Alert queued for Agentic AIOps analysis."
        ),
        "alert": incident.get("alert"),
        "namespace": incident.get("namespace"),
        "pod": incident.get("pod"),
    }


@app.get("/incidents")
def incidents(
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
) -> list[dict]:
    return list_incidents(limit)


@app.get(
    "/incidents/pending-approval",
    tags=["Human Approval"],
    summary="List incidents waiting for human approval",
)
def pending_approval_incidents(
    limit: int = Query(default=100, ge=1, le=200),
) -> list[dict]:
    return list_pending_approval(limit)


@app.get("/incidents/{incident_id}")
def incident_details(
    incident_id: int,
) -> dict:
    incident = get_incident(incident_id)

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    return incident

@app.post(
    "/incidents/{incident_id}/chat",
    response_model=IncidentChatResponse,
    tags=["SRE Copilot"],
    summary="Ask SRE Copilot about an incident",
)
def chat_with_incident(
    incident_id: int,
    request: IncidentChatRequest,
) -> IncidentChatResponse:
    """
    Answer a question using one stored incident's evidence.

    The endpoint is read-only. It cannot execute kubectl commands,
    modify Kubernetes, apply GitOps changes, or authorize remediation.
    """

    stored_incident = _read_stored_incident(
        incident_id
    )

    status = str(
        stored_incident.get(
            "status",
            "UNKNOWN",
        )
    )

    if status in {
        "QUEUED",
        "RUNNING",
    }:
        raise HTTPException(
            status_code=409,
            detail=(
                "The incident workflow is still running. "
                "Wait for it to complete before asking questions."
            ),
        )

    result = stored_incident.get(
        "result"
    )

    if not isinstance(
        result,
        dict,
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "This incident does not contain a completed "
                "workflow result."
            ),
        )

    try:
        response = answer_incident_question(
            stored_incident=stored_incident,
            question=request.question,
        )

    except ChatServiceError as exc:
        logger.warning(
            (
                "SRE Copilot could not answer: "
                "incident_id=%s error=%s"
            ),
            incident_id,
            exc,
        )

        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        logger.exception(
            (
                "Unexpected SRE Copilot failure: "
                "incident_id=%s"
            ),
            incident_id,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "The SRE Copilot encountered an unexpected error."
            ),
        ) from exc

    logger.info(
        (
            "SRE Copilot answered incident question: "
            "incident_id=%s mode=%s question_length=%s"
        ),
        incident_id,
        response.get(
            "mode",
            "unknown",
        ),
        len(request.question),
    )

    return IncidentChatResponse(
        incident_id=incident_id,
        answer=str(
            response.get(
                "answer",
                "",
            )
        ),
        mode=str(
            response.get(
                "mode",
                "unknown",
            )
        ),
    )



def _process_human_decision(
    incident_id: int,
    decision: str,
    request: ApprovalDecisionRequest,
) -> ApprovalDecisionResponse:
    stored = _read_stored_incident(incident_id)
    downstream: dict = {
        "gitops": {"status": "SKIPPED", "reason": "Human rejected the recommendation."},
        "github": {"status": "SKIPPED", "reason": "Human rejected the recommendation."},
        "argocd": {"status": "SKIPPED", "reason": "Human rejected the recommendation."},
    }

    if decision == "APPROVED":
        # Use a temporary approved view so the planner can enforce the gate
        # before the immutable audit record is written.
        approved_view = dict(stored)
        approved_view["approval_status"] = "HUMAN APPROVED"
        plan = generate_gitops_plan(approved_view)
        github = create_github_pr(plan)
        argocd = verify_argocd(plan, github)
        downstream = {"gitops": plan, "github": github, "argocd": argocd}

    try:
        event = record_approval_decision(
            incident_id=incident_id,
            decision=decision,
            reviewer=request.reviewer.strip(),
            comment=request.comment.strip(),
            downstream=downstream,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return ApprovalDecisionResponse(**event)


@app.post(
    "/incidents/{incident_id}/approve",
    response_model=ApprovalDecisionResponse,
    tags=["Human Approval"],
)
def approve_incident(
    incident_id: int,
    request: ApprovalDecisionRequest,
) -> ApprovalDecisionResponse:
    return _process_human_decision(incident_id, "APPROVED", request)


@app.post(
    "/incidents/{incident_id}/reject",
    response_model=ApprovalDecisionResponse,
    tags=["Human Approval"],
)
def reject_incident(
    incident_id: int,
    request: ApprovalDecisionRequest,
) -> ApprovalDecisionResponse:
    return _process_human_decision(incident_id, "REJECTED", request)


@app.get(
    "/incidents/{incident_id}/audit",
    tags=["Human Approval"],
)
def incident_audit(incident_id: int) -> list[dict]:
    _read_stored_incident(incident_id)
    return list_approval_history(incident_id)
