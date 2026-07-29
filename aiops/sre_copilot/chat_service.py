from __future__ import annotations

import json
import re
from typing import Any

from llm.llm_client import LLMClient


llm = LLMClient()


MAX_LOG_LINES = 40
MAX_LOKI_LINES = 40
MAX_REPORT_CHARACTERS = 12000


class ChatServiceError(RuntimeError):
    """Raised when the SRE Copilot cannot answer a question."""


def _safe_dict(
    value: Any,
) -> dict[str, Any]:
    return (
        value
        if isinstance(value, dict)
        else {}
    )


def _safe_list(
    value: Any,
) -> list[Any]:
    return (
        value
        if isinstance(value, list)
        else []
    )


def _trim_text(
    value: Any,
    limit: int,
) -> str:
    text = str(
        value
        if value is not None
        else ""
    )

    if len(text) <= limit:
        return text

    return (
        text[:limit]
        + "\n...[truncated]"
    )


def _historical_metric(
    incident: dict[str, Any],
    name: str,
) -> dict[str, Any]:
    historical_metrics = _safe_dict(
        incident.get(
            "historical_metrics"
        )
    )

    return _safe_dict(
        historical_metrics.get(name)
    )


def _historical_logs(
    incident: dict[str, Any],
) -> dict[str, Any]:
    return _safe_dict(
        incident.get(
            "historical_logs"
        )
    )


def _result_section(
    result: dict[str, Any],
    key: str,
) -> str:
    return _trim_text(
        result.get(
            key,
            "",
        ),
        MAX_REPORT_CHARACTERS,
    )


def build_chat_context(
    stored_incident: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a compact, factual chat context from one stored incident.

    The returned context contains no new AI interpretation.
    """

    incident = _safe_dict(
        stored_incident.get(
            "incident"
        )
    )

    result = _safe_dict(
        stored_incident.get(
            "result"
        )
    )

    alert_assessment = _safe_dict(
        incident.get(
            "alert_assessment"
        )
    )

    memory_history = _historical_metric(
        incident,
        "memory",
    )

    cpu_history = _historical_metric(
        incident,
        "cpu",
    )

    restart_history = _historical_metric(
        incident,
        "restarts",
    )

    loki = _historical_logs(
        incident
    )

    historical_log_lines = [
        str(line)
        for line in _safe_list(
            incident.get(
                "historical_log_lines"
            )
        )[-MAX_LOKI_LINES:]
    ]

    current_logs = [
        str(line)
        for line in _safe_list(
            incident.get(
                "logs"
            )
        )[-MAX_LOG_LINES:]
    ]

    events = [
        str(event)
        for event in _safe_list(
            incident.get(
                "events"
            )
        )[-30:]
    ]

    workflow_summary = _safe_dict(
        result.get(
            "workflow_summary"
        )
    )

    workflow_stages = [
        stage
        for stage in _safe_list(
            result.get(
                "workflow_stages"
            )
        )
        if isinstance(stage, dict)
    ]

    return {
        "record": {
            "id": stored_incident.get("id"),
            "status": stored_incident.get("status"),
            "approval_status": stored_incident.get(
                "approval_status"
            ),
            "retry_count": stored_incident.get(
                "retry_count"
            ),
            "created_at": stored_incident.get(
                "created_at"
            ),
            "updated_at": stored_incident.get(
                "updated_at"
            ),
            "error": stored_incident.get(
                "error"
            ),
        },
        "identity": {
            "alert": incident.get(
                "alert",
                "Unknown",
            ),
            "namespace": incident.get(
                "namespace",
                "Unknown",
            ),
            "pod": incident.get(
                "pod",
                "Unknown",
            ),
            "workload_kind": incident.get(
                "workload_kind",
                "Unknown",
            ),
            "workload_name": incident.get(
                "workload_name",
                "Unknown",
            ),
            "evidence_source": incident.get(
                "evidence_source",
                "Unknown",
            ),
        },
        "live_kubernetes": {
            "pod_phase": incident.get(
                "pod_phase"
            ),
            "node_name": incident.get(
                "node_name"
            ),
            "pod_ip": incident.get(
                "pod_ip"
            ),
            "cpu_usage": incident.get(
                "cpu_usage"
            ),
            "memory_usage": incident.get(
                "memory_usage"
            ),
            "restart_count": incident.get(
                "restart_count"
            ),
            "container_states": incident.get(
                "container_states",
                [],
            ),
            "termination_reasons": incident.get(
                "termination_reasons",
                [],
            ),
            "ownership_chain": incident.get(
                "ownership_chain",
                [],
            ),
            "container_images": incident.get(
                "container_images",
                [],
            ),
            "container_resources": incident.get(
                "container_resources",
                [],
            ),
            "desired_replicas": incident.get(
                "desired_replicas"
            ),
            "available_replicas": incident.get(
                "available_replicas"
            ),
            "ready_replicas": incident.get(
                "ready_replicas"
            ),
            "events": events,
            "recent_logs": current_logs,
        },
        "prometheus": {
            "memory": {
                "available": memory_history.get(
                    "available"
                ),
                "sample_count": memory_history.get(
                    "sample_count"
                ),
                "latest_mib": memory_history.get(
                    "latest_mib"
                ),
                "average_mib": memory_history.get(
                    "average_mib"
                ),
                "maximum_mib": memory_history.get(
                    "maximum_mib"
                ),
                "trend": memory_history.get(
                    "trend"
                ),
                "peak_timestamp": memory_history.get(
                    "peak_timestamp"
                ),
            },
            "cpu": {
                "available": cpu_history.get(
                    "available"
                ),
                "sample_count": cpu_history.get(
                    "sample_count"
                ),
                "latest_millicores": cpu_history.get(
                    "latest_millicores"
                ),
                "average_millicores": cpu_history.get(
                    "average_millicores"
                ),
                "maximum_millicores": cpu_history.get(
                    "maximum_millicores"
                ),
                "trend": cpu_history.get(
                    "trend"
                ),
                "peak_timestamp": cpu_history.get(
                    "peak_timestamp"
                ),
            },
            "restarts": {
                "latest": restart_history.get(
                    "latest"
                ),
                "maximum": restart_history.get(
                    "maximum"
                ),
                "restart_increase": restart_history.get(
                    "restart_increase"
                ),
                "trend": restart_history.get(
                    "trend"
                ),
            },
        },
        "loki": {
            "available": loki.get(
                "available"
            ),
            "lookback_minutes": loki.get(
                "lookback_minutes"
            ),
            "entry_count": loki.get(
                "entry_count"
            ),
            "error_count": loki.get(
                "error_count"
            ),
            "warning_count": loki.get(
                "warning_count"
            ),
            "level_counts": loki.get(
                "level_counts",
                {},
            ),
            "first_timestamp": loki.get(
                "first_timestamp"
            ),
            "last_timestamp": loki.get(
                "last_timestamp"
            ),
            "recent_entries": historical_log_lines,
        },
        "alert_assessment": alert_assessment,
        "workflow": {
            "summary": workflow_summary,
            "stages": workflow_stages,
        },
        "outputs": {
            "analysis": _result_section(
                result,
                "analysis",
            ),
            "remediation": _result_section(
                result,
                "remediation",
            ),
            "validation": _result_section(
                result,
                "validation",
            ),
            "report": _result_section(
                result,
                "report",
            ),
            "policy_violations": result.get(
                "policy_violations",
                [],
            ),
            "validation_passed": result.get(
                "validation_passed"
            ),
        },
    }


def _normalized_question(
    question: str,
) -> str:
    return " ".join(
        question.lower().split()
    )


def _deterministic_answer(
    question: str,
    context: dict[str, Any],
) -> str | None:
    """
    Answer common factual questions without using the LLM.

    This reduces hallucinations and avoids unnecessary Ollama usage.
    """

    normalized = _normalized_question(
        question
    )

    identity = _safe_dict(
        context.get("identity")
    )

    live = _safe_dict(
        context.get(
            "live_kubernetes"
        )
    )

    prometheus = _safe_dict(
        context.get("prometheus")
    )

    loki = _safe_dict(
        context.get("loki")
    )

    assessment = _safe_dict(
        context.get(
            "alert_assessment"
        )
    )

    workflow = _safe_dict(
        context.get("workflow")
    )

    outputs = _safe_dict(
        context.get("outputs")
    )

    memory = _safe_dict(
        prometheus.get("memory")
    )

    cpu = _safe_dict(
        prometheus.get("cpu")
    )

    restarts = _safe_dict(
        prometheus.get("restarts")
    )

    if any(
        phrase in normalized
        for phrase in (
            "is the alert confirmed",
            "was the alert confirmed",
            "alert confirmed",
            "why was alert rejected",
            "why was the alert rejected",
        )
    ):
        return (
            f"The alert is confirmed: "
            f"`{assessment.get('alert_confirmed', False)}`.\n\n"
            f"Assessment status: "
            f"`{assessment.get('status', 'Unavailable')}`.\n\n"
            "Current snapshot confirmation: "
            f"`{assessment.get('current_snapshot_confirms_alert', False)}`.\n\n"
            "Prometheus history confirmation: "
            f"`{assessment.get('historical_evidence_confirms_alert', False)}`."
        )

    if any(
        phrase in normalized
        for phrase in (
            "highest memory",
            "maximum memory",
            "peak memory",
        )
    ):
        return (
            "The highest Prometheus memory value was "
            f"`{memory.get('maximum_mib')} MiB` at "
            f"`{memory.get('peak_timestamp')}`. "
            f"The trend was `{memory.get('trend')}`."
        )

    if any(
        phrase in normalized
        for phrase in (
            "highest cpu",
            "maximum cpu",
            "peak cpu",
        )
    ):
        return (
            "The highest Prometheus CPU value was "
            f"`{cpu.get('maximum_millicores')}m` at "
            f"`{cpu.get('peak_timestamp')}`. "
            f"The trend was `{cpu.get('trend')}`."
        )

    if any(
        phrase in normalized
        for phrase in (
            "loki error",
            "loki errors",
            "did loki",
            "log errors",
        )
    ):
        return (
            f"Loki availability: `{loki.get('available')}`.\n\n"
            f"Entries retrieved: `{loki.get('entry_count')}`.\n\n"
            f"Detected errors: `{loki.get('error_count')}`.\n\n"
            f"Detected warnings: `{loki.get('warning_count')}`.\n\n"
            "A zero keyword-based error count does not prove that no "
            "application issue occurred."
        )

    if any(
        phrase in normalized
        for phrase in (
            "who owns",
            "owning workload",
            "which workload",
            "workload owns",
        )
    ):
        return (
            f"The pod `{identity.get('pod')}` is owned by "
            f"`{identity.get('workload_kind')}/"
            f"{identity.get('workload_name')}`."
        )

    if any(
        phrase in normalized
        for phrase in (
            "restart count",
            "did it restart",
            "restarts",
        )
    ):
        return (
            f"The current restart count is "
            f"`{live.get('restart_count')}`. "
            f"The increase during the Prometheus lookback was "
            f"`{restarts.get('restart_increase')}`."
        )

    if any(
        phrase in normalized
        for phrase in (
            "workflow status",
            "which stages",
            "stage status",
            "workflow completed",
        )
    ):
        summary = _safe_dict(
            workflow.get("summary")
        )

        return (
            f"Workflow status: "
            f"`{summary.get('overall_status', 'Unknown')}`.\n\n"
            f"Completed stages: "
            f"`{summary.get('completed_stages', 0)}`.\n\n"
            f"Failed stages: "
            f"`{summary.get('failed_stages', 0)}`.\n\n"
            f"Skipped stages: "
            f"`{summary.get('skipped_stages', 0)}`."
        )

    if any(
        phrase in normalized
        for phrase in (
            "policy violation",
            "policy violations",
            "validation passed",
            "was validation successful",
        )
    ):
        violations = _safe_list(
            outputs.get(
                "policy_violations"
            )
        )

        return (
            f"Validation passed: "
            f"`{outputs.get('validation_passed')}`.\n\n"
            f"Policy violations: `{len(violations)}`."
        )

    return None


def _validate_question(
    question: str,
) -> str:
    cleaned = question.strip()

    if not cleaned:
        raise ChatServiceError(
            "The question cannot be empty."
        )

    if len(cleaned) > 2000:
        raise ChatServiceError(
            "The question is too long. Maximum length is 2000 characters."
        )

    return cleaned


def _contains_execution_request(
    question: str,
) -> bool:
    normalized = _normalized_question(
        question
    )

    patterns = (
        r"\bexecute\b",
        r"\brun\s+kubectl\b",
        r"\bapply\s+(?:the\s+)?change\b",
        r"\bdelete\s+(?:the\s+)?pod\b",
        r"\brestart\s+(?:the\s+)?deployment\b",
        r"\bscale\s+(?:the\s+)?deployment\b",
        r"\bpatch\s+(?:the\s+)?deployment\b",
        r"\bmodify\s+(?:the\s+)?cluster\b",
    )

    return any(
        re.search(
            pattern,
            normalized,
        )
        for pattern in patterns
    )


def answer_incident_question(
    stored_incident: dict[str, Any],
    question: str,
) -> dict[str, Any]:
    """
    Answer one incident-specific SRE question.

    Common factual questions use deterministic Python answers.
    More complex questions use the local LLM with strict evidence
    grounding.
    """

    cleaned_question = _validate_question(
        question
    )

    context = build_chat_context(
        stored_incident
    )

    if _contains_execution_request(
        cleaned_question
    ):
        return {
            "answer": (
                "I cannot execute Kubernetes commands or modify the "
                "cluster. This SRE Copilot operates in recommendation-only "
                "mode. I can explain the evidence, provide safe read-only "
                "commands, or describe a GitOps proposal for human review."
            ),
            "mode": "safety-refusal",
            "incident_id": stored_incident.get(
                "id"
            ),
        }

    deterministic = _deterministic_answer(
        cleaned_question,
        context,
    )

    if deterministic is not None:
        return {
            "answer": deterministic,
            "mode": "deterministic",
            "incident_id": stored_incident.get(
                "id"
            ),
        }

    prompt = f"""
You are an incident-specific SRE Copilot.

Answer the engineer's question using only the supplied incident context.

Rules:

- Do not invent facts, numbers, timestamps, commands, resource values,
  causes, or verification results.
- Treat the deterministic alert assessment and validation as authoritative.
- Clearly distinguish confirmed facts, hypotheses, and missing evidence.
- Do not claim that zero Loki errors proves there was no incident.
- Do not claim that a future action has already succeeded.
- Do not execute commands or claim that you executed them.
- Do not authorize automatic remediation.
- When suggesting commands, use only read-only commands already present
  in the deterministic remediation plan.
- Keep the answer focused on this incident.
- When evidence is insufficient, state exactly what is missing.

INCIDENT CONTEXT:

{json.dumps(
    context,
    indent=2,
    default=str,
)}

ENGINEER QUESTION:

{cleaned_question}

Return a direct, evidence-grounded answer.
"""

    try:
        answer = llm.generate(
            prompt
        )

    except Exception as exc:
        raise ChatServiceError(
            f"The local LLM could not answer the question: {exc}"
        ) from exc

    return {
        "answer": answer,
        "mode": "grounded-llm",
        "incident_id": stored_incident.get(
            "id"
        ),
    }