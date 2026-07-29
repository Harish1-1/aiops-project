from __future__ import annotations

from typing import Any

from agents.alert_assessment import (
    assess_alert,
    format_alert_assessment,
)
from agents.evidence_summary import (
    build_evidence_summary,
)
from llm.llm_client import LLMClient
from rag.query import retrieve_context


llm = LLMClient()


def _markdown_list(
    values: list[str] | None,
    empty_message: str = "None available.",
) -> str:
    if not values:
        return f"- {empty_message}"

    return "\n".join(
        f"- {value}"
        for value in values
    )


def _historical_logs(
    incident: dict[str, Any],
) -> dict[str, Any]:
    value = incident.get(
        "historical_logs",
        {},
    )

    return (
        value
        if isinstance(value, dict)
        else {}
    )


def _deterministic_unconfirmed_rca(
    incident: dict[str, Any],
    assessment: dict[str, Any],
) -> str:
    """
    Generate a deterministic RCA when the alert is not confirmed.

    Loki evidence is included as factual context, but a lack of Loki
    errors does not prove that the application had no incident.
    """

    current_metrics = assessment.get(
        "current_metrics",
        {},
    )

    resources = assessment.get(
        "configured_resources",
        {},
    )

    utilization = assessment.get(
        "calculated_utilization",
        {},
    )

    history = assessment.get(
        "historical_summary",
        {},
    )

    memory_history = history.get(
        "memory",
        {},
    )

    cpu_history = history.get(
        "cpu",
        {},
    )

    loki = _historical_logs(
        incident
    )

    loki_levels = loki.get(
        "level_counts",
        {},
    )

    if not isinstance(
        loki_levels,
        dict,
    ):
        loki_levels = {}

    supported_findings = assessment.get(
        "supported_findings",
        [],
    )

    contradictions = assessment.get(
        "contradictions",
        [],
    )

    missing_evidence = assessment.get(
        "missing_evidence",
        [],
    )

    if not isinstance(
        supported_findings,
        list,
    ):
        supported_findings = []

    if not isinstance(
        contradictions,
        list,
    ):
        contradictions = []

    if not isinstance(
        missing_evidence,
        list,
    ):
        missing_evidence = []

    namespace = incident.get(
        "namespace",
        "Unknown",
    )

    pod = incident.get(
        "pod",
        "Unknown",
    )

    workload_kind = incident.get(
        "workload_kind",
        "Unknown",
    )

    workload_name = incident.get(
        "workload_name",
        "Unknown",
    )

    loki_available = bool(
        loki.get(
            "available",
            False,
        )
    )

    loki_summary = (
        (
            f"Loki returned {loki.get('entry_count', 0)} log entries "
            f"over {loki.get('lookback_minutes')} minutes. "
            f"Detected critical={loki_levels.get('CRITICAL', 0)}, "
            f"errors={loki.get('error_count', 0)}, "
            f"warnings={loki.get('warning_count', 0)}."
        )
        if loki_available
        else (
            "Loki historical logs were unavailable or no matching "
            "entries were returned."
        )
    )

    return f"""
## Evidence Interpretation

The deterministic alert assessment found that the alert is not supported
by either the current Kubernetes snapshot or the collected Prometheus
lookback window.

- Current CPU: {current_metrics.get("cpu")}
- Current memory: {current_metrics.get("memory")}
- CPU limit: {resources.get("cpu_limit")}
- Memory limit: {resources.get("memory_limit")}
- Current CPU utilization: {
    utilization.get("current_cpu_percent_of_limit")
}%
- Current memory utilization: {
    utilization.get("current_memory_percent_of_limit")
}%
- Historical maximum CPU utilization: {
    utilization.get("historical_max_cpu_percent_of_limit")
}%
- Historical maximum memory utilization: {
    utilization.get("historical_max_memory_percent_of_limit")
}%
- Historical memory maximum: {
    memory_history.get("maximum_mib")
} MiB
- Historical memory trend: {
    memory_history.get("trend")
}
- Historical CPU maximum: {
    cpu_history.get("maximum_millicores")
}m
- Historical CPU trend: {
    cpu_history.get("trend")
}
- Restart increase during lookback: {
    history.get("restart_increase")
}
- Loki evidence: {loki_summary}

## Confirmed Findings

- Pod `{namespace}/{pod}` is currently in phase {
    incident.get("pod_phase", "Unknown")
}.
- The owning workload is {
    workload_kind
}/{workload_name}.
- The alert is not confirmed by the collected current or historical
  resource evidence.
- No resource spike is visible in the collected Prometheus lookback
  window.
- No new restart occurred during the Prometheus lookback window.
- Loki log counts are reported only as observed evidence and are not
  treated as proof that no earlier application issue occurred.

Additional supported findings:

{_markdown_list(supported_findings)}

## Alert-to-Evidence Alignment

**Assessment status:** {
    assessment.get("status")
}

**Alert confirmed:** False

The available Kubernetes and Prometheus evidence contradicts the
`{incident.get("alert", "Unknown")}` alert. Loki evidence may provide
application context, but it does not override the deterministic metric
assessment.

## Root Cause Assessment

No workload root cause can currently be confirmed because the collected
resource evidence does not confirm that the reported condition occurred.

The main investigation target is the alerting configuration rather than
the workload configuration. Review the Prometheus rule, label selection,
threshold, evaluation window, alert timestamp, and Alertmanager payload.

Loki logs should be reviewed for application errors close to the alert
time. A lack of detected error keywords does not prove that the
application was healthy.

## Alternative Hypotheses

1. The alert may reference a different pod, container, or workload.
2. The condition may have occurred outside the collected lookback.
3. The alert may use a different metric or threshold.
4. The alert may be stale or manually submitted for testing.
5. Relevant application failures may not contain standard error keywords.
6. The affected pod may have been replaced before log collection.

These are hypotheses only.

## Confidence Score

Confidence: 95 out of 100.

The confidence is high because live Kubernetes evidence and Prometheus
history agree. It is not 100 because the exact PrometheusRule expression,
Alertmanager firing timestamp, and complete application context were not
evaluated.

## Additional Evidence Required

{_markdown_list(missing_evidence)}

- Inspect the exact PrometheusRule expression.
- Confirm the alert labels identify `{namespace}/{pod}`.
- Compare the alert timestamp with the Prometheus and Loki windows.
- Review the complete Alertmanager firing payload.
- Review Loki entries around the alert timestamp.
- Review recent deployment and configuration changes.

## Safe Investigation Actions

- Review the PrometheusRule expression and threshold.
- Review the Alertmanager firing timestamp and labels.
- Review Prometheus memory, CPU, and restart history.
- Review Loki error, warning, and surrounding application logs.
- Review Kubernetes events and current/previous container logs.
- Keep the workload unchanged until evidence supports a specific change.
""".strip()


def _llm_confirmed_rca(
    incident: dict[str, Any],
    assessment: dict[str, Any],
) -> str:
    """
    Use RAG-assisted LLM analysis only when deterministic evidence
    confirms the alert.
    """

    alert = str(
        incident.get(
            "alert",
            "Unknown",
        )
    )

    evidence_summary = build_evidence_summary(
        incident
    )

    assessment_text = format_alert_assessment(
        assessment
    )

    runbook_context = retrieve_context(
        alert
    )

    prompt = f"""
You are a Kubernetes Root Cause Analysis Agent.

The deterministic assessment confirms this alert.

Use only:

1. Kubernetes evidence
2. Prometheus history
3. Loki historical logs
4. The deterministic alert assessment
5. Retrieved runbook guidance

The deterministic assessment is authoritative.

Never invent or recalculate:

- CPU values,
- memory values,
- percentages,
- restart counts,
- timestamps,
- error counts,
- warning counts,
- traffic spikes,
- memory leaks,
- deployment changes,
- image versions,
- replica counts,
- commands already executed,
- successful verification.

Loki rules:

- A detected keyword is evidence only of the exact log line.
- Do not infer a root cause solely from the word "error".
- A zero error count does not prove that no incident occurred.
- Logs outside the query window are unknown.
- Do not claim that a pod had no errors unless the supplied evidence
  explicitly supports that limited time window.
- Clearly distinguish current kubectl logs from historical Loki logs.

FACTUAL KUBERNETES, PROMETHEUS, AND LOKI EVIDENCE:

{evidence_summary}

AUTHORITATIVE ALERT ASSESSMENT:

{assessment_text}

RETRIEVED RUNBOOK:

{runbook_context}

Return exactly these sections:

## Evidence Interpretation

## Confirmed Findings

## Alert-to-Evidence Alignment

## Root Cause Assessment

## Alternative Hypotheses

## Confidence Score

## Additional Evidence Required

## Safe Investigation Actions
"""

    return llm.generate(prompt)


def analyze_incident(
    incident: dict[str, Any],
) -> str:
    """
    Generate an evidence-grounded RCA.

    Unconfirmed alerts use deterministic RCA.
    Confirmed alerts use RAG-assisted LLM RCA.
    """

    assessment = incident.get(
        "alert_assessment"
    )

    if not isinstance(
        assessment,
        dict,
    ):
        assessment = assess_alert(
            incident
        )

    if not bool(
        assessment.get(
            "alert_confirmed",
            False,
        )
    ):
        return _deterministic_unconfirmed_rca(
            incident=incident,
            assessment=assessment,
        )

    return _llm_confirmed_rca(
        incident=incident,
        assessment=assessment,
    )