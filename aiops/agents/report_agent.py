from __future__ import annotations

from typing import Any

from agents.evidence_summary import (
    build_evidence_dictionary,
)


def _markdown_list(
    values: list[Any] | None,
    empty_message: str = "None available.",
) -> str:
    if not values:
        return f"- {empty_message}"

    return "\n".join(
        f"- {value}"
        for value in values
    )


def _historical_metric(
    incident: dict[str, Any],
    metric_name: str,
) -> dict[str, Any]:
    historical_metrics = incident.get(
        "historical_metrics",
        {},
    )

    if not isinstance(
        historical_metrics,
        dict,
    ):
        return {}

    metric = historical_metrics.get(
        metric_name,
        {},
    )

    return (
        metric
        if isinstance(metric, dict)
        else {}
    )


def _alert_assessment(
    incident: dict[str, Any],
) -> dict[str, Any]:
    assessment = incident.get(
        "alert_assessment",
        {},
    )

    return (
        assessment
        if isinstance(
            assessment,
            dict,
        )
        else {}
    )


def generate_report(
    incident: dict[str, Any],
    investigation: dict[str, Any],
    analysis: str,
    remediation: str,
    validation: str,
    approval_status: str,
    retry_count: int,
) -> str:
    """
    Generate a single deterministic final report.

    Live facts, historical metrics, assessment results, remediation and
    validation are rendered once. Retry feedback is never appended.
    """

    evidence = (
        build_evidence_dictionary(
            incident
        )
    )

    assessment = _alert_assessment(
        incident
    )

    memory_history = _historical_metric(
        incident,
        "memory",
    )

    cpu_history = _historical_metric(
        incident,
        "cpu",
    )

    restart_history = (
        _historical_metric(
            incident,
            "restarts",
        )
    )

    loki_history = incident.get(
        "historical_logs",
        {},
    )

    if not isinstance(
        loki_history,
        dict,
    ):
        loki_history = {}

    loki_level_counts = loki_history.get(
        "level_counts",
        {},
    )

    if not isinstance(
        loki_level_counts,
        dict,
    ):
        loki_level_counts = {}

    loki_error_entries = loki_history.get(
        "error_entries",
        [],
    )

    if not isinstance(
        loki_error_entries,
        list,
    ):
        loki_error_entries = []

    loki_warning_entries = loki_history.get(
        "warning_entries",
        [],
    )

    if not isinstance(
        loki_warning_entries,
        list,
    ):
        loki_warning_entries = []

    loki_recent_lines = incident.get(
        "historical_log_lines",
        [],
    )

    if not isinstance(
        loki_recent_lines,
        list,
    ):
        loki_recent_lines = []

    utilization = assessment.get(
        "calculated_utilization",
        {},
    )

    if not isinstance(
        utilization,
        dict,
    ):
        utilization = {}

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

    rejected = (
        approval_status
        != "APPROVED FOR HUMAN REVIEW"
    )

    safety_notice = (
        "The proposed remediation must not be executed. "
        "Human engineering review and correction are required."
        if rejected
        else (
            "The recommendation passed deterministic safety checks and "
            "is approved only for human review. No action was executed."
        )
    )

    return f"""
# Final Workflow Decision

- **Approval status:** {approval_status}
- **Correction attempts:** 0
- **Execution mode:** RECOMMENDATION ONLY
- **Automatic execution:** DISABLED

> **Safety notice:** {safety_notice}

---

## Incident Summary

- **Alert:** {evidence["alert"]}
- **Namespace:** {evidence["namespace"]}
- **Pod:** {evidence["pod"]}
- **Workload:** {
    evidence.get(
        "workload_kind",
        "Unknown",
    )
}/{
    evidence.get(
        "workload_name",
        "Unknown",
    )
}
- **Evidence source:** {
    evidence["evidence_source"]
}

## Live Kubernetes Evidence

- **Pod phase:** {
    evidence["pod_phase"]
}
- **Node:** {
    evidence["node_name"]
}
- **Pod IP:** {
    evidence["pod_ip"]
}
- **Current CPU:** {
    evidence["cpu"]
}
- **Current memory:** {
    evidence["memory"]
}
- **Restart count:** {
    evidence["restart_count"]
}

### Workload Configuration

- **Desired replicas:** {
    evidence.get(
        "desired_replicas"
    )
}
- **Available replicas:** {
    evidence.get(
        "available_replicas"
    )
}
- **Container names:** {
    evidence.get(
        "container_names",
        [],
    )
}
- **Container images:** {
    evidence.get(
        "container_images",
        [],
    )
}
- **Container resources:** {
    evidence.get(
        "container_resources",
        [],
    )
}

### Container States

{_markdown_list(
    evidence["container_states"]
)}

### Termination Reasons

{_markdown_list(
    evidence["termination_reasons"]
)}

### Kubernetes Events

{_markdown_list(
    evidence["events"]
)}

### Recent Logs

{_markdown_list(
    evidence["logs"][-30:]
)}

### Collection Errors

{_markdown_list(
    evidence[
        "investigation_errors"
    ]
)}

---

## Prometheus Historical Evidence

### Memory

- **Samples:** {
    memory_history.get(
        "sample_count"
    )
}
- **Latest:** {
    memory_history.get(
        "latest_mib"
    )
} MiB
- **Average:** {
    memory_history.get(
        "average_mib"
    )
} MiB
- **Maximum:** {
    memory_history.get(
        "maximum_mib"
    )
} MiB
- **Trend:** {
    memory_history.get(
        "trend"
    )
}
- **Peak time:** {
    memory_history.get(
        "peak_timestamp"
    )
}

### CPU

- **Samples:** {
    cpu_history.get(
        "sample_count"
    )
}
- **Latest:** {
    cpu_history.get(
        "latest_millicores"
    )
}m
- **Average:** {
    cpu_history.get(
        "average_millicores"
    )
}m
- **Maximum:** {
    cpu_history.get(
        "maximum_millicores"
    )
}m
- **Trend:** {
    cpu_history.get(
        "trend"
    )
}
- **Peak time:** {
    cpu_history.get(
        "peak_timestamp"
    )
}

### Restarts

- **Latest:** {
    restart_history.get(
        "latest"
    )
}
- **Maximum:** {
    restart_history.get(
        "maximum"
    )
}
- **Increase during lookback:** {
    restart_history.get(
        "restart_increase"
    )
}
- **Trend:** {
    restart_history.get(
        "trend"
    )
}

---

---

## Loki Historical Log Evidence

- **Available:** {
    loki_history.get(
        "available",
        False,
    )
}
- **Lookback:** {
    loki_history.get(
        "lookback_minutes"
    )
} minutes
- **Entries retrieved:** {
    loki_history.get(
        "entry_count",
        0,
    )
}
- **First log timestamp:** {
    loki_history.get(
        "first_timestamp"
    )
}
- **Last log timestamp:** {
    loki_history.get(
        "last_timestamp"
    )
}
- **Critical entries:** {
    loki_level_counts.get(
        "CRITICAL",
        0,
    )
}
- **Error entries:** {
    loki_history.get(
        "error_count",
        0,
    )
}
- **Warning entries:** {
    loki_history.get(
        "warning_count",
        0,
    )
}

### Loki Error Evidence

{_markdown_list(
    [
        (
            f"{entry.get('timestamp')} | "
            f"{entry.get('container')} | "
            f"{entry.get('line')}"
        )
        for entry in loki_error_entries[-30:]
        if isinstance(entry, dict)
    ],
    empty_message="No error entries found.",
)}

### Loki Warning Evidence

{_markdown_list(
    [
        (
            f"{entry.get('timestamp')} | "
            f"{entry.get('container')} | "
            f"{entry.get('line')}"
        )
        for entry in loki_warning_entries[-30:]
        if isinstance(entry, dict)
    ],
    empty_message="No warning entries found.",
)}

### Recent Loki Logs

{_markdown_list(
    loki_recent_lines[-50:],
    empty_message="No Loki log entries retrieved.",
)}

## Deterministic Alert Assessment

- **Status:** {
    assessment.get(
        "status",
        "Unavailable",
    )
}
- **Alert confirmed:** {
    assessment.get(
        "alert_confirmed",
        False,
    )
}
- **Current snapshot confirms alert:** {
    assessment.get(
        "current_snapshot_confirms_alert",
        False,
    )
}
- **Prometheus history confirms alert:** {
    assessment.get(
        "historical_evidence_confirms_alert",
        False,
    )
}
- **Current memory utilization:** {
    utilization.get(
        "current_memory_percent_of_limit"
    )
}%
- **Historical maximum memory utilization:** {
    utilization.get(
        "historical_max_memory_percent_of_limit"
    )
}%
- **Current CPU utilization:** {
    utilization.get(
        "current_cpu_percent_of_limit"
    )
}%
- **Historical maximum CPU utilization:** {
    utilization.get(
        "historical_max_cpu_percent_of_limit"
    )
}%

### Supported Findings

{_markdown_list(
    supported_findings
)}

### Contradictions

{_markdown_list(
    contradictions
)}

### Missing Evidence

{_markdown_list(
    missing_evidence
)}

---

## AI Root Cause Interpretation

The following section is an AI interpretation. It cannot override the
live evidence, Prometheus history, deterministic assessment or policy
decision.

{analysis or "No AI RCA output was returned."}

---

## Deterministic Remediation Plan

{remediation}

---

## Deterministic Validation

{validation}

---

## Human Review Requirements

- Review the AI interpretation against the deterministic evidence.
- Confirm that the alert rule targets the intended namespace, pod,
  container and workload.
- Review relevant Loki logs around the alert timestamp.
- Review recent Git, image and configuration changes.
- Do not modify resources unless the root cause and required values are
  confirmed.
- Apply any future change through a reviewed GitOps pull request.
- Do not directly mutate the cluster from the AI workflow.

## Post-Change Verification Plan

After a future human-approved GitOps change:

1. Confirm the ArgoCD application reaches `Synced` and `Healthy`.
2. Confirm workload rollout completion.
3. Confirm pod readiness.
4. Confirm service availability.
5. Compare CPU, memory and restart metrics before and after the change.
6. Review Kubernetes events and application logs.
7. Confirm that the original alert resolves.
8. Roll back if health or availability deteriorates.

No verification check is currently marked as passed.

## Rollback Strategy

Restore the previous known-good Git revision or manifest through the
GitOps repository. Confirm ArgoCD synchronization and verify the
workload after rollback. No Git revision or rollout revision is assumed.

## Final Safety Notice

{safety_notice}
""".strip()