from __future__ import annotations

from typing import Any


def _format_items(
    values: Any,
    limit: int = 30,
) -> str:
    if not values:
        return "- None"

    if not isinstance(values, list):
        return f"- {values}"

    selected = values[-limit:]

    return "\n".join(
        f"- {value}"
        for value in selected
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


def build_evidence_summary(
    incident: dict[str, Any],
) -> str:
    """
    Build a compact factual evidence block for downstream agents.

    Values are copied from Kubernetes, Prometheus, Loki, and the
    deterministic assessment. This function performs no AI reasoning.
    """

    alert = incident.get(
        "alert",
        "Unknown",
    )

    namespace = incident.get(
        "namespace",
        "Unknown",
    )

    pod = incident.get(
        "pod",
        "Unknown",
    )

    metrics = incident.get(
        "metrics",
        {},
    )

    if not isinstance(metrics, dict):
        metrics = {}

    cpu = metrics.get(
        "cpu",
        "Unavailable",
    )

    memory = metrics.get(
        "memory",
        "Unavailable",
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

    return f"""
ALERT
- Alert name: {alert}
- Namespace: {namespace}
- Pod: {pod}

LIVE POD STATE
- Pod phase: {incident.get("pod_phase", "Unknown")}
- Node: {incident.get("node_name", "Unknown")}
- Pod IP: {incident.get("pod_ip", "Unknown")}
- Restart count: {incident.get("restart_count", 0)}
- Evidence source: {incident.get("evidence_source", "unknown")}

WORKLOAD OWNERSHIP
- Workload kind: {incident.get("workload_kind", "Unknown")}
- Workload name: {incident.get("workload_name", "Unknown")}
- Ownership chain: {incident.get("ownership_chain", [])}
- Desired replicas: {incident.get("desired_replicas")}
- Available replicas: {incident.get("available_replicas")}
- Ready replicas: {incident.get("ready_replicas")}
- Updated replicas: {incident.get("updated_replicas")}
- Container names: {incident.get("container_names", [])}
- Container images: {incident.get("container_images", [])}
- Container resources: {incident.get("container_resources", [])}

CURRENT METRICS SNAPSHOT
- CPU: {cpu}
- Memory: {memory}

PROMETHEUS MEMORY HISTORY
- Available: {memory_history.get("available", False)}
- Samples: {memory_history.get("sample_count")}
- Latest: {memory_history.get("latest_mib")} MiB
- Average: {memory_history.get("average_mib")} MiB
- Maximum: {memory_history.get("maximum_mib")} MiB
- Trend: {memory_history.get("trend")}
- Peak timestamp: {memory_history.get("peak_timestamp")}

PROMETHEUS CPU HISTORY
- Available: {cpu_history.get("available", False)}
- Samples: {cpu_history.get("sample_count")}
- Latest: {cpu_history.get("latest_millicores")}m
- Average: {cpu_history.get("average_millicores")}m
- Maximum: {cpu_history.get("maximum_millicores")}m
- Trend: {cpu_history.get("trend")}
- Peak timestamp: {cpu_history.get("peak_timestamp")}

PROMETHEUS RESTART HISTORY
- Available: {restart_history.get("available", False)}
- Latest: {restart_history.get("latest")}
- Maximum: {restart_history.get("maximum")}
- Increase during lookback: {restart_history.get("restart_increase")}
- Trend: {restart_history.get("trend")}

LOKI HISTORICAL LOG SUMMARY
- Available: {loki.get("available", False)}
- Lookback minutes: {loki.get("lookback_minutes")}
- Entry count: {loki.get("entry_count", 0)}
- First timestamp: {loki.get("first_timestamp")}
- Last timestamp: {loki.get("last_timestamp")}
- Critical count: {
    loki.get("level_counts", {}).get("CRITICAL", 0)
    if isinstance(loki.get("level_counts"), dict)
    else 0
}
- Error count: {loki.get("error_count", 0)}
- Warning count: {loki.get("warning_count", 0)}

LOKI ERROR ENTRIES
{_format_items(
    [
        (
            f"{entry.get('timestamp')} | "
            f"{entry.get('container')} | "
            f"{entry.get('line')}"
        )
        for entry in loki.get("error_entries", [])
        if isinstance(entry, dict)
    ],
    limit=30,
)}

LOKI WARNING ENTRIES
{_format_items(
    [
        (
            f"{entry.get('timestamp')} | "
            f"{entry.get('container')} | "
            f"{entry.get('line')}"
        )
        for entry in loki.get("warning_entries", [])
        if isinstance(entry, dict)
    ],
    limit=30,
)}

RECENT LOKI LOGS
{_format_items(
    incident.get(
        "historical_log_lines",
        [],
    ),
    limit=50,
)}

CONTAINER STATES
{_format_items(
    incident.get(
        "container_states",
        [],
    )
)}

TERMINATION REASONS
{_format_items(
    incident.get(
        "termination_reasons",
        [],
    )
)}

KUBERNETES EVENTS
{_format_items(
    incident.get(
        "events",
        [],
    ),
    limit=30,
)}

CURRENT AND PREVIOUS KUBERNETES LOGS
{_format_items(
    incident.get(
        "logs",
        [],
    ),
    limit=50,
)}

COLLECTION ERRORS
{_format_items(
    incident.get(
        "investigation_errors",
        [],
    )
)}
""".strip()


def build_evidence_dictionary(
    incident: dict[str, Any],
) -> dict[str, Any]:
    """
    Return factual evidence in structured form for reports and APIs.
    """

    metrics = incident.get(
        "metrics",
        {},
    )

    if not isinstance(metrics, dict):
        metrics = {}

    return {
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
        "cpu": metrics.get(
            "cpu",
            "Unavailable",
        ),
        "memory": metrics.get(
            "memory",
            "Unavailable",
        ),
        "restart_count": incident.get(
            "restart_count",
            0,
        ),
        "pod_phase": incident.get(
            "pod_phase",
            "Unknown",
        ),
        "pod_ip": incident.get(
            "pod_ip",
            "Unknown",
        ),
        "node_name": incident.get(
            "node_name",
            "Unknown",
        ),
        "container_states": incident.get(
            "container_states",
            [],
        ),
        "termination_reasons": incident.get(
            "termination_reasons",
            [],
        ),
        "events": incident.get(
            "events",
            [],
        ),
        "logs": incident.get(
            "logs",
            [],
        ),
        "workload_kind": incident.get(
            "workload_kind",
            "Unknown",
        ),
        "workload_name": incident.get(
            "workload_name",
            "Unknown",
        ),
        "ownership_chain": incident.get(
            "ownership_chain",
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
        "updated_replicas": incident.get(
            "updated_replicas"
        ),
        "container_names": incident.get(
            "container_names",
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
        "historical_metrics": incident.get(
            "historical_metrics",
            {},
        ),
        "historical_logs": incident.get(
            "historical_logs",
            {},
        ),
        "historical_log_lines": incident.get(
            "historical_log_lines",
            [],
        ),
        "evidence_source": incident.get(
            "evidence_source",
            "unknown",
        ),
        "investigation_errors": incident.get(
            "investigation_errors",
            [],
        ),
    }