from __future__ import annotations

import re
from typing import Any


QUANTITY_PATTERN = re.compile(
    r"^\s*(\d+(?:\.\d+)?)\s*([a-zA-Z]*)\s*$"
)

HIGH_USAGE_THRESHOLD_PERCENT = 80.0


def _parse_memory_to_mib(
    value: str | int | float | None,
) -> float | None:
    if value is None:
        return None

    match = QUANTITY_PATTERN.match(str(value))

    if not match:
        return None

    number = float(match.group(1))
    unit = match.group(2).lower()

    multipliers = {
        "": 1 / (1024**2),
        "b": 1 / (1024**2),
        "k": 1000 / (1024**2),
        "kb": 1000 / (1024**2),
        "ki": 1 / 1024,
        "kib": 1 / 1024,
        "m": 1000**2 / (1024**2),
        "mb": 1000**2 / (1024**2),
        "mi": 1,
        "mib": 1,
        "g": 1000**3 / (1024**2),
        "gb": 1000**3 / (1024**2),
        "gi": 1024,
        "gib": 1024,
        "t": 1000**4 / (1024**2),
        "tb": 1000**4 / (1024**2),
        "ti": 1024**2,
        "tib": 1024**2,
    }

    multiplier = multipliers.get(unit)

    if multiplier is None:
        return None

    return number * multiplier


def _parse_cpu_to_millicores(
    value: str | int | float | None,
) -> float | None:
    if value is None:
        return None

    text = str(value).strip().lower()

    if not text:
        return None

    try:
        if text.endswith("m"):
            return float(text[:-1])

        return float(text) * 1000
    except ValueError:
        return None


def _find_container_resource(
    incident: dict[str, Any],
    resource_name: str,
    resource_type: str,
) -> str | None:
    resources = incident.get(
        "container_resources",
        [],
    )

    if not isinstance(resources, list):
        return None

    for container_resource in resources:
        if not isinstance(container_resource, dict):
            continue

        resource_group = container_resource.get(
            resource_type,
            {},
        )

        if not isinstance(resource_group, dict):
            continue

        value = resource_group.get(resource_name)

        if value is not None:
            return str(value)

    return None


def _percentage(
    usage: float | None,
    limit: float | None,
) -> float | None:
    if (
        usage is None
        or limit is None
        or limit <= 0
    ):
        return None

    return round(
        usage / limit * 100,
        2,
    )


def _normalize_alert(
    alert: str,
) -> str:
    return (
        alert
        .replace("_", "")
        .replace("-", "")
        .replace(" ", "")
        .lower()
    )


def _termination_contains(
    incident: dict[str, Any],
    reason: str,
) -> bool:
    expected = reason.lower()

    return any(
        expected in str(item).lower()
        for item in incident.get(
            "termination_reasons",
            [],
        )
    )


def _state_contains(
    incident: dict[str, Any],
    state: str,
) -> bool:
    expected = state.lower()

    return any(
        expected in str(item).lower()
        for item in incident.get(
            "container_states",
            [],
        )
    )


def _historical_section(
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

    section = historical_metrics.get(
        metric_name,
        {},
    )

    return (
        section
        if isinstance(section, dict)
        else {}
    )


def assess_alert(
    incident: dict[str, Any],
) -> dict[str, Any]:
    """
    Deterministically assess an alert using both:

    1. Current Kubernetes/Metrics Server evidence
    2. Historical Prometheus evidence

    No LLM is used in this function.
    """

    alert = str(
        incident.get(
            "alert",
            "Unknown",
        )
    )

    normalized_alert = _normalize_alert(
        alert
    )

    metrics = incident.get(
        "metrics",
        {},
    )

    if not isinstance(metrics, dict):
        metrics = {}

    current_cpu = str(
        metrics.get(
            "cpu",
            "Unavailable",
        )
    )

    current_memory = str(
        metrics.get(
            "memory",
            "Unavailable",
        )
    )

    cpu_request = _find_container_resource(
        incident,
        resource_name="cpu",
        resource_type="requests",
    )

    cpu_limit = _find_container_resource(
        incident,
        resource_name="cpu",
        resource_type="limits",
    )

    memory_request = _find_container_resource(
        incident,
        resource_name="memory",
        resource_type="requests",
    )

    memory_limit = _find_container_resource(
        incident,
        resource_name="memory",
        resource_type="limits",
    )

    current_memory_mib = _parse_memory_to_mib(
        current_memory
    )

    memory_limit_mib = _parse_memory_to_mib(
        memory_limit
    )

    current_cpu_millicores = (
        _parse_cpu_to_millicores(
            current_cpu
        )
    )

    cpu_limit_millicores = (
        _parse_cpu_to_millicores(
            cpu_limit
        )
    )

    current_memory_percent = _percentage(
        current_memory_mib,
        memory_limit_mib,
    )

    current_cpu_percent = _percentage(
        current_cpu_millicores,
        cpu_limit_millicores,
    )

    historical_memory = _historical_section(
        incident,
        "memory",
    )

    historical_cpu = _historical_section(
        incident,
        "cpu",
    )

    historical_restarts = _historical_section(
        incident,
        "restarts",
    )

    history_available = bool(
        incident
        .get(
            "historical_metrics",
            {},
        )
        .get(
            "available",
            False,
        )
    )

    historical_memory_max_mib = (
        historical_memory.get(
            "maximum_mib"
        )
    )

    historical_memory_average_mib = (
        historical_memory.get(
            "average_mib"
        )
    )

    historical_memory_latest_mib = (
        historical_memory.get(
            "latest_mib"
        )
    )

    historical_memory_percent = _percentage(
        historical_memory_max_mib,
        memory_limit_mib,
    )

    historical_cpu_max_millicores = (
        historical_cpu.get(
            "maximum_millicores"
        )
    )

    historical_cpu_average_millicores = (
        historical_cpu.get(
            "average_millicores"
        )
    )

    historical_cpu_latest_millicores = (
        historical_cpu.get(
            "latest_millicores"
        )
    )

    historical_cpu_percent = _percentage(
        historical_cpu_max_millicores,
        cpu_limit_millicores,
    )

    restart_increase = historical_restarts.get(
        "restart_increase"
    )

    supported_findings: list[str] = []
    contradictions: list[str] = []
    missing_evidence: list[str] = []

    status = "NO_DETERMINISTIC_RULE_AVAILABLE"
    current_snapshot_confirms_alert = False
    historical_evidence_confirms_alert = False
    historical_metrics_required = False

    if normalized_alert in {
        "highmemory",
        "highmemoryusage",
        "memoryhigh",
    }:
        historical_metrics_required = True

        if (
            current_memory_percent is not None
            and current_memory_percent
            >= HIGH_USAGE_THRESHOLD_PERCENT
        ):
            current_snapshot_confirms_alert = True

            supported_findings.append(
                (
                    f"Current memory usage is {current_memory} "
                    f"against a limit of {memory_limit}, equal to "
                    f"{current_memory_percent}% of the limit."
                )
            )

        if (
            historical_memory_percent is not None
            and historical_memory_percent
            >= HIGH_USAGE_THRESHOLD_PERCENT
        ):
            historical_evidence_confirms_alert = True

            supported_findings.append(
                (
                    "Prometheus history recorded a maximum memory "
                    f"value of {historical_memory_max_mib} MiB, "
                    f"equal to {historical_memory_percent}% of the "
                    f"{memory_limit} limit."
                )
            )

        if current_snapshot_confirms_alert:
            status = "SUPPORTED_BY_CURRENT_SNAPSHOT"

        elif historical_evidence_confirms_alert:
            status = "SUPPORTED_BY_PROMETHEUS_HISTORY"

        elif history_available:
            status = (
                "NOT_SUPPORTED_BY_CURRENT_OR_HISTORICAL_EVIDENCE"
            )

            contradictions.append(
                (
                    f"Current memory is {current_memory}, equal to "
                    f"{current_memory_percent}% of the configured "
                    f"{memory_limit} limit."
                )
            )

            contradictions.append(
                (
                    "The Prometheus lookback maximum was "
                    f"{historical_memory_max_mib} MiB, equal to "
                    f"{historical_memory_percent}% of the limit."
                )
            )

        else:
            status = "NOT_SUPPORTED_BY_CURRENT_SNAPSHOT"

            missing_evidence.append(
                "Prometheus historical memory data is unavailable."
            )

    elif normalized_alert in {
        "highcpu",
        "highcpuusage",
        "cpuhigh",
    }:
        historical_metrics_required = True

        if (
            current_cpu_percent is not None
            and current_cpu_percent
            >= HIGH_USAGE_THRESHOLD_PERCENT
        ):
            current_snapshot_confirms_alert = True

            supported_findings.append(
                (
                    f"Current CPU usage is {current_cpu} against "
                    f"a limit of {cpu_limit}, equal to "
                    f"{current_cpu_percent}% of the limit."
                )
            )

        if (
            historical_cpu_percent is not None
            and historical_cpu_percent
            >= HIGH_USAGE_THRESHOLD_PERCENT
        ):
            historical_evidence_confirms_alert = True

            supported_findings.append(
                (
                    "Prometheus history recorded a maximum CPU "
                    f"value of {historical_cpu_max_millicores}m, "
                    f"equal to {historical_cpu_percent}% of the "
                    f"{cpu_limit} limit."
                )
            )

        if current_snapshot_confirms_alert:
            status = "SUPPORTED_BY_CURRENT_SNAPSHOT"

        elif historical_evidence_confirms_alert:
            status = "SUPPORTED_BY_PROMETHEUS_HISTORY"

        elif history_available:
            status = (
                "NOT_SUPPORTED_BY_CURRENT_OR_HISTORICAL_EVIDENCE"
            )

            contradictions.append(
                (
                    f"Current CPU is {current_cpu}, equal to "
                    f"{current_cpu_percent}% of the configured "
                    f"{cpu_limit} limit."
                )
            )

            contradictions.append(
                (
                    "The Prometheus lookback maximum was "
                    f"{historical_cpu_max_millicores}m, equal to "
                    f"{historical_cpu_percent}% of the limit."
                )
            )

        else:
            status = "NOT_SUPPORTED_BY_CURRENT_SNAPSHOT"

            missing_evidence.append(
                "Prometheus historical CPU data is unavailable."
            )

    elif "oomkilled" in normalized_alert:
        if _termination_contains(
            incident,
            "OOMKilled",
        ):
            status = "CONFIRMED_BY_TERMINATION_EVIDENCE"
            current_snapshot_confirms_alert = True

            supported_findings.append(
                "Termination evidence contains OOMKilled."
            )
        else:
            status = "NOT_CONFIRMED_BY_CURRENT_POD_STATE"

            missing_evidence.append(
                "No OOMKilled termination evidence is present."
            )

    elif "crashloop" in normalized_alert:
        if _state_contains(
            incident,
            "CrashLoopBackOff",
        ):
            status = "CONFIRMED_BY_CONTAINER_STATE"
            current_snapshot_confirms_alert = True

            supported_findings.append(
                "Container state contains CrashLoopBackOff."
            )
        else:
            status = "NOT_CONFIRMED_BY_CURRENT_POD_STATE"

            missing_evidence.append(
                "Current state does not contain CrashLoopBackOff."
            )

    else:
        missing_evidence.append(
            (
                "No deterministic alert rule is implemented for "
                f"'{alert}'."
            )
        )

    alert_confirmed = (
        current_snapshot_confirms_alert
        or historical_evidence_confirms_alert
    )

    return {
        "alert": alert,
        "status": status,
        "alert_confirmed": alert_confirmed,
        "current_snapshot_confirms_alert": (
            current_snapshot_confirms_alert
        ),
        "historical_evidence_confirms_alert": (
            historical_evidence_confirms_alert
        ),
        "historical_metrics_available": history_available,
        "historical_metrics_required": (
            historical_metrics_required
        ),
        "threshold_percent": (
            HIGH_USAGE_THRESHOLD_PERCENT
        ),
        "current_metrics": {
            "cpu": current_cpu,
            "memory": current_memory,
        },
        "configured_resources": {
            "cpu_request": cpu_request,
            "cpu_limit": cpu_limit,
            "memory_request": memory_request,
            "memory_limit": memory_limit,
        },
        "calculated_utilization": {
            "current_cpu_percent_of_limit": (
                current_cpu_percent
            ),
            "current_memory_percent_of_limit": (
                current_memory_percent
            ),
            "historical_max_cpu_percent_of_limit": (
                historical_cpu_percent
            ),
            "historical_max_memory_percent_of_limit": (
                historical_memory_percent
            ),
        },
        "historical_summary": {
            "memory": {
                "latest_mib": (
                    historical_memory_latest_mib
                ),
                "average_mib": (
                    historical_memory_average_mib
                ),
                "maximum_mib": (
                    historical_memory_max_mib
                ),
                "trend": historical_memory.get(
                    "trend"
                ),
                "sample_count": historical_memory.get(
                    "sample_count"
                ),
            },
            "cpu": {
                "latest_millicores": (
                    historical_cpu_latest_millicores
                ),
                "average_millicores": (
                    historical_cpu_average_millicores
                ),
                "maximum_millicores": (
                    historical_cpu_max_millicores
                ),
                "trend": historical_cpu.get(
                    "trend"
                ),
                "sample_count": historical_cpu.get(
                    "sample_count"
                ),
            },
            "restart_increase": restart_increase,
        },
        "supported_findings": supported_findings,
        "contradictions": contradictions,
        "missing_evidence": missing_evidence,
    }


def format_alert_assessment(
    assessment: dict[str, Any],
) -> str:
    def items(
        values: list[str],
    ) -> str:
        if not values:
            return "- None"

        return "\n".join(
            f"- {value}"
            for value in values
        )

    current = assessment.get(
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

    return f"""
ALERT ASSESSMENT
- Alert: {assessment.get("alert")}
- Status: {assessment.get("status")}
- Alert confirmed: {assessment.get("alert_confirmed")}
- Current snapshot confirms alert: {
    assessment.get("current_snapshot_confirms_alert")
}
- Prometheus history confirms alert: {
    assessment.get("historical_evidence_confirms_alert")
}
- Prometheus history available: {
    assessment.get("historical_metrics_available")
}

CURRENT SNAPSHOT
- CPU: {current.get("cpu")}
- Memory: {current.get("memory")}

CONFIGURED RESOURCES
- CPU request: {resources.get("cpu_request")}
- CPU limit: {resources.get("cpu_limit")}
- Memory request: {resources.get("memory_request")}
- Memory limit: {resources.get("memory_limit")}

DETERMINISTIC UTILIZATION
- Current CPU percent of limit: {
    utilization.get("current_cpu_percent_of_limit")
}
- Current memory percent of limit: {
    utilization.get("current_memory_percent_of_limit")
}
- Historical maximum CPU percent of limit: {
    utilization.get("historical_max_cpu_percent_of_limit")
}
- Historical maximum memory percent of limit: {
    utilization.get("historical_max_memory_percent_of_limit")
}

PROMETHEUS SUMMARY
- Memory: {history.get("memory")}
- CPU: {history.get("cpu")}
- Restart increase: {history.get("restart_increase")}

SUPPORTED FINDINGS
{items(assessment.get("supported_findings", []))}

CONTRADICTIONS
{items(assessment.get("contradictions", []))}

MISSING EVIDENCE
{items(assessment.get("missing_evidence", []))}
""".strip()