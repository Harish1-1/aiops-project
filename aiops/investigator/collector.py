from __future__ import annotations

import logging
from typing import Any

from investigator.kubernetes import (
    extract_workload_details,
    get_pod_description,
    get_pod_events,
    get_pod_json,
    get_pod_logs,
    get_pod_metrics,
    resolve_workload_owner,
)
from investigator.loki_client import (
    collect_loki_history,
)
from investigator.parser import (
    extract_container_status,
    parse_events,
    parse_metrics_output,
    split_log_lines,
)
from investigator.prometheus_client import (
    collect_prometheus_history,
)


logger = logging.getLogger(__name__)


def _historical_log_lines(
    historical_logs: dict[str, Any],
    limit: int = 150,
) -> list[str]:
    """
    Convert normalized Loki entries into readable evidence lines.

    The complete structured Loki response remains available under
    incident["historical_logs"]. This helper creates a compact list for
    RCA and dashboard display.
    """

    entries = historical_logs.get(
        "entries",
        [],
    )

    if not isinstance(entries, list):
        return []

    formatted: list[str] = []

    for entry in entries[-limit:]:
        if not isinstance(entry, dict):
            continue

        timestamp = str(
            entry.get(
                "timestamp",
                "unknown-time",
            )
        )

        level = str(
            entry.get(
                "level",
                "INFO",
            )
        )

        container = str(
            entry.get(
                "container",
                "unknown-container",
            )
        )

        line = str(
            entry.get(
                "line",
                "",
            )
        ).strip()

        if not line:
            continue

        formatted.append(
            (
                f"{timestamp} | {level} | "
                f"{container} | {line}"
            )
        )

    return formatted


def collect_live_incident_evidence(
    incident: dict[str, Any],
) -> dict[str, Any]:
    """
    Enrich an incident using:

    - live Kubernetes evidence,
    - current Metrics Server data,
    - historical Prometheus metrics,
    - historical Loki logs.

    Optional collection failures are stored as investigation errors and
    do not stop the Agentic AIOps workflow.
    """

    enriched = dict(incident)

    namespace = str(
        incident.get(
            "namespace",
            "default",
        )
    ).strip()

    pod = str(
        incident.get(
            "pod",
            "unknown",
        )
    ).strip()

    investigation_errors: list[str] = []

    if not pod or pod == "unknown":
        enriched["investigation_errors"] = [
            "The alert did not contain a pod name."
        ]

        return enriched

    pod_payload = get_pod_json(
        namespace=namespace,
        pod=pod,
    )

    if pod_payload is None:
        enriched.update(
            {
                "metrics": incident.get(
                    "metrics",
                    {},
                ),
                "events": incident.get(
                    "events",
                    [],
                ),
                "logs": incident.get(
                    "logs",
                    [],
                ),
                "workload_kind": "Unknown",
                "workload_name": "Unknown",
                "ownership_chain": [],
                "historical_metrics": {
                    "available": False,
                    "source": "prometheus",
                    "errors": [
                        (
                            "Historical metrics were not collected "
                            "because the pod could not be resolved."
                        )
                    ],
                },
                "historical_logs": {
                    "available": False,
                    "source": "loki",
                    "errors": [
                        (
                            "Historical logs were not collected "
                            "because the pod could not be resolved."
                        )
                    ],
                    "entries": [],
                },
                "historical_log_lines": [],
                "investigation_errors": [
                    (
                        f"Pod {namespace}/{pod} was not found. "
                        "It may have already been replaced or deleted."
                    )
                ],
            }
        )

        return enriched

    status_data = extract_container_status(
        pod_payload
    )

    owner_data = resolve_workload_owner(
        namespace=namespace,
        pod_payload=pod_payload,
    )

    workload_details = extract_workload_details(
        owner_data.get(
            "workload_resource"
        )
    )

    container_names = workload_details.get(
        "container_names",
        [],
    )

    workload_name = str(
        owner_data.get(
            "workload_name",
            "Unknown",
        )
    )

    metrics_output = get_pod_metrics(
        namespace=namespace,
        pod=pod,
    )

    metrics = parse_metrics_output(
        metrics_output
    )

    current_logs = get_pod_logs(
        namespace=namespace,
        pod=pod,
        previous=False,
    )

    previous_logs = get_pod_logs(
        namespace=namespace,
        pod=pod,
        previous=True,
    )

    event_payload = get_pod_events(
        namespace=namespace,
        pod=pod,
    )

    pod_description = get_pod_description(
        namespace=namespace,
        pod=pod,
    )

    historical_metrics = collect_prometheus_history(
        namespace=namespace,
        pod=pod,
        container_names=container_names,
        lookback_minutes=60,
        step_seconds=60,
    )

    historical_logs = collect_loki_history(
        namespace=namespace,
        pod=pod,
        container_names=container_names,
        workload_name=workload_name,
        lookback_minutes=60,
        limit=300,
    )

    for historical_error in historical_metrics.get(
        "errors",
        [],
    ):
        investigation_errors.append(
            historical_error
        )

    for loki_error in historical_logs.get(
        "errors",
        [],
    ):
        investigation_errors.append(
            loki_error
        )

    existing_logs = list(
        incident.get(
            "logs",
            [],
        )
    )

    collected_logs = (
        split_log_lines(
            previous_logs
        )
        + split_log_lines(
            current_logs
        )
    )

    combined_logs = list(
        dict.fromkeys(
            [
                *existing_logs,
                *collected_logs,
            ]
        )
    )

    existing_events = list(
        incident.get(
            "events",
            [],
        )
    )

    collected_events = parse_events(
        event_payload
    )

    combined_events = list(
        dict.fromkeys(
            [
                *existing_events,
                *collected_events,
            ]
        )
    )

    historical_log_lines = _historical_log_lines(
        historical_logs,
        limit=150,
    )

    evidence_sources = [
        "live-kubernetes",
    ]

    if historical_metrics.get(
        "available",
        False,
    ):
        evidence_sources.append(
            "prometheus"
        )

    if historical_logs.get(
        "available",
        False,
    ):
        evidence_sources.append(
            "loki"
        )

    evidence_source = "+".join(
        evidence_sources
    )

    enriched.update(
        {
            "namespace": namespace,
            "pod": pod,
            "logs": combined_logs[-150:],
            "events": combined_events[-50:],
            "metrics": metrics,
            "cpu_usage": metrics.get(
                "cpu",
                "unavailable",
            ),
            "memory_usage": metrics.get(
                "memory",
                "unavailable",
            ),
            "restart_count": status_data[
                "restart_count"
            ],
            "pod_phase": status_data[
                "phase"
            ],
            "pod_ip": status_data[
                "pod_ip"
            ],
            "node_name": status_data[
                "node_name"
            ],
            "container_states": status_data[
                "container_states"
            ],
            "termination_reasons": status_data[
                "termination_reasons"
            ],
            "pod_description": (
                pod_description[-12000:]
            ),
            "workload_kind": owner_data.get(
                "workload_kind",
                "Unknown",
            ),
            "workload_name": workload_name,
            "ownership_chain": owner_data.get(
                "ownership_chain",
                [],
            ),
            "desired_replicas": workload_details.get(
                "desired_replicas"
            ),
            "available_replicas": workload_details.get(
                "available_replicas"
            ),
            "ready_replicas": workload_details.get(
                "ready_replicas"
            ),
            "updated_replicas": workload_details.get(
                "updated_replicas"
            ),
            "container_names": container_names,
            "container_images": workload_details.get(
                "container_images",
                [],
            ),
            "container_resources": workload_details.get(
                "container_resources",
                [],
            ),
            "historical_metrics": historical_metrics,
            "historical_logs": historical_logs,
            "historical_log_lines": historical_log_lines,
            "evidence_source": evidence_source,
            "investigation_errors": investigation_errors,
        }
    )

    logger.info(
        "Collected incident evidence: "
        "namespace=%s pod=%s workload=%s/%s "
        "cpu=%s memory=%s restarts=%s "
        "prometheus=%s loki=%s loki_entries=%s",
        namespace,
        pod,
        enriched.get(
            "workload_kind"
        ),
        workload_name,
        metrics.get(
            "cpu"
        ),
        metrics.get(
            "memory"
        ),
        status_data[
            "restart_count"
        ],
        historical_metrics.get(
            "available",
            False,
        ),
        historical_logs.get(
            "available",
            False,
        ),
        historical_logs.get(
            "entry_count",
            0,
        ),
    )

    return enriched