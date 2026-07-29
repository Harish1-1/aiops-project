from __future__ import annotations

from typing import Any


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


def _resource_value(
    incident: dict[str, Any],
    resource_type: str,
    resource_name: str,
) -> str:
    """
    Return a resource request or limit collected from Kubernetes.

    No value is invented. If the resource is unavailable, the function
    returns 'Unavailable'.
    """

    container_resources = incident.get(
        "container_resources",
        [],
    )

    if not isinstance(
        container_resources,
        list,
    ):
        return "Unavailable"

    for container_resource in container_resources:
        if not isinstance(
            container_resource,
            dict,
        ):
            continue

        resource_group = container_resource.get(
            resource_type,
            {},
        )

        if not isinstance(
            resource_group,
            dict,
        ):
            continue

        value = resource_group.get(
            resource_name
        )

        if value is not None:
            return str(value)

    return "Unavailable"


def _historical_metric_summary(
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


def _build_read_only_commands(
    incident: dict[str, Any],
) -> list[str]:
    """
    Generate only valid, read-only Kubernetes commands.

    Every namespaced command includes the real namespace. Commands use
    the pod and workload names collected directly from Kubernetes.
    """

    namespace = str(
        incident.get(
            "namespace",
            "default",
        )
    )

    pod = str(
        incident.get(
            "pod",
            "unknown",
        )
    )

    workload_name = str(
        incident.get(
            "workload_name",
            "Unknown",
        )
    )

    workload_kind = str(
        incident.get(
            "workload_kind",
            "Unknown",
        )
    )

    workload_kind_lower = (
        workload_kind.lower()
    )

    commands = [
        (
            f"kubectl get pod {pod} "
            f"-n {namespace} -o wide"
        ),
        (
            f"kubectl describe pod {pod} "
            f"-n {namespace}"
        ),
        (
            f"kubectl logs pod/{pod} "
            f"-n {namespace} "
            "--all-containers=true "
            "--tail=100"
        ),
        (
            f"kubectl logs pod/{pod} "
            f"-n {namespace} "
            "--all-containers=true "
            "--previous "
            "--tail=100"
        ),
        (
            f"kubectl top pod {pod} "
            f"-n {namespace}"
        ),
        (
            f"kubectl get events "
            f"-n {namespace} "
            "--sort-by=.lastTimestamp"
        ),
    ]

    if (
        workload_name
        and workload_name != "Unknown"
        and workload_kind_lower
        not in {
            "",
            "unknown",
            "pod",
        }
    ):
        commands.extend(
            [
                (
                    f"kubectl get "
                    f"{workload_kind_lower} "
                    f"{workload_name} "
                    f"-n {namespace} -o yaml"
                ),
                (
                    f"kubectl describe "
                    f"{workload_kind_lower} "
                    f"{workload_name} "
                    f"-n {namespace}"
                ),
            ]
        )

        if workload_kind_lower in {
            "deployment",
            "statefulset",
            "daemonset",
        }:
            commands.append(
                (
                    "kubectl rollout history "
                    f"{workload_kind_lower}/"
                    f"{workload_name} "
                    f"-n {namespace}"
                )
            )

    return list(
        dict.fromkeys(commands)
    )


def _build_evidence_required(
    incident: dict[str, Any],
) -> list[str]:
    assessment = incident.get(
        "alert_assessment",
        {},
    )

    if not isinstance(
        assessment,
        dict,
    ):
        assessment = {}

    required: list[str] = []

    missing_evidence = assessment.get(
        "missing_evidence",
        [],
    )

    if isinstance(
        missing_evidence,
        list,
    ):
        required.extend(
            str(item)
            for item in missing_evidence
        )

    alert_confirmed = bool(
        assessment.get(
            "alert_confirmed",
            False,
        )
    )

    if not alert_confirmed:
        required.append(
            (
                "Confirm that the alert expression and labels reference "
                "the correct pod, container, namespace and workload."
            )
        )

    historical_metrics = incident.get(
        "historical_metrics",
        {},
    )

    historical_available = bool(
        historical_metrics.get(
            "available",
            False,
        )
        if isinstance(
            historical_metrics,
            dict,
        )
        else False
    )

    if not historical_available:
        required.append(
            (
                "Collect Prometheus metric history covering the alert "
                "start time and the period immediately before it."
            )
        )

    required.extend(
        [
            (
                "Review application and Kubernetes logs around the "
                "alert timestamp."
            ),
            (
                "Review recent deployment, configuration and image "
                "changes for the affected workload."
            ),
        ]
    )

    return list(
        dict.fromkeys(required)
    )


def _build_immediate_actions(
    incident: dict[str, Any],
) -> list[str]:
    assessment = incident.get(
        "alert_assessment",
        {},
    )

    if not isinstance(
        assessment,
        dict,
    ):
        assessment = {}

    alert_confirmed = bool(
        assessment.get(
            "alert_confirmed",
            False,
        )
    )

    actions = [
        (
            "Review the collected Kubernetes events, current logs and "
            "previous-container logs."
        ),
        (
            "Review the Prometheus metric window and compare the peak, "
            "average and current values."
        ),
        (
            "Confirm the current workload specification and resource "
            "configuration from Kubernetes or the GitOps repository."
        ),
    ]

    if alert_confirmed:
        actions.insert(
            0,
            (
                "Treat the alert as supported by deterministic evidence "
                "and begin human-led investigation."
            ),
        )
    else:
        actions.insert(
            0,
            (
                "Do not change the workload configuration because the "
                "collected evidence does not currently confirm the alert."
            ),
        )

    return actions


def _build_gitops_recommendation(
    incident: dict[str, Any],
) -> str:
    assessment = incident.get(
        "alert_assessment",
        {},
    )

    if not isinstance(
        assessment,
        dict,
    ):
        assessment = {}

    alert_confirmed = bool(
        assessment.get(
            "alert_confirmed",
            False,
        )
    )

    workload_kind = str(
        incident.get(
            "workload_kind",
            "Unknown",
        )
    )

    workload_name = str(
        incident.get(
            "workload_name",
            "Unknown",
        )
    )

    if not alert_confirmed:
        return (
            "No configuration change is currently justified by the "
            "collected Kubernetes and Prometheus evidence. Keep the "
            "workload unchanged and investigate the alert definition, "
            "historical logs and deployment history."
        )

    if (
        workload_kind == "Unknown"
        or workload_name == "Unknown"
    ):
        return (
            "A GitOps change cannot be prepared because the owning "
            "Kubernetes workload could not be identified."
        )

    return (
        f"Review the source-controlled manifest for "
        f"{workload_kind}/{workload_name}. Prepare a proposed change "
        "only after a human confirms the root cause and determines the "
        "required configuration values. Do not invent resource values. "
        "Open the proposed change as a reviewed pull request before "
        "ArgoCD synchronization."
    )


def _build_risk_assessment(
    incident: dict[str, Any],
) -> str:
    assessment = incident.get(
        "alert_assessment",
        {},
    )

    if not isinstance(
        assessment,
        dict,
    ):
        assessment = {}

    alert_confirmed = bool(
        assessment.get(
            "alert_confirmed",
            False,
        )
    )

    if alert_confirmed:
        return (
            "Not responding to a confirmed alert may allow service "
            "degradation or repeated failures to continue. Changing "
            "resources or workload configuration without confirming the "
            "root cause may hide the issue, increase resource usage or "
            "introduce a new failure."
        )

    return (
        "Changing the workload when current and historical evidence do "
        "not confirm the alert may introduce unnecessary resource usage "
        "or configuration risk. The safer action is to investigate the "
        "alert rule and supporting evidence before modifying the system."
    )


def _build_verification_plan(
    incident: dict[str, Any],
) -> list[str]:
    namespace = str(
        incident.get(
            "namespace",
            "default",
        )
    )

    workload_kind = str(
        incident.get(
            "workload_kind",
            "Unknown",
        )
    )

    workload_name = str(
        incident.get(
            "workload_name",
            "Unknown",
        )
    )

    verification = [
        (
            "Confirm that the original alert has resolved in "
            "Prometheus and Alertmanager."
        ),
        (
            "Compare Prometheus CPU, memory and restart trends before "
            "and after any approved change."
        ),
        (
            "Confirm pod readiness and application availability."
        ),
        (
            "Confirm that restart count remains stable."
        ),
        (
            "Review logs and Kubernetes events for new warnings or "
            "errors."
        ),
    ]

    if (
        workload_kind != "Unknown"
        and workload_name != "Unknown"
    ):
        verification.insert(
            0,
            (
                f"Confirm rollout health for "
                f"{workload_kind}/{workload_name} "
                f"in namespace {namespace}."
            ),
        )

    return verification


def build_deterministic_remediation(
    incident: dict[str, Any],
    analysis: str = "",
) -> str:
    """
    Build a recommendation-only remediation plan.

    The plan is generated entirely by Python from collected evidence.
    The LLM does not generate commands, YAML, resource values, images,
    replica counts, controller names or manifest paths.
    """

    alert = str(
        incident.get(
            "alert",
            "Unknown",
        )
    )

    namespace = str(
        incident.get(
            "namespace",
            "default",
        )
    )

    pod = str(
        incident.get(
            "pod",
            "Unknown",
        )
    )

    workload_kind = str(
        incident.get(
            "workload_kind",
            "Unknown",
        )
    )

    workload_name = str(
        incident.get(
            "workload_name",
            "Unknown",
        )
    )

    metrics = incident.get(
        "metrics",
        {},
    )

    if not isinstance(metrics, dict):
        metrics = {}

    current_cpu = metrics.get(
        "cpu",
        "Unavailable",
    )

    current_memory = metrics.get(
        "memory",
        "Unavailable",
    )

    cpu_request = _resource_value(
        incident,
        resource_type="requests",
        resource_name="cpu",
    )

    cpu_limit = _resource_value(
        incident,
        resource_type="limits",
        resource_name="cpu",
    )

    memory_request = _resource_value(
        incident,
        resource_type="requests",
        resource_name="memory",
    )

    memory_limit = _resource_value(
        incident,
        resource_type="limits",
        resource_name="memory",
    )

    memory_history = (
        _historical_metric_summary(
            incident,
            "memory",
        )
    )

    cpu_history = (
        _historical_metric_summary(
            incident,
            "cpu",
        )
    )

    restart_history = (
        _historical_metric_summary(
            incident,
            "restarts",
        )
    )

    assessment = incident.get(
        "alert_assessment",
        {},
    )

    if not isinstance(
        assessment,
        dict,
    ):
        assessment = {}

    immediate_actions = (
        _build_immediate_actions(
            incident
        )
    )

    evidence_required = (
        _build_evidence_required(
            incident
        )
    )

    read_only_commands = (
        _build_read_only_commands(
            incident
        )
    )

    verification_plan = (
        _build_verification_plan(
            incident
        )
    )

    gitops_recommendation = (
        _build_gitops_recommendation(
            incident
        )
    )

    risk_assessment = (
        _build_risk_assessment(
            incident
        )
    )

    assessment_status = assessment.get(
        "status",
        "Unavailable",
    )

    alert_confirmed = assessment.get(
        "alert_confirmed",
        False,
    )

    commands_text = "\n".join(
        f"```bash\n{command}\n```"
        for command in read_only_commands
    )

    return f"""
# Deterministic Remediation Plan

## Decision Summary

- **Alert:** {alert}
- **Namespace:** {namespace}
- **Pod:** {pod}
- **Workload:** {workload_kind}/{workload_name}
- **Assessment status:** {assessment_status}
- **Alert confirmed by collected evidence:** {alert_confirmed}

## Current Evidence

- **Current CPU:** {current_cpu}
- **Current memory:** {current_memory}
- **CPU request:** {cpu_request}
- **CPU limit:** {cpu_limit}
- **Memory request:** {memory_request}
- **Memory limit:** {memory_limit}
- **Restart count:** {incident.get("restart_count", "Unavailable")}

### Prometheus Memory History

- **Latest:** {memory_history.get("latest_mib")} MiB
- **Average:** {memory_history.get("average_mib")} MiB
- **Maximum:** {memory_history.get("maximum_mib")} MiB
- **Trend:** {memory_history.get("trend")}
- **Samples:** {memory_history.get("sample_count")}

### Prometheus CPU History

- **Latest:** {cpu_history.get("latest_millicores")}m
- **Average:** {cpu_history.get("average_millicores")}m
- **Maximum:** {cpu_history.get("maximum_millicores")}m
- **Trend:** {cpu_history.get("trend")}
- **Samples:** {cpu_history.get("sample_count")}

### Restart History

- **Latest:** {restart_history.get("latest")}
- **Maximum:** {restart_history.get("maximum")}
- **Increase during lookback:** {
    restart_history.get("restart_increase")
}

## Recommended Immediate Actions

{_markdown_list(immediate_actions)}

## Evidence Required Before Change

{_markdown_list(evidence_required)}

## Proposed GitOps Change

{gitops_recommendation}

## Read-Only Commands for Human Review

{commands_text}

## Risk Assessment

{risk_assessment}

## Verification Plan

{_markdown_list(verification_plan)}

## Rollback Plan

If a future human-approved GitOps change causes degradation, restore the
previous known-good Git revision or manifest through the GitOps
repository. Confirm ArgoCD synchronization and verify workload health
after the rollback. No revision identifier is assumed or invented.

## Recommendation-Only Notice

This remediation plan was generated deterministically from collected
Kubernetes and Prometheus evidence. No command, configuration change,
Git commit, pull request, ArgoCD synchronization or Kubernetes mutation
was executed.
""".strip()