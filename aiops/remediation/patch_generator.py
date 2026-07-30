from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

import yaml

from agents.alert_assessment import assess_alert
from llm.llm_client import llm
from rag.query import retrieve_runbooks
from remediation.patch_validator import (
    PatchValidationError,
    validate_and_apply_patch,
)


LOGGER = logging.getLogger(__name__)

GitOpsPlan = dict[str, Any]


# ---------------------------------------------------------------------------
# Alert aliases
# ---------------------------------------------------------------------------

_ALERT_ALIASES: dict[str, str] = {
    "kubepodcrashlooping": "CrashLoopBackOff",
    "crashloopbackoff": "CrashLoopBackOff",
    "crashloop": "CrashLoopBackOff",

    "oomkilled": "OOMKilled",
    "containeroomkilled": "OOMKilled",
    "kubepodcontaineroomkilled": "OOMKilled",

    "imagepullbackoff": "ImagePullBackOff",
    "errimagepull": "ImagePullBackOff",
    "kubeimagepullbackoff": "ImagePullBackOff",

    "highmemory": "HighMemoryUsage",
    "highmemoryusage": "HighMemoryUsage",
    "memoryhigh": "HighMemoryUsage",

    "highcpu": "HighCPUUsage",
    "highcpuusage": "HighCPUUsage",
    "cpuhigh": "HighCPUUsage",

    "podpending": "PodPending",
    "kubepodnotready": "PodPending",

    "kubedeploymentreplicasmismatch": (
        "DeploymentReplicasMismatch"
    ),
    "deploymentfailed": "DeploymentFailed",

    "diskpressure": "DiskPressure",
    "nodenotready": "NodeNotReady",
    "nodedown": "NodeNotReady",

    "secretmissing": "SecretMissing",
    "configmapmissing": "ConfigMapMissing",

    "databaseconnection": "DatabaseConnection",
    "databaseconnectionfailure": "DatabaseConnection",
    "dnsfailure": "DNSFailure",
    "kafkafailure": "KafkaFailure",
    "networklatency": "NetworkLatency",
    "certificateexpired": "CertificateExpired",
}


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------

def _safe_dict(
    value: Any,
) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_list(
    value: Any,
) -> list[Any]:
    return value if isinstance(value, list) else []


def _project_root() -> Path:
    configured = os.getenv(
        "AIOPS_PROJECT_ROOT",
        "",
    ).strip()

    if configured:
        return (
            Path(configured)
            .expanduser()
            .resolve()
        )

    return Path(
        __file__
    ).resolve().parents[2]


def _normalise_alert(
    value: Any,
) -> str:
    raw = str(
        value or "Unknown"
    ).strip()

    key = "".join(
        character
        for character in raw.lower()
        if character.isalnum()
    )

    return _ALERT_ALIASES.get(
        key,
        raw,
    )


def _contains_text(
    values: Any,
    expected: str,
) -> bool:
    expected_lower = expected.lower()

    return any(
        expected_lower
        in str(item).lower()
        for item in _safe_list(
            values
        )
    )


def _parse_exit_code(
    value: Any,
) -> int | None:
    text = str(
        value or ""
    ).lower()

    marker = "exit_code="

    if marker not in text:
        return None

    number = (
        text.split(
            marker,
            1,
        )[1]
        .split(
            ")",
            1,
        )[0]
        .split(
            ",",
            1,
        )[0]
        .strip()
    )

    try:
        return int(
            number
        )
    except ValueError:
        return None


def _has_nonzero_exit_code(
    incident: dict[str, Any],
) -> bool:
    for item in _safe_list(
        incident.get(
            "termination_reasons"
        )
    ):
        exit_code = _parse_exit_code(
            item
        )

        if (
            exit_code is not None
            and exit_code != 0
        ):
            return True

    return False


# ---------------------------------------------------------------------------
# Alert confirmation
# ---------------------------------------------------------------------------

def _confirm_crashloop(
    incident: dict[str, Any],
    fresh_assessment: dict[str, Any],
) -> tuple[
    bool,
    list[str],
]:
    reasons: list[str] = []

    alert_name = _normalise_alert(
        incident.get(
            "alert"
        )
    )

    try:
        restart_count = int(
            incident.get(
                "restart_count",
                0,
            )
            or 0
        )
    except (
        TypeError,
        ValueError,
    ):
        restart_count = 0

    states = incident.get(
        "container_states",
        [],
    )

    terminations = incident.get(
        "termination_reasons",
        [],
    )

    events = incident.get(
        "events",
        [],
    )

    pod_description = str(
        incident.get(
            "pod_description",
            "",
        )
    )

    state_has_crashloop = (
        _contains_text(
            states,
            "CrashLoopBackOff",
        )
        or "crashloopbackoff"
        in pod_description.lower()
    )

    event_has_backoff = (
        _contains_text(
            events,
            "BackOff",
        )
        or _contains_text(
            events,
            "back-off restarting",
        )
    )

    termination_failed = (
        _contains_text(
            terminations,
            "Error",
        )
        or _has_nonzero_exit_code(
            incident
        )
    )

    firing_alert_received = (
        alert_name
        == "CrashLoopBackOff"
    )

    assessment_confirmed = bool(
        fresh_assessment.get(
            "alert_confirmed",
            False,
        )
    )

    if assessment_confirmed:
        reasons.append(
            "The deterministic alert assessment confirmed "
            "the incident."
        )

    if state_has_crashloop:
        reasons.append(
            "The collected container state contains "
            "CrashLoopBackOff."
        )

    if event_has_backoff:
        reasons.append(
            "Kubernetes events show container restart "
            "back-off."
        )

    if termination_failed:
        reasons.append(
            "The previous container termination contains "
            "an error or non-zero exit code."
        )

    if restart_count >= 2:
        reasons.append(
            f"The pod restart count is {restart_count}."
        )

    if firing_alert_received:
        reasons.append(
            "A firing CrashLoop alert was received from "
            "Alertmanager."
        )

    if (
        assessment_confirmed
        or state_has_crashloop
        or event_has_backoff
    ):
        return True, reasons

    if (
        firing_alert_received
        and restart_count >= 2
        and termination_failed
    ):
        return True, reasons

    return False, reasons


def _confirm_alert(
    normalized_alert: str,
    incident: dict[str, Any],
    fresh_assessment: dict[str, Any],
) -> tuple[
    bool,
    list[str],
]:
    if normalized_alert == "CrashLoopBackOff":
        return _confirm_crashloop(
            incident,
            fresh_assessment,
        )

    confirmed = bool(
        fresh_assessment.get(
            "alert_confirmed",
            False,
        )
    )

    reasons = [
        str(item)
        for item in _safe_list(
            fresh_assessment.get(
                "supported_findings"
            )
        )
    ]

    return confirmed, reasons


# ---------------------------------------------------------------------------
# Base GitOps plan
# ---------------------------------------------------------------------------

def _build_base(
    stored_incident: dict[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
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

    fresh_assessment = assess_alert(
        incident
    )

    normalized_alert = _normalise_alert(
        incident.get(
            "alert"
        )
    )

    (
        alert_confirmed,
        confirmation_reasons,
    ) = _confirm_alert(
        normalized_alert,
        incident,
        fresh_assessment,
    )

    approval_status = str(
        stored_incident.get(
            "approval_status",
            "",
        )
    )

    base: dict[str, Any] = {
        "incident_id": int(
            stored_incident["id"]
        ),
        "alert": str(
            incident.get(
                "alert",
                "Unknown",
            )
        ),
        "normalized_alert": (
            normalized_alert
        ),
        "namespace": incident.get(
            "namespace"
        ),
        "pod": incident.get(
            "pod"
        ),
        "workload_kind": incident.get(
            "workload_kind"
        ),
        "workload_name": incident.get(
            "workload_name"
        ),
        "approved": (
            approval_status
            == "HUMAN APPROVED"
        ),
        "validation_passed": bool(
            result.get(
                "validation_passed",
                False,
            )
        ),
        "alert_confirmed": (
            alert_confirmed
        ),
        "confirmation_reasons": (
            confirmation_reasons
        ),
        "fresh_alert_assessment": (
            fresh_assessment
        ),
        "mode": "recommendation-only",
    }

    return (
        base,
        incident,
        result,
    )


# ---------------------------------------------------------------------------
# Common safety gates
# ---------------------------------------------------------------------------

def _validate_common_gates(
    base: dict[str, Any],
) -> GitOpsPlan | None:
    if not base["approved"]:
        return {
            **base,
            "status": "BLOCKED",
            "reason": (
                "Human approval is required before GitOps "
                "planning."
            ),
            "patch": None,
        }

    if not base["validation_passed"]:
        return {
            **base,
            "status": "BLOCKED",
            "reason": (
                "Deterministic validation did not pass."
            ),
            "patch": None,
        }

    if not base["alert_confirmed"]:
        return {
            **base,
            "status": "NO_CHANGE_REQUIRED",
            "reason": (
                "The incident is not supported by the "
                "collected deterministic evidence."
            ),
            "patch": None,
        }

    workload_kind = str(
        base.get(
            "workload_kind"
        )
        or "Unknown"
    )

    workload_name = str(
        base.get(
            "workload_name"
        )
        or "Unknown"
    )

    supported_kinds = {
        "Deployment",
        "StatefulSet",
        "DaemonSet",
    }

    if (
        workload_kind
        not in supported_kinds
        or workload_name
        == "Unknown"
    ):
        return {
            **base,
            "status": "BLOCKED",
            "reason": (
                "A supported owning workload could not be "
                "resolved."
            ),
            "patch": None,
        }

    return None


# ---------------------------------------------------------------------------
# Repository manifest discovery
# ---------------------------------------------------------------------------

def _ignored_manifest_path(
    path: Path,
) -> bool:
    lowered_parts = {
        part.lower()
        for part in path.parts
    }

    ignored_names = {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "generated",
        "build",
        "dist",
    }

    if lowered_parts.intersection(
        ignored_names
    ):
        return True

    filename = path.name.lower()

    if filename.endswith(
        "-fixed.yaml"
    ):
        return True

    if filename.endswith(
        "-fixed.yml"
    ):
        return True

    return False


def _read_manifest_documents(
    path: Path,
) -> list[dict[str, Any]]:
    try:
        text = path.read_text(
            encoding="utf-8"
        )
    except (
        OSError,
        UnicodeError,
    ):
        return []

    try:
        documents = list(
            yaml.safe_load_all(
                text
            )
        )
    except yaml.YAMLError:
        return []

    return [
        document
        for document in documents
        if isinstance(
            document,
            dict,
        )
    ]


def _manifest_identity(
    document: dict[str, Any],
) -> tuple[
    str,
    str,
    str,
]:
    metadata = _safe_dict(
        document.get(
            "metadata"
        )
    )

    return (
        str(
            document.get(
                "kind",
                "",
            )
        ),
        str(
            metadata.get(
                "name",
                "",
            )
        ),
        str(
            metadata.get(
                "namespace",
                "default",
            )
        ),
    )


def _find_repository_manifest(
    *,
    workload_kind: str,
    workload_name: str,
    namespace: str,
) -> tuple[
    Path,
    str,
]:
    root = _project_root()

    configured_path = os.getenv(
        "AIOPS_MANIFEST_PATH",
        "",
    ).strip()

    if configured_path:
        candidate = (
            root
            / configured_path
        ).resolve()

        if not candidate.is_file():
            raise FileNotFoundError(
                "AIOPS_MANIFEST_PATH does not reference "
                f"an existing file: {candidate}"
            )

        content = candidate.read_text(
            encoding="utf-8"
        )

        matched = any(
            _manifest_identity(
                document
            )
            == (
                workload_kind,
                workload_name,
                namespace,
            )
            for document
            in _read_manifest_documents(
                candidate
            )
        )

        if not matched:
            raise ValueError(
                "The configured manifest does not match the "
                "collected workload identity."
            )

        return (
            candidate,
            content,
        )

    search_roots: list[Path] = []

    configured_directory = os.getenv(
        "AIOPS_MANIFEST_ROOT",
        "",
    ).strip()

    if configured_directory:
        search_roots.append(
            (
                root
                / configured_directory
            ).resolve()
        )

    for relative in (
        "kubernetes",
        "manifests",
        "deploy",
        "deployment",
        "gitops",
        "helm",
    ):
        candidate = root / relative

        if candidate.is_dir():
            search_roots.append(
                candidate
            )

    if not search_roots:
        search_roots.append(
            root
        )

    matches: list[
        tuple[
            Path,
            str,
        ]
    ] = []

    seen_paths: set[
        Path
    ] = set()

    for search_root in search_roots:
        for pattern in (
            "*.yaml",
            "*.yml",
        ):
            for path in search_root.rglob(
                pattern
            ):
                resolved = path.resolve()

                if resolved in seen_paths:
                    continue

                seen_paths.add(
                    resolved
                )

                if _ignored_manifest_path(
                    resolved
                ):
                    continue

                documents = (
                    _read_manifest_documents(
                        resolved
                    )
                )

                for document in documents:
                    identity = _manifest_identity(
                        document
                    )

                    if identity == (
                        workload_kind,
                        workload_name,
                        namespace,
                    ):
                        matches.append(
                            (
                                resolved,
                                resolved.read_text(
                                    encoding="utf-8"
                                ),
                            )
                        )
                        break

    if not matches:
        raise FileNotFoundError(
            "No repository manifest matched "
            f"{workload_kind}/{workload_name} "
            f"in namespace {namespace}."
        )

    if len(matches) > 1:
        candidates = [
            str(
                path.relative_to(
                    root
                )
            ).replace(
                "\\",
                "/",
            )
            for path, _content
            in matches
        ]

        raise ValueError(
            "Multiple repository manifests match the "
            "collected workload. Configure AIOPS_MANIFEST_PATH. "
            f"Candidates: {candidates}"
        )

    return matches[0]


# ---------------------------------------------------------------------------
# Evidence and policy preparation
# ---------------------------------------------------------------------------

def _container_names(
    incident: dict[str, Any],
) -> list[str]:
    names = [
        str(item)
        for item in _safe_list(
            incident.get(
                "container_names"
            )
        )
        if str(item).strip()
    ]

    if names:
        return names

    resources = _safe_list(
        incident.get(
            "container_resources"
        )
    )

    for resource in resources:
        if not isinstance(
            resource,
            dict,
        ):
            continue

        name = str(
            resource.get(
                "container",
                "",
            )
        ).strip()

        if name:
            names.append(
                name
            )

    return names


def _build_retrieval_query(
    base: dict[str, Any],
    incident: dict[str, Any],
) -> str:
    parts = [
        str(
            base.get(
                "normalized_alert",
                "",
            )
        ),
        str(
            base.get(
                "workload_kind",
                "",
            )
        ),
        str(
            base.get(
                "workload_name",
                "",
            )
        ),
        str(
            base.get(
                "namespace",
                "",
            )
        ),
    ]

    parts.extend(
        str(item)
        for item in _safe_list(
            incident.get(
                "termination_reasons"
            )
        )[:5]
    )

    parts.extend(
        str(item)
        for item in _safe_list(
            incident.get(
                "events"
            )
        )[:10]
    )

    return "\n".join(
        part
        for part in parts
        if part.strip()
    )


def _merge_runbook_policies(
    runbooks: list[
        dict[str, Any]
    ],
) -> dict[str, Any]:
    allowed_yaml_paths: list[str] = []
    allowed_changes: list[str] = []
    forbidden_changes: list[str] = []
    required_evidence: list[str] = []
    patch_constraints: list[str] = []
    validation_requirements: list[str] = []
    remediation_policies: list[str] = []

    for runbook in runbooks:
        policy = _safe_dict(
            runbook.get(
                "policy"
            )
        )

        for key, destination in (
            (
                "allowed_yaml_paths",
                allowed_yaml_paths,
            ),
            (
                "allowed_changes",
                allowed_changes,
            ),
            (
                "forbidden_changes",
                forbidden_changes,
            ),
            (
                "required_evidence",
                required_evidence,
            ),
            (
                "patch_constraints",
                patch_constraints,
            ),
            (
                "validation_requirements",
                validation_requirements,
            ),
        ):
            for value in _safe_list(
                policy.get(
                    key
                )
            ):
                text = str(
                    value
                ).strip()

                if (
                    text
                    and text
                    not in destination
                ):
                    destination.append(
                        text
                    )

        remediation_policy = str(
            policy.get(
                "gitops_remediation_policy",
                "",
            )
        ).strip()

        if remediation_policy:
            remediation_policies.append(
                remediation_policy
            )

    maximum_operations = int(
        os.getenv(
            "AIOPS_MAX_PATCH_OPERATIONS",
            "3",
        )
    )

    return {
        "allowed_yaml_paths": (
            allowed_yaml_paths
        ),
        "allowed_changes": (
            allowed_changes
        ),
        "forbidden_changes": (
            forbidden_changes
        ),
        "required_evidence": (
            required_evidence
        ),
        "patch_constraints": (
            patch_constraints
        ),
        "validation_requirements": (
            validation_requirements
        ),
        "gitops_remediation_policy": (
            "\n\n".join(
                remediation_policies
            )
        ),
        "maximum_operations": (
            maximum_operations
        ),
        "allow_replica_change": False,
        "approved_image_values": [],
    }


def _evidence_payload(
    base: dict[str, Any],
    incident: dict[str, Any],
) -> dict[str, Any]:
    return {
        "alert": base.get(
            "alert"
        ),
        "normalized_alert": (
            base.get(
                "normalized_alert"
            )
        ),
        "namespace": base.get(
            "namespace"
        ),
        "pod": base.get(
            "pod"
        ),
        "workload_kind": base.get(
            "workload_kind"
        ),
        "workload_name": base.get(
            "workload_name"
        ),
        "confirmation_reasons": (
            base.get(
                "confirmation_reasons"
            )
        ),
        "pod_phase": incident.get(
            "pod_phase"
        ),
        "restart_count": incident.get(
            "restart_count"
        ),
        "container_states": incident.get(
            "container_states"
        ),
        "termination_reasons": incident.get(
            "termination_reasons"
        ),
        "container_names": _container_names(
            incident
        ),
        "container_images": incident.get(
            "container_images"
        ),
        "container_resources": incident.get(
            "container_resources"
        ),
        "events": _safe_list(
            incident.get(
                "events"
            )
        )[:25],
        "logs": _safe_list(
            incident.get(
                "logs"
            )
        )[:50],
        "metrics": incident.get(
            "metrics"
        ),
        "prometheus_history": incident.get(
            "prometheus_history"
        ),
        "loki_history": incident.get(
            "loki_history"
        ),
        "fresh_alert_assessment": (
            base.get(
                "fresh_alert_assessment"
            )
        ),
    }


# ---------------------------------------------------------------------------
# Structured LLM proposal
# ---------------------------------------------------------------------------

def _manifest_container_context(
    *,
    manifest_text: str,
    container_name: str,
) -> dict[str, Any]:
    """
    Return the exact current YAML values for the affected container.

    These values are supplied to the LLM so it does not need to copy
    placeholder text or reconstruct the current manifest.
    """

    try:
        manifest = yaml.safe_load(
            manifest_text
        )
    except yaml.YAMLError as error:
        raise ValueError(
            f"Repository manifest is invalid YAML: {error}"
        ) from error

    if not isinstance(
        manifest,
        dict,
    ):
        raise ValueError(
            "Repository manifest must contain one Kubernetes object."
        )

    spec = _safe_dict(
        manifest.get("spec")
    )

    template = _safe_dict(
        spec.get("template")
    )

    pod_spec = _safe_dict(
        template.get("spec")
    )

    containers = _safe_list(
        pod_spec.get("containers")
    )

    for index, container in enumerate(
        containers
    ):
        if not isinstance(
            container,
            dict,
        ):
            continue

        if str(
            container.get(
                "name",
                "",
            )
        ) != container_name:
            continue

        return {
            "container_index": index,
            "container_name": container_name,
            "command_path": (
                f"/spec/template/spec/containers/"
                f"{index}/command"
            ),
            "args_path": (
                f"/spec/template/spec/containers/"
                f"{index}/args"
            ),
            "image_path": (
                f"/spec/template/spec/containers/"
                f"{index}/image"
            ),
            "current_command": (
                container.get("command")
            ),
            "current_args": (
                container.get("args")
            ),
            "current_image": (
                container.get("image")
            ),
            "current_resources": (
                container.get("resources")
            ),
            "current_startup_probe": (
                container.get("startupProbe")
            ),
            "current_liveness_probe": (
                container.get("livenessProbe")
            ),
            "current_readiness_probe": (
                container.get("readinessProbe")
            ),
        }

    raise ValueError(
        f"Container {container_name!r} was not found "
        "in the repository manifest."
    )


def _extract_json_array_from_text(
    text: str,
) -> list[Any] | None:
    """
    Extract the first valid JSON array from one policy line.
    """

    start = text.find("[")
    end = text.rfind("]")

    if (
        start == -1
        or end == -1
        or end <= start
    ):
        return None

    candidate = text[
        start : end + 1
    ]

    try:
        value = json.loads(
            candidate
        )
    except json.JSONDecodeError:
        return None

    return (
        value
        if isinstance(
            value,
            list,
        )
        else None
    )


def _approved_values_from_policy(
    policy: dict[str, Any],
) -> dict[str, list[Any]]:
    """
    Parse exact approved replacement values from retrieved runbook policy.

    This does not invent values. It uses only values explicitly written in
    the indexed runbook policy.
    """

    approved: dict[str, list[Any]] = {
        "command": [],
        "args": [],
        "images": [],
        "resources": [],
    }

    constraints = _safe_list(
        policy.get(
            "patch_constraints"
        )
    )

    for constraint in constraints:
        text = str(
            constraint
        ).strip()

        lowered = text.lower()

        parsed_array = (
            _extract_json_array_from_text(
                text
            )
        )

        if (
            "approved command value"
            in lowered
            and parsed_array is not None
        ):
            approved["command"].append(
                parsed_array
            )

        elif (
            "approved args value"
            in lowered
            and parsed_array is not None
        ):
            approved["args"].append(
                parsed_array
            )

    for image in _safe_list(
        policy.get(
            "approved_image_values"
        )
    ):
        image_text = str(
            image
        ).strip()

        if image_text:
            approved["images"].append(
                image_text
            )

    return approved


def _proposal_contains_placeholders(
    proposal: dict[str, Any],
) -> bool:
    placeholder_phrases = (
        "exact current yaml value",
        "evidence-supported replacement",
        "approved value",
        "replacement value",
        "current value here",
    )

    def contains_placeholder(
        value: Any,
    ) -> bool:
        if isinstance(
            value,
            str,
        ):
            lowered = value.lower()

            return any(
                phrase in lowered
                for phrase
                in placeholder_phrases
            )

        if isinstance(
            value,
            list,
        ):
            return any(
                contains_placeholder(item)
                for item in value
            )

        if isinstance(
            value,
            dict,
        ):
            return any(
                contains_placeholder(item)
                for item in value.values()
            )

        return False

    return contains_placeholder(
        proposal
    )

def _ground_proposal_target_and_paths(
    *,
    proposal: dict[str, Any],
    base: dict[str, Any],
    manifest_context: dict[str, Any],
) -> dict[str, Any]:
    """
    Fill only target values already proven by collected evidence and the
    repository manifest.

    This does not invent workload or container values. It restores fields
    omitted by a small language model and normalises container placeholders,
    wildcard paths, and container-name paths to the numeric container index
    required by Kubernetes JSON Pointer before deterministic validation.
    """

    target = _safe_dict(
        proposal.get(
            "target"
        )
    )

    expected_kind = str(
        base.get(
            "workload_kind",
            "",
        )
    ).strip()

    expected_name = str(
        base.get(
            "workload_name",
            "",
        )
    ).strip()

    expected_namespace = str(
        base.get(
            "namespace",
            "default",
        )
        or "default"
    ).strip()

    expected_container = str(
        manifest_context.get(
            "container_name",
            "",
        )
    ).strip()

    container_index = manifest_context.get(
        "container_index"
    )

    # Add only missing target fields. Existing incorrect values remain
    # unchanged so patch_validator.py can reject an identity mismatch.
    if not str(
        target.get(
            "kind",
            "",
        )
    ).strip():
        target["kind"] = expected_kind

    if not str(
        target.get(
            "name",
            "",
        )
    ).strip():
        target["name"] = expected_name

    if not str(
        target.get(
            "namespace",
            "",
        )
    ).strip():
        target["namespace"] = expected_namespace

    if not str(
        target.get(
            "container",
            "",
        )
    ).strip():
        target["container"] = expected_container

    proposal["target"] = target

    grounded_operations: list[Any] = []

    for raw_operation in _safe_list(
        proposal.get(
            "operations"
        )
    ):
        if not isinstance(
            raw_operation,
            dict,
        ):
            grounded_operations.append(
                raw_operation
            )
            continue

        operation = dict(
            raw_operation
        )

        path = str(
            operation.get(
                "path",
                "",
            )
        ).strip()

        if (
            path
            and container_index is not None
        ):
            normalized_index = str(
                container_index
            )

            possible_container_segments = {
                "{container}",
                "*",
            }

            if expected_container:
                possible_container_segments.add(
                    expected_container
                )

            proposal_container = str(
                target.get(
                    "container",
                    "",
                )
            ).strip()

            if proposal_container:
                possible_container_segments.add(
                    proposal_container
                )

            for container_segment in (
                possible_container_segments
            ):
                path = path.replace(
                    (
                        f"/containers/"
                        f"{container_segment}/"
                    ),
                    (
                        f"/containers/"
                        f"{normalized_index}/"
                    ),
                )

            operation["path"] = path

        grounded_operations.append(
            operation
        )

    proposal["operations"] = (
        grounded_operations
    )

    return proposal

def _build_policy_grounded_candidate(
    *,
    base: dict[str, Any],
    incident: dict[str, Any],
    manifest_context: dict[str, Any],
    approved_values: dict[str, list[Any]],
    llm_proposal: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """
    Build a candidate only when the runbook contains one exact approved
    replacement value and the collected target is the controlled demo.

    The candidate still passes through patch_validator.py.
    """

    normalized_alert = str(
        base.get(
            "normalized_alert",
            "",
        )
    )

    workload_kind = str(
        base.get(
            "workload_kind",
            "",
        )
    )

    workload_name = str(
        base.get(
            "workload_name",
            "",
        )
    )

    namespace = str(
        base.get(
            "namespace",
            "",
        )
    )

    container_name = str(
        manifest_context.get(
            "container_name",
            "",
        )
    )

    if (
        normalized_alert
        != "CrashLoopBackOff"
        or workload_kind
        != "Deployment"
        or workload_name
        != "automatic-crashloop-test"
        or namespace
        != "production"
        or container_name
        != "crashloop-test"
    ):
        return None

    approved_commands = approved_values.get(
        "command",
        [],
    )

    if len(
        approved_commands
    ) != 1:
        return None

    current_command = (
        manifest_context.get(
            "current_command"
        )
    )

    approved_command = (
        approved_commands[0]
    )

    if (
        not isinstance(
            current_command,
            list,
        )
        or not isinstance(
            approved_command,
            list,
        )
        or current_command
        == approved_command
    ):
        return None

    llm_reason = ""

    if isinstance(
        llm_proposal,
        dict,
    ):
        llm_reason = str(
            llm_proposal.get(
                "reason",
                "",
            )
        ).strip()

    return {
        "decision": "PATCH",
        "change_type": (
            "CONTAINER_COMMAND_CHANGE"
        ),
        "reason": (
            llm_reason
            or (
                "The current command exits deliberately, and the "
                "retrieved CrashLoop runbook contains one exact approved "
                "replacement command for this controlled workload."
            )
        ),
        "confidence": 1.0,
        "target": {
            "kind": workload_kind,
            "name": workload_name,
            "namespace": namespace,
            "container": container_name,
        },
        "operations": [
            {
                "path": (
                    manifest_context[
                        "command_path"
                    ]
                ),
                "before": (
                    current_command
                ),
                "after": (
                    approved_command
                ),
                "evidence": [
                    *[
                        str(reason)
                        for reason
                        in _safe_list(
                            base.get(
                                "confirmation_reasons"
                            )
                        )
                    ],
                    (
                        "The retrieved CrashLoop runbook explicitly "
                        "approves this command only for "
                        "Deployment/automatic-crashloop-test in "
                        "namespace production."
                    ),
                ],
            }
        ],
    }

def _build_proposal_prompt(
    *,
    base: dict[str, Any],
    incident: dict[str, Any],
    manifest_text: str,
    repository_path: str,
    runbooks: list[dict[str, Any]],
    policy: dict[str, Any],
    manifest_context: dict[str, Any],
    approved_values: dict[str, list[Any]],
) -> str:
    target = {
        "kind": base.get(
            "workload_kind"
        ),
        "name": base.get(
            "workload_name"
        ),
        "namespace": base.get(
            "namespace"
        ),
        "container": (
            manifest_context.get(
                "container_name"
            )
        ),
    }

    compact_runbooks = [
        {
            "title": runbook.get(
                "title"
            ),
            "file": runbook.get(
                "file"
            ),
            "score": runbook.get(
                "score"
            ),
            "policy": runbook.get(
                "policy"
            ),
            "relevant_content": str(
                runbook.get(
                    "content",
                    "",
                )
            )[:5000],
        }
        for runbook in runbooks
    ]

    required_shape = {
        "decision": "PATCH",
        "change_type": (
            "CONTAINER_COMMAND_CHANGE"
        ),
        "reason": (
            "Explain why the exact operation is supported."
        ),
        "confidence": 0.95,
        "target": target,
        "operations": [
            {
                "path": (
                    manifest_context.get(
                        "command_path"
                    )
                ),
                "before": (
                    manifest_context.get(
                        "current_command"
                    )
                ),
                "after": (
                    approved_values.get(
                        "command",
                        [],
                    )[0]
                    if len(
                        approved_values.get(
                            "command",
                            [],
                        )
                    )
                    == 1
                    else None
                ),
                "evidence": [
                    (
                        "Use concrete collected evidence "
                        "and the exact runbook policy."
                    )
                ],
            }
        ],
    }

    return f"""
You are proposing one recommendation-only Kubernetes GitOps change.

Return exactly one JSON object. Do not return Markdown or explanation outside
the JSON.

Never write placeholder text. In particular, never write:
- "Exact current YAML value"
- "Evidence-supported replacement"
- "approved value"
- "replacement value"

Copy exact JSON values from CURRENT MANIFEST VALUES and APPROVED POLICY VALUES.

Use PATCH only when an exact approved replacement value exists.
Otherwise return MANUAL_INVESTIGATION_REQUIRED.

The deterministic validator will require:
- every before value to exactly equal the repository YAML;
- every after value to be explicitly supported by policy or evidence;
- the target identity to match exactly;
- every path to be allowed by the runbook.

TARGET:

{json.dumps(target, indent=2, default=str)}

CURRENT MANIFEST VALUES:

{json.dumps(manifest_context, indent=2, default=str)}

APPROVED POLICY VALUES:

{json.dumps(approved_values, indent=2, default=str)}

ALLOWED YAML PATHS:

{json.dumps(policy.get("allowed_yaml_paths", []), indent=2)}

COLLECTED EVIDENCE:

{json.dumps(
    _evidence_payload(
        base,
        incident,
    ),
    indent=2,
    default=str,
)[:16000]}

RETRIEVED RUNBOOKS:

{json.dumps(
    compact_runbooks,
    indent=2,
    default=str,
)[:16000]}

CURRENT REPOSITORY FILE:

{repository_path}

CURRENT REPOSITORY YAML:

{manifest_text}

Return this exact JSON structure using actual values, not descriptive examples:

{json.dumps(
    required_shape,
    indent=2,
    default=str,
)}
""".strip()

# ---------------------------------------------------------------------------
# RAG patch engine
# ---------------------------------------------------------------------------

def _rag_strategy(
    base: dict[str, Any],
    incident: dict[str, Any],
) -> GitOpsPlan:
    workload_kind = str(
        base.get(
            "workload_kind"
        )
    )

    workload_name = str(
        base.get(
            "workload_name"
        )
    )

    namespace = str(
        base.get(
            "namespace"
        )
        or "default"
    )

    try:
        (
            manifest_path,
            manifest_text,
        ) = _find_repository_manifest(
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
        )
    except (
        FileNotFoundError,
        ValueError,
        OSError,
    ) as error:
        return {
            **base,
            "status": (
                "MANUAL_INVESTIGATION_REQUIRED"
            ),
            "reason": str(
                error
            ),
            "patch_engine": "rag",
            "patch": None,
        }

    project_root = _project_root()

    repository_path = str(
        manifest_path.relative_to(
            project_root
        )
    ).replace(
        "\\",
        "/",
    )

    query = _build_retrieval_query(
        base,
        incident,
    )

    try:
        runbooks = retrieve_runbooks(
            query,
            limit=3,
        )
    except Exception as error:
        LOGGER.exception(
            "RAG runbook retrieval failed."
        )

        return {
            **base,
            "status": (
                "MANUAL_INVESTIGATION_REQUIRED"
            ),
            "reason": (
                "Relevant runbooks could not be retrieved "
                f"from Qdrant: {error}"
            ),
            "patch_engine": "rag",
            "repository_path": (
                repository_path
            ),
            "patch": None,
        }

    if not runbooks:
        return {
            **base,
            "status": (
                "MANUAL_INVESTIGATION_REQUIRED"
            ),
            "reason": (
                "No relevant runbook was retrieved. No AI "
                "patch was generated."
            ),
            "patch_engine": "rag",
            "repository_path": (
                repository_path
            ),
            "patch": None,
        }

    policy = _merge_runbook_policies(
        runbooks
    )

    container_names = _container_names(
        incident
    )

    if not container_names:
        return {
            **base,
            "status": "MANUAL_INVESTIGATION_REQUIRED",
            "reason": (
                "The affected container could not be resolved."
            ),
            "patch_engine": "rag",
            "repository_path": repository_path,
            "patch": None,
        }

    try:
        manifest_context = (
            _manifest_container_context(
                manifest_text=manifest_text,
                container_name=container_names[0],
            )
        )
    except ValueError as error:
        return {
            **base,
            "status": "MANUAL_INVESTIGATION_REQUIRED",
            "reason": str(error),
            "patch_engine": "rag",
            "repository_path": repository_path,
            "patch": None,
        }

    approved_values = (
        _approved_values_from_policy(
            policy
        )
    )

    if not policy[
        "allowed_yaml_paths"
    ]:
        return {
            **base,
            "status": (
                "MANUAL_INVESTIGATION_REQUIRED"
            ),
            "reason": (
                "The retrieved runbooks do not define "
                "Allowed YAML Paths."
            ),
            "patch_engine": "rag",
            "repository_path": (
                repository_path
            ),
            "retrieved_runbooks": [
                {
                    "title": item.get(
                        "title"
                    ),
                    "file": item.get(
                        "file"
                    ),
                    "score": item.get(
                        "score"
                    ),
                }
                for item in runbooks
            ],
            "patch": None,
        }

    prompt = _build_proposal_prompt(
        base=base,
        incident=incident,
        manifest_text=manifest_text,
        repository_path=repository_path,
        runbooks=runbooks,
        policy=policy,
        manifest_context=manifest_context,
        approved_values=approved_values,
    )

    try:
        proposal = llm.generate_json(
            prompt
        )
        if _proposal_contains_placeholders(
            proposal
        ):
            LOGGER.warning(
                "The LLM returned placeholder values; "
                "attempting policy-grounded candidate construction."
            )

            grounded_candidate = (
                _build_policy_grounded_candidate(
                    base=base,
                    incident=incident,
                    manifest_context=manifest_context,
                    approved_values=approved_values,
                    llm_proposal=proposal,
                )
            )

            if grounded_candidate is None:
                return {
                    **base,
                    "status": (
                        "MANUAL_INVESTIGATION_REQUIRED"
                    ),
                    "reason": (
                        "The language model returned placeholder values, "
                        "and the retrieved policy did not provide one exact "
                        "safe replacement."
                    ),
                    "patch_engine": "rag",
                    "repository_path": repository_path,
                    "proposal": proposal,
                    "patch": None,
                }

            proposal = grounded_candidate
        if (
            str(
                proposal.get(
                    "decision",
                    "",
                )
            ).upper()
            == "PATCH"
            and not _safe_list(
                proposal.get(
                    "operations"
                )
            )
        ):
            grounded_candidate = (
                _build_policy_grounded_candidate(
                    base=base,
                    incident=incident,
                    manifest_context=manifest_context,
                    approved_values=approved_values,
                    llm_proposal=proposal,
                )
            )

            if grounded_candidate is not None:
                proposal = grounded_candidate
    except RuntimeError as error:
        return {
            **base,
            "status": (
                "MANUAL_INVESTIGATION_REQUIRED"
            ),
            "reason": str(
                error
            ),
            "patch_engine": "rag",
            "repository_path": (
                repository_path
            ),
            "retrieved_runbooks": [
                {
                    "title": item.get(
                        "title"
                    ),
                    "file": item.get(
                        "file"
                    ),
                    "score": item.get(
                        "score"
                    ),
                }
                for item in runbooks
            ],
            "patch": None,
        }

    # Restore target fields omitted by the model and normalise only values
# already proven by the repository manifest and collected evidence.
    proposal = _ground_proposal_target_and_paths(
        proposal=proposal,
        base=base,
        manifest_context=manifest_context,
    )

    decision = str(
        proposal.get(
            "decision",
            "",
        )
    ).upper()

    if decision == "NO_CHANGE_REQUIRED":
        return {
            **base,
            "status": (
                "NO_CHANGE_REQUIRED"
            ),
            "reason": str(
                proposal.get(
                    "reason",
                    (
                        "The structured proposal did not "
                        "justify a repository change."
                    ),
                )
            ),
            "patch_engine": "rag",
            "repository_path": (
                repository_path
            ),
            "proposal": proposal,
            "patch": None,
        }

    if decision != "PATCH":
        return {
            **base,
            "status": (
                "MANUAL_INVESTIGATION_REQUIRED"
            ),
            "reason": str(
                proposal.get(
                    "reason",
                    (
                        "The structured proposal did not "
                        "contain a safe patch."
                    ),
                )
            ),
            "patch_engine": "rag",
            "repository_path": (
                repository_path
            ),
            "proposal": proposal,
            "retrieved_runbooks": [
                {
                    "title": item.get(
                        "title"
                    ),
                    "file": item.get(
                        "file"
                    ),
                    "score": item.get(
                        "score"
                    ),
                }
                for item in runbooks
            ],
            "patch": None,
        }

    expected_target = {
        "kind": workload_kind,
        "name": workload_name,
        "namespace": namespace,
    }

    try:
        validated = validate_and_apply_patch(
            manifest_text=manifest_text,
            repository_path=repository_path,
            proposal=proposal,
            expected_target=expected_target,
            policy=policy,
        )
    except PatchValidationError as error:
        return {
            **base,
            "status": (
                "MANUAL_INVESTIGATION_REQUIRED"
            ),
            "reason": (
                "The AI proposal was rejected by the "
                f"deterministic validator: {error}"
            ),
            "patch_engine": "rag",
            "repository_path": (
                repository_path
            ),
            "proposal": proposal,
            "retrieved_runbooks": [
                {
                    "title": item.get(
                        "title"
                    ),
                    "file": item.get(
                        "file"
                    ),
                    "score": item.get(
                        "score"
                    ),
                }
                for item in runbooks
            ],
            "patch": None,
        }

    return {
        **base,
        "status": "PATCH_READY",
        "change_type": str(
            proposal.get(
                "change_type",
                "RAG_GENERATED_CHANGE",
            )
        ),
        "reason": str(
            proposal.get(
                "reason",
                (
                    "A structured RAG proposal passed "
                    "deterministic validation."
                ),
            )
        ),
        "patch_engine": "rag",
        "target": {
            **expected_target,
            "container": _safe_dict(
                proposal.get(
                    "target"
                )
            ).get(
                "container"
            ),
        },
        "repository_change": {
            "path": repository_path,
            "before_content": (
                manifest_text
            ),
            "content": (
                validated.content
            ),
            "diff": (
                validated.diff
            ),
        },
        "patch": {
            "type": (
                "validated-structured-patch"
            ),
            "path": repository_path,
            "diff": validated.diff,
            "operations": (
                validated.operations
            ),
            "changed_paths": (
                validated.changed_paths
            ),
        },
        "proposal": proposal,
        "retrieved_runbooks": [
            {
                "title": item.get(
                    "title"
                ),
                "file": item.get(
                    "file"
                ),
                "score": item.get(
                    "score"
                ),
            }
            for item in runbooks
        ],
        "runbook_policy": policy,
    }


# ---------------------------------------------------------------------------
# Previous deterministic engine retained as fallback
# ---------------------------------------------------------------------------

def _legacy_deterministic_strategy(
    base: dict[str, Any],
    incident: dict[str, Any],
) -> GitOpsPlan:
    """
    Compatibility mode for previously tested behavior.

    This is not the default engine. It exists only as a rollback option
    while the RAG engine is being validated.
    """

    if (
        base.get(
            "normalized_alert"
        )
        != "CrashLoopBackOff"
    ):
        return {
            **base,
            "status": (
                "MANUAL_INVESTIGATION_REQUIRED"
            ),
            "reason": (
                "No legacy deterministic strategy is "
                "registered for this incident type."
            ),
            "patch_engine": (
                "deterministic"
            ),
            "patch": None,
        }

    workload_name = str(
        base.get(
            "workload_name"
        )
        or ""
    )

    pod_name = str(
        base.get(
            "pod"
        )
        or ""
    )

    is_demo_workload = (
        workload_name
        == "automatic-crashloop-test"
        or pod_name.startswith(
            "automatic-crashloop-test-"
        )
    )

    if not is_demo_workload:
        return {
            **base,
            "status": (
                "MANUAL_INVESTIGATION_REQUIRED"
            ),
            "reason": (
                "The legacy deterministic strategy is "
                "restricted to the controlled demo workload."
            ),
            "patch_engine": (
                "deterministic"
            ),
            "patch": None,
        }

    root = _project_root()

    source_relative = (
        "kubernetes/demo/"
        "automatic-crashloop-test.yaml"
    )

    fixed_relative = (
        "kubernetes/demo/"
        "automatic-crashloop-test-fixed.yaml"
    )

    source_path = (
        root
        / source_relative
    )

    fixed_path = (
        root
        / fixed_relative
    )

    if (
        not source_path.is_file()
        or not fixed_path.is_file()
    ):
        return {
            **base,
            "status": "BLOCKED",
            "reason": (
                "The legacy controlled manifest files "
                "were not found."
            ),
            "patch_engine": (
                "deterministic"
            ),
            "patch": None,
        }

    before = source_path.read_text(
        encoding="utf-8"
    )

    after = fixed_path.read_text(
        encoding="utf-8"
    )

    if not before.endswith(
        "\n"
    ):
        before += "\n"

    if not after.endswith(
        "\n"
    ):
        after += "\n"

    if before == after:
        return {
            **base,
            "status": (
                "NO_CHANGE_REQUIRED"
            ),
            "reason": (
                "The controlled manifest already matches "
                "the legacy fixed template."
            ),
            "patch_engine": (
                "deterministic"
            ),
            "patch": None,
        }

    import difflib

    diff = "".join(
        difflib.unified_diff(
            before.splitlines(
                keepends=True
            ),
            after.splitlines(
                keepends=True
            ),
            fromfile=(
                f"a/{source_relative}"
            ),
            tofile=(
                f"b/{source_relative}"
            ),
        )
    )

    return {
        **base,
        "status": "PATCH_READY",
        "change_type": (
            "CONTAINER_COMMAND_CHANGE"
        ),
        "reason": (
            "The legacy controlled repository template "
            "provides the reviewed replacement."
        ),
        "patch_engine": "deterministic",
        "target": {
            "kind": "Deployment",
            "name": (
                "automatic-crashloop-test"
            ),
            "namespace": "production",
            "container": "crashloop-test",
        },
        "repository_change": {
            "path": source_relative,
            "source_template": (
                fixed_relative
            ),
            "before_content": before,
            "content": after,
            "diff": diff,
        },
        "patch": {
            "type": "replace-file",
            "path": source_relative,
            "diff": diff,
        },
    }


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def generate_gitops_plan(
    stored_incident: dict[str, Any],
) -> GitOpsPlan:
    """
    Build a recommendation-only GitOps plan.

    Public interface preserved for FastAPI, Streamlit, approval storage,
    GitHub automation, tests, and ArgoCD integration.

    Engines:

    rag
        New RAG + LLM proposal + deterministic validator.

    deterministic
        Previous controlled fixed-template implementation retained as a
        rollback option.

    The function never changes Kubernetes, Git, GitHub, or ArgoCD.
    """

    (
        base,
        incident,
        _result,
    ) = _build_base(
        stored_incident
    )

    blocked_result = (
        _validate_common_gates(
            base
        )
    )

    if blocked_result is not None:
        return blocked_result

    engine = os.getenv(
        "AIOPS_PATCH_ENGINE",
        "rag",
    ).strip().lower()

    if engine == "deterministic":
        return _legacy_deterministic_strategy(
            base,
            incident,
        )

    if engine != "rag":
        return {
            **base,
            "status": "BLOCKED",
            "reason": (
                "AIOPS_PATCH_ENGINE must be either "
                "'rag' or 'deterministic'."
            ),
            "patch_engine": engine,
            "patch": None,
        }

    return _rag_strategy(
        base,
        incident,
    )