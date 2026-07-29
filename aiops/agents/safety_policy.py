from __future__ import annotations

import re
from typing import Any


FORBIDDEN_PATTERNS = {
    r"\bkubectl\s+edit\b":
        "Command 'kubectl edit' is not allowed.",
    r"\bkubectl\s+patch\b":
        "Command 'kubectl patch' is not allowed.",
    r"\bkubectl\s+delete\b":
        "Command 'kubectl delete' is not allowed.",
    r"\bkubectl\s+exec\b":
        "Command 'kubectl exec' is not allowed.",
    r"\bkubectl\s+scale\b":
        "Command 'kubectl scale' is not allowed.",
    r"\bkubectl\s+rollout\s+restart\b":
        "Command 'kubectl rollout restart' is not allowed.",
    r"\bkubectl\s+restart\b":
        "Command 'kubectl restart' is invalid.",
    r"\bheapcheck\b":
        "Unknown tool 'heapcheck' is not allowed.",
    r"\bsolo\s*metrics\b":
        "Unknown tool 'SOLO metrics' is not allowed.",
    r"\bkubectl\s+top\s+network\b":
        "Invalid command 'kubectl top network'.",
}


ALLOWED_ACTIONS = {
    "get",
    "describe",
    "logs",
    "top",
    "rollout",
    "api-resources",
    "api-versions",
    "explain",
}


COMMAND_PATTERN = re.compile(
    r"(?im)^\s*(kubectl\s+[^\n`]+)"
)


NAMESPACE_WIDE_PATTERNS = (
    re.compile(
        r"(?i)^kubectl\s+get\s+pods?\b"
    ),
    re.compile(
        r"(?i)^kubectl\s+get\s+events?\b"
    ),
    re.compile(
        r"(?i)^kubectl\s+top\s+pods?\b"
    ),
    re.compile(
        r"(?i)^kubectl\s+get\s+deployments?\b"
    ),
    re.compile(
        r"(?i)^kubectl\s+get\s+replicasets?\b"
    ),
)


def _extract_commands(
    text: str,
) -> list[str]:
    return [
        command.strip()
        for command in COMMAND_PATTERN.findall(
            text
        )
    ]


def _action(
    command: str,
) -> str | None:
    parts = command.split()

    return (
        parts[1].lower()
        if len(parts) >= 2
        else None
    )


def _has_namespace(
    command: str,
    namespace: str,
) -> bool:
    patterns = (
        rf"(?:^|\s)-n\s+{re.escape(namespace)}(?:\s|$)",
        (
            rf"(?:^|\s)--namespace(?:=|\s+)"
            rf"{re.escape(namespace)}(?:\s|$)"
        ),
    )

    return any(
        re.search(
            pattern,
            command,
            flags=re.IGNORECASE,
        )
        for pattern in patterns
    )


def _is_namespace_wide_command(
    command: str,
) -> bool:
    return any(
        pattern.search(command)
        for pattern in NAMESPACE_WIDE_PATTERNS
    )


def _references_known_target(
    command: str,
    incident: dict[str, Any],
) -> bool:
    normalized = command.lower()

    pod = str(
        incident.get(
            "pod",
            "",
        )
    ).lower()

    workload = str(
        incident.get(
            "workload_name",
            "",
        )
    ).lower()

    workload_kind = str(
        incident.get(
            "workload_kind",
            "",
        )
    ).lower()

    names = {
        pod,
        workload,
        f"pod/{pod}",
        f"deployment/{workload}",
        f"deploy/{workload}",
        f"{workload_kind}/{workload}",
    }

    return any(
        name
        and name in normalized
        for name in names
    )


def _invented_replicas(
    remediation: str,
    incident: dict[str, Any],
) -> bool:
    matches = re.findall(
        r"(?i)\breplicas?\s*[:=]\s*(\d+)",
        remediation,
    )

    if not matches:
        return False

    allowed = {
        str(value)
        for value in (
            incident.get("desired_replicas"),
            incident.get("available_replicas"),
            incident.get("ready_replicas"),
            incident.get("updated_replicas"),
        )
        if value is not None
    }

    return any(
        value not in allowed
        for value in matches
    )


def _invented_image(
    remediation: str,
    incident: dict[str, Any],
) -> bool:
    supplied = {
        str(image).lower()
        for image in incident.get(
            "container_images",
            [],
        )
    }

    candidates = re.findall(
        r"(?i)\bimage\s*:\s*([^\s]+)",
        remediation,
    )

    return any(
        candidate.lower()
        not in supplied
        for candidate in candidates
    )


def check_remediation_policy(
    incident: dict[str, Any],
    remediation: str,
) -> list[str]:
    violations: list[str] = []

    namespace = str(
        incident.get(
            "namespace",
            "default",
        )
    )

    for pattern, message in FORBIDDEN_PATTERNS.items():
        if re.search(
            pattern,
            remediation,
            flags=re.IGNORECASE,
        ):
            violations.append(message)

    for command in _extract_commands(
        remediation
    ):
        action = _action(command)

        if action not in ALLOWED_ACTIONS:
            violations.append(
                (
                    "Unsupported kubectl action "
                    f"'{action or 'unknown'}': {command}"
                )
            )

        if not _has_namespace(
            command,
            namespace,
        ):
            violations.append(
                (
                    "Kubernetes command must include namespace "
                    f"'-n {namespace}': {command}"
                )
            )

        # Listing all pods/events/deployments within a namespace is a
        # valid read-only investigation command and does not need to
        # include one specific workload name.
        if (
            not _is_namespace_wide_command(
                command
            )
            and not _references_known_target(
                command,
                incident,
            )
        ):
            violations.append(
                (
                    "Kubernetes command must reference the known "
                    "pod or workload: "
                    f"{command}"
                )
            )

    if _invented_replicas(
        remediation,
        incident,
    ):
        violations.append(
            "Remediation contains an invented replica count."
        )

    if _invented_image(
        remediation,
        incident,
    ):
        violations.append(
            "Remediation contains an invented image name."
        )

    return list(
        dict.fromkeys(
            violations
        )
    )