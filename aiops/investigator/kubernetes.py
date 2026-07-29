from __future__ import annotations

import json
import subprocess
from typing import Any


class KubernetesCommandError(RuntimeError):
    """Raised when a kubectl command cannot be executed."""


def run_kubectl(
    arguments: list[str],
    timeout: int = 30,
    allow_failure: bool = False,
) -> str:
    """
    Execute kubectl without using a shell.

    A list of arguments avoids PowerShell quoting problems and reduces
    command-injection risk.
    """

    command = ["kubectl", *arguments]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )

    except FileNotFoundError as exc:
        raise KubernetesCommandError(
            "kubectl was not found in PATH."
        ) from exc

    except subprocess.TimeoutExpired as exc:
        raise KubernetesCommandError(
            f"kubectl command timed out: {' '.join(command)}"
        ) from exc

    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()

    if completed.returncode != 0:
        if allow_failure:
            return ""

        raise KubernetesCommandError(
            stderr
            or (
                "kubectl returned exit code "
                f"{completed.returncode}"
            )
        )

    return stdout


def _load_json(
    output: str,
) -> dict[str, Any] | None:
    if not output:
        return None

    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    return payload


def get_resource_json(
    kind: str,
    name: str,
    namespace: str,
) -> dict[str, Any] | None:
    """
    Retrieve any namespaced Kubernetes resource as JSON.
    """

    output = run_kubectl(
        [
            "get",
            kind,
            name,
            "-n",
            namespace,
            "-o",
            "json",
        ],
        allow_failure=True,
    )

    return _load_json(output)


def get_pod_json(
    namespace: str,
    pod: str,
) -> dict[str, Any] | None:
    return get_resource_json(
        kind="pod",
        name=pod,
        namespace=namespace,
    )


def get_pod_logs(
    namespace: str,
    pod: str,
    previous: bool = False,
    tail: int = 100,
) -> str:
    arguments = [
        "logs",
        pod,
        "-n",
        namespace,
        "--all-containers=true",
        f"--tail={tail}",
        "--timestamps=true",
    ]

    if previous:
        arguments.append("--previous")

    return run_kubectl(
        arguments,
        timeout=45,
        allow_failure=True,
    )


def get_pod_description(
    namespace: str,
    pod: str,
) -> str:
    return run_kubectl(
        [
            "describe",
            "pod",
            pod,
            "-n",
            namespace,
        ],
        timeout=30,
        allow_failure=True,
    )


def get_pod_events(
    namespace: str,
    pod: str,
) -> dict[str, Any]:
    output = run_kubectl(
        [
            "get",
            "events",
            "-n",
            namespace,
            "--field-selector",
            (
                "involvedObject.kind=Pod,"
                f"involvedObject.name={pod}"
            ),
            "--sort-by=.lastTimestamp",
            "-o",
            "json",
        ],
        timeout=30,
        allow_failure=True,
    )

    payload = _load_json(output)

    if payload is None:
        return {"items": []}

    return payload


def get_pod_metrics(
    namespace: str,
    pod: str,
) -> str:
    return run_kubectl(
        [
            "top",
            "pod",
            pod,
            "-n",
            namespace,
            "--no-headers",
        ],
        timeout=20,
        allow_failure=True,
    )


def get_namespace_pods(
    namespace: str,
) -> list[dict[str, Any]]:
    output = run_kubectl(
        [
            "get",
            "pods",
            "-n",
            namespace,
            "-o",
            "json",
        ],
        timeout=30,
        allow_failure=True,
    )

    payload = _load_json(output)

    if payload is None:
        return []

    items = payload.get("items", [])

    return (
        items
        if isinstance(items, list)
        else []
    )


def get_controller_owner(
    resource: dict[str, Any],
) -> dict[str, str] | None:
    """
    Return the managing ownerReference for a Kubernetes resource.
    """

    metadata = resource.get("metadata", {})

    owner_references = metadata.get(
        "ownerReferences",
        [],
    )

    if not isinstance(owner_references, list):
        return None

    for owner in owner_references:
        if not isinstance(owner, dict):
            continue

        if owner.get("controller") is True:
            kind = str(
                owner.get("kind", "")
            ).strip()

            name = str(
                owner.get("name", "")
            ).strip()

            if kind and name:
                return {
                    "kind": kind,
                    "name": name,
                }

    # Fallback when controller=true is unexpectedly absent.
    for owner in owner_references:
        if not isinstance(owner, dict):
            continue

        kind = str(
            owner.get("kind", "")
        ).strip()

        name = str(
            owner.get("name", "")
        ).strip()

        if kind and name:
            return {
                "kind": kind,
                "name": name,
            }

    return None


def resolve_workload_owner(
    namespace: str,
    pod_payload: dict[str, Any],
) -> dict[str, Any]:
    """
    Resolve a Pod to its highest useful workload controller.

    Common ownership paths:

    Pod -> ReplicaSet -> Deployment
    Pod -> StatefulSet
    Pod -> DaemonSet
    Pod -> Job -> CronJob
    """

    pod_name = str(
        pod_payload
        .get("metadata", {})
        .get("name", "unknown")
    )

    ownership_chain: list[dict[str, str]] = [
        {
            "kind": "Pod",
            "name": pod_name,
        }
    ]

    current_resource = pod_payload
    current_owner = get_controller_owner(
        current_resource
    )

    visited: set[tuple[str, str]] = set()

    highest_resource: dict[str, Any] | None = None
    highest_kind = "Pod"
    highest_name = pod_name

    while current_owner is not None:
        owner_kind = current_owner["kind"]
        owner_name = current_owner["name"]

        owner_key = (
            owner_kind.lower(),
            owner_name,
        )

        if owner_key in visited:
            break

        visited.add(owner_key)

        ownership_chain.append(
            {
                "kind": owner_kind,
                "name": owner_name,
            }
        )

        owner_payload = get_resource_json(
            kind=owner_kind.lower(),
            name=owner_name,
            namespace=namespace,
        )

        highest_kind = owner_kind
        highest_name = owner_name

        if owner_payload is None:
            break

        highest_resource = owner_payload

        next_owner = get_controller_owner(
            owner_payload
        )

        if next_owner is None:
            break

        current_resource = owner_payload
        current_owner = next_owner

    return {
        "workload_kind": highest_kind,
        "workload_name": highest_name,
        "ownership_chain": ownership_chain,
        "workload_resource": highest_resource,
    }


def extract_workload_details(
    workload_resource: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Extract exact workload configuration values.

    These values come from Kubernetes and may safely be shown to the
    LLM and deterministic policy engine.
    """

    if workload_resource is None:
        return {
            "desired_replicas": None,
            "available_replicas": None,
            "container_names": [],
            "container_images": [],
            "container_resources": [],
        }

    spec = workload_resource.get(
        "spec",
        {},
    )

    status = workload_resource.get(
        "status",
        {},
    )

    template = spec.get(
        "template",
        {},
    )

    pod_spec = template.get(
        "spec",
        {},
    )

    containers = pod_spec.get(
        "containers",
        [],
    )

    if not isinstance(containers, list):
        containers = []

    container_names: list[str] = []
    container_images: list[str] = []
    container_resources: list[dict[str, Any]] = []

    for container in containers:
        if not isinstance(container, dict):
            continue

        container_name = str(
            container.get("name", "unknown")
        )

        container_image = str(
            container.get("image", "unknown")
        )

        resources = container.get(
            "resources",
            {},
        )

        container_names.append(
            container_name
        )

        container_images.append(
            container_image
        )

        container_resources.append(
            {
                "container": container_name,
                "requests": resources.get(
                    "requests",
                    {},
                ),
                "limits": resources.get(
                    "limits",
                    {},
                ),
            }
        )

    return {
        "desired_replicas": spec.get(
            "replicas"
        ),
        "available_replicas": status.get(
            "availableReplicas"
        ),
        "ready_replicas": status.get(
            "readyReplicas"
        ),
        "updated_replicas": status.get(
            "updatedReplicas"
        ),
        "container_names": container_names,
        "container_images": container_images,
        "container_resources": container_resources,
    }