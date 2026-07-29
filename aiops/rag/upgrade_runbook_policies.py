from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any


RUNBOOK_DIRECTORY = (
    Path(__file__).resolve().parent
    / "docs"
)

BACKUP_DIRECTORY = (
    RUNBOOK_DIRECTORY
    / "_policy_backup"
)

POLICY_START_MARKER = (
    "<!-- AIOPS_GITOPS_POLICY_START -->"
)

POLICY_END_MARKER = (
    "<!-- AIOPS_GITOPS_POLICY_END -->"
)


POLICIES: dict[str, dict[str, Any]] = {
    "runbook-crashloop.md": {
        "allowed_changes": [
            "Update a container command when the correct replacement is explicitly present in approved evidence or this runbook.",
            "Update container arguments when the exact replacement is explicitly supported.",
            "Correct startup, liveness, or readiness probes when probe failure is confirmed.",
            "For the controlled Deployment/automatic-crashloop-test demo only, replace the intentionally failing command with the approved healthy demonstration command.",
        ],
        "forbidden_changes": [
            "Do not invent an application startup command.",
            "Do not change the image unless a verified image value is available.",
            "Do not change replicas, namespace, selectors, Secrets, or ConfigMaps.",
            "Do not apply a generic restart as a permanent fix.",
        ],
        "required_evidence": [
            "CrashLoopBackOff or KubePodCrashLooping alert evidence.",
            "Repeated restart increase or restart back-off events.",
            "Previous container termination reason or non-zero exit code.",
            "Current source-controlled workload manifest.",
            "The exact replacement command, argument, or probe value must exist in approved evidence or policy.",
        ],
        "allowed_yaml_paths": [
            "/spec/template/spec/containers/{container}/command",
            "/spec/template/spec/containers/{container}/args",
            "/spec/template/spec/containers/{container}/startupProbe",
            "/spec/template/spec/containers/{container}/livenessProbe",
            "/spec/template/spec/containers/{container}/readinessProbe",
        ],
        "patch_constraints": [
            "Maximum three YAML operations.",
            "Modify only the affected container.",
            "Preserve image, resources, environment variables, selectors, identity, and replicas unless separately supported.",
            "Controlled demo approved command value: [\"/bin/sh\", \"-c\", \"echo \\\"AIOps remediation applied through GitOps\\\"; while true; do echo \\\"Application is healthy\\\"; sleep 30; done\"].",
            "The controlled demo command is permitted only for Deployment/automatic-crashloop-test in namespace production.",
        ],
    },

    "runbook-oomkilled.md": {
        "allowed_changes": [
            "Update the affected container memory request.",
            "Update the affected container memory limit.",
        ],
        "forbidden_changes": [
            "Do not assume that OOMKilled proves a memory leak.",
            "Do not invent memory values.",
            "Do not change CPU, replicas, image, namespace, selectors, Secrets, or ConfigMaps.",
        ],
        "required_evidence": [
            "Confirmed OOMKilled termination evidence.",
            "Current memory request and limit.",
            "Prometheus memory history covering the incident.",
            "An approved target memory value from policy, repository metadata, or human input.",
        ],
        "allowed_yaml_paths": [
            "/spec/template/spec/containers/{container}/resources/requests/memory",
            "/spec/template/spec/containers/{container}/resources/limits/memory",
        ],
        "patch_constraints": [
            "Maximum two YAML operations.",
            "The proposed value must be explicitly approved and must use valid Kubernetes quantity syntax.",
            "The memory request must not exceed the memory limit.",
        ],
    },

    "runbook-highmemory.md": {
        "allowed_changes": [
            "Update memory request or memory limit only when sustained pressure is confirmed.",
        ],
        "forbidden_changes": [
            "Do not change the workload from one instantaneous memory sample.",
            "Do not invent resource values.",
            "Do not change CPU, replicas, image, identity, or selectors.",
        ],
        "required_evidence": [
            "Current Kubernetes resource configuration.",
            "Prometheus historical memory samples.",
            "Confirmed threshold breach over the alert evaluation window.",
            "An approved target resource value.",
        ],
        "allowed_yaml_paths": [
            "/spec/template/spec/containers/{container}/resources/requests/memory",
            "/spec/template/spec/containers/{container}/resources/limits/memory",
        ],
        "patch_constraints": [
            "Maximum two YAML operations.",
            "No change is allowed when current and historical evidence contradict the alert.",
        ],
    },

    "runbook-highcpu.md": {
        "allowed_changes": [
            "Update the affected container CPU request or limit when sustained CPU pressure is confirmed.",
        ],
        "forbidden_changes": [
            "Do not invent CPU values.",
            "Do not change memory, replicas, image, selectors, or identity.",
        ],
        "required_evidence": [
            "Prometheus CPU history.",
            "Current CPU request and limit.",
            "Confirmed threshold breach.",
            "An approved target CPU value.",
        ],
        "allowed_yaml_paths": [
            "/spec/template/spec/containers/{container}/resources/requests/cpu",
            "/spec/template/spec/containers/{container}/resources/limits/cpu",
        ],
        "patch_constraints": [
            "Maximum two YAML operations.",
            "Use valid Kubernetes CPU quantity syntax.",
        ],
    },

    "runbook-imagepull.md": {
        "allowed_changes": [
            "Correct the affected container image only when the exact approved image exists in Git history, release metadata, registry metadata, or human-approved evidence.",
            "Correct an existing imagePullSecrets reference only when the correct existing reference is proven.",
        ],
        "forbidden_changes": [
            "Do not invent an image repository or tag.",
            "Do not create credentials or Secrets.",
            "Do not change replicas, resources, selectors, or workload identity.",
        ],
        "required_evidence": [
            "ImagePullBackOff or ErrImagePull state.",
            "Registry or kubelet error message.",
            "Current image value.",
            "Verified replacement image or existing imagePullSecrets reference.",
        ],
        "allowed_yaml_paths": [
            "/spec/template/spec/containers/{container}/image",
            "/spec/template/spec/imagePullSecrets",
        ],
        "patch_constraints": [
            "Maximum one image operation or one imagePullSecrets operation.",
            "Replacement image must come from approved evidence.",
        ],
    },

    "runbook-podpending.md": {
        "allowed_changes": [
            "Update requests only when the scheduler evidence identifies an unschedulable resource request and an approved value exists.",
            "Correct an existing nodeSelector, affinity, or toleration only when the intended repository value is proven.",
        ],
        "forbidden_changes": [
            "Do not remove scheduling security controls merely to make the pod run.",
            "Do not invent nodes, labels, tolerations, storage classes, or resource values.",
        ],
        "required_evidence": [
            "PodPending state.",
            "Scheduler events.",
            "Current workload scheduling configuration.",
            "Approved replacement values.",
        ],
        "allowed_yaml_paths": [
            "/spec/template/spec/containers/{container}/resources/requests/cpu",
            "/spec/template/spec/containers/{container}/resources/requests/memory",
            "/spec/template/spec/nodeSelector",
            "/spec/template/spec/affinity",
            "/spec/template/spec/tolerations",
        ],
        "patch_constraints": [
            "Maximum two YAML operations.",
            "Prefer manual investigation when scheduler evidence does not identify a precise configuration defect.",
        ],
    },

    "runbook-secretmissing.md": {
        "allowed_changes": [
            "Correct a Secret reference only when the intended existing Secret name is found in approved repository or cluster evidence.",
        ],
        "forbidden_changes": [
            "Do not create Secret data.",
            "Do not generate, expose, copy, or modify credentials.",
            "Do not invent Secret names or keys.",
        ],
        "required_evidence": [
            "Exact missing Secret or key error.",
            "Current workload manifest.",
            "Verified existing Secret reference.",
        ],
        "allowed_yaml_paths": [
            "/spec/template/spec/containers/{container}/env",
            "/spec/template/spec/containers/{container}/envFrom",
            "/spec/template/spec/volumes",
        ],
        "patch_constraints": [
            "Maximum one YAML operation.",
            "A proposal containing secret values must always be rejected.",
        ],
    },

    "runbook-deploymentfailed.md": {
        "allowed_changes": [
            "Correct a proven manifest configuration defect.",
            "Restore a repository value from a verified known-good Git revision.",
            "Correct a confirmed probe, command, argument, image, or resource field when the exact replacement is supported.",
        ],
        "forbidden_changes": [
            "Do not invent a rollback revision.",
            "Do not delete the workload.",
            "Do not change selectors or identity.",
        ],
        "required_evidence": [
            "Deployment rollout failure evidence.",
            "Current and previous rollout information.",
            "Current repository manifest.",
            "Verified known-good value or revision.",
        ],
        "allowed_yaml_paths": [
            "/spec/template/spec/containers/{container}/command",
            "/spec/template/spec/containers/{container}/args",
            "/spec/template/spec/containers/{container}/image",
            "/spec/template/spec/containers/{container}/resources",
            "/spec/template/spec/containers/{container}/startupProbe",
            "/spec/template/spec/containers/{container}/livenessProbe",
            "/spec/template/spec/containers/{container}/readinessProbe",
        ],
        "patch_constraints": [
            "Maximum three YAML operations.",
            "Every replacement value must be verified.",
        ],
    },

    "runbook-diskpressure.md": {
        "allowed_changes": [
            "Update ephemeral-storage requests or limits only when a workload resource configuration is proven to cause the issue and an approved value exists.",
        ],
        "forbidden_changes": [
            "Do not generate disk-cleanup commands.",
            "Do not modify node configuration.",
            "Do not delete logs, volumes, pods, or data.",
        ],
        "required_evidence": [
            "Node DiskPressure condition.",
            "Filesystem or ephemeral-storage evidence.",
            "Workload resource configuration.",
            "Approved resource value.",
        ],
        "allowed_yaml_paths": [
            "/spec/template/spec/containers/{container}/resources/requests/ephemeral-storage",
            "/spec/template/spec/containers/{container}/resources/limits/ephemeral-storage",
        ],
        "patch_constraints": [
            "Maximum two YAML operations.",
            "Node-level disk pressure normally requires manual investigation.",
        ],
    },

    "runbook-nodedown.md": {
        "allowed_changes": [],
        "forbidden_changes": [
            "Do not patch a workload merely because a node is unavailable.",
            "Do not issue drain, cordon, delete, reboot, or infrastructure commands.",
        ],
        "required_evidence": [
            "Node condition history.",
            "Kubernetes events.",
            "Infrastructure or control-plane evidence.",
        ],
        "allowed_yaml_paths": [],
        "patch_constraints": [
            "Always return MANUAL_INVESTIGATION_REQUIRED unless a separately approved workload scheduling policy exists.",
        ],
    },

    "runbook-databaseconnection.md": {
        "allowed_changes": [
            "Correct a non-secret endpoint, service name, port, or ConfigMap reference only when the exact value is verified.",
        ],
        "forbidden_changes": [
            "Do not generate passwords, connection strings containing credentials, or Secret data.",
            "Do not invent database endpoints or ports.",
        ],
        "required_evidence": [
            "Application connection error.",
            "Current configuration reference.",
            "Verified service or endpoint metadata.",
        ],
        "allowed_yaml_paths": [
            "/spec/template/spec/containers/{container}/env",
            "/spec/template/spec/containers/{container}/envFrom",
        ],
        "patch_constraints": [
            "Maximum one YAML operation.",
            "Any credential-bearing value must be rejected.",
        ],
    },

    "runbook-dnsfailure.md": {
        "allowed_changes": [
            "Correct an application hostname or service reference only when the intended value is verified.",
            "Correct dnsPolicy or dnsConfig only when a repository policy explicitly defines the replacement.",
        ],
        "forbidden_changes": [
            "Do not modify cluster DNS infrastructure.",
            "Do not invent hostnames, IP addresses, or nameservers.",
        ],
        "required_evidence": [
            "DNS resolution errors.",
            "Current workload DNS configuration.",
            "Verified service or hostname.",
        ],
        "allowed_yaml_paths": [
            "/spec/template/spec/dnsPolicy",
            "/spec/template/spec/dnsConfig",
            "/spec/template/spec/containers/{container}/env",
        ],
        "patch_constraints": [
            "Maximum one YAML operation.",
        ],
    },

    "runbook-kafkafailure.md": {
        "allowed_changes": [
            "Correct a non-secret broker service reference or port only when the exact replacement is verified.",
        ],
        "forbidden_changes": [
            "Do not invent broker addresses, credentials, topics, or security settings.",
            "Do not weaken TLS or authentication.",
        ],
        "required_evidence": [
            "Kafka client or broker connection error.",
            "Current workload configuration.",
            "Verified broker service metadata.",
        ],
        "allowed_yaml_paths": [
            "/spec/template/spec/containers/{container}/env",
            "/spec/template/spec/containers/{container}/envFrom",
        ],
        "patch_constraints": [
            "Maximum one YAML operation.",
            "Security-related fields require manual investigation.",
        ],
    },

    "runbook-networklatency.md": {
        "allowed_changes": [
            "Correct a verified service endpoint, port, timeout, or probe timeout only when the intended value is explicitly supported.",
        ],
        "forbidden_changes": [
            "Do not invent network addresses or timeouts.",
            "Do not disable probes, TLS, network policy, or authentication.",
        ],
        "required_evidence": [
            "Latency history.",
            "Application logs or traces.",
            "Current service and workload configuration.",
            "Verified replacement value.",
        ],
        "allowed_yaml_paths": [
            "/spec/template/spec/containers/{container}/env",
            "/spec/template/spec/containers/{container}/readinessProbe/timeoutSeconds",
            "/spec/template/spec/containers/{container}/livenessProbe/timeoutSeconds",
        ],
        "patch_constraints": [
            "Maximum one YAML operation.",
        ],
    },

    "runbook-certificatexpired.md": {
        "allowed_changes": [
            "Correct a certificate Secret reference only when the replacement existing Secret is verified.",
            "Correct a certificate file path only when the approved repository value is known.",
        ],
        "forbidden_changes": [
            "Do not generate certificates or private keys.",
            "Do not place certificate or key material in Git.",
            "Do not disable TLS verification.",
        ],
        "required_evidence": [
            "Certificate expiration or validation error.",
            "Current certificate reference.",
            "Verified replacement Secret or path.",
        ],
        "allowed_yaml_paths": [
            "/spec/template/spec/containers/{container}/env",
            "/spec/template/spec/containers/{container}/volumeMounts",
            "/spec/template/spec/volumes",
        ],
        "patch_constraints": [
            "Maximum one YAML operation.",
            "Any private-key content must be rejected.",
        ],
    },
}


def _render_list(
    values: list[str],
) -> str:
    if not values:
        return (
            "- No automatic GitOps modification is approved "
            "for this incident type."
        )

    return "\n".join(
        f"- {value}"
        for value in values
    )


def _render_policy(
    policy: dict[str, Any],
) -> str:
    return f"""
{POLICY_START_MARKER}

## GitOps Remediation Policy

The runbook supplies reviewed operational guidance. It does not authorize
execution. The language model may propose a candidate change, but deterministic
Python validation and human approval remain mandatory.

When the required replacement value is unavailable or ambiguous, return
`MANUAL_INVESTIGATION_REQUIRED`.

## Allowed Changes

{_render_list(policy["allowed_changes"])}

## Forbidden Changes

{_render_list(policy["forbidden_changes"])}

## Required Evidence

{_render_list(policy["required_evidence"])}

## Allowed YAML Paths

{_render_list(policy["allowed_yaml_paths"])}

## Patch Constraints

{_render_list(policy["patch_constraints"])}

## Validation Requirements

- The affected kind, workload name, namespace, and container must match collected evidence.
- Every `before` value must exactly match the source-controlled manifest.
- Only paths listed under Allowed YAML Paths may be modified.
- The generated Kubernetes YAML must remain valid.
- Protected identity and selector fields must remain unchanged.
- The proposal must not contain direct Kubernetes, Git, GitHub, Helm, or ArgoCD execution commands.
- Deterministic incident validation must pass.
- Human approval must be recorded.
- GitHub and ArgoCD actions remain disabled unless explicitly configured.

## Rollback Policy

Revert the merged Git commit or pull request through the GitOps repository.
Allow ArgoCD to synchronize the previous known-good revision, then repeat the
same Kubernetes, Prometheus, Loki, readiness, restart, and event verification.
No Git revision may be invented.

{POLICY_END_MARKER}
""".strip()


def _remove_existing_generated_policy(
    content: str,
) -> str:
    start = content.find(
        POLICY_START_MARKER
    )

    end = content.find(
        POLICY_END_MARKER
    )

    if (
        start == -1
        and end == -1
    ):
        return content.rstrip()

    if (
        start == -1
        or end == -1
        or end < start
    ):
        raise ValueError(
            "A runbook contains an incomplete generated policy block."
        )

    end += len(
        POLICY_END_MARKER
    )

    combined = (
        content[:start].rstrip()
        + "\n"
        + content[end:].lstrip()
    )

    return combined.strip()


def upgrade_runbook(
    path: Path,
    policy: dict[str, Any],
) -> None:
    original = path.read_text(
        encoding="utf-8"
    )

    BACKUP_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    backup = (
        BACKUP_DIRECTORY
        / path.name
    )

    if not backup.exists():
        shutil.copy2(
            path,
            backup,
        )

    preserved = (
        _remove_existing_generated_policy(
            original
        )
    )

    updated = (
        preserved
        + "\n\n"
        + _render_policy(
            policy
        )
        + "\n"
    )

    path.write_text(
        updated,
        encoding="utf-8",
        newline="\n",
    )

    print(
        f"UPDATED: {path.name}"
    )


def main() -> None:
    if not RUNBOOK_DIRECTORY.is_dir():
        raise FileNotFoundError(
            f"Runbook directory was not found: {RUNBOOK_DIRECTORY}"
        )

    actual_files = {
        path.name
        for path in RUNBOOK_DIRECTORY.glob(
            "runbook-*.md"
        )
    }

    configured_files = set(
        POLICIES
    )

    missing_policies = (
        actual_files
        - configured_files
    )

    missing_files = (
        configured_files
        - actual_files
    )

    if missing_policies:
        raise RuntimeError(
            "Policy configuration is missing for: "
            f"{sorted(missing_policies)}"
        )

    if missing_files:
        raise RuntimeError(
            "Configured runbook files were not found: "
            f"{sorted(missing_files)}"
        )

    for filename in sorted(
        POLICIES
    ):
        upgrade_runbook(
            RUNBOOK_DIRECTORY
            / filename,
            POLICIES[filename],
        )

    print()
    print(
        f"Successfully upgraded {len(POLICIES)} runbooks."
    )
    print(
        f"Original backups: {BACKUP_DIRECTORY}"
    )


if __name__ == "__main__":
    main()