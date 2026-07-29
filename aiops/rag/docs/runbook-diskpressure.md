# DiskPressure

## Symptoms

- Node disk usage above 90%

## Root Cause

Storage exhaustion.

## Fix

- Clean unused data
- Expand storage

## Prevention

- Storage monitoring
- Retention policies

<!-- AIOPS_GITOPS_POLICY_START -->

## GitOps Remediation Policy

The runbook supplies reviewed operational guidance. It does not authorize
execution. The language model may propose a candidate change, but deterministic
Python validation and human approval remain mandatory.

When the required replacement value is unavailable or ambiguous, return
`MANUAL_INVESTIGATION_REQUIRED`.

## Allowed Changes

- Update ephemeral-storage requests or limits only when a workload resource configuration is proven to cause the issue and an approved value exists.

## Forbidden Changes

- Do not generate disk-cleanup commands.
- Do not modify node configuration.
- Do not delete logs, volumes, pods, or data.

## Required Evidence

- Node DiskPressure condition.
- Filesystem or ephemeral-storage evidence.
- Workload resource configuration.
- Approved resource value.

## Allowed YAML Paths

- /spec/template/spec/containers/{container}/resources/requests/ephemeral-storage
- /spec/template/spec/containers/{container}/resources/limits/ephemeral-storage

## Patch Constraints

- Maximum two YAML operations.
- Node-level disk pressure normally requires manual investigation.

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

<!-- AIOPS_GITOPS_POLICY_END -->
