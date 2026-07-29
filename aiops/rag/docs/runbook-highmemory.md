# HighMemoryUsage

## Symptoms

- Memory above 90%

## Root Cause

Memory leak or large cache.

## Fix

- Increase limits
- Analyze heap usage

## Prevention

- Memory profiling
- Cache optimization

<!-- AIOPS_GITOPS_POLICY_START -->

## GitOps Remediation Policy

The runbook supplies reviewed operational guidance. It does not authorize
execution. The language model may propose a candidate change, but deterministic
Python validation and human approval remain mandatory.

When the required replacement value is unavailable or ambiguous, return
`MANUAL_INVESTIGATION_REQUIRED`.

## Allowed Changes

- Update memory request or memory limit only when sustained pressure is confirmed.

## Forbidden Changes

- Do not change the workload from one instantaneous memory sample.
- Do not invent resource values.
- Do not change CPU, replicas, image, identity, or selectors.

## Required Evidence

- Current Kubernetes resource configuration.
- Prometheus historical memory samples.
- Confirmed threshold breach over the alert evaluation window.
- An approved target resource value.

## Allowed YAML Paths

- /spec/template/spec/containers/{container}/resources/requests/memory
- /spec/template/spec/containers/{container}/resources/limits/memory

## Patch Constraints

- Maximum two YAML operations.
- No change is allowed when current and historical evidence contradict the alert.

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
