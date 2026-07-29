# HighCPUUsage

## Symptoms

- CPU above 90%
- Increased response time

## Root Cause

Traffic spike or inefficient application code.

## Fix

- Scale application
- Optimize CPU-intensive operations

## Prevention

- HPA
- Load testing

<!-- AIOPS_GITOPS_POLICY_START -->

## GitOps Remediation Policy

The runbook supplies reviewed operational guidance. It does not authorize
execution. The language model may propose a candidate change, but deterministic
Python validation and human approval remain mandatory.

When the required replacement value is unavailable or ambiguous, return
`MANUAL_INVESTIGATION_REQUIRED`.

## Allowed Changes

- Update the affected container CPU request or limit when sustained CPU pressure is confirmed.

## Forbidden Changes

- Do not invent CPU values.
- Do not change memory, replicas, image, selectors, or identity.

## Required Evidence

- Prometheus CPU history.
- Current CPU request and limit.
- Confirmed threshold breach.
- An approved target CPU value.

## Allowed YAML Paths

- /spec/template/spec/containers/{container}/resources/requests/cpu
- /spec/template/spec/containers/{container}/resources/limits/cpu

## Patch Constraints

- Maximum two YAML operations.
- Use valid Kubernetes CPU quantity syntax.

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
