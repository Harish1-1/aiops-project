# OOMKilled

## Symptoms

- Container restarted
- OOMKilled event
- Memory usage above 95%

## Root Cause

Container exceeded memory limit.

## Fix

- Increase memory limits
- Investigate memory leak

## Prevention

- Set proper resource limits
- Monitor memory growth

<!-- AIOPS_GITOPS_POLICY_START -->

## GitOps Remediation Policy

The runbook supplies reviewed operational guidance. It does not authorize
execution. The language model may propose a candidate change, but deterministic
Python validation and human approval remain mandatory.

When the required replacement value is unavailable or ambiguous, return
`MANUAL_INVESTIGATION_REQUIRED`.

## Allowed Changes

- Update the affected container memory request.
- Update the affected container memory limit.

## Forbidden Changes

- Do not assume that OOMKilled proves a memory leak.
- Do not invent memory values.
- Do not change CPU, replicas, image, namespace, selectors, Secrets, or ConfigMaps.

## Required Evidence

- Confirmed OOMKilled termination evidence.
- Current memory request and limit.
- Prometheus memory history covering the incident.
- An approved target memory value from policy, repository metadata, or human input.

## Allowed YAML Paths

- /spec/template/spec/containers/{container}/resources/requests/memory
- /spec/template/spec/containers/{container}/resources/limits/memory

## Patch Constraints

- Maximum two YAML operations.
- The proposed value must be explicitly approved and must use valid Kubernetes quantity syntax.
- The memory request must not exceed the memory limit.

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
