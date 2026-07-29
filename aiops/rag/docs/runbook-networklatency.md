# HighLatency

## Symptoms

- Slow response times

## Root Cause

Backend bottleneck or network congestion.

## Fix

- Identify slow dependencies
- Optimize queries

## Prevention

- Performance monitoring
- Capacity planning

<!-- AIOPS_GITOPS_POLICY_START -->

## GitOps Remediation Policy

The runbook supplies reviewed operational guidance. It does not authorize
execution. The language model may propose a candidate change, but deterministic
Python validation and human approval remain mandatory.

When the required replacement value is unavailable or ambiguous, return
`MANUAL_INVESTIGATION_REQUIRED`.

## Allowed Changes

- Correct a verified service endpoint, port, timeout, or probe timeout only when the intended value is explicitly supported.

## Forbidden Changes

- Do not invent network addresses or timeouts.
- Do not disable probes, TLS, network policy, or authentication.

## Required Evidence

- Latency history.
- Application logs or traces.
- Current service and workload configuration.
- Verified replacement value.

## Allowed YAML Paths

- /spec/template/spec/containers/{container}/env
- /spec/template/spec/containers/{container}/readinessProbe/timeoutSeconds
- /spec/template/spec/containers/{container}/livenessProbe/timeoutSeconds

## Patch Constraints

- Maximum one YAML operation.

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
