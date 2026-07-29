# KafkaBrokerUnavailable

## Symptoms

- Message publish failures
- Leader not available

## Root Cause

Kafka broker unavailable.

## Fix

- Verify broker health
- Check networking

## Prevention

- Kafka monitoring
- Replication and failovers

<!-- AIOPS_GITOPS_POLICY_START -->

## GitOps Remediation Policy

The runbook supplies reviewed operational guidance. It does not authorize
execution. The language model may propose a candidate change, but deterministic
Python validation and human approval remain mandatory.

When the required replacement value is unavailable or ambiguous, return
`MANUAL_INVESTIGATION_REQUIRED`.

## Allowed Changes

- Correct a non-secret broker service reference or port only when the exact replacement is verified.

## Forbidden Changes

- Do not invent broker addresses, credentials, topics, or security settings.
- Do not weaken TLS or authentication.

## Required Evidence

- Kafka client or broker connection error.
- Current workload configuration.
- Verified broker service metadata.

## Allowed YAML Paths

- /spec/template/spec/containers/{container}/env
- /spec/template/spec/containers/{container}/envFrom

## Patch Constraints

- Maximum one YAML operation.
- Security-related fields require manual investigation.

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
