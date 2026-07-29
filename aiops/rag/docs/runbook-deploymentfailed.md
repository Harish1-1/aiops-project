# DeploymentFailed

## Symptoms

- Deployment unavailable
- Readiness probe failures

## Root Cause

Application not becoming healthy.

## Fix

- Review readiness probe
- Check startup logs

## Prevention

- Pre-deployment validation
- Health checks

<!-- AIOPS_GITOPS_POLICY_START -->

## GitOps Remediation Policy

The runbook supplies reviewed operational guidance. It does not authorize
execution. The language model may propose a candidate change, but deterministic
Python validation and human approval remain mandatory.

When the required replacement value is unavailable or ambiguous, return
`MANUAL_INVESTIGATION_REQUIRED`.

## Allowed Changes

- Correct a proven manifest configuration defect.
- Restore a repository value from a verified known-good Git revision.
- Correct a confirmed probe, command, argument, image, or resource field when the exact replacement is supported.

## Forbidden Changes

- Do not invent a rollback revision.
- Do not delete the workload.
- Do not change selectors or identity.

## Required Evidence

- Deployment rollout failure evidence.
- Current and previous rollout information.
- Current repository manifest.
- Verified known-good value or revision.

## Allowed YAML Paths

- /spec/template/spec/containers/{container}/command
- /spec/template/spec/containers/{container}/args
- /spec/template/spec/containers/{container}/image
- /spec/template/spec/containers/{container}/resources
- /spec/template/spec/containers/{container}/startupProbe
- /spec/template/spec/containers/{container}/livenessProbe
- /spec/template/spec/containers/{container}/readinessProbe

## Patch Constraints

- Maximum three YAML operations.
- Every replacement value must be verified.

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
