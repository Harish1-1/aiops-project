# CrashLoopBackOff

## Symptoms

- Pod repeatedly restarting
- CrashLoopBackOff status

## Root Cause

Application startup failure.

## Fix

- Check logs
- Validate environment variables
- Verify database connectivity

## Prevention

- Add startup checks
- Improve application validation

<!-- AIOPS_GITOPS_POLICY_START -->

## GitOps Remediation Policy

The runbook supplies reviewed operational guidance. It does not authorize
execution. The language model may propose a candidate change, but deterministic
Python validation and human approval remain mandatory.

When the required replacement value is unavailable or ambiguous, return
`MANUAL_INVESTIGATION_REQUIRED`.

## Allowed Changes

- Update a container command when the correct replacement is explicitly present in approved evidence or this runbook.
- Update container arguments when the exact replacement is explicitly supported.
- Correct startup, liveness, or readiness probes when probe failure is confirmed.
- For the controlled Deployment/automatic-crashloop-test demo only, replace the intentionally failing command with the approved healthy demonstration command.

## Forbidden Changes

- Do not invent an application startup command.
- Do not change the image unless a verified image value is available.
- Do not change replicas, namespace, selectors, Secrets, or ConfigMaps.
- Do not apply a generic restart as a permanent fix.

## Required Evidence

- CrashLoopBackOff or KubePodCrashLooping alert evidence.
- Repeated restart increase or restart back-off events.
- Previous container termination reason or non-zero exit code.
- Current source-controlled workload manifest.
- The exact replacement command, argument, or probe value must exist in approved evidence or policy.

## Allowed YAML Paths

- /spec/template/spec/containers/{container}/command
- /spec/template/spec/containers/{container}/args
- /spec/template/spec/containers/{container}/startupProbe
- /spec/template/spec/containers/{container}/livenessProbe
- /spec/template/spec/containers/{container}/readinessProbe

## Patch Constraints

- Maximum three YAML operations.
- Modify only the affected container.
- Preserve image, resources, environment variables, selectors, identity, and replicas unless separately supported.
- Controlled demo approved command value: ["/bin/sh", "-c", "echo \"AIOps remediation applied through GitOps\"; while true; do echo \"Application is healthy\"; sleep 30; done"].
- The controlled demo command is permitted only for Deployment/automatic-crashloop-test in namespace production.

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
