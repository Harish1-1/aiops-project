# DNSResolutionFailure

## Symptoms

- Service lookup failures

## Root Cause

CoreDNS issue or invalid service name.

## Fix

- Verify service DNS
- Restart CoreDNS

## Prevention

- DNS monitoring
- Service validation

<!-- AIOPS_GITOPS_POLICY_START -->

## GitOps Remediation Policy

The runbook supplies reviewed operational guidance. It does not authorize
execution. The language model may propose a candidate change, but deterministic
Python validation and human approval remain mandatory.

When the required replacement value is unavailable or ambiguous, return
`MANUAL_INVESTIGATION_REQUIRED`.

## Allowed Changes

- Correct an application hostname or service reference only when the intended value is verified.
- Correct dnsPolicy or dnsConfig only when a repository policy explicitly defines the replacement.

## Forbidden Changes

- Do not modify cluster DNS infrastructure.
- Do not invent hostnames, IP addresses, or nameservers.

## Required Evidence

- DNS resolution errors.
- Current workload DNS configuration.
- Verified service or hostname.

## Allowed YAML Paths

- /spec/template/spec/dnsPolicy
- /spec/template/spec/dnsConfig
- /spec/template/spec/containers/{container}/env

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
