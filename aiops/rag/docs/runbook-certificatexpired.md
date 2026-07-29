# CertificateExpired

## Symptoms

- TLS handshake failures

## Root Cause

Expired certificate.

## Fix

- Renew certificate
- Restart application

## Prevention

- Certificate expiry monitoring
- Automated renewal

<!-- AIOPS_GITOPS_POLICY_START -->

## GitOps Remediation Policy

The runbook supplies reviewed operational guidance. It does not authorize
execution. The language model may propose a candidate change, but deterministic
Python validation and human approval remain mandatory.

When the required replacement value is unavailable or ambiguous, return
`MANUAL_INVESTIGATION_REQUIRED`.

## Allowed Changes

- Correct a certificate Secret reference only when the replacement existing Secret is verified.
- Correct a certificate file path only when the approved repository value is known.

## Forbidden Changes

- Do not generate certificates or private keys.
- Do not place certificate or key material in Git.
- Do not disable TLS verification.

## Required Evidence

- Certificate expiration or validation error.
- Current certificate reference.
- Verified replacement Secret or path.

## Allowed YAML Paths

- /spec/template/spec/containers/{container}/env
- /spec/template/spec/containers/{container}/volumeMounts
- /spec/template/spec/volumes

## Patch Constraints

- Maximum one YAML operation.
- Any private-key content must be rejected.

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
