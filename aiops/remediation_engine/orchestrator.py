from __future__ import annotations

from pathlib import Path
from typing import Any

from .evidence_resolver import EvidenceProvider, EvidenceResolutionError
from .models import RemediationResult, Target
from .operation_builder import OperationBuildError, build_operations
from .policy_parser import PolicyError, load_policy_directory
from .root_cause import resolve_root_cause
from .runbook_selector import select_policy
from .validator import EngineValidationError, validate_operations


def generate_plan(
    incident: dict[str, Any],
    manifest: dict[str, Any],
    target: Target,
    provider: EvidenceProvider,
    policy_directory: Path,
) -> RemediationResult:
    root_cause = resolve_root_cause(incident)
    try:
        policies = load_policy_directory(policy_directory)
        policy = select_policy(root_cause, policies)
        if policy is None:
            return RemediationResult("BLOCKED", root_cause, "No policy matches the resolved root cause.", target)
        if policy.decision == "NO_GITOPS_CHANGE":
            return RemediationResult("NO_GITOPS_CHANGE", root_cause, policy.reason, target, policy_id=policy.policy_id)
        operations = build_operations(manifest, target, policy.operations, provider)
        validate_operations(manifest, target, operations)
        if not operations:
            return RemediationResult("NO_GITOPS_CHANGE", root_cause, "Authoritative state already matches the policy-derived state.", target, policy_id=policy.policy_id)
        return RemediationResult("PATCH", root_cause, policy.reason or "Patch derived from authoritative evidence.", target, operations, policy.policy_id)
    except (PolicyError, EvidenceResolutionError, OperationBuildError, EngineValidationError) as exc:
        return RemediationResult("BLOCKED", root_cause, str(exc), target, diagnostics=(type(exc).__name__,))
