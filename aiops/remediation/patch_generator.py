from __future__ import annotations

"""Policy-driven GitOps patch adapter.

This module preserves the public ``generate_gitops_plan`` API used by FastAPI,
GitHub PR automation, the approval audit, and Argo CD integration. Patch paths
and replacement values are produced by the deterministic remediation engine;
the LLM is not permitted to construct YAML operations.
"""

import difflib
import os
from pathlib import Path
from typing import Any

import yaml

try:
    from remediation.patch_generator_legacy import (
    _build_base,
    _container_names,
    _find_repository_manifest,
    _legacy_deterministic_strategy,
    _project_root,
    _validate_common_gates,
    )
    from remediation_engine.live_evidence import CompositeEvidenceProvider
    from remediation_engine.models import PatchOperation, Target
    from remediation_engine.orchestrator import generate_plan
    from remediation_engine.validator import apply_operations
except ModuleNotFoundError:
    from .patch_generator_legacy import (
        _build_base, _container_names, _find_repository_manifest,
        _legacy_deterministic_strategy, _project_root, _validate_common_gates,
    )
    from ..remediation_engine.live_evidence import CompositeEvidenceProvider
    from ..remediation_engine.models import PatchOperation, Target
    from ..remediation_engine.orchestrator import generate_plan
    from ..remediation_engine.validator import apply_operations

GitOpsPlan = dict[str, Any]


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _manifest_identity(document: dict[str, Any]) -> tuple[str, str, str]:
    metadata = _safe_dict(document.get("metadata"))
    return (
        str(document.get("kind") or ""),
        str(metadata.get("name") or ""),
        str(metadata.get("namespace") or "default"),
    )


def _load_documents(text: str) -> list[Any]:
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise ValueError(f"Repository manifest is invalid YAML: {exc}") from exc
    if not documents:
        raise ValueError("Repository manifest is empty.")
    return documents


def _select_document(
    documents: list[Any], *, kind: str, name: str, namespace: str
) -> tuple[int, dict[str, Any]]:
    matches: list[tuple[int, dict[str, Any]]] = []
    expected = (kind, name, namespace)
    for index, document in enumerate(documents):
        if isinstance(document, dict) and _manifest_identity(document) == expected:
            matches.append((index, document))
    if len(matches) != 1:
        raise ValueError(
            "Repository file must contain exactly one object matching "
            f"{kind}/{name} in namespace {namespace}; found {len(matches)}."
        )
    return matches[0]


def _dump_documents(documents: list[Any]) -> str:
    content = yaml.safe_dump_all(
        documents,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        explicit_start=len(documents) > 1,
    )
    return content if content.endswith("\n") else content + "\n"


def _diff(before: str, after: str, repository_path: str) -> str:
    before = before.replace("\r\n", "\n").replace("\r", "\n")
    after = after.replace("\r\n", "\n").replace("\r", "\n")
    if not before.endswith("\n"):
        before += "\n"
    if not after.endswith("\n"):
        after += "\n"
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{repository_path}",
            tofile=f"b/{repository_path}",
        )
    )


def _operation_dict(operation: PatchOperation) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "op": operation.op,
        "path": operation.path,
        "before": operation.before,
        "source": operation.source,
    }
    if operation.op != "remove":
        payload["value"] = operation.value
        # Compatibility with the previous audit schema.
        payload["after"] = operation.value
    return payload


def _policy_strategy(base: dict[str, Any], incident: dict[str, Any]) -> GitOpsPlan:
    workload_kind = str(base.get("workload_kind") or "")
    workload_name = str(base.get("workload_name") or "")
    namespace = str(base.get("namespace") or "default")

    try:
        manifest_path, manifest_text = _find_repository_manifest(
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
        )
        documents = _load_documents(manifest_text)
        document_index, manifest = _select_document(
            documents,
            kind=workload_kind,
            name=workload_name,
            namespace=namespace,
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        return {
            **base,
            "status": "MANUAL_INVESTIGATION_REQUIRED",
            "reason": str(exc),
            "patch_engine": "policy",
            "patch": None,
        }

    container_names = _container_names(incident)
    container_name = container_names[0] if len(container_names) == 1 else None
    target = Target(workload_kind, workload_name, namespace, container_name)
    provider = CompositeEvidenceProvider(
        incident=incident,
        manifest_path=manifest_path,
        manifest=manifest,
    )
    policy_directory = Path(
        os.getenv(
            "AIOPS_REMEDIATION_POLICY_DIR",
            str(_project_root() / "aiops" / "remediation_policies"),
        )
    ).expanduser().resolve()

    result = generate_plan(
        incident=incident,
        manifest=manifest,
        target=target,
        provider=provider,
        policy_directory=policy_directory,
    )
    common = {
        **base,
        "effective_alert": result.root_cause.name,
        "root_cause_confidence": result.root_cause.confidence,
        "root_cause_evidence": list(result.root_cause.evidence),
        "policy_id": result.policy_id,
        "patch_engine": "policy",
    }

    if result.decision == "NO_GITOPS_CHANGE":
        return {
            **common,
            "status": "NO_CHANGE_REQUIRED",
            "reason": result.reason,
            "target": {
                "kind": target.kind,
                "name": target.name,
                "namespace": target.namespace,
                "container": target.container,
            },
            "patch": None,
        }

    if result.decision != "PATCH":
        return {
            **common,
            "status": "MANUAL_INVESTIGATION_REQUIRED",
            "reason": result.reason,
            "diagnostics": list(result.diagnostics),
            "target": {
                "kind": target.kind,
                "name": target.name,
                "namespace": target.namespace,
                "container": target.container,
            },
            "patch": None,
        }

    modified = apply_operations(manifest, result.operations)
    documents[document_index] = modified
    content = _dump_documents(documents)
    repository_path = str(manifest_path.relative_to(_project_root())).replace("\\", "/")
    unified_diff = _diff(manifest_text, content, repository_path)
    operations = [_operation_dict(item) for item in result.operations]

    if not unified_diff:
        return {
            **common,
            "status": "NO_CHANGE_REQUIRED",
            "reason": "Policy-derived state already matches the repository manifest.",
            "patch": None,
        }

    return {
        **common,
        "status": "PATCH_READY",
        "change_type": f"POLICY_{result.root_cause.name.upper()}_CHANGE",
        "reason": result.reason,
        "target": {
            "kind": target.kind,
            "name": target.name,
            "namespace": target.namespace,
            "container": target.container,
        },
        "repository_change": {
            "path": repository_path,
            "before_content": manifest_text,
            "content": content,
            "diff": unified_diff,
        },
        "patch": {
            "type": "validated-policy-patch",
            "path": repository_path,
            "diff": unified_diff,
            "operations": operations,
            "changed_paths": [item.path for item in result.operations],
        },
        "proposal": {
            "decision": "PATCH",
            "source": "deterministic-policy-engine",
            "policy_id": result.policy_id,
            "operations": operations,
        },
    }


def generate_gitops_plan(stored_incident: dict[str, Any]) -> GitOpsPlan:
    """Build a recommendation-only GitOps plan without mutating external state."""
    base, incident, _result = _build_base(stored_incident)
    blocked = _validate_common_gates(base)
    if blocked is not None:
        return blocked

    engine = os.getenv("AIOPS_PATCH_ENGINE", "policy").strip().lower()
    if engine == "deterministic":
        return _legacy_deterministic_strategy(base, incident)
    if engine == "rag-legacy":
        try:
            from remediation.patch_generator_legacy import _rag_strategy
        except ModuleNotFoundError:
            from .patch_generator_legacy import _rag_strategy
        return _rag_strategy(base, incident)
    if engine != "policy":
        return {
            **base,
            "status": "BLOCKED",
            "reason": "AIOPS_PATCH_ENGINE must be policy, rag-legacy, or deterministic.",
            "patch_engine": engine,
            "patch": None,
        }
    return _policy_strategy(base, incident)
