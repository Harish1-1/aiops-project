from __future__ import annotations
from typing import Any
from .evidence_resolver import EvidenceProvider, EvidenceResolutionError, resolve_derived_value
from .models import PatchOperation, Target

class OperationBuildError(ValueError):
    pass

def _decode(segment: str) -> str:
    return segment.replace("~1", "/").replace("~0", "~")

def pointer_get(document: Any, path: str) -> tuple[bool, Any]:
    current = document
    for raw in path.lstrip("/").split("/") if path != "/" else []:
        segment = _decode(raw)
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        elif isinstance(current, list) and segment.isdigit() and int(segment) < len(current):
            current = current[int(segment)]
        else:
            return False, None
    return True, current

def _container_index(manifest: dict[str, Any], target: Target) -> int | None:
    containers = (((manifest.get("spec") or {}).get("template") or {}).get("spec") or {}).get("containers") or []
    if not target.container:
        return None
    matches = [i for i, item in enumerate(containers) if isinstance(item, dict) and item.get("name") == target.container]
    if len(matches) != 1:
        raise OperationBuildError(f"target container must match exactly once: {target.container}")
    return matches[0]

def _expand_path(template: str, target: Target, container_index: int | None) -> str:
    values = {"kind": target.kind, "name": target.name, "namespace": target.namespace, "container": container_index if container_index is not None else ""}
    try:
        path = template.format(**values)
    except KeyError as exc:
        raise OperationBuildError(f"unknown path placeholder: {exc.args[0]}") from exc
    if not path.startswith("/"):
        raise OperationBuildError(f"derived path must be absolute: {path}")
    return path

def build_operations(manifest: dict[str, Any], target: Target, operation_rules: tuple[dict[str, Any], ...], provider: EvidenceProvider) -> tuple[PatchOperation, ...]:
    container_index = _container_index(manifest, target)
    operations: list[PatchOperation] = []
    failures: list[str] = []
    for rule in operation_rules:
        try:
            if rule.get("path_from"):
                path_value = resolve_derived_value(dict(rule["path_from"]), provider, target).value
                path = _expand_path(str(path_value), target, container_index)
            else:
                path = _expand_path(str(rule["path"]), target, container_index)
            exists, before = pointer_get(manifest, path)
            derived = resolve_derived_value(dict(rule["derive"]), provider, target)
            if exists and before == derived.value:
                continue
            op = "replace" if exists else "add"
            if op == "add" and not bool(rule.get("allow_add", False)):
                raise OperationBuildError(f"path is absent and policy does not permit add: {path}")
            operations.append(PatchOperation(op, path, derived.value, before, derived.source))
        except (EvidenceResolutionError, OperationBuildError) as exc:
            if rule.get("optional", False):
                failures.append(str(exc))
                continue
            raise
    if not operations and failures:
        raise OperationBuildError("; ".join(failures))
    return tuple(operations)
