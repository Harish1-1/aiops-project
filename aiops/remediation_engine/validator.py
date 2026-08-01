from __future__ import annotations

import copy
from typing import Any

import yaml

from .models import PatchOperation, Target
from .operation_builder import pointer_get


class EngineValidationError(ValueError):
    pass


def validate_operations(manifest: dict[str, Any], target: Target, operations: tuple[PatchOperation, ...]) -> None:
    metadata = manifest.get("metadata") or {}
    if manifest.get("kind") != target.kind or metadata.get("name") != target.name or metadata.get("namespace", "default") != target.namespace:
        raise EngineValidationError("target does not match repository manifest")
    seen: set[str] = set()
    for operation in operations:
        if operation.path in seen:
            raise EngineValidationError(f"duplicate patch path: {operation.path}")
        seen.add(operation.path)
        exists, current = pointer_get(manifest, operation.path)
        if operation.op == "replace" and not exists:
            raise EngineValidationError(f"replace path does not exist: {operation.path}")
        if operation.op == "replace" and current != operation.before:
            raise EngineValidationError(f"before value mismatch: {operation.path}")
        if operation.op == "add" and exists:
            raise EngineValidationError(f"add path already exists: {operation.path}")
        if operation.path.startswith(("/metadata", "/status", "/spec/selector")):
            raise EngineValidationError(f"immutable or unsafe path: {operation.path}")


def apply_operations(manifest: dict[str, Any], operations: tuple[PatchOperation, ...]) -> dict[str, Any]:
    result = copy.deepcopy(manifest)
    for operation in operations:
        parts = operation.path.lstrip("/").split("/")
        current: Any = result
        for part in parts[:-1]:
            if isinstance(current, list):
                current = current[int(part)]
            else:
                current = current.setdefault(part, {})
        leaf = parts[-1]
        if isinstance(current, list):
            index = int(leaf)
            if operation.op == "remove":
                current.pop(index)
            elif operation.op == "add":
                current.insert(index, operation.value)
            else:
                current[index] = operation.value
        elif operation.op == "remove":
            current.pop(leaf, None)
        else:
            current[leaf] = operation.value
    yaml.safe_dump(result, sort_keys=False)
    return result
