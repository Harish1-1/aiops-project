from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import yaml

class PolicyError(ValueError):
    pass

@dataclass(frozen=True)
class Policy:
    policy_id: str
    root_cause: str
    decision: str
    operations: tuple[dict[str, Any], ...]
    reason: str
    raw: dict[str, Any]

def load_policy(path: Path) -> Policy:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise PolicyError(f"Policy must be a mapping: {path}")
    policy_id = str(data.get("id") or path.stem).strip()
    root_cause = str(data.get("root_cause") or "").strip()
    decision = str(data.get("decision") or "PATCH").strip().upper()
    operations = data.get("operations") or []
    reason = str(data.get("reason") or "").strip()
    if not policy_id or not root_cause:
        raise PolicyError(f"Policy id and root_cause are required: {path}")
    if decision not in {"PATCH", "NO_GITOPS_CHANGE"}:
        raise PolicyError(f"Unsupported decision {decision!r}: {path}")
    if not isinstance(operations, list):
        raise PolicyError(f"operations must be a list: {path}")
    if decision == "PATCH" and not operations:
        raise PolicyError(f"PATCH policy must declare operations: {path}")
    for index, operation in enumerate(operations):
        if not isinstance(operation, dict):
            raise PolicyError(f"operation {index} must be a mapping: {path}")
        fixed_path = operation.get("path")
        path_from = operation.get("path_from")
        if bool(fixed_path) == bool(path_from):
            raise PolicyError(f"operation {index} needs exactly one of path or path_from: {path}")
        if fixed_path and not str(fixed_path).startswith("/"):
            raise PolicyError(f"operation {index} needs an absolute YAML path: {path}")
        if path_from and (not isinstance(path_from, dict) or not path_from.get("source")):
            raise PolicyError(f"operation {index} path_from needs source: {path}")
        derive = operation.get("derive")
        if not isinstance(derive, dict) or not derive.get("source"):
            raise PolicyError(f"operation {index} needs derive.source: {path}")
        if any(key in operation for key in ("value", "after", "before")):
            raise PolicyError(f"literal remediation values are forbidden: {path}")
    return Policy(policy_id, root_cause, decision, tuple(operations), reason, data)

def load_policy_directory(directory: Path) -> dict[str, Policy]:
    policies: dict[str, Policy] = {}
    for path in sorted(directory.glob("*.yaml")):
        policy = load_policy(path)
        if policy.root_cause in policies:
            raise PolicyError(f"Duplicate root cause policy: {policy.root_cause}")
        policies[policy.root_cause] = policy
    if not policies:
        raise PolicyError(f"No policies found in {directory}")
    return policies
