from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Decision = Literal["PATCH", "NO_GITOPS_CHANGE", "BLOCKED"]


@dataclass(frozen=True)
class RootCause:
    name: str
    confidence: float
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class Target:
    kind: str
    name: str
    namespace: str
    container: str | None = None


@dataclass(frozen=True)
class DerivedValue:
    value: Any
    source: str
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PatchOperation:
    op: Literal["add", "replace", "remove"]
    path: str
    value: Any = None
    before: Any = None
    source: str = ""


@dataclass(frozen=True)
class RemediationResult:
    decision: Decision
    root_cause: RootCause
    reason: str
    target: Target | None = None
    operations: tuple[PatchOperation, ...] = ()
    policy_id: str | None = None
    diagnostics: tuple[str, ...] = ()
