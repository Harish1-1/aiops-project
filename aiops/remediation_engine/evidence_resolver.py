from __future__ import annotations
import math
import re
from typing import Any, Protocol
from .models import DerivedValue, Target

class EvidenceResolutionError(ValueError):
    pass

class EvidenceProvider(Protocol):
    def get(self, source: str, query: dict[str, Any], target: Target) -> DerivedValue: ...

class MappingEvidenceProvider:
    def __init__(self, values: dict[str, Any]):
        self._values = values
    def get(self, source: str, query: dict[str, Any], target: Target) -> DerivedValue:
        key = str(query.get("key") or query.get("selector") or query.get("metric") or "")
        lookup = f"{source}:{key}"
        if lookup not in self._values:
            raise EvidenceResolutionError(f"authoritative evidence unavailable: {lookup}")
        return DerivedValue(self._values[lookup], source, {"lookup": lookup})

def _number(value: Any) -> float:
    if isinstance(value, bool):
        raise EvidenceResolutionError("boolean cannot be numeric evidence")
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise EvidenceResolutionError(f"expected numeric evidence, got {value!r}") from exc

def _quantity(value: Any) -> tuple[float, str]:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value), ""
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)?\s*", str(value))
    if not match:
        raise EvidenceResolutionError(f"invalid Kubernetes quantity: {value!r}")
    return float(match.group(1)), match.group(2) or ""

def _apply_transform(value: Any, transform: dict[str, Any]) -> Any:
    operation = str(transform.get("operation") or "identity").lower()
    if operation == "identity": return value
    if operation == "multiply": return _number(value) * _number(transform["factor"])
    if operation == "ceil": return math.ceil(_number(value))
    if operation == "floor": return math.floor(_number(value))
    if operation == "max":
        candidates = value if isinstance(value, list) else [value]
        return max(_number(item) for item in candidates)
    if operation == "min":
        candidates = value if isinstance(value, list) else [value]
        return min(_number(item) for item in candidates)
    if operation == "quantity_multiply":
        number, suffix = _quantity(value)
        factor = _number(transform.get("factor"))
        result = math.ceil(number * factor)
        return f"{result}{suffix}"
    if operation == "format_quantity":
        suffix = str(transform.get("suffix") or "")
        number = _number(value)
        rendered = str(int(math.ceil(number)))
        return f"{rendered}{suffix}"
    if operation == "ensure_increase":
        current = transform.get("current")
        if current is None:
            return value
        proposed_num, proposed_suffix = _quantity(value)
        current_num, current_suffix = _quantity(current)
        if proposed_suffix != current_suffix:
            return value
        if proposed_num <= current_num:
            step = _number(transform.get("factor", 1.25))
            return f"{math.ceil(current_num * step)}{current_suffix}"
        return value
    raise EvidenceResolutionError(f"unsupported transform: {operation}")

def resolve_derived_value(rule: dict[str, Any], provider: EvidenceProvider, target: Target) -> DerivedValue:
    source = str(rule.get("source") or "").strip()
    if not source:
        raise EvidenceResolutionError("derive.source is required")
    base = provider.get(source, rule, target)
    value = base.value
    for transform in rule.get("transforms") or []:
        if not isinstance(transform, dict):
            raise EvidenceResolutionError("each transform must be a mapping")
        value = _apply_transform(value, transform)
    return DerivedValue(value, base.source, {**base.provenance, "rule": rule})
