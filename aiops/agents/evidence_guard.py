from __future__ import annotations

import math
import re
from typing import Any


PERCENT_PATTERN = re.compile(
    r"\b(\d+(?:\.\d+)?)%"
)

RESOURCE_PATTERN = re.compile(
    r"\b\d+(?:\.\d+)?(?:Ki|Mi|Gi|Ti|m)\b",
    flags=re.IGNORECASE,
)

LOG_COUNT_PATTERN = re.compile(
    (
        r"(?i)\b"
        r"(?:critical|errors?|warnings?|entries|logs?)"
        r"\s*(?:=|:|were|was|count(?:\s+was)?|is)?\s*"
        r"(\d+)\b"
    )
)


def _flatten_values(
    value: Any,
) -> list[str]:
    values: list[str] = []

    if isinstance(value, dict):
        for nested in value.values():
            values.extend(
                _flatten_values(nested)
            )

    elif isinstance(value, list):
        for nested in value:
            values.extend(
                _flatten_values(nested)
            )

    elif value is not None:
        values.append(
            str(value)
        )

    return values


def _add_resource_value(
    allowed: set[str],
    value: Any,
    suffix: str,
) -> None:
    if not isinstance(
        value,
        (int, float),
    ):
        return

    numeric = float(value)

    variants = {
        f"{numeric}{suffix}",
        f"{round(numeric, 3)}{suffix}",
        f"{round(numeric, 2)}{suffix}",
        f"{round(numeric, 1)}{suffix}",
    }

    if numeric.is_integer():
        variants.add(
            f"{int(numeric)}{suffix}"
        )

    allowed.update(
        value.lower()
        for value in variants
    )


def _allowed_resource_values(
    incident: dict[str, Any],
) -> set[str]:
    evidence_parts = [
        incident.get("metrics", {}),
        incident.get("cpu_usage"),
        incident.get("memory_usage"),
        incident.get("logs", []),
        incident.get("events", []),
        incident.get(
            "termination_reasons",
            [],
        ),
        incident.get(
            "container_resources",
            [],
        ),
        incident.get(
            "historical_metrics",
            {},
        ),
        incident.get(
            "alert_assessment",
            {},
        ),
    ]

    flattened: list[str] = []

    for part in evidence_parts:
        flattened.extend(
            _flatten_values(part)
        )

    allowed = {
        value.lower()
        for value in RESOURCE_PATTERN.findall(
            "\n".join(flattened)
        )
    }

    historical_metrics = incident.get(
        "historical_metrics",
        {},
    )

    if not isinstance(
        historical_metrics,
        dict,
    ):
        return allowed

    cpu_history = historical_metrics.get(
        "cpu",
        {},
    )

    memory_history = historical_metrics.get(
        "memory",
        {},
    )

    if isinstance(
        cpu_history,
        dict,
    ):
        for key in (
            "latest_millicores",
            "minimum_millicores",
            "maximum_millicores",
            "average_millicores",
        ):
            _add_resource_value(
                allowed,
                cpu_history.get(key),
                "m",
            )

        samples = cpu_history.get(
            "samples_millicores",
            [],
        )

        if isinstance(samples, list):
            for sample in samples:
                if isinstance(sample, dict):
                    _add_resource_value(
                        allowed,
                        sample.get(
                            "value_millicores"
                        ),
                        "m",
                    )

    if isinstance(
        memory_history,
        dict,
    ):
        for key in (
            "latest_mib",
            "minimum_mib",
            "maximum_mib",
            "average_mib",
        ):
            _add_resource_value(
                allowed,
                memory_history.get(key),
                "Mi",
            )

        samples = memory_history.get(
            "samples_mib",
            [],
        )

        if isinstance(samples, list):
            for sample in samples:
                if isinstance(sample, dict):
                    _add_resource_value(
                        allowed,
                        sample.get(
                            "value_mib"
                        ),
                        "Mi",
                    )

    return allowed


def _allowed_percentages(
    incident: dict[str, Any],
) -> list[float]:
    assessment = incident.get(
        "alert_assessment",
        {},
    )

    if not isinstance(
        assessment,
        dict,
    ):
        return []

    utilization = assessment.get(
        "calculated_utilization",
        {},
    )

    if not isinstance(
        utilization,
        dict,
    ):
        return []

    return [
        float(value)
        for value in utilization.values()
        if isinstance(
            value,
            (int, float),
        )
    ]


def _allowed_loki_counts(
    incident: dict[str, Any],
) -> set[int]:
    """
    Loki counts are deterministic evidence.

    Include the overall count and all level-specific counts.
    """

    historical_logs = incident.get(
        "historical_logs",
        {},
    )

    if not isinstance(
        historical_logs,
        dict,
    ):
        return set()

    counts: set[int] = set()

    for key in (
        "entry_count",
        "error_count",
        "warning_count",
    ):
        value = historical_logs.get(key)

        if isinstance(value, int):
            counts.add(value)

    level_counts = historical_logs.get(
        "level_counts",
        {},
    )

    if isinstance(
        level_counts,
        dict,
    ):
        for value in level_counts.values():
            if isinstance(value, int):
                counts.add(value)

    return counts


def _percentage_is_allowed(
    generated_value: float,
    allowed_values: list[float],
) -> bool:
    for allowed in allowed_values:
        variants = {
            allowed,
            round(allowed, 2),
            round(allowed, 1),
            float(round(allowed)),
            float(math.floor(allowed)),
            float(math.ceil(allowed)),
        }

        if any(
            abs(
                generated_value
                - variant
            )
            < 0.001
            for variant in variants
        ):
            return True

        if abs(
            generated_value
            - allowed
        ) <= 1.0:
            return True

    return False


def _is_confidence_percentage(
    text: str,
    percentage_text: str,
) -> bool:
    pattern = re.compile(
        (
            r"confidence[^.\n]{0,100}"
            + re.escape(
                percentage_text
            )
        ),
        flags=re.IGNORECASE,
    )

    return bool(
        pattern.search(text)
    )


def check_evidence_claims(
    incident: dict[str, Any],
    generated_text: str,
) -> list[str]:
    """
    Validate generated operational values against deterministic evidence.
    """

    allowed_resources = _allowed_resource_values(
        incident
    )

    allowed_percentages = _allowed_percentages(
        incident
    )

    allowed_loki_counts = _allowed_loki_counts(
        incident
    )

    violations: list[str] = []

    for match in PERCENT_PATTERN.finditer(
        generated_text
    ):
        percentage_text = match.group(0)

        try:
            generated_value = float(
                match.group(1)
            )
        except ValueError:
            continue

        if _is_confidence_percentage(
            generated_text,
            percentage_text,
        ):
            continue

        if _percentage_is_allowed(
            generated_value,
            allowed_percentages,
        ):
            continue

        violations.append(
            (
                "Generated text contains unsupported operational "
                f"percentage '{percentage_text}'."
            )
        )

    generated_resources = {
        value.lower()
        for value in RESOURCE_PATTERN.findall(
            generated_text
        )
    }

    for value in sorted(
        generated_resources
    ):
        if value not in allowed_resources:
            violations.append(
                (
                    "Generated text contains unsupported operational "
                    f"resource value '{value}'."
                )
            )

    for match in LOG_COUNT_PATTERN.finditer(
        generated_text
    ):
        try:
            count = int(
                match.group(1)
            )
        except ValueError:
            continue

        if count not in allowed_loki_counts:
            violations.append(
                (
                    "Generated text contains unsupported Loki log "
                    f"count '{count}'."
                )
            )

    return list(
        dict.fromkeys(
            violations
        )
    )