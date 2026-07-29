from __future__ import annotations

from typing import Any

from agents.remediation_builder import (
    build_deterministic_remediation,
)


def suggest_remediation(
    incident: dict[str, Any],
    analysis: str,
) -> str:
    """
    Return a deterministic recommendation-only remediation plan.

    The analysis argument is retained for compatibility with the
    LangGraph workflow, but the builder does not allow the LLM analysis
    to generate commands, YAML or concrete mutation values.
    """

    return build_deterministic_remediation(
        incident=incident,
        analysis=analysis,
    )