from __future__ import annotations

import logging
from typing import Any

from rag.embedding import create_embedding
from rag.qdrant_manager import QdrantManager


LOGGER = logging.getLogger(__name__)

qdrant = QdrantManager()


def _safe_payload(
    result: Any,
) -> dict[str, Any]:
    payload = getattr(
        result,
        "payload",
        None,
    )

    return (
        payload
        if isinstance(
            payload,
            dict,
        )
        else {}
    )


def _safe_score(
    result: Any,
) -> float | None:
    value = getattr(
        result,
        "score",
        None,
    )

    try:
        return (
            float(value)
            if value is not None
            else None
        )
    except (
        TypeError,
        ValueError,
    ):
        return None


def _extract_title(
    content: str,
    filename: str,
) -> str:
    for line in content.splitlines():
        stripped = line.strip()

        if stripped.startswith(
            "# "
        ):
            return stripped[
                2:
            ].strip()

    if filename:
        return (
            filename
            .removesuffix(".md")
            .replace(
                "runbook-",
                "",
            )
            .replace(
                "-",
                " ",
            )
            .strip()
            .title()
        )

    return "Unknown Runbook"


def _extract_markdown_sections(
    content: str,
) -> dict[str, str]:
    """
    Split a Markdown runbook into heading-based sections.

    Existing runbooks without the new GitOps policy headings are still
    supported; their section dictionary will simply contain the headings
    that already exist.
    """

    sections: dict[str, list[str]] = {}

    current_heading = "Document"

    sections[current_heading] = []

    for line in content.splitlines():
        stripped = line.strip()

        if stripped.startswith(
            "#"
        ):
            heading = stripped.lstrip(
                "#"
            ).strip()

            if heading:
                current_heading = (
                    heading
                )

                sections.setdefault(
                    current_heading,
                    [],
                )

                continue

        sections.setdefault(
            current_heading,
            [],
        ).append(
            line
        )

    return {
        heading: "\n".join(
            lines
        ).strip()
        for heading, lines
        in sections.items()
        if "\n".join(
            lines
        ).strip()
    }


def _find_section(
    sections: dict[str, str],
    *names: str,
) -> str:
    normalized_sections = {
        "".join(
            character
            for character
            in heading.lower()
            if character.isalnum()
        ): content
        for heading, content
        in sections.items()
    }

    for name in names:
        normalized_name = "".join(
            character
            for character
            in name.lower()
            if character.isalnum()
        )

        if normalized_name in (
            normalized_sections
        ):
            return normalized_sections[
                normalized_name
            ]

    return ""


def _parse_bullet_values(
    text: str,
) -> list[str]:
    values: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()

        if stripped.startswith(
            "-"
        ):
            value = stripped[
                1:
            ].strip()

            if value:
                values.append(
                    value
                )

    return values


def _extract_policy(
    sections: dict[str, str],
) -> dict[str, Any]:
    allowed_changes_text = (
        _find_section(
            sections,
            "Allowed Changes",
        )
    )

    forbidden_changes_text = (
        _find_section(
            sections,
            "Forbidden Changes",
        )
    )

    required_evidence_text = (
        _find_section(
            sections,
            "Required Evidence",
        )
    )

    allowed_paths_text = (
        _find_section(
            sections,
            "Allowed YAML Paths",
        )
    )

    patch_constraints_text = (
        _find_section(
            sections,
            "Patch Constraints",
        )
    )

    validation_text = (
        _find_section(
            sections,
            "Validation Requirements",
            "Validation Checklist",
        )
    )

    rollback_text = (
        _find_section(
            sections,
            "Rollback Policy",
            "Rollback Plan",
        )
    )

    remediation_policy_text = (
        _find_section(
            sections,
            "GitOps Remediation Policy",
        )
    )

    allowed_yaml_paths = []

    for value in _parse_bullet_values(
        allowed_paths_text
    ):
        cleaned = (
            value
            .strip()
            .strip("`")
        )

        if cleaned.startswith(
            "/"
        ):
            allowed_yaml_paths.append(
                cleaned
            )

    return {
        "gitops_remediation_policy": (
            remediation_policy_text
        ),
        "allowed_changes": (
            _parse_bullet_values(
                allowed_changes_text
            )
        ),
        "forbidden_changes": (
            _parse_bullet_values(
                forbidden_changes_text
            )
        ),
        "required_evidence": (
            _parse_bullet_values(
                required_evidence_text
            )
        ),
        "allowed_yaml_paths": (
            allowed_yaml_paths
        ),
        "patch_constraints": (
            _parse_bullet_values(
                patch_constraints_text
            )
        ),
        "validation_requirements": (
            _parse_bullet_values(
                validation_text
            )
        ),
        "rollback_policy": (
            rollback_text
        ),
    }


def retrieve_runbooks(
    query: str,
    *,
    limit: int = 3,
) -> list[dict[str, Any]]:
    """
    Retrieve rich runbook records for remediation generation.

    Returns content, metadata, relevance score, parsed Markdown sections,
    and GitOps policy fields.

    QdrantManager currently returns a maximum of three results. The limit
    parameter still prevents callers from receiving more than requested.
    """

    if not isinstance(
        query,
        str,
    ):
        raise TypeError(
            "The runbook query must be a string."
        )

    if not query.strip():
        return []

    safe_limit = max(
        1,
        min(
            int(limit),
            3,
        ),
    )

    try:
        vector = create_embedding(
            query
        )

        results = qdrant.search(
            vector
        )

    except Exception:
        LOGGER.exception(
            "Runbook retrieval failed."
        )
        raise

    runbooks: list[
        dict[str, Any]
    ] = []

    for result in results[
        :safe_limit
    ]:
        payload = _safe_payload(
            result
        )

        content = str(
            payload.get(
                "content",
                "",
            )
        )

        filename = str(
            payload.get(
                "file",
                "",
            )
        )

        if not content.strip():
            continue

        sections = (
            _extract_markdown_sections(
                content
            )
        )

        runbooks.append(
            {
                "file": filename,
                "title": _extract_title(
                    content,
                    filename,
                ),
                "content": content,
                "score": _safe_score(
                    result
                ),
                "sections": sections,
                "policy": _extract_policy(
                    sections
                ),
                "metadata": {
                    key: value
                    for key, value
                    in payload.items()
                    if key not in {
                        "content",
                    }
                },
            }
        )

    return runbooks


def retrieve_context(
    query: str,
) -> list[str]:
    """
    Backward-compatible interface used by the existing RCA agent.

    The result remains a list of runbook content strings.
    """

    return [
        runbook["content"]
        for runbook
        in retrieve_runbooks(
            query,
            limit=3,
        )
    ]