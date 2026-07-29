from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


STATUS_NOT_STARTED = "NOT_STARTED"
STATUS_RUNNING = "RUNNING"
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"
STATUS_SKIPPED = "SKIPPED"


WORKFLOW_STAGE_ORDER = [
    "investigation",
    "alert_assessment",
    "rca",
    "remediation",
    "validation",
    "report",
]


WORKFLOW_STAGE_LABELS = {
    "investigation": "Live Investigation",
    "alert_assessment": "Alert Assessment",
    "rca": "Root Cause Analysis",
    "remediation": "Remediation",
    "validation": "Safety Validation",
    "report": "Final Report",
}


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def create_workflow_stages() -> list[dict[str, Any]]:
    """
    Create a fresh ordered workflow-stage list.

    This is deterministic and does not rely on the LLM.
    """

    return [
        {
            "stage": stage,
            "label": WORKFLOW_STAGE_LABELS[stage],
            "status": STATUS_NOT_STARTED,
            "started_at": None,
            "completed_at": None,
            "duration_ms": None,
            "error": None,
            "details": {},
        }
        for stage in WORKFLOW_STAGE_ORDER
    ]


def _find_stage(
    stages: list[dict[str, Any]],
    stage_name: str,
) -> dict[str, Any] | None:
    for stage in stages:
        if stage.get("stage") == stage_name:
            return stage

    return None


def _parse_datetime(
    value: str | None,
) -> datetime | None:
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            value.replace(
                "Z",
                "+00:00",
            )
        )
    except ValueError:
        return None


def _calculate_duration_ms(
    started_at: str | None,
    completed_at: str | None,
) -> int | None:
    started = _parse_datetime(
        started_at
    )

    completed = _parse_datetime(
        completed_at
    )

    if (
        started is None
        or completed is None
    ):
        return None

    duration = (
        completed - started
    ).total_seconds() * 1000

    return max(
        0,
        round(duration),
    )


def start_stage(
    stages: list[dict[str, Any]],
    stage_name: str,
    details: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    stage = _find_stage(
        stages,
        stage_name,
    )

    if stage is None:
        return stages

    stage["status"] = STATUS_RUNNING
    stage["started_at"] = utc_now()
    stage["completed_at"] = None
    stage["duration_ms"] = None
    stage["error"] = None

    if details:
        stage["details"] = {
            **stage.get(
                "details",
                {},
            ),
            **details,
        }

    return stages


def complete_stage(
    stages: list[dict[str, Any]],
    stage_name: str,
    details: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    stage = _find_stage(
        stages,
        stage_name,
    )

    if stage is None:
        return stages

    if not stage.get(
        "started_at"
    ):
        stage["started_at"] = utc_now()

    stage["status"] = STATUS_COMPLETED
    stage["completed_at"] = utc_now()
    stage["duration_ms"] = _calculate_duration_ms(
        stage.get("started_at"),
        stage.get("completed_at"),
    )
    stage["error"] = None

    if details:
        stage["details"] = {
            **stage.get(
                "details",
                {},
            ),
            **details,
        }

    return stages


def fail_stage(
    stages: list[dict[str, Any]],
    stage_name: str,
    error: str,
    details: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    stage = _find_stage(
        stages,
        stage_name,
    )

    if stage is None:
        return stages

    if not stage.get(
        "started_at"
    ):
        stage["started_at"] = utc_now()

    stage["status"] = STATUS_FAILED
    stage["completed_at"] = utc_now()
    stage["duration_ms"] = _calculate_duration_ms(
        stage.get("started_at"),
        stage.get("completed_at"),
    )
    stage["error"] = str(error)

    if details:
        stage["details"] = {
            **stage.get(
                "details",
                {},
            ),
            **details,
        }

    return stages


def skip_remaining_stages(
    stages: list[dict[str, Any]],
    after_stage: str,
    reason: str,
) -> list[dict[str, Any]]:
    """
    Mark untouched stages after a failed stage as skipped.
    """

    try:
        failed_index = WORKFLOW_STAGE_ORDER.index(
            after_stage
        )
    except ValueError:
        return stages

    for stage_name in WORKFLOW_STAGE_ORDER[
        failed_index + 1:
    ]:
        stage = _find_stage(
            stages,
            stage_name,
        )

        if (
            stage
            and stage.get("status")
            == STATUS_NOT_STARTED
        ):
            stage["status"] = STATUS_SKIPPED
            stage["error"] = reason

    return stages


def workflow_summary(
    stages: list[dict[str, Any]],
) -> dict[str, Any]:
    counts = {
        STATUS_NOT_STARTED: 0,
        STATUS_RUNNING: 0,
        STATUS_COMPLETED: 0,
        STATUS_FAILED: 0,
        STATUS_SKIPPED: 0,
    }

    total_duration_ms = 0

    for stage in stages:
        status = str(
            stage.get(
                "status",
                STATUS_NOT_STARTED,
            )
        )

        counts[status] = (
            counts.get(status, 0)
            + 1
        )

        duration = stage.get(
            "duration_ms"
        )

        if isinstance(
            duration,
            int,
        ):
            total_duration_ms += duration

    overall_status = "COMPLETED"

    if counts[STATUS_FAILED] > 0:
        overall_status = "FAILED"

    elif counts[STATUS_RUNNING] > 0:
        overall_status = "RUNNING"

    elif counts[STATUS_NOT_STARTED] > 0:
        overall_status = "INCOMPLETE"

    return {
        "overall_status": overall_status,
        "total_stages": len(stages),
        "completed_stages": counts[
            STATUS_COMPLETED
        ],
        "failed_stages": counts[
            STATUS_FAILED
        ],
        "skipped_stages": counts[
            STATUS_SKIPPED
        ],
        "running_stages": counts[
            STATUS_RUNNING
        ],
        "not_started_stages": counts[
            STATUS_NOT_STARTED
        ],
        "total_duration_ms": (
            total_duration_ms
        ),
    }