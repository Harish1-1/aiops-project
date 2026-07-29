from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import requests


logger = logging.getLogger(__name__)


LOKI_URL = os.getenv(
    "LOKI_URL",
    "http://127.0.0.1:3100",
).rstrip("/")

LOKI_TIMEOUT_SECONDS = int(
    os.getenv(
        "LOKI_TIMEOUT_SECONDS",
        "15",
    )
)

DEFAULT_LOOKBACK_MINUTES = int(
    os.getenv(
        "LOKI_LOOKBACK_MINUTES",
        "60",
    )
)

DEFAULT_LOG_LIMIT = int(
    os.getenv(
        "LOKI_LOG_LIMIT",
        "300",
    )
)


class LokiQueryError(RuntimeError):
    """Raised when Loki cannot complete a query."""


def _escape_logql_value(
    value: str,
) -> str:
    """
    Escape a value before inserting it into a LogQL label matcher.
    """

    return (
        value
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


def _to_nanoseconds(
    value: datetime,
) -> int:
    """
    Convert a timezone-aware datetime into Unix nanoseconds.
    """

    return int(
        value.timestamp()
        * 1_000_000_000
    )


def _nanoseconds_to_iso(
    value: str | int,
) -> str:
    """
    Convert Loki's nanosecond Unix timestamp to an ISO-8601 timestamp.
    """

    try:
        nanoseconds = int(value)

        seconds = (
            nanoseconds
            / 1_000_000_000
        )

        return datetime.fromtimestamp(
            seconds,
            tz=timezone.utc,
        ).isoformat()

    except (
        TypeError,
        ValueError,
        OverflowError,
    ):
        return str(value)


def build_logql_query(
    namespace: str,
    pod: str | None = None,
    container: str | None = None,
    workload_name: str | None = None,
) -> str:
    """
    Build a LogQL stream selector using labels commonly produced by
    Promtail's Kubernetes service discovery.

    The pod matcher is preferred because it identifies the exact
    incident target. Workload matching is used only as a fallback.
    """

    matchers = [
        (
            'namespace="'
            f"{_escape_logql_value(namespace)}"
            '"'
        )
    ]

    if pod and pod != "unknown":
        matchers.append(
            (
                'pod="'
                f"{_escape_logql_value(pod)}"
                '"'
            )
        )

    elif workload_name and workload_name != "Unknown":
        escaped_workload = _escape_logql_value(
            workload_name
        )

        matchers.append(
            f'pod=~"{escaped_workload}-.+"'
        )

    if container:
        matchers.append(
            (
                'container="'
                f"{_escape_logql_value(container)}"
                '"'
            )
        )

    return (
        "{"
        + ", ".join(matchers)
        + "}"
    )


def _query_range(
    query: str,
    start: datetime,
    end: datetime,
    limit: int,
    direction: str = "backward",
) -> dict[str, Any]:
    """
    Execute one Loki query_range request.
    """

    if direction not in {
        "forward",
        "backward",
    }:
        raise ValueError(
            "direction must be 'forward' or 'backward'"
        )

    url = (
        f"{LOKI_URL}"
        "/loki/api/v1/query_range"
    )

    params = {
        "query": query,
        "start": _to_nanoseconds(start),
        "end": _to_nanoseconds(end),
        "limit": limit,
        "direction": direction,
    }

    try:
        response = requests.get(
            url,
            params=params,
            timeout=LOKI_TIMEOUT_SECONDS,
        )

        response.raise_for_status()

    except requests.RequestException as exc:
        raise LokiQueryError(
            f"Loki request failed: {exc}"
        ) from exc

    try:
        payload = response.json()

    except ValueError as exc:
        raise LokiQueryError(
            "Loki returned invalid JSON."
        ) from exc

    if payload.get("status") != "success":
        raise LokiQueryError(
            (
                "Loki query failed: "
                f"{payload.get('error', 'unknown error')}"
            )
        )

    data = payload.get(
        "data",
        {},
    )

    if not isinstance(
        data,
        dict,
    ):
        raise LokiQueryError(
            "Loki response does not contain a valid data object."
        )

    return data


def _parse_streams(
    data: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Flatten Loki stream results into normalized log entries.
    """

    result_type = data.get(
        "resultType"
    )

    if result_type != "streams":
        return []

    streams = data.get(
        "result",
        [],
    )

    if not isinstance(
        streams,
        list,
    ):
        return []

    entries: list[dict[str, Any]] = []

    for stream_result in streams:
        if not isinstance(
            stream_result,
            dict,
        ):
            continue

        labels = stream_result.get(
            "stream",
            {},
        )

        if not isinstance(
            labels,
            dict,
        ):
            labels = {}

        values = stream_result.get(
            "values",
            [],
        )

        if not isinstance(
            values,
            list,
        ):
            continue

        for value in values:
            if (
                not isinstance(
                    value,
                    list,
                )
                or len(value) < 2
            ):
                continue

            raw_timestamp = value[0]
            line = str(value[1])

            entries.append(
                {
                    "timestamp": (
                        _nanoseconds_to_iso(
                            raw_timestamp
                        )
                    ),
                    "timestamp_ns": str(
                        raw_timestamp
                    ),
                    "line": line,
                    "namespace": labels.get(
                        "namespace"
                    ),
                    "pod": labels.get(
                        "pod"
                    ),
                    "container": labels.get(
                        "container"
                    ),
                    "app": (
                        labels.get("app")
                        or labels.get(
                            "app_kubernetes_io_name"
                        )
                    ),
                    "labels": labels,
                }
            )

    entries.sort(
        key=lambda item: item[
            "timestamp_ns"
        ]
    )

    return entries


def _detect_log_level(
    line: str,
) -> str:
    """
    Infer a basic level for dashboard summaries.

    This does not alter or replace the original log line.
    """

    normalized = line.lower()

    if any(
        token in normalized
        for token in (
            "fatal",
            "panic",
            "critical",
        )
    ):
        return "CRITICAL"

    if any(
        token in normalized
        for token in (
            "error",
            "exception",
            "failed",
            "failure",
        )
    ):
        return "ERROR"

    if any(
        token in normalized
        for token in (
            "warn",
            "warning",
        )
    ):
        return "WARNING"

    return "INFO"


def _summarize_logs(
    entries: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Produce deterministic statistics for the retrieved log window.
    """

    level_counts = {
        "CRITICAL": 0,
        "ERROR": 0,
        "WARNING": 0,
        "INFO": 0,
    }

    normalized_entries: list[
        dict[str, Any]
    ] = []

    for entry in entries:
        enriched_entry = dict(
            entry
        )

        level = _detect_log_level(
            str(entry.get("line", ""))
        )

        enriched_entry["level"] = level

        level_counts[level] += 1

        normalized_entries.append(
            enriched_entry
        )

    error_entries = [
        entry
        for entry in normalized_entries
        if entry["level"]
        in {
            "CRITICAL",
            "ERROR",
        }
    ]

    warning_entries = [
        entry
        for entry in normalized_entries
        if entry["level"]
        == "WARNING"
    ]

    return {
        "available": bool(
            normalized_entries
        ),
        "entry_count": len(
            normalized_entries
        ),
        "first_timestamp": (
            normalized_entries[0][
                "timestamp"
            ]
            if normalized_entries
            else None
        ),
        "last_timestamp": (
            normalized_entries[-1][
                "timestamp"
            ]
            if normalized_entries
            else None
        ),
        "level_counts": level_counts,
        "error_count": len(
            error_entries
        ),
        "warning_count": len(
            warning_entries
        ),
        "error_entries": (
            error_entries[-50:]
        ),
        "warning_entries": (
            warning_entries[-50:]
        ),
        "entries": normalized_entries,
    }


def check_loki_readiness() -> dict[str, Any]:
    """
    Check Loki's /ready endpoint without stopping the main workflow.
    """

    try:
        response = requests.get(
            f"{LOKI_URL}/ready",
            timeout=LOKI_TIMEOUT_SECONDS,
        )

        return {
            "ready": (
                response.status_code
                == 200
            ),
            "status_code": (
                response.status_code
            ),
            "message": (
                response.text.strip()
            ),
        }

    except requests.RequestException as exc:
        return {
            "ready": False,
            "status_code": None,
            "message": str(exc),
        }


def collect_loki_history(
    namespace: str,
    pod: str,
    container_names: list[str] | None = None,
    workload_name: str | None = None,
    lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
    limit: int = DEFAULT_LOG_LIMIT,
) -> dict[str, Any]:
    """
    Collect historical logs for the incident target.

    The function queries each known container separately when container
    names are available. This avoids mixing logs from unrelated
    sidecars. Failures are returned as warnings rather than raising into
    the incident workflow.
    """

    end = datetime.now(
        timezone.utc
    )

    start = end - timedelta(
        minutes=lookback_minutes
    )

    errors: list[str] = []
    queries: list[str] = []
    all_entries: list[
        dict[str, Any]
    ] = []

    containers = [
        str(container)
        for container in (
            container_names
            or []
        )
        if str(container).strip()
    ]

    query_containers: list[
        str | None
    ] = (
        containers
        if containers
        else [None]
    )

    per_query_limit = max(
        1,
        limit
        // len(query_containers)
    )

    for container in query_containers:
        query = build_logql_query(
            namespace=namespace,
            pod=pod,
            container=container,
            workload_name=workload_name,
        )

        queries.append(query)

        try:
            data = _query_range(
                query=query,
                start=start,
                end=end,
                limit=per_query_limit,
                direction="backward",
            )

            entries = _parse_streams(
                data
            )

            all_entries.extend(
                entries
            )

        except LokiQueryError as exc:
            container_label = (
                container
                or "all containers"
            )

            errors.append(
                (
                    f"Loki history unavailable for "
                    f"{container_label}: {exc}"
                )
            )

    deduplicated: dict[
        tuple[str, str, str],
        dict[str, Any],
    ] = {}

    for entry in all_entries:
        key = (
            str(
                entry.get(
                    "timestamp_ns",
                    "",
                )
            ),
            str(
                entry.get(
                    "container",
                    "",
                )
            ),
            str(
                entry.get(
                    "line",
                    "",
                )
            ),
        )

        deduplicated[key] = entry

    entries = sorted(
        deduplicated.values(),
        key=lambda item: item[
            "timestamp_ns"
        ],
    )

    if len(entries) > limit:
        entries = entries[
            -limit:
        ]

    summary = _summarize_logs(
        entries
    )

    logger.info(
        "Collected Loki history: "
        "namespace=%s pod=%s "
        "entries=%s errors=%s",
        namespace,
        pod,
        summary["entry_count"],
        len(errors),
    )

    return {
        "available": summary[
            "available"
        ],
        "source": "loki",
        "loki_url": LOKI_URL,
        "lookback_minutes": (
            lookback_minutes
        ),
        "limit": limit,
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "queries": queries,
        "entry_count": summary[
            "entry_count"
        ],
        "first_timestamp": summary[
            "first_timestamp"
        ],
        "last_timestamp": summary[
            "last_timestamp"
        ],
        "level_counts": summary[
            "level_counts"
        ],
        "error_count": summary[
            "error_count"
        ],
        "warning_count": summary[
            "warning_count"
        ],
        "error_entries": summary[
            "error_entries"
        ],
        "warning_entries": summary[
            "warning_entries"
        ],
        "entries": summary[
            "entries"
        ],
        "errors": errors,
    }