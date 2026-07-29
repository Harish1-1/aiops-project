from __future__ import annotations

import logging
import os
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any

import requests


logger = logging.getLogger(__name__)


PROMETHEUS_URL = os.getenv(
    "PROMETHEUS_URL",
    "http://127.0.0.1:9090",
).rstrip("/")

PROMETHEUS_TIMEOUT_SECONDS = int(
    os.getenv(
        "PROMETHEUS_TIMEOUT_SECONDS",
        "15",
    )
)

DEFAULT_LOOKBACK_MINUTES = int(
    os.getenv(
        "PROMETHEUS_LOOKBACK_MINUTES",
        "60",
    )
)

DEFAULT_STEP_SECONDS = int(
    os.getenv(
        "PROMETHEUS_STEP_SECONDS",
        "60",
    )
)


class PrometheusQueryError(RuntimeError):
    """Raised when Prometheus cannot execute a query."""


def _escape_promql_label(
    value: str,
) -> str:
    """
    Escape a string before inserting it into a PromQL label matcher.
    """

    return (
        value
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


def _query_range(
    query: str,
    start: datetime,
    end: datetime,
    step_seconds: int,
) -> list[dict[str, Any]]:
    """
    Execute a Prometheus range query.

    Returns the raw matrix result list. Failures raise
    PrometheusQueryError so the caller can record a collection warning.
    """

    url = f"{PROMETHEUS_URL}/api/v1/query_range"

    params = {
        "query": query,
        "start": start.timestamp(),
        "end": end.timestamp(),
        "step": step_seconds,
    }

    try:
        response = requests.get(
            url,
            params=params,
            timeout=PROMETHEUS_TIMEOUT_SECONDS,
        )

        response.raise_for_status()

    except requests.RequestException as exc:
        raise PrometheusQueryError(
            f"Prometheus request failed: {exc}"
        ) from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise PrometheusQueryError(
            "Prometheus returned invalid JSON."
        ) from exc

    if payload.get("status") != "success":
        raise PrometheusQueryError(
            (
                "Prometheus query failed: "
                f"{payload.get('error', 'unknown error')}"
            )
        )

    data = payload.get("data", {})

    if data.get("resultType") != "matrix":
        return []

    result = data.get("result", [])

    return result if isinstance(result, list) else []


def _merge_matrix_values(
    result: list[dict[str, Any]],
) -> list[dict[str, float]]:
    """
    Merge one or more Prometheus series by timestamp.

    The PromQL queries normally return one aggregated pod series, but
    merging makes this robust if multiple series are returned.
    """

    samples_by_timestamp: dict[float, float] = {}

    for series in result:
        values = series.get("values", [])

        if not isinstance(values, list):
            continue

        for sample in values:
            if (
                not isinstance(sample, list)
                or len(sample) < 2
            ):
                continue

            try:
                timestamp = float(sample[0])
                value = float(sample[1])
            except (TypeError, ValueError):
                continue

            samples_by_timestamp[timestamp] = (
                samples_by_timestamp.get(
                    timestamp,
                    0.0,
                )
                + value
            )

    return [
        {
            "timestamp": timestamp,
            "value": value,
        }
        for timestamp, value
        in sorted(samples_by_timestamp.items())
    ]


def _calculate_trend(
    values: list[float],
) -> str:
    """
    Determine a simple trend from the first and last parts of a series.
    """

    if len(values) < 3:
        return "INSUFFICIENT_DATA"

    segment_size = max(
        1,
        len(values) // 3,
    )

    first_average = statistics.fmean(
        values[:segment_size]
    )

    last_average = statistics.fmean(
        values[-segment_size:]
    )

    if first_average == 0:
        if last_average > 0:
            return "INCREASING"

        return "STABLE"

    percentage_change = (
        (last_average - first_average)
        / abs(first_average)
        * 100
    )

    if percentage_change >= 20:
        return "INCREASING"

    if percentage_change <= -20:
        return "DECREASING"

    return "STABLE"


def _summarize_series(
    samples: list[dict[str, float]],
    value_type: str,
) -> dict[str, Any]:
    """
    Produce deterministic summary statistics for one metric series.
    """

    values = [
        sample["value"]
        for sample in samples
    ]

    if not values:
        return {
            "available": False,
            "sample_count": 0,
            "latest": None,
            "minimum": None,
            "maximum": None,
            "average": None,
            "trend": "NO_DATA",
            "samples": [],
        }

    peak_index = max(
        range(len(values)),
        key=values.__getitem__,
    )

    peak_sample = samples[peak_index]

    return {
        "available": True,
        "value_type": value_type,
        "sample_count": len(values),
        "latest": values[-1],
        "minimum": min(values),
        "maximum": max(values),
        "average": statistics.fmean(values),
        "trend": _calculate_trend(values),
        "peak_timestamp": datetime.fromtimestamp(
            peak_sample["timestamp"],
            tz=timezone.utc,
        ).isoformat(),
        "samples": [
            {
                "timestamp": datetime.fromtimestamp(
                    sample["timestamp"],
                    tz=timezone.utc,
                ).isoformat(),
                "value": sample["value"],
            }
            for sample in samples
        ],
    }


def _bytes_to_mebibytes(
    value: float | None,
) -> float | None:
    if value is None:
        return None

    return round(
        value / (1024 ** 2),
        2,
    )


def _cores_to_millicores(
    value: float | None,
) -> float | None:
    if value is None:
        return None

    return round(
        value * 1000,
        3,
    )


def _convert_memory_summary(
    summary: dict[str, Any],
) -> dict[str, Any]:
    converted = dict(summary)

    for key in (
        "latest",
        "minimum",
        "maximum",
        "average",
    ):
        converted[f"{key}_mib"] = (
            _bytes_to_mebibytes(
                summary.get(key)
            )
        )

    converted["samples_mib"] = [
        {
            "timestamp": sample["timestamp"],
            "value_mib": _bytes_to_mebibytes(
                sample["value"]
            ),
        }
        for sample in summary.get(
            "samples",
            [],
        )
    ]

    # Avoid storing the large duplicate raw-byte sample list.
    converted.pop(
        "samples",
        None,
    )

    return converted


def _convert_cpu_summary(
    summary: dict[str, Any],
) -> dict[str, Any]:
    converted = dict(summary)

    for key in (
        "latest",
        "minimum",
        "maximum",
        "average",
    ):
        converted[f"{key}_millicores"] = (
            _cores_to_millicores(
                summary.get(key)
            )
        )

    converted["samples_millicores"] = [
        {
            "timestamp": sample["timestamp"],
            "value_millicores": _cores_to_millicores(
                sample["value"]
            ),
        }
        for sample in summary.get(
            "samples",
            [],
        )
    ]

    converted.pop(
        "samples",
        None,
    )

    return converted


def _convert_restart_summary(
    summary: dict[str, Any],
) -> dict[str, Any]:
    converted = dict(summary)

    values = [
        sample["value"]
        for sample in summary.get(
            "samples",
            [],
        )
    ]

    restart_increase = None

    if values:
        restart_increase = max(
            0,
            values[-1] - values[0],
        )

    converted["restart_increase"] = restart_increase

    converted["samples"] = [
        {
            "timestamp": sample["timestamp"],
            "value": round(
                sample["value"],
                3,
            ),
        }
        for sample in summary.get(
            "samples",
            [],
        )
    ]

    return converted


def collect_prometheus_history(
    namespace: str,
    pod: str,
    container_names: list[str] | None = None,
    lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
    step_seconds: int = DEFAULT_STEP_SECONDS,
) -> dict[str, Any]:
    """
    Collect pod CPU, memory and restart history from Prometheus.

    This is a read-only operation. Failures are represented in the
    returned object and do not stop the incident workflow.
    """

    end = datetime.now(
        timezone.utc
    )

    start = end - timedelta(
        minutes=lookback_minutes
    )

    escaped_namespace = _escape_promql_label(
        namespace
    )

    escaped_pod = _escape_promql_label(
        pod
    )

    container_filter = 'container!=""'

    if container_names:
        escaped_names = [
            re_escape
            for re_escape in (
                _escape_promql_label(name)
                for name in container_names
            )
            if re_escape
        ]

        if escaped_names:
            regex = "|".join(
                escaped_names
            )

            container_filter = (
                f'container=~"{regex}"'
            )

    memory_query = f"""
sum(
  container_memory_working_set_bytes{{
    namespace="{escaped_namespace}",
    pod="{escaped_pod}",
    {container_filter},
    image!=""
  }}
)
""".strip()

    cpu_query = f"""
sum(
  rate(
    container_cpu_usage_seconds_total{{
      namespace="{escaped_namespace}",
      pod="{escaped_pod}",
      {container_filter},
      image!=""
    }}[5m]
  )
)
""".strip()

    restart_query = f"""
sum(
  kube_pod_container_status_restarts_total{{
    namespace="{escaped_namespace}",
    pod="{escaped_pod}"
  }}
)
""".strip()

    errors: list[str] = []

    memory_result: list[dict[str, Any]] = []
    cpu_result: list[dict[str, Any]] = []
    restart_result: list[dict[str, Any]] = []

    try:
        memory_result = _query_range(
            query=memory_query,
            start=start,
            end=end,
            step_seconds=step_seconds,
        )
    except PrometheusQueryError as exc:
        errors.append(
            f"Memory history unavailable: {exc}"
        )

    try:
        cpu_result = _query_range(
            query=cpu_query,
            start=start,
            end=end,
            step_seconds=step_seconds,
        )
    except PrometheusQueryError as exc:
        errors.append(
            f"CPU history unavailable: {exc}"
        )

    try:
        restart_result = _query_range(
            query=restart_query,
            start=start,
            end=end,
            step_seconds=step_seconds,
        )
    except PrometheusQueryError as exc:
        errors.append(
            f"Restart history unavailable: {exc}"
        )

    memory_samples = _merge_matrix_values(
        memory_result
    )

    cpu_samples = _merge_matrix_values(
        cpu_result
    )

    restart_samples = _merge_matrix_values(
        restart_result
    )

    memory_summary = _convert_memory_summary(
        _summarize_series(
            memory_samples,
            value_type="bytes",
        )
    )

    cpu_summary = _convert_cpu_summary(
        _summarize_series(
            cpu_samples,
            value_type="cores",
        )
    )

    restart_summary = _convert_restart_summary(
        _summarize_series(
            restart_samples,
            value_type="restart_count",
        )
    )

    available = any(
        summary.get(
            "available",
            False,
        )
        for summary in (
            memory_summary,
            cpu_summary,
            restart_summary,
        )
    )

    logger.info(
        "Collected Prometheus history: "
        "namespace=%s pod=%s available=%s "
        "memory_samples=%s cpu_samples=%s "
        "restart_samples=%s",
        namespace,
        pod,
        available,
        memory_summary.get(
            "sample_count",
            0,
        ),
        cpu_summary.get(
            "sample_count",
            0,
        ),
        restart_summary.get(
            "sample_count",
            0,
        ),
    )

    return {
        "available": available,
        "source": "prometheus",
        "prometheus_url": PROMETHEUS_URL,
        "lookback_minutes": lookback_minutes,
        "step_seconds": step_seconds,
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "memory": memory_summary,
        "cpu": cpu_summary,
        "restarts": restart_summary,
        "queries": {
            "memory": memory_query,
            "cpu": cpu_query,
            "restarts": restart_query,
        },
        "errors": errors,
    }