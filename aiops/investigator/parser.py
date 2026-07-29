from __future__ import annotations

from typing import Any


def parse_metrics_output(
    output: str,
) -> dict[str, str]:
    """
    Parse output such as:

    payment-service-abc123   1m   7Mi
    """

    if not output:
        return {
            "cpu": "unavailable",
            "memory": "unavailable",
        }

    parts = output.split()

    if len(parts) < 3:
        return {
            "cpu": "unavailable",
            "memory": "unavailable",
        }

    return {
        "cpu": parts[-2],
        "memory": parts[-1],
    }


def parse_events(
    events_payload: dict[str, Any],
    maximum: int = 20,
) -> list[str]:
    items = events_payload.get("items", [])

    parsed: list[str] = []

    for item in items[-maximum:]:
        event_type = item.get("type", "Unknown")
        reason = item.get("reason", "Unknown")
        message = item.get("message", "")
        count = item.get("count", 1)

        parsed.append(
            f"{event_type} | {reason} | count={count} | {message}"
        )

    return parsed


def extract_container_status(
    pod_payload: dict[str, Any],
) -> dict[str, Any]:
    statuses = (
        pod_payload
        .get("status", {})
        .get("containerStatuses", [])
    )

    total_restarts = 0
    termination_reasons: list[str] = []
    container_states: list[str] = []

    for status in statuses:
        total_restarts += int(status.get("restartCount", 0))

        container_name = status.get("name", "unknown")
        state = status.get("state", {})
        last_state = status.get("lastState", {})

        if state.get("running"):
            container_states.append(
                f"{container_name}: Running"
            )

        elif state.get("waiting"):
            reason = (
                state["waiting"].get("reason")
                or "Waiting"
            )
            container_states.append(
                f"{container_name}: {reason}"
            )

        elif state.get("terminated"):
            reason = (
                state["terminated"].get("reason")
                or "Terminated"
            )
            container_states.append(
                f"{container_name}: {reason}"
            )

        last_terminated = last_state.get("terminated")

        if last_terminated:
            reason = (
                last_terminated.get("reason")
                or "Unknown"
            )
            exit_code = last_terminated.get(
                "exitCode",
                "unknown",
            )

            termination_reasons.append(
                f"{container_name}: "
                f"{reason} (exit_code={exit_code})"
            )

    pod_status = pod_payload.get("status", {})

    return {
        "phase": pod_status.get("phase", "Unknown"),
        "pod_ip": pod_status.get("podIP"),
        "node_name": pod_payload.get(
            "spec",
            {},
        ).get("nodeName"),
        "restart_count": total_restarts,
        "container_states": container_states,
        "termination_reasons": termination_reasons,
    }


def split_log_lines(
    log_text: str,
    maximum: int = 100,
) -> list[str]:
    if not log_text:
        return []

    lines = [
        line.strip()
        for line in log_text.splitlines()
        if line.strip()
    ]

    return lines[-maximum:]