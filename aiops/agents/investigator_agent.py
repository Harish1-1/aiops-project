def investigate(incident: dict) -> dict:
    """
    Extract and normalize evidence collected for an incident.
    """

    metrics = incident.get("metrics", {})

    return {
        "alert": incident.get(
            "alert",
            incident.get("alert_name", "unknown"),
        ),
        "namespace": incident.get("namespace", "default"),
        "pod": incident.get("pod", "unknown"),
        "logs": incident.get("logs", []),
        "events": incident.get("events", []),
        "metrics": metrics,
        "cpu_usage": metrics.get("cpu", "unknown"),
        "memory_usage": metrics.get("memory", "unknown"),
        "restart_count": incident.get("restart_count", "unknown"),
    }