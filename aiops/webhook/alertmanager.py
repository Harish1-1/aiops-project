from webhook.models import AlertManagerPayload


def convert_alert(alert: AlertManagerPayload):

    first = alert.alerts[0]

    labels = first.labels

    annotations = first.annotations

    return {
        "alert": labels.get(
            "alertname",
            "Unknown Alert"
        ),
        "namespace": labels.get(
            "namespace",
            "default"
        ),
        "pod": labels.get(
            "pod",
            "unknown"
        ),
        "logs": [
            annotations.get(
                "description",
                ""
            )
        ],
        "events": [],
        "metrics": {},
        "restart_count": 0
    }