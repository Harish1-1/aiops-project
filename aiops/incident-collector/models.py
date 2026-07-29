def extract_alert_details(alert_data):

    try:

        alert = alert_data["alerts"][0]

        labels = alert.get("labels", {})

        return {

            "pod": labels.get("pod", "unknown"),

            "namespace": labels.get(
                "namespace",
                "default"
            ),

            "alertname": labels.get(
                "alertname",
                "unknown"
            )
        }

    except Exception:

        return {

            "pod": "unknown",

            "namespace": "default",

            "alertname": "unknown"
        }