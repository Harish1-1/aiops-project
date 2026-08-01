import json
from datetime import datetime

from kubernetes_client import get_events, get_pod_logs
from models import extract_alert_details
from prometheus_client import get_metrics


def collect_incident(alert_data):
    details = extract_alert_details(alert_data)
    pod_name = details["pod"]
    namespace = details["namespace"]

    logs = get_pod_logs(pod_name, namespace)
    events = get_events(namespace)
    metrics = get_metrics()

    incident = {
        "timestamp": str(datetime.now()),
        "alert": alert_data,
        "namespace": namespace,
        "pod": pod_name,
        "logs": logs,
        "events": events,
        "metrics": metrics,
    }

    with open("incident.json", "w", encoding="utf-8") as handle:
        json.dump(incident, handle, indent=2)

    return incident
