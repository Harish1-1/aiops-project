from kubernetes import client, config

config.load_kube_config()

v1 = client.CoreV1Api()

def get_pod_logs(
    pod_name,
    namespace="default"
):
    try:
        return v1.read_namespaced_pod_log(
            name=pod_name,
            namespace=namespace,
            tail_lines=100
        )
    except Exception as e:
        return str(e)


def get_events(
    namespace="default"
):
    try:
        events = v1.list_namespaced_event(namespace)

        return [
            event.message
            for event in events.items
        ]

    except Exception as e:
        return [str(e)]