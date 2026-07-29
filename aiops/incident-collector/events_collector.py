from kubernetes import client

def get_events(
    namespace,
):

    v1 = client.CoreV1Api()

    events = v1.list_namespaced_event(
        namespace
    )

    return [

        event.message

        for event in events.items
    ]