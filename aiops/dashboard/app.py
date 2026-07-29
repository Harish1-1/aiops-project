from __future__ import annotations

import json
from typing import Any

import requests
import streamlit as st
import pandas as pd


API_BASE_URL = "http://127.0.0.1:8000"
ANALYZE_URL = f"{API_BASE_URL}/analyze"
INCIDENTS_URL = f"{API_BASE_URL}/incidents"


st.set_page_config(
    page_title="Agentic AIOps SRE Copilot",
    page_icon="🤖",
    layout="wide",
)

WORKFLOW_STATUS_ICONS = {
    "NOT_STARTED": "⚪",
    "RUNNING": "🔵",
    "COMPLETED": "🟢",
    "FAILED": "🔴",
    "SKIPPED": "🟡",
}


WORKFLOW_STATUS_LABELS = {
    "NOT_STARTED": "Not Started",
    "RUNNING": "Running",
    "COMPLETED": "Completed",
    "FAILED": "Failed",
    "SKIPPED": "Skipped",
}


def _safe_result(
    incident_or_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Accept either:
    - a complete incident object containing ``result``, or
    - the workflow result dictionary itself.

    This keeps the timeline compatible with both the manual-analysis
    response and incidents loaded from history.
    """

    if not isinstance(
        incident_or_result,
        dict,
    ):
        return {}

    if (
        "workflow_stages" in incident_or_result
        or "workflow_summary" in incident_or_result
    ):
        return incident_or_result

    result = incident_or_result.get(
        "result",
        {},
    )

    return (
        result
        if isinstance(result, dict)
        else {}
    )


def _workflow_stages(
    incident: dict[str, Any],
) -> list[dict[str, Any]]:
    result = _safe_result(
        incident
    )

    stages = result.get(
        "workflow_stages",
        [],
    )

    if not isinstance(
        stages,
        list,
    ):
        return []

    return [
        stage
        for stage in stages
        if isinstance(stage, dict)
    ]


def _workflow_summary(
    incident: dict[str, Any],
) -> dict[str, Any]:
    result = _safe_result(
        incident
    )

    summary = result.get(
        "workflow_summary",
        {},
    )

    return (
        summary
        if isinstance(summary, dict)
        else {}
    )


def _format_duration(
    duration_ms: Any,
) -> str:
    if not isinstance(
        duration_ms,
        (int, float),
    ):
        return "Unavailable"

    if duration_ms < 1000:
        return f"{round(duration_ms)} ms"

    seconds = duration_ms / 1000

    if seconds < 60:
        return f"{seconds:.2f} s"

    minutes = seconds / 60

    return f"{minutes:.2f} min"


def _stage_details_text(
    details: Any,
) -> str:
    if not isinstance(
        details,
        dict,
    ):
        return "No stage details recorded."

    if not details:
        return "No stage details recorded."

    lines = []

    for key, value in details.items():
        label = (
            str(key)
            .replace("_", " ")
            .title()
        )

        lines.append(
            f"**{label}:** `{value}`"
        )

    return "\n\n".join(lines)


def render_workflow_timeline(
    incident: dict[str, Any],
) -> None:
    """
    Render the saved LangGraph stage history.

    Old incidents remain compatible. They will show a message instead
    of failing if workflow-stage tracking was not yet enabled.
    """

    stages = _workflow_stages(
        incident
    )

    summary = _workflow_summary(
        incident
    )

    st.subheader(
        "Workflow Execution Timeline"
    )

    if not stages:
        st.info(
            (
                "Workflow-stage history is not available for this "
                "incident. It may have been created before Step 22 "
                "stage tracking was enabled."
            )
        )

        return

    overall_status = str(
        summary.get(
            "overall_status",
            "UNKNOWN",
        )
    )

    status_icon = (
        WORKFLOW_STATUS_ICONS.get(
            overall_status,
            "⚪",
        )
    )

    metric_columns = st.columns(5)

    metric_columns[0].metric(
        "Overall",
        f"{status_icon} {overall_status}",
    )

    metric_columns[1].metric(
        "Completed",
        summary.get(
            "completed_stages",
            0,
        ),
    )

    metric_columns[2].metric(
        "Failed",
        summary.get(
            "failed_stages",
            0,
        ),
    )

    metric_columns[3].metric(
        "Skipped",
        summary.get(
            "skipped_stages",
            0,
        ),
    )

    metric_columns[4].metric(
        "Total Duration",
        _format_duration(
            summary.get(
                "total_duration_ms"
            )
        ),
    )

    st.markdown("---")

    for index, stage in enumerate(
        stages,
        start=1,
    ):
        status = str(
            stage.get(
                "status",
                "NOT_STARTED",
            )
        )

        icon = WORKFLOW_STATUS_ICONS.get(
            status,
            "⚪",
        )

        label = str(
            stage.get(
                "label",
                stage.get(
                    "stage",
                    "Unknown Stage",
                ),
            )
        )

        duration = _format_duration(
            stage.get(
                "duration_ms"
            )
        )

        title = (
            f"{index}. {icon} {label} — "
            f"{WORKFLOW_STATUS_LABELS.get(status, status)}"
        )

        with st.expander(
            title,
            expanded=(
                status
                in {
                    "FAILED",
                    "RUNNING",
                }
            ),
        ):
            stage_columns = st.columns(3)

            stage_columns[0].metric(
                "Status",
                WORKFLOW_STATUS_LABELS.get(
                    status,
                    status,
                ),
            )

            stage_columns[1].metric(
                "Duration",
                duration,
            )

            stage_columns[2].metric(
                "Stage Key",
                stage.get(
                    "stage",
                    "unknown",
                ),
            )

            st.markdown(
                f"""
**Started:** `{stage.get("started_at") or "Unavailable"}`

**Completed:** `{stage.get("completed_at") or "Unavailable"}`
"""
            )

            error = stage.get(
                "error"
            )

            if error:
                st.error(
                    str(error)
                )

            st.markdown(
                "#### Stage Details"
            )

            st.markdown(
                _stage_details_text(
                    stage.get(
                        "details",
                        {},
                    )
                )
            )

        if index < len(stages):
            st.markdown(
                "<div style='text-align:center;font-size:24px;'>↓</div>",
                unsafe_allow_html=True,
            )


def render_workflow_stage_table(
    incident: dict[str, Any],
) -> None:
    stages = _workflow_stages(
        incident
    )

    if not stages:
        return

    rows = []

    for stage in stages:
        status = str(
            stage.get(
                "status",
                "NOT_STARTED",
            )
        )

        rows.append(
            {
                "Stage": stage.get(
                    "label",
                    stage.get(
                        "stage",
                        "Unknown",
                    ),
                ),
                "Status": (
                    f"{WORKFLOW_STATUS_ICONS.get(status, '⚪')} "
                    f"{WORKFLOW_STATUS_LABELS.get(status, status)}"
                ),
                "Duration": _format_duration(
                    stage.get(
                        "duration_ms"
                    )
                ),
                "Started": stage.get(
                    "started_at"
                ),
                "Completed": stage.get(
                    "completed_at"
                ),
                "Error": stage.get(
                    "error"
                ),
            }
        )

    dataframe = pd.DataFrame(
        rows
    )

    st.dataframe(
        dataframe,
        use_container_width=True,
        hide_index=True,
    )


def _chat_history_key(
    incident_id: int,
) -> str:
    return (
        f"incident_chat_history_"
        f"{incident_id}"
    )


def _chat_input_key(
    incident_id: int,
) -> str:
    return (
        f"incident_chat_input_"
        f"{incident_id}"
    )


def _get_chat_history(
    incident_id: int,
) -> list[dict[str, str]]:
    key = _chat_history_key(
        incident_id
    )

    history = st.session_state.get(
        key
    )

    if not isinstance(
        history,
        list,
    ):
        history = []
        st.session_state[key] = history

    return history


def _add_chat_message(
    incident_id: int,
    role: str,
    content: str,
    mode: str | None = None,
) -> None:
    history = _get_chat_history(
        incident_id
    )

    history.append(
        {
            "role": role,
            "content": content,
            "mode": mode or "",
        }
    )

    st.session_state[
        _chat_history_key(
            incident_id
        )
    ] = history


def _clear_chat_history(
    incident_id: int,
) -> None:
    st.session_state[
        _chat_history_key(
            incident_id
        )
    ] = []


def render_incident_chat(
    incident_id: int,
    incident_status: str,
) -> None:
    """
    Render an incident-specific SRE Copilot conversation.

    The chatbot reads only the stored incident evidence and workflow
    result. It cannot execute Kubernetes commands or modify the cluster.
    """

    st.subheader(
        "SRE Copilot Chat"
    )

    st.caption(
        (
            "Ask evidence-grounded questions about this incident. "
            "The chatbot operates in recommendation-only mode and "
            "cannot execute Kubernetes commands."
        )
    )

    if incident_status in {
        "QUEUED",
        "RUNNING",
    }:
        st.info(
            (
                "The incident workflow is still running. "
                "Chat will be available after it completes."
            )
        )
        return

    suggested_questions = [
        "Why was this alert not confirmed?",
        "What was the highest memory usage?",
        "Did Loki show any errors?",
        "Which workload owns this pod?",
        "Did validation pass?",
        "What should an engineer investigate next?",
    ]

    st.markdown(
        "#### Suggested Questions"
    )

    suggestion_columns = st.columns(
        2
    )

    selected_suggestion: str | None = None

    for index, suggestion in enumerate(
        suggested_questions
    ):
        column = suggestion_columns[
            index % 2
        ]

        with column:
            if st.button(
                suggestion,
                key=(
                    f"chat_suggestion_"
                    f"{incident_id}_"
                    f"{index}"
                ),
                use_container_width=True,
            ):
                selected_suggestion = suggestion

    history = _get_chat_history(
        incident_id
    )

    if not history:
        st.info(
            (
                "No questions have been asked about this "
                "incident yet."
            )
        )

    for message in history:
        role = message.get(
            "role",
            "assistant",
        )

        content = message.get(
            "content",
            "",
        )

        mode = message.get(
            "mode",
            "",
        )

        with st.chat_message(
            role
        ):
            st.markdown(
                content
            )

            if (
                role == "assistant"
                and mode
            ):
                st.caption(
                    f"Response mode: {mode}"
                )

    question = st.chat_input(
        (
            "Ask about alert evidence, RCA, "
            "metrics, logs, validation, or remediation..."
        ),
        key=_chat_input_key(
            incident_id
        ),
    )

    submitted_question = (
        selected_suggestion
        or question
    )

    if submitted_question:
        _add_chat_message(
            incident_id=incident_id,
            role="user",
            content=submitted_question,
        )

        with st.chat_message(
            "user"
        ):
            st.markdown(
                submitted_question
            )

        with st.chat_message(
            "assistant"
        ):
            with st.spinner(
                "SRE Copilot is reviewing the incident evidence..."
            ):
                try:
                    response = (
                        ask_incident_copilot(
                            incident_id=incident_id,
                            question=submitted_question,
                        )
                    )

                except requests.ConnectionError:
                    error_message = (
                        "Could not connect to FastAPI. "
                        "Confirm Uvicorn is running on port 8000."
                    )

                    st.error(
                        error_message
                    )

                    _add_chat_message(
                        incident_id=incident_id,
                        role="assistant",
                        content=error_message,
                        mode="error",
                    )

                    return

                except requests.Timeout:
                    error_message = (
                        "The SRE Copilot request timed out. "
                        "The local LLM may still be loading."
                    )

                    st.error(
                        error_message
                    )

                    _add_chat_message(
                        incident_id=incident_id,
                        role="assistant",
                        content=error_message,
                        mode="error",
                    )

                    return

                except requests.HTTPError as exc:
                    response_text = (
                        exc.response.text
                        if exc.response is not None
                        else ""
                    )

                    error_message = (
                        "The SRE Copilot request failed.\n\n"
                        f"{response_text or str(exc)}"
                    )

                    st.error(
                        error_message
                    )

                    _add_chat_message(
                        incident_id=incident_id,
                        role="assistant",
                        content=error_message,
                        mode="error",
                    )

                    return

                answer = str(
                    response.get(
                        "answer",
                        "No answer was returned.",
                    )
                )

                mode = str(
                    response.get(
                        "mode",
                        "unknown",
                    )
                )

                st.markdown(
                    answer
                )

                st.caption(
                    f"Response mode: {mode}"
                )

                _add_chat_message(
                    incident_id=incident_id,
                    role="assistant",
                    content=answer,
                    mode=mode,
                )

        st.rerun()

    st.divider()

    clear_column, safety_column = st.columns(
        [1, 3]
    )

    with clear_column:
        if st.button(
            "Clear Chat",
            key=(
                f"clear_incident_chat_"
                f"{incident_id}"
            ),
            use_container_width=True,
        ):
            _clear_chat_history(
                incident_id
            )

            st.rerun()

    with safety_column:
        st.warning(
            (
                "The SRE Copilot explains evidence and recommendations "
                "only. Cluster-changing actions require the separate "
                "human approval and GitOps workflow."
            )
        )



def default_incident() -> dict[str, Any]:
    return {
        "alert": "OOMKilled",
        "namespace": "production",
        "pod": "payment-service",
        "logs": [
            "java.lang.OutOfMemoryError: Java heap space",
            "Container terminated",
        ],
        "events": [
            "OOMKilled",
            "Container restarted",
        ],
        "metrics": {
            "cpu": "45%",
            "memory": "99%",
        },
        "restart_count": 2,
    }


def api_get(
    url: str,
    timeout: int = 30,
) -> Any:
    response = requests.get(
        url,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def api_post(
    url: str,
    payload: dict[str, Any],
    timeout: int = 900,
) -> Any:
    response = requests.post(
        url,
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()

def ask_incident_copilot(
    incident_id: int,
    question: str,
) -> dict[str, Any]:
    """
    Ask the SRE Copilot a question about one stored incident.
    """

    return api_post(
        (
            f"{INCIDENTS_URL}/"
            f"{incident_id}/chat"
        ),
        {
            "question": question,
        },
        timeout=900,
    )


def display_status(result: dict[str, Any]) -> None:
    approval_status = result.get(
        "approval_status",
        "NOT APPROVED",
    )

    retry_count = result.get("retry_count", 0)

    violations = result.get(
        "policy_violations",
        [],
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Approval Status",
        approval_status,
    )

    col2.metric(
        "Correction Attempts",
        retry_count,
    )

    col3.metric(
        "Policy Violations",
        len(violations),
    )

    if approval_status == "APPROVED FOR HUMAN REVIEW":
        st.success(
            "The recommendation passed validation and policy checks. "
            "Human review is still required."
        )
    else:
        st.error(
            "The proposed remediation was rejected. Do not execute it."
        )


def display_policy_violations(
    violations: list[str],
) -> None:
    st.subheader("Deterministic Policy Violations")

    if not violations:
        st.success(
            "No deterministic policy violations were found."
        )
        return

    for violation in violations:
        st.error(violation)


def display_workflow_results(
    result: dict[str, Any],
    incident_id: int | None = None,
    incident_status: str = "COMPLETED",
) -> None:
    """
    Display the complete workflow result.

    Stored incidents include the workflow timeline and SRE Copilot chat.
    Manual, unsaved analyses omit the chat tab because they do not have
    a persistent incident ID.
    """

    display_status(
        result
    )

    st.divider()

    tab_names = [
        "Workflow Timeline",
        "Investigation",
        "Root Cause Analysis",
        "Remediation",
        "Validation",
        "Final Report",
    ]

    if incident_id is not None:
        tab_names.append(
            "SRE Copilot Chat"
        )

    tabs = st.tabs(
        tab_names
    )

    timeline_tab = tabs[0]
    investigation_tab = tabs[1]
    rca_tab = tabs[2]
    remediation_tab = tabs[3]
    validation_tab = tabs[4]
    report_tab = tabs[5]

    with timeline_tab:
        render_workflow_timeline(
            result
        )

        st.markdown("---")

        with st.expander(
            "Workflow Stage Table",
            expanded=False,
        ):
            render_workflow_stage_table(
                result
            )

    with investigation_tab:
        st.json(
            result.get(
                "investigation",
                {},
            )
        )

    with rca_tab:
        analysis = result.get(
            "analysis"
        )

        if analysis:
            st.markdown(
                analysis
            )

        else:
            st.warning(
                (
                    "No RCA output was stored for this incident. "
                    "This may be an older or failed workflow record."
                )
            )

    with remediation_tab:
        st.markdown(
            result.get(
                "remediation",
                "No remediation output was returned.",
            )
        )

    with validation_tab:
        display_policy_violations(
            result.get(
                "policy_violations",
                [],
            )
        )

        st.markdown(
            result.get(
                "validation",
                "No validation output was returned.",
            )
        )

    with report_tab:
        st.markdown(
            result.get(
                "report",
                "No final report was returned.",
            )
        )

    if incident_id is not None:
        chat_tab = tabs[6]

        with chat_tab:
            render_incident_chat(
                incident_id=incident_id,
                incident_status=incident_status,
            )


def render_manual_analysis() -> None:
    st.title("Agentic AIOps SRE Copilot")

    st.caption(
        "RAG-powered Kubernetes incident investigation, RCA, "
        "remediation planning, validation, and reporting."
    )

    st.warning(
        "Recommendation-only mode: this dashboard does not execute "
        "Kubernetes commands or modify manifests."
    )

    defaults = default_incident()

    st.sidebar.header("Incident Input")

    input_mode = st.sidebar.radio(
        "Choose input method",
        [
            "Form",
            "Raw JSON",
        ],
        key="manual_input_mode",
    )

    incident: dict[str, Any]

    if input_mode == "Form":
        alert = st.sidebar.text_input(
            "Alert",
            value=defaults["alert"],
        )

        namespace = st.sidebar.text_input(
            "Namespace",
            value=defaults["namespace"],
        )

        pod = st.sidebar.text_input(
            "Pod or workload",
            value=defaults["pod"],
        )

        cpu = st.sidebar.text_input(
            "CPU usage",
            value=defaults["metrics"]["cpu"],
        )

        memory = st.sidebar.text_input(
            "Memory usage",
            value=defaults["metrics"]["memory"],
        )

        restart_count = st.sidebar.number_input(
            "Restart count",
            min_value=0,
            value=defaults["restart_count"],
        )

        logs_text = st.sidebar.text_area(
            "Logs, one entry per line",
            value="\n".join(defaults["logs"]),
            height=130,
        )

        events_text = st.sidebar.text_area(
            "Events, one entry per line",
            value="\n".join(defaults["events"]),
            height=100,
        )

        incident = {
            "alert": alert.strip(),
            "namespace": namespace.strip(),
            "pod": pod.strip(),
            "logs": [
                line.strip()
                for line in logs_text.splitlines()
                if line.strip()
            ],
            "events": [
                line.strip()
                for line in events_text.splitlines()
                if line.strip()
            ],
            "metrics": {
                "cpu": cpu.strip(),
                "memory": memory.strip(),
            },
            "restart_count": int(restart_count),
        }

    else:
        raw_json = st.sidebar.text_area(
            "Incident JSON",
            value=json.dumps(
                defaults,
                indent=2,
            ),
            height=500,
        )

        try:
            incident = json.loads(raw_json)

        except json.JSONDecodeError as exc:
            st.sidebar.error(
                f"Invalid JSON: {exc}"
            )
            return

    st.subheader("Incident Preview")
    st.json(incident)

    analyze_clicked = st.button(
        "Analyze Incident",
        type="primary",
        use_container_width=True,
    )

    if not analyze_clicked:
        return

    with st.spinner(
        "Running the complete Agentic AIOps workflow..."
    ):
        try:
            result = api_post(
                ANALYZE_URL,
                incident,
            )

        except requests.ConnectionError:
            st.error(
                "Could not connect to FastAPI. "
                "Start Uvicorn on port 8000."
            )
            return

        except requests.Timeout:
            st.error(
                "The workflow timed out."
            )
            return

        except requests.HTTPError as exc:
            response_text = (
                exc.response.text
                if exc.response is not None
                else ""
            )

            st.error(
                f"API request failed: {exc}\n\n{response_text}"
            )
            return

    st.success("Incident workflow completed.")
    display_workflow_results(result)


def status_badge(status: str) -> str:
    mapping = {
        "QUEUED": "🟡 QUEUED",
        "RUNNING": "🔵 RUNNING",
        "COMPLETED": "🟢 COMPLETED",
        "FAILED": "🔴 FAILED",
    }

    return mapping.get(
        status,
        status,
    )


def approval_badge(
    approval_status: str,
) -> str:
    if approval_status == "APPROVED FOR HUMAN REVIEW":
        return "🟢 APPROVED FOR HUMAN REVIEW"

    if approval_status == "PENDING":
        return "🟡 PENDING"

    return "🔴 NOT APPROVED"


def render_incident_history() -> None:
    st.title("Live Incident History")

    st.caption(
        "Incidents received automatically from Prometheus "
        "Alertmanager."
    )

    selected_key = "selected_incident_id"

    if selected_key not in st.session_state:
        st.session_state[selected_key] = None

    refresh_col, limit_col = st.columns(
        [1, 3]
    )

    with refresh_col:
        refresh_clicked = st.button(
            "Refresh",
            use_container_width=True,
        )

    with limit_col:
        limit = st.selectbox(
            "Number of incidents",
            options=[
                10,
                25,
                50,
                100,
            ],
            index=1,
        )

    if refresh_clicked:
        st.rerun()

    try:
        incidents = api_get(
            f"{INCIDENTS_URL}?limit={limit}"
        )

    except requests.ConnectionError:
        st.error(
            "Could not connect to FastAPI on port 8000."
        )
        return

    except requests.HTTPError as exc:
        st.error(
            f"Could not retrieve incidents: {exc}"
        )
        return

    if not incidents:
        st.info(
            "No incidents have been stored yet."
        )
        return

    queued_count = sum(
        1
        for item in incidents
        if item["status"] == "QUEUED"
    )

    running_count = sum(
        1
        for item in incidents
        if item["status"] == "RUNNING"
    )

    completed_count = sum(
        1
        for item in incidents
        if item["status"] == "COMPLETED"
    )

    failed_count = sum(
        1
        for item in incidents
        if item["status"] == "FAILED"
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Queued", queued_count)
    col2.metric("Running", running_count)
    col3.metric("Completed", completed_count)
    col4.metric("Failed", failed_count)

    st.divider()
    st.subheader("Incidents")

    selected_incident_id = st.session_state.get(
        selected_key
    )

    for incident in incidents:
        incident_id = incident["id"]
        is_selected = (
            selected_incident_id == incident_id
        )

        title = (
            f"#{incident_id} · "
            f"{incident['alert']} · "
            f"{incident['namespace']}/{incident['pod']}"
        )

        with st.expander(
            title,
            expanded=is_selected,
        ):
            col1, col2, col3 = st.columns(3)

            col1.write(
                f"**Status:** "
                f"{status_badge(incident['status'])}"
            )

            col2.write(
                f"**Approval:** "
                f"{approval_badge(incident['approval_status'])}"
            )

            col3.write(
                f"**Retries:** "
                f"{incident['retry_count']}"
            )

            st.write(
                f"**Created:** {incident['created_at']}"
            )

            st.write(
                f"**Updated:** {incident['updated_at']}"
            )

            if incident.get("error"):
                st.error(incident["error"])

            if not is_selected:
                if st.button(
                    "Open Incident Details",
                    key=f"open_incident_{incident_id}",
                    use_container_width=True,
                ):
                    st.session_state[selected_key] = incident_id
                    st.rerun()

                continue

            close_col, spacer_col = st.columns([1, 3])

            with close_col:
                if st.button(
                    "Close Details",
                    key=f"close_incident_{incident_id}",
                    use_container_width=True,
                ):
                    st.session_state[selected_key] = None
                    st.rerun()

            try:
                details = api_get(
                    f"{INCIDENTS_URL}/{incident_id}"
                )

            except requests.HTTPError as exc:
                st.error(
                    f"Could not retrieve incident details: {exc}"
                )
                continue

            st.subheader(
                f"Incident #{incident_id}"
            )

            st.json(
                details.get(
                    "incident",
                    {},
                )
            )

            result = details.get("result")

            if result:
                display_workflow_results(
                    result=result,
                    incident_id=incident_id,
                    incident_status=str(
                        details.get(
                            "status",
                            "UNKNOWN",
                        )
                    ),
                )

            elif details["status"] == "RUNNING":
                st.info(
                    "The Agentic AIOps workflow is still running. "
                    "Refresh this page after a few minutes."
                )

            elif details["status"] == "FAILED":
                st.error(
                    details.get(
                        "error",
                        "The workflow failed.",
                    )
                )

            else:
                st.info(
                    "The incident is queued and has not started yet."
                )



def approval_api_action(
    incident_id: int,
    action: str,
    reviewer: str,
    comment: str,
) -> dict[str, Any]:
    return api_post(
        f"{INCIDENTS_URL}/{incident_id}/{action}",
        {"reviewer": reviewer, "comment": comment},
        timeout=120,
    )


def render_approval_queue() -> None:
    st.title("Human Approval Queue")
    st.caption(
        "Review validated recommendations before any GitOps, GitHub, or ArgoCD activity. "
        "Direct cluster mutation remains disabled."
    )

    try:
        pending = api_get(f"{INCIDENTS_URL}/pending-approval?limit=100")
    except requests.RequestException as exc:
        st.error(f"Could not load the approval queue: {exc}")
        return

    if not pending:
        st.success("No incidents are waiting for human approval.")
        return

    for item in pending:
        incident_id = int(item["id"])
        title = f"#{incident_id} · {item['alert']} · {item['namespace']}/{item['pod']}"
        with st.expander(title, expanded=False):
            try:
                details = api_get(f"{INCIDENTS_URL}/{incident_id}")
            except requests.RequestException as exc:
                st.error(f"Could not load incident details: {exc}")
                continue

            result = details.get("result") or {}
            st.write(f"**Workflow status:** {details.get('status')}")
            st.write(f"**Approval status:** {details.get('approval_status')}")
            st.write(f"**Validation passed:** {result.get('validation_passed')}")
            st.write(f"**Policy violations:** {len(result.get('policy_violations', []))}")

            with st.expander("Review RCA and Remediation", expanded=False):
                st.markdown("### Root Cause Analysis")
                st.markdown(result.get("analysis", "No RCA available."))
                st.markdown("### Deterministic Remediation")
                st.markdown(result.get("remediation", "No remediation available."))
                st.markdown("### Validation")
                st.markdown(result.get("validation", "No validation available."))

            reviewer = st.text_input(
                "Reviewer",
                key=f"approval_reviewer_{incident_id}",
                placeholder="Engineer name",
            )
            comment = st.text_area(
                "Decision comment",
                key=f"approval_comment_{incident_id}",
                placeholder="Reason for approving or rejecting",
            )

            approve_col, reject_col = st.columns(2)
            with approve_col:
                approve_clicked = st.button(
                    "Approve Recommendation",
                    key=f"approve_{incident_id}",
                    type="primary",
                    use_container_width=True,
                )
            with reject_col:
                reject_clicked = st.button(
                    "Reject Recommendation",
                    key=f"reject_{incident_id}",
                    use_container_width=True,
                )

            action = "approve" if approve_clicked else "reject" if reject_clicked else None
            if action:
                if not reviewer.strip():
                    st.error("Reviewer name is required.")
                else:
                    try:
                        response = approval_api_action(
                            incident_id, action, reviewer.strip(), comment.strip()
                        )
                        if action == "approve":
                            st.success("Recommendation approved and audit event recorded.")
                        else:
                            st.warning("Recommendation rejected and audit event recorded.")
                        st.json(response.get("downstream", {}))
                        st.rerun()
                    except requests.HTTPError as exc:
                        body = exc.response.text if exc.response is not None else str(exc)
                        st.error(body)


def render_audit_history() -> None:
    st.title("Approval Audit History")
    try:
        incidents = api_get(f"{INCIDENTS_URL}?limit=100")
    except requests.RequestException as exc:
        st.error(f"Could not load incidents: {exc}")
        return

    reviewed = [item for item in incidents if item.get("approval_status") in {"HUMAN APPROVED", "HUMAN REJECTED"}]
    if not reviewed:
        st.info("No human approval decisions have been recorded yet.")
        return

    for item in reviewed:
        incident_id = int(item["id"])
        with st.expander(f"#{incident_id} · {item['alert']} · {item['approval_status']}"):
            try:
                events = api_get(f"{INCIDENTS_URL}/{incident_id}/audit")
            except requests.RequestException as exc:
                st.error(str(exc))
                continue
            for event in events:
                st.markdown(
                    f"**{event.get('decision')}** by `{event.get('reviewer')}` at "
                    f"`{event.get('created_at')}`"
                )
                st.write(event.get("comment") or "No comment")
                st.json(event.get("downstream", {}))
                st.divider()


def main() -> None:
    page = st.sidebar.radio(
        "Navigation",
        [
            "Manual Analysis",
            "Incident History",
            "Approval Queue",
            "Approval Audit",
        ],
    )

    if page == "Manual Analysis":
        render_manual_analysis()
    elif page == "Incident History":
        render_incident_history()
    elif page == "Approval Queue":
        render_approval_queue()
    else:
        render_audit_history()


if __name__ == "__main__":
    main()