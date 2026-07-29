from __future__ import annotations

import base64
import logging
import os
from typing import Any
from urllib.parse import quote

import requests


LOGGER = logging.getLogger(__name__)

_GITHUB_API_VERSION = "2022-11-28"
_REQUEST_TIMEOUT_SECONDS = 30


def _headers(
    token: str,
) -> dict[str, str]:
    return {
        "Authorization": (
            f"Bearer {token}"
        ),
        "Accept": (
            "application/vnd.github+json"
        ),
        "X-GitHub-Api-Version": (
            _GITHUB_API_VERSION
        ),
    }


def _request(
    method: str,
    url: str,
    token: str,
    **kwargs: Any,
) -> requests.Response:
    response = requests.request(
        method=method,
        url=url,
        headers=_headers(
            token
        ),
        timeout=(
            _REQUEST_TIMEOUT_SECONDS
        ),
        **kwargs,
    )

    response.raise_for_status()

    return response


def _safe_dict(
    value: Any,
) -> dict[str, Any]:
    return (
        value
        if isinstance(
            value,
            dict,
        )
        else {}
    )


def _enabled() -> bool:
    return (
        os.getenv(
            "GITHUB_GITOPS_ENABLED",
            "false",
        )
        .strip()
        .lower()
        == "true"
    )


def _repository() -> str:
    return os.getenv(
        "GITHUB_REPOSITORY",
        "Harish1-1/aiops-project",
    ).strip()


def _base_branch() -> str:
    return os.getenv(
        "GITHUB_BASE_BRANCH",
        "main",
    ).strip()


def _incident_branch(
    plan: dict[str, Any],
) -> str:
    incident_id = plan.get(
        "incident_id"
    )

    return (
        f"aiops/incident-{incident_id}"
    )


def _encode_ref(
    ref: str,
) -> str:
    """
    GitHub branch names may contain slashes.

    Encode each ref when placing it inside an API URL.
    """

    return quote(
        ref,
        safe="",
    )


def _encode_repository_path(
    path: str,
) -> str:
    """
    Preserve repository path separators while URL-encoding each segment.
    """

    return "/".join(
        quote(
            segment,
            safe="",
        )
        for segment in path.split(
            "/"
        )
    )


def _decode_github_content(
    payload: dict[str, Any],
) -> str | None:
    encoded = payload.get(
        "content"
    )

    encoding = str(
        payload.get(
            "encoding",
            "",
        )
    ).lower()

    if (
        not isinstance(
            encoded,
            str,
        )
        or encoding != "base64"
    ):
        return None

    try:
        compact = "".join(
            encoded.split()
        )

        return (
            base64.b64decode(
                compact
            )
            .decode(
                "utf-8"
            )
        )

    except (
        ValueError,
        UnicodeDecodeError,
    ):
        return None


def _normalise_text(
    value: str,
) -> str:
    """
    Avoid duplicate commits caused only by line-ending or final-newline
    differences.
    """

    normalised = (
        value
        .replace(
            "\r\n",
            "\n",
        )
        .replace(
            "\r",
            "\n",
        )
    )

    if not normalised.endswith(
        "\n"
    ):
        normalised += "\n"

    return normalised


def _get_branch_ref(
    *,
    api: str,
    branch: str,
    token: str,
) -> dict[str, Any] | None:
    encoded_branch = _encode_ref(
        branch
    )

    try:
        return _request(
            "GET",
            (
                f"{api}/git/ref/heads/"
                f"{encoded_branch}"
            ),
            token,
        ).json()

    except requests.HTTPError as error:
        if (
            error.response is not None
            and error.response.status_code
            == 404
        ):
            return None

        raise


def _create_branch(
    *,
    api: str,
    branch: str,
    base_sha: str,
    token: str,
) -> None:
    _request(
        "POST",
        f"{api}/git/refs",
        token,
        json={
            "ref": (
                f"refs/heads/{branch}"
            ),
            "sha": base_sha,
        },
    )


def _get_repository_file(
    *,
    api: str,
    repository_path: str,
    ref: str,
    token: str,
) -> dict[str, Any] | None:
    encoded_path = (
        _encode_repository_path(
            repository_path
        )
    )

    try:
        return _request(
            "GET",
            (
                f"{api}/contents/"
                f"{encoded_path}"
            ),
            token,
            params={
                "ref": ref,
            },
        ).json()

    except requests.HTTPError as error:
        if (
            error.response is not None
            and error.response.status_code
            == 404
        ):
            return None

        raise


def _find_open_pull_request(
    *,
    api: str,
    repository: str,
    branch: str,
    base_branch: str,
    token: str,
) -> dict[str, Any] | None:
    owner = repository.split(
        "/",
        1,
    )[0]

    pull_requests = _request(
        "GET",
        f"{api}/pulls",
        token,
        params={
            "state": "open",
            "head": (
                f"{owner}:{branch}"
            ),
            "base": base_branch,
        },
    ).json()

    if (
        isinstance(
            pull_requests,
            list,
        )
        and pull_requests
    ):
        first = pull_requests[
            0
        ]

        if isinstance(
            first,
            dict,
        ):
            return first

    return None


def _latest_branch_commit_sha(
    branch_ref: dict[str, Any] | None,
) -> str | None:
    if not branch_ref:
        return None

    object_data = _safe_dict(
        branch_ref.get(
            "object"
        )
    )

    sha = object_data.get(
        "sha"
    )

    return (
        str(sha)
        if sha
        else None
    )


def _build_pull_request_body(
    plan: dict[str, Any],
) -> str:
    retrieved_runbooks = plan.get(
        "retrieved_runbooks",
        [],
    )

    runbook_lines: list[str] = []

    if isinstance(
        retrieved_runbooks,
        list,
    ):
        for runbook in (
            retrieved_runbooks
        ):
            if not isinstance(
                runbook,
                dict,
            ):
                continue

            title = str(
                runbook.get(
                    "title",
                    "Unknown",
                )
            )

            filename = str(
                runbook.get(
                    "file",
                    "",
                )
            )

            score = runbook.get(
                "score"
            )

            line = f"- {title}"

            if filename:
                line += (
                    f" (`{filename}`)"
                )

            if score is not None:
                try:
                    line += (
                        f" — score "
                        f"{float(score):.4f}"
                    )
                except (
                    TypeError,
                    ValueError,
                ):
                    pass

            runbook_lines.append(
                line
            )

    runbook_section = (
        "\n".join(
            runbook_lines
        )
        if runbook_lines
        else "- No runbook metadata recorded."
    )

    change = _safe_dict(
        plan.get(
            "repository_change"
        )
    )

    changed_path = str(
        change.get(
            "path",
            "Unknown",
        )
    )

    change_type = str(
        plan.get(
            "change_type",
            "Unknown",
        )
    )

    patch_engine = str(
        plan.get(
            "patch_engine",
            "deterministic",
        )
    )

    confirmation_reasons = (
        plan.get(
            "confirmation_reasons",
            [],
        )
    )

    confirmation_lines: list[str] = []

    if isinstance(
        confirmation_reasons,
        list,
    ):
        confirmation_lines = [
            f"- {str(reason)}"
            for reason
            in confirmation_reasons
        ]

    confirmation_section = (
        "\n".join(
            confirmation_lines
        )
        if confirmation_lines
        else "- No confirmation reasons recorded."
    )

    return f"""
## AIOps GitOps Proposal

Automated GitOps proposal for AIOps incident #{plan.get("incident_id")}.

### Incident

- Alert: `{plan.get("alert")}`
- Normalized alert: `{plan.get("normalized_alert")}`
- Namespace: `{plan.get("namespace")}`
- Pod: `{plan.get("pod")}`
- Workload: `{plan.get("workload_kind")}/{plan.get("workload_name")}`
- Change type: `{change_type}`
- Patch engine: `{patch_engine}`
- Repository path: `{changed_path}`

### Evidence Confirmation

{confirmation_section}

### Retrieved Runbooks

{runbook_section}

### Safety Controls

- Deterministic validation passed before this pull request was created.
- Human approval was recorded before GitHub write actions were enabled.
- The language model proposed the candidate change but did not approve it.
- The proposal was checked against repository YAML and runbook policy.
- No direct Kubernetes mutation was executed.
- ArgoCD must apply the change only after a human merges this pull request.

### Reason

{plan.get("reason", "No reason recorded.")}

### Review Requirement

This pull request must be reviewed and merged by a human.
""".strip()


def _dry_run_result(
    *,
    plan: dict[str, Any],
    repository: str,
    base_branch: str,
    branch: str,
    change: dict[str, Any],
) -> dict[str, Any]:
    return {
        "status": "DRY_RUN",
        "repository": repository,
        "base_branch": (
            base_branch
        ),
        "proposed_branch": branch,
        "path": change.get(
            "path"
        ),
        "diff": change.get(
            "diff",
            "",
        ),
        "reason": (
            "GitHub write actions are disabled."
        ),
        "incident_id": plan.get(
            "incident_id"
        ),
    }


def create_github_pr(
    plan: dict[str, Any],
) -> dict[str, Any]:
    """
    Create or reuse one GitHub pull request for a validated GitOps plan.

    Idempotency rules:

    - If the same incident branch already has an open PR and the proposed
      repository content is unchanged, return PR_EXISTS without committing.
    - If the branch exists but the content differs, commit only the new
      content and reuse the existing open PR.
    - If no PR exists, create one after the branch contains the proposed
      content.
    """

    repository = _repository()
    base_branch = _base_branch()
    branch = _incident_branch(
        plan
    )

    status = str(
        plan.get(
            "status",
            "",
        )
    )

    if status == "NO_CHANGE_REQUIRED":
        return {
            "status": "SKIPPED",
            "reason": (
                "No GitOps change is required."
            ),
            "repository": repository,
        }

    if status != "PATCH_READY":
        return {
            "status": "BLOCKED",
            "reason": plan.get(
                "reason",
                (
                    "GitOps patch is not ready."
                ),
            ),
            "repository": repository,
        }

    change = _safe_dict(
        plan.get(
            "repository_change"
        )
    )

    repository_path = str(
        change.get(
            "path",
            "",
        )
    ).strip()

    proposed_content = change.get(
        "content"
    )

    if (
        not repository_path
        or not isinstance(
            proposed_content,
            str,
        )
        or not proposed_content
    ):
        return {
            "status": "BLOCKED",
            "reason": (
                "The GitOps plan does not contain a validated "
                "repository file change."
            ),
            "repository": repository,
        }

    dry_run = _dry_run_result(
        plan=plan,
        repository=repository,
        base_branch=base_branch,
        branch=branch,
        change=change,
    )

    if not _enabled():
        return dry_run

    token = os.getenv(
        "GITHUB_TOKEN",
        "",
    ).strip()

    if not token:
        return {
            **dry_run,
            "status": "BLOCKED",
            "reason": (
                "GITHUB_TOKEN is not configured."
            ),
        }

    if (
        not repository
        or "/" not in repository
    ):
        return {
            "status": "BLOCKED",
            "reason": (
                "GITHUB_REPOSITORY must use owner/repository format."
            ),
            "repository": repository,
        }

    api = (
        f"https://api.github.com/repos/"
        f"{repository}"
    )

    try:
        base_ref = _get_branch_ref(
            api=api,
            branch=base_branch,
            token=token,
        )

        base_sha = (
            _latest_branch_commit_sha(
                base_ref
            )
        )

        if not base_sha:
            return {
                "status": "ERROR",
                "reason": (
                    "The GitHub base branch could not be resolved."
                ),
                "repository": repository,
                "branch": branch,
            }

        branch_ref = _get_branch_ref(
            api=api,
            branch=branch,
            token=token,
        )

        if branch_ref is None:
            _create_branch(
                api=api,
                branch=branch,
                base_sha=base_sha,
                token=token,
            )

            branch_ref = _get_branch_ref(
                api=api,
                branch=branch,
                token=token,
            )

        existing_pr = (
            _find_open_pull_request(
                api=api,
                repository=repository,
                branch=branch,
                base_branch=base_branch,
                token=token,
            )
        )

        current_file = (
            _get_repository_file(
                api=api,
                repository_path=(
                    repository_path
                ),
                ref=branch,
                token=token,
            )
        )

        current_content = (
            _decode_github_content(
                current_file
            )
            if current_file
            else None
        )

        proposed_normalised = (
            _normalise_text(
                proposed_content
            )
        )

        current_normalised = (
            _normalise_text(
                current_content
            )
            if current_content
            is not None
            else None
        )

        content_unchanged = (
            current_normalised
            == proposed_normalised
        )

        current_file_sha = (
            str(
                current_file.get(
                    "sha"
                )
            )
            if current_file
            and current_file.get(
                "sha"
            )
            else None
        )

        latest_commit_sha = (
            _latest_branch_commit_sha(
                branch_ref
            )
        )

        # Strong idempotency:
        # return the existing PR before writing another commit.
        if (
            existing_pr is not None
            and content_unchanged
        ):
            return {
                "status": "PR_EXISTS",
                "repository": repository,
                "base_branch": (
                    base_branch
                ),
                "branch": branch,
                "commit_sha": (
                    latest_commit_sha
                ),
                "pr_number": (
                    existing_pr.get(
                        "number"
                    )
                ),
                "pr_url": (
                    existing_pr.get(
                        "html_url"
                    )
                ),
                "path": (
                    repository_path
                ),
                "content_changed": False,
                "reason": (
                    "An open pull request already contains "
                    "the same validated repository content."
                ),
            }

        commit_sha: str | None = (
            latest_commit_sha
        )

        if not content_unchanged:
            encoded_path = (
                _encode_repository_path(
                    repository_path
                )
            )

            body: dict[str, Any] = {
                "message": (
                    "fix(aiops): remediate "
                    f"incident "
                    f"{plan.get('incident_id')}"
                ),
                "content": (
                    base64.b64encode(
                        proposed_normalised.encode(
                            "utf-8"
                        )
                    )
                    .decode(
                        "ascii"
                    )
                ),
                "branch": branch,
            }

            if current_file_sha:
                body["sha"] = (
                    current_file_sha
                )

            commit_response = _request(
                "PUT",
                (
                    f"{api}/contents/"
                    f"{encoded_path}"
                ),
                token,
                json=body,
            ).json()

            commit_data = _safe_dict(
                commit_response.get(
                    "commit"
                )
            )

            raw_commit_sha = (
                commit_data.get(
                    "sha"
                )
            )

            if raw_commit_sha:
                commit_sha = str(
                    raw_commit_sha
                )

        # The PR may already exist but require a newly generated commit.
        if existing_pr is not None:
            return {
                "status": "PR_EXISTS",
                "repository": repository,
                "base_branch": (
                    base_branch
                ),
                "branch": branch,
                "commit_sha": (
                    commit_sha
                ),
                "pr_number": (
                    existing_pr.get(
                        "number"
                    )
                ),
                "pr_url": (
                    existing_pr.get(
                        "html_url"
                    )
                ),
                "path": (
                    repository_path
                ),
                "content_changed": (
                    not content_unchanged
                ),
                "reason": (
                    "The existing pull request was reused."
                ),
            }

        pull_request = _request(
            "POST",
            f"{api}/pulls",
            token,
            json={
                "title": (
                    f"AIOps incident "
                    f"#{plan.get('incident_id')}: "
                    f"{plan.get('normalized_alert')}"
                ),
                "head": branch,
                "base": base_branch,
                "body": (
                    _build_pull_request_body(
                        plan
                    )
                ),
            },
        ).json()

        return {
            "status": "PR_CREATED",
            "repository": repository,
            "base_branch": (
                base_branch
            ),
            "branch": branch,
            "commit_sha": commit_sha,
            "pr_number": (
                pull_request.get(
                    "number"
                )
            ),
            "pr_url": (
                pull_request.get(
                    "html_url"
                )
            ),
            "path": repository_path,
            "content_changed": (
                not content_unchanged
            ),
        }

    except requests.HTTPError as error:
        response = error.response

        detail = (
            response.text
            if response is not None
            else str(error)
        )

        status_code = (
            response.status_code
            if response is not None
            else None
        )

        LOGGER.exception(
            "GitHub API request failed: "
            "status=%s detail=%s",
            status_code,
            detail,
        )

        return {
            "status": "ERROR",
            "reason": detail,
            "http_status": (
                status_code
            ),
            "repository": repository,
            "branch": branch,
        }

    except Exception as error:
        LOGGER.exception(
            "GitHub pull-request automation failed."
        )

        return {
            "status": "ERROR",
            "reason": str(error),
            "repository": repository,
            "branch": branch,
        }