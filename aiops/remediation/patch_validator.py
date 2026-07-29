from __future__ import annotations

import copy
import difflib
import re
from dataclasses import dataclass
from typing import Any

import yaml


class PatchValidationError(ValueError):
    """
    Raised when an AI-generated GitOps proposal violates deterministic
    safety rules.
    """


@dataclass(frozen=True)
class ValidatedPatch:
    """
    Result produced only after every deterministic patch check passes.
    """

    content: str
    diff: str
    operations: list[dict[str, Any]]
    changed_paths: list[str]


_ALWAYS_FORBIDDEN_PATH_PREFIXES = (
    "/apiVersion",
    "/kind",
    "/metadata/name",
    "/metadata/namespace",
    "/metadata/uid",
    "/metadata/resourceVersion",
    "/metadata/ownerReferences",
    "/spec/selector",
    "/status",
)

_DANGEROUS_COMMAND_PATTERNS = (
    r"\bkubectl\b",
    r"\bhelm\b",
    r"\bargocd\b",
    r"\bgit\s+(push|reset|clean|checkout)\b",
    r"\brm\s+-rf\b",
    r"\bmkfs\b",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bchmod\s+777\b",
    r"\bcurl\b.*\|\s*(sh|bash)\b",
    r"\bwget\b.*\|\s*(sh|bash)\b",
    r":\(\)\s*\{\s*:\|:&\s*\};:",
)

_RESOURCE_PATTERN = re.compile(
    r"^[0-9]+(?:\.[0-9]+)?"
    r"(?:m|Ki|Mi|Gi|Ti|Pi|Ei|n|u)?$"
)

_IMAGE_PATTERN = re.compile(
    r"^[A-Za-z0-9._/-]+"
    r"(?::[A-Za-z0-9._-]+)?"
    r"(?:@sha256:[a-fA-F0-9]{64})?$"
)


def _safe_dict(
    value: Any,
) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_list(
    value: Any,
) -> list[Any]:
    return value if isinstance(value, list) else []


def _normalise_path(
    value: Any,
) -> str:
    path = str(
        value or ""
    ).strip()

    if not path.startswith("/"):
        raise PatchValidationError(
            f"Patch path must start with '/': {path!r}"
        )

    while "//" in path:
        path = path.replace(
            "//",
            "/",
        )

    if path != "/" and path.endswith("/"):
        path = path[:-1]

    return path


def _decode_pointer_segment(
    value: str,
) -> str:
    return (
        value
        .replace("~1", "/")
        .replace("~0", "~")
    )


def _pointer_segments(
    path: str,
) -> list[str]:
    if path == "/":
        return []

    return [
        _decode_pointer_segment(
            segment
        )
        for segment in path.lstrip("/").split("/")
    ]


def _get_pointer_value(
    document: Any,
    path: str,
) -> Any:
    current = document

    for segment in _pointer_segments(
        path
    ):
        if isinstance(
            current,
            dict,
        ):
            if segment not in current:
                raise PatchValidationError(
                    f"YAML path does not exist: {path}"
                )

            current = current[
                segment
            ]

        elif isinstance(
            current,
            list,
        ):
            try:
                index = int(
                    segment
                )
            except ValueError as error:
                raise PatchValidationError(
                    f"Expected list index in path: {path}"
                ) from error

            if (
                index < 0
                or index >= len(current)
            ):
                raise PatchValidationError(
                    f"List index is out of range: {path}"
                )

            current = current[
                index
            ]

        else:
            raise PatchValidationError(
                f"Cannot traverse YAML path: {path}"
            )

    return current


def _set_pointer_value(
    document: Any,
    path: str,
    value: Any,
) -> None:
    segments = _pointer_segments(
        path
    )

    if not segments:
        raise PatchValidationError(
            "Replacing the entire Kubernetes resource is forbidden."
        )

    current = document

    for segment in segments[:-1]:
        if isinstance(
            current,
            dict,
        ):
            if segment not in current:
                raise PatchValidationError(
                    f"Parent YAML path does not exist: {path}"
                )

            current = current[
                segment
            ]

        elif isinstance(
            current,
            list,
        ):
            try:
                index = int(
                    segment
                )
            except ValueError as error:
                raise PatchValidationError(
                    f"Expected list index in path: {path}"
                ) from error

            if (
                index < 0
                or index >= len(current)
            ):
                raise PatchValidationError(
                    f"List index is out of range: {path}"
                )

            current = current[
                index
            ]

        else:
            raise PatchValidationError(
                f"Cannot traverse YAML path: {path}"
            )

    last = segments[-1]

    if isinstance(
        current,
        dict,
    ):
        if last not in current:
            raise PatchValidationError(
                f"Target YAML path does not exist: {path}"
            )

        current[last] = copy.deepcopy(
            value
        )
        return

    if isinstance(
        current,
        list,
    ):
        try:
            index = int(
                last
            )
        except ValueError as error:
            raise PatchValidationError(
                f"Expected list index in path: {path}"
            ) from error

        if (
            index < 0
            or index >= len(current)
        ):
            raise PatchValidationError(
                f"List index is out of range: {path}"
            )

        current[index] = copy.deepcopy(
            value
        )
        return

    raise PatchValidationError(
        f"Cannot update YAML path: {path}"
    )


def _path_matches_policy(
    path: str,
    allowed_paths: list[str],
) -> bool:
    for allowed in allowed_paths:
        normalised_allowed = (
            _normalise_path(
                allowed
            )
        )

        # Exact JSON pointer.
        if path == normalised_allowed:
            return True

        # Wildcard path, for example:
        # /spec/template/spec/containers/*/resources/limits/memory
        allowed_segments = (
            _pointer_segments(
                normalised_allowed
            )
        )

        actual_segments = (
            _pointer_segments(
                path
            )
        )

        if (
            len(allowed_segments)
            != len(actual_segments)
        ):
            continue

        matched = all(
            expected == "*"
            or expected == actual
            for expected, actual
            in zip(
                allowed_segments,
                actual_segments,
            )
        )

        if matched:
            return True

    return False


def _validate_forbidden_path(
    path: str,
) -> None:
    for prefix in (
        _ALWAYS_FORBIDDEN_PATH_PREFIXES
    ):
        if (
            path == prefix
            or path.startswith(
                f"{prefix}/"
            )
        ):
            raise PatchValidationError(
                f"Modification of protected YAML path is forbidden: "
                f"{path}"
            )


def _all_strings(
    value: Any,
) -> list[str]:
    strings: list[str] = []

    if isinstance(
        value,
        str,
    ):
        strings.append(
            value
        )

    elif isinstance(
        value,
        list,
    ):
        for item in value:
            strings.extend(
                _all_strings(
                    item
                )
            )

    elif isinstance(
        value,
        dict,
    ):
        for item in value.values():
            strings.extend(
                _all_strings(
                    item
                )
            )

    return strings


def _validate_no_dangerous_commands(
    value: Any,
) -> None:
    for text in _all_strings(
        value
    ):
        for pattern in (
            _DANGEROUS_COMMAND_PATTERNS
        ):
            if re.search(
                pattern,
                text,
                flags=re.IGNORECASE,
            ):
                raise PatchValidationError(
                    "The proposed value contains a forbidden "
                    f"operational command: {pattern}"
                )


def _validate_resource_value(
    path: str,
    value: Any,
) -> None:
    if "/resources/" not in path:
        return

    if not isinstance(
        value,
        str,
    ):
        raise PatchValidationError(
            f"Resource value must be a string: {path}"
        )

    if not _RESOURCE_PATTERN.fullmatch(
        value
    ):
        raise PatchValidationError(
            f"Invalid Kubernetes resource value at {path}: {value!r}"
        )


def _validate_image_value(
    path: str,
    value: Any,
    approved_values: list[str],
) -> None:
    if not path.endswith(
        "/image"
    ):
        return

    if not isinstance(
        value,
        str,
    ):
        raise PatchValidationError(
            "Container image must be a string."
        )

    if not _IMAGE_PATTERN.fullmatch(
        value
    ):
        raise PatchValidationError(
            f"Invalid container image value: {value!r}"
        )

    if (
        approved_values
        and value not in approved_values
    ):
        raise PatchValidationError(
            "The proposed image was not found in the approved "
            "evidence or policy values."
        )


def _validate_replica_value(
    path: str,
    value: Any,
    allow_replica_change: bool,
) -> None:
    if path != "/spec/replicas":
        return

    if not allow_replica_change:
        raise PatchValidationError(
            "Replica changes are not allowed by the retrieved policy."
        )

    if (
        not isinstance(
            value,
            int,
        )
        or isinstance(
            value,
            bool,
        )
        or value < 0
        or value > 100
    ):
        raise PatchValidationError(
            "Replica value must be an integer between 0 and 100."
        )


def _validate_target(
    manifest: dict[str, Any],
    target: dict[str, Any],
    expected_target: dict[str, Any],
) -> None:
    actual_kind = str(
        manifest.get(
            "kind",
            "",
        )
    )

    metadata = _safe_dict(
        manifest.get(
            "metadata"
        )
    )

    actual_name = str(
        metadata.get(
            "name",
            "",
        )
    )

    actual_namespace = str(
        metadata.get(
            "namespace",
            "default",
        )
    )

    expected_kind = str(
        expected_target.get(
            "kind",
            "",
        )
    )

    expected_name = str(
        expected_target.get(
            "name",
            "",
        )
    )

    expected_namespace = str(
        expected_target.get(
            "namespace",
            "default",
        )
    )

    proposed_kind = str(
        target.get(
            "kind",
            "",
        )
    )

    proposed_name = str(
        target.get(
            "name",
            "",
        )
    )

    proposed_namespace = str(
        target.get(
            "namespace",
            "default",
        )
    )

    triples = {
        (
            actual_kind,
            actual_name,
            actual_namespace,
        ),
        (
            expected_kind,
            expected_name,
            expected_namespace,
        ),
        (
            proposed_kind,
            proposed_name,
            proposed_namespace,
        ),
    }

    if len(
        triples
    ) != 1:
        raise PatchValidationError(
            "The proposed workload identity does not match the "
            "repository manifest and collected evidence."
        )


def _find_container_index(
    manifest: dict[str, Any],
    container_name: str,
) -> int:
    spec = _safe_dict(
        manifest.get(
            "spec"
        )
    )

    template = _safe_dict(
        spec.get(
            "template"
        )
    )

    pod_spec = _safe_dict(
        template.get(
            "spec"
        )
    )

    containers = _safe_list(
        pod_spec.get(
            "containers"
        )
    )

    for index, container in enumerate(
        containers
    ):
        if (
            isinstance(
                container,
                dict,
            )
            and str(
                container.get(
                    "name",
                    "",
                )
            )
            == container_name
        ):
            return index

    raise PatchValidationError(
        f"Container was not found in the manifest: {container_name}"
    )


def _replace_container_placeholder(
    path: str,
    container_index: int,
) -> str:
    return (
        path
        .replace(
            "/containers/{container}/",
            (
                f"/containers/"
                f"{container_index}/"
            ),
        )
        .replace(
            "/containers/*/",
            (
                f"/containers/"
                f"{container_index}/"
            ),
        )
    )


def _yaml_dump(
    document: dict[str, Any],
) -> str:
    content = yaml.safe_dump(
        document,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )

    if not content.endswith(
        "\n"
    ):
        content += "\n"

    return content


def _unified_diff(
    before: str,
    after: str,
    repository_path: str,
) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(
                keepends=True
            ),
            after.splitlines(
                keepends=True
            ),
            fromfile=(
                f"a/{repository_path}"
            ),
            tofile=(
                f"b/{repository_path}"
            ),
        )
    )


def validate_and_apply_patch(
    *,
    manifest_text: str,
    repository_path: str,
    proposal: dict[str, Any],
    expected_target: dict[str, Any],
    policy: dict[str, Any],
) -> ValidatedPatch:
    """
    Validate and apply a structured LLM patch proposal.

    The LLM is only a proposer. This function is the authority.
    """

    try:
        loaded = yaml.safe_load(
            manifest_text
        )
    except yaml.YAMLError as error:
        raise PatchValidationError(
            f"The current repository manifest is invalid YAML: {error}"
        ) from error

    if not isinstance(
        loaded,
        dict,
    ):
        raise PatchValidationError(
            "The repository YAML must contain one Kubernetes object."
        )

    decision = str(
        proposal.get(
            "decision",
            "",
        )
    ).upper()

    if decision != "PATCH":
        raise PatchValidationError(
            "The proposal decision is not PATCH."
        )

    target = _safe_dict(
        proposal.get(
            "target"
        )
    )

    _validate_target(
        loaded,
        target,
        expected_target,
    )

    container_name = str(
        target.get(
            "container",
            "",
        )
    )

    container_index: int | None = None

    if container_name:
        container_index = (
            _find_container_index(
                loaded,
                container_name,
            )
        )

    allowed_paths = [
        str(path)
        for path in _safe_list(
            policy.get(
                "allowed_yaml_paths"
            )
        )
        if str(path).strip()
    ]

    if not allowed_paths:
        raise PatchValidationError(
            "The retrieved runbook policy does not define any "
            "allowed YAML paths."
        )

    approved_images = [
        str(value)
        for value in _safe_list(
            policy.get(
                "approved_image_values"
            )
        )
    ]

    allow_replica_change = bool(
        policy.get(
            "allow_replica_change",
            False,
        )
    )

    operations = _safe_list(
        proposal.get(
            "operations"
        )
    )

    if not operations:
        raise PatchValidationError(
            "The proposal does not contain any patch operations."
        )

    maximum_operations = int(
        policy.get(
            "maximum_operations",
            3,
        )
    )

    if len(
        operations
    ) > maximum_operations:
        raise PatchValidationError(
            "The proposal changes more fields than the runbook policy "
            "allows."
        )

    modified = copy.deepcopy(
        loaded
    )

    validated_operations: list[
        dict[str, Any]
    ] = []

    changed_paths: list[
        str
    ] = []

    for operation in operations:
        if not isinstance(
            operation,
            dict,
        ):
            raise PatchValidationError(
                "Every patch operation must be an object."
            )

        raw_path = _normalise_path(
            operation.get(
                "path"
            )
        )

        if container_index is not None:
            path = (
                _replace_container_placeholder(
                    raw_path,
                    container_index,
                )
            )
        else:
            path = raw_path

        _validate_forbidden_path(
            path
        )

        policy_paths = [
            (
                _replace_container_placeholder(
                    allowed,
                    container_index,
                )
                if container_index is not None
                else allowed
            )
            for allowed in allowed_paths
        ]

        if not _path_matches_policy(
            path,
            policy_paths,
        ):
            raise PatchValidationError(
                f"The runbook policy does not allow modification of "
                f"{path}."
            )

        before = operation.get(
            "before"
        )

        after = operation.get(
            "after"
        )

        actual_before = (
            _get_pointer_value(
                modified,
                path,
            )
        )

        if actual_before != before:
            raise PatchValidationError(
                f"The proposal's before value does not match the "
                f"repository YAML at {path}."
            )

        if after == before:
            raise PatchValidationError(
                f"The proposal does not change the value at {path}."
            )

        _validate_no_dangerous_commands(
            after
        )

        _validate_resource_value(
            path,
            after,
        )

        _validate_image_value(
            path,
            after,
            approved_images,
        )

        _validate_replica_value(
            path,
            after,
            allow_replica_change,
        )

        _set_pointer_value(
            modified,
            path,
            after,
        )

        validated_operations.append(
            {
                "path": path,
                "before": before,
                "after": after,
                "evidence": _safe_list(
                    operation.get(
                        "evidence"
                    )
                ),
            }
        )

        changed_paths.append(
            path
        )

    # Reconfirm that the identity did not change while applying operations.
    _validate_target(
        modified,
        target,
        expected_target,
    )

    after_text = _yaml_dump(
        modified
    )

    before_text = manifest_text

    if not before_text.endswith(
        "\n"
    ):
        before_text += "\n"

    if before_text == after_text:
        raise PatchValidationError(
            "The validated operations did not produce a repository "
            "change."
        )

    diff = _unified_diff(
        before_text,
        after_text,
        repository_path,
    )

    return ValidatedPatch(
        content=after_text,
        diff=diff,
        operations=(
            validated_operations
        ),
        changed_paths=(
            changed_paths
        ),
    )