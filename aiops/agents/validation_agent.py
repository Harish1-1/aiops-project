from __future__ import annotations

import re
from typing import Any

from agents.evidence_guard import (
    check_evidence_claims,
)
from agents.safety_policy import (
    check_remediation_policy,
)


APPROVED_STATUS = (
    "APPROVED FOR HUMAN REVIEW"
)

REJECTED_STATUS = (
    "NOT APPROVED"
)


def _markdown_list(
    values: list[str],
    empty_message: str = "None",
) -> str:
    if not values:
        return f"- {empty_message}"

    return "\n".join(
        f"- {value}"
        for value in values
    )


def _assessment_findings(
    incident: dict[str, Any],
    key: str,
) -> list[str]:
    assessment = incident.get(
        "alert_assessment",
        {},
    )

    if not isinstance(
        assessment,
        dict,
    ):
        return []

    values = assessment.get(
        key,
        [],
    )

    if not isinstance(
        values,
        list,
    ):
        return []

    return [
        str(value)
        for value in values
    ]


def _check_rca_assessment_alignment(
    incident: dict[str, Any],
    analysis: str,
) -> list[str]:
    """
    Detect direct contradictions between the RCA and the authoritative
    deterministic alert assessment.
    """

    assessment = incident.get(
        "alert_assessment",
        {},
    )

    if not isinstance(
        assessment,
        dict,
    ):
        return [
            (
                "RCA alignment could not be checked because the "
                "deterministic alert assessment is unavailable."
            )
        ]

    alert_confirmed = bool(
        assessment.get(
            "alert_confirmed",
            False,
        )
    )

    normalized = " ".join(
        analysis.lower().split()
    )

    violations: list[str] = []

    confirming_patterns = [
        r"\bthe alert is confirmed\b",
        r"\balert is confirmed\b",
        r"\balert confirms\b",
        r"\bcurrent snapshot confirms the alert\b",
        r"\bcurrent snapshot supports confirming the alert\b",
        r"\bsupports confirming the alert\b",
        r"\bshould remain confirmed\b",
        r"\bno evidence to contradict the alert\b",
        r"\balert stands as verified\b",
    ]

    rejecting_patterns = [
        r"\bthe alert is not confirmed\b",
        r"\balert is not confirmed\b",
        r"\bdoes not confirm the alert\b",
        r"\bdoes not support the alert\b",
        r"\bnot supported by current\b",
        r"\bnot supported by.*historical\b",
    ]

    if not alert_confirmed:
        for pattern in confirming_patterns:
            if re.search(
                pattern,
                normalized,
            ):
                violations.append(
                    (
                        "RCA contradicts the deterministic assessment "
                        "by claiming that the alert is confirmed."
                    )
                )

                break

        incorrect_threshold_patterns = [
            r"\bmemory usage exceeds the configured limit\b",
            r"\bmemory usage exceeds the threshold\b",
            r"\bcpu usage exceeds the configured limit\b",
            r"\bcpu usage exceeds the threshold\b",
        ]

        for pattern in incorrect_threshold_patterns:
            if re.search(
                pattern,
                normalized,
            ):
                violations.append(
                    (
                        "RCA claims that an operational threshold was "
                        "exceeded, but deterministic evidence does not "
                        "confirm this."
                    )
                )

                break

        unsafe_certainty_patterns = [
            r"\bno further investigation is needed\b",
            r"\bwill not trigger in the future\b",
            r"\bno additional evidence is required\b",
        ]

        for pattern in unsafe_certainty_patterns:
            if re.search(
                pattern,
                normalized,
            ):
                violations.append(
                    (
                        "RCA makes an unsupported certainty claim about "
                        "future behavior or further investigation."
                    )
                )

                break

    else:
        for pattern in rejecting_patterns:
            if re.search(
                pattern,
                normalized,
            ):
                violations.append(
                    (
                        "RCA contradicts the deterministic assessment "
                        "by claiming that a confirmed alert is not "
                        "supported."
                    )
                )

                break

    return list(
        dict.fromkeys(
            violations
        )
    )


def _build_validation_checks(
    incident: dict[str, Any],
    policy_violations: list[str],
) -> dict[str, bool]:
    assessment = incident.get(
        "alert_assessment",
        {},
    )

    if not isinstance(
        assessment,
        dict,
    ):
        assessment = {}

    historical_metrics = incident.get(
        "historical_metrics",
        {},
    )

    historical_logs = incident.get(
        "historical_logs",
        {},
    )

    if not isinstance(
        historical_logs,
        dict,
    ):
        historical_logs = {}

    if not isinstance(
        historical_metrics,
        dict,
    ):
        historical_metrics = {}

    workload_resolved = bool(
        incident.get("workload_name")
        and incident.get("workload_name")
        != "Unknown"
        and incident.get("workload_kind")
        and incident.get("workload_kind")
        != "Unknown"
    )

    evidence_source = incident.get(
        "evidence_source",
        "",
    )

    live_evidence_available = (
        isinstance(
            evidence_source,
            str,
        )
        and evidence_source.startswith(
            "live-kubernetes"
        )
    )

    return {
        "live_kubernetes_evidence_available": (
            live_evidence_available
        ),
        "workload_owner_resolved": (
            workload_resolved
        ),
        "prometheus_history_available": bool(
            historical_metrics.get(
                "available",
                False,
            )
        ),
        "loki_history_available": bool(
            historical_logs.get(
                "available",
                False,
            )
        ),
        "alert_assessment_available": bool(
            assessment
        ),
        "rca_aligned_with_assessment": (
            not any(
                "RCA" in violation
                for violation in policy_violations
            )
        ),
        "remediation_is_deterministic": True,
        "no_policy_violations": (
            not policy_violations
        ),
        "recommendation_only_mode": True,
        "automatic_execution_disabled": True,
    }


def build_deterministic_validation(
    incident: dict[str, Any],
    analysis: str,
    remediation: str,
) -> dict[str, Any]:
    remediation_violations = (
        check_remediation_policy(
            incident=incident,
            remediation=remediation,
        )
    )

    evidence_violations = (
        check_evidence_claims(
            incident=incident,
            generated_text=analysis,
        )
    )

    alignment_violations = (
        _check_rca_assessment_alignment(
            incident=incident,
            analysis=analysis,
        )
    )

    policy_violations = list(
        dict.fromkeys(
            [
                *remediation_violations,
                *evidence_violations,
                *alignment_violations,
            ]
        )
    )

    checks = _build_validation_checks(
        incident=incident,
        policy_violations=policy_violations,
    )

    required_checks = [
        "live_kubernetes_evidence_available",
        "workload_owner_resolved",
        "alert_assessment_available",
        "rca_aligned_with_assessment",
        "remediation_is_deterministic",
        "no_policy_violations",
        "recommendation_only_mode",
        "automatic_execution_disabled",
    ]

    passed = all(
        checks.get(
            check_name,
            False,
        )
        for check_name in required_checks
    )

    approval_status = (
        APPROVED_STATUS
        if passed
        else REJECTED_STATUS
    )

    assessment = incident.get(
        "alert_assessment",
        {},
    )

    if not isinstance(
        assessment,
        dict,
    ):
        assessment = {}

    supported_findings = (
        _assessment_findings(
            incident,
            "supported_findings",
        )
    )

    contradictions = (
        _assessment_findings(
            incident,
            "contradictions",
        )
    )

    missing_evidence = (
        _assessment_findings(
            incident,
            "missing_evidence",
        )
    )

    passed_checks = [
        name
        for name, result
        in checks.items()
        if result
    ]

    failed_checks = [
        name
        for name, result
        in checks.items()
        if not result
    ]

    validation_text = f"""
# Deterministic Validation Result

## Final Decision

- **Validation result:** {
    "PASS" if passed else "FAIL"
}
- **Approval status:** {approval_status}
- **Automatic execution:** DISABLED
- **Operating mode:** RECOMMENDATION ONLY

## Alert Assessment

- **Alert:** {
    assessment.get(
        "alert",
        incident.get(
            "alert",
            "Unknown",
        ),
    )
}
- **Assessment status:** {
    assessment.get(
        "status",
        "Unavailable",
    )
}
- **Alert confirmed:** {
    assessment.get(
        "alert_confirmed",
        False,
    )
}
- **Current snapshot confirms alert:** {
    assessment.get(
        "current_snapshot_confirms_alert",
        False,
    )
}
- **Prometheus history confirms alert:** {
    assessment.get(
        "historical_evidence_confirms_alert",
        False,
    )
}

## Supported Findings

{_markdown_list(supported_findings)}

## Contradictions

{_markdown_list(contradictions)}

## Missing Evidence

{_markdown_list(missing_evidence)}

## Validation Checks Passed

{_markdown_list(passed_checks)}

## Validation Checks Failed

{_markdown_list(failed_checks)}

## Deterministic Policy Violations

{_markdown_list(
    policy_violations,
    empty_message="No violations found.",
)}

## Validation Authority

This decision was generated by deterministic Python checks.

The language model cannot approve remediation, override evidence,
override the alert assessment, or authorize execution.

## Final Validation

VALIDATION: {
    "PASS" if passed else "FAIL"
}
""".strip()

    return {
        "passed": passed,
        "approval_status": approval_status,
        "policy_violations": policy_violations,
        "checks": checks,
        "validation_text": validation_text,
    }


def validate_analysis(
    incident: dict[str, Any],
    analysis: str,
    remediation: str,
) -> str:
    result = build_deterministic_validation(
        incident=incident,
        analysis=analysis,
        remediation=remediation,
    )

    return str(
        result["validation_text"]
    )