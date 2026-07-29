from __future__ import annotations

import os
from typing import Any

import requests


def verify_argocd(plan: dict[str, Any], github: dict[str, Any]) -> dict[str, Any]:
    server = os.getenv("ARGOCD_SERVER", "").rstrip("/")
    token = os.getenv("ARGOCD_TOKEN", "")
    app_name = os.getenv("ARGOCD_APPLICATION", "")

    if plan.get("status") == "NO_CHANGE_REQUIRED":
        return {"status": "SKIPPED", "reason": "No change was required, so ArgoCD synchronization was not expected."}
    if plan.get("status") != "PATCH_READY":
        return {"status": "BLOCKED", "reason": "No validated GitOps patch is available."}
    if github.get("status") == "DRY_RUN":
        return {"status": "SKIPPED", "reason": "GitHub is in dry-run mode; no merged Git revision exists."}
    if github.get("status") in {"PR_CREATED", "PR_EXISTS"}:
        return {
            "status": "WAITING_FOR_MERGE",
            "reason": "The pull request must be reviewed and merged before ArgoCD can observe the change.",
            "pr_url": github.get("pr_url"),
        }
    if github.get("status") in {"BLOCKED", "SKIPPED", "ERROR"}:
        return {"status": "SKIPPED", "reason": f"GitHub stage status is {github.get('status')}; no merged Git change is available."}
    if not server or not token or not app_name:
        return {"status": "NOT_CONFIGURED", "reason": "ARGOCD_SERVER, ARGOCD_TOKEN, and ARGOCD_APPLICATION are required for live verification."}

    try:
        response = requests.get(
            f"{server}/api/v1/applications/{app_name}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
            verify=os.getenv("ARGOCD_VERIFY_TLS", "true").lower() == "true",
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        return {"status": "ERROR", "reason": str(exc)}

    status = payload.get("status", {}) if isinstance(payload, dict) else {}
    sync = status.get("sync", {}) if isinstance(status, dict) else {}
    health = status.get("health", {}) if isinstance(status, dict) else {}
    sync_status = sync.get("status")
    health_status = health.get("status")
    observed = sync_status == "Synced" and health_status == "Healthy"
    return {
        "status": "VERIFIED" if observed else "OBSERVED",
        "application": app_name,
        "sync_status": sync_status,
        "revision": sync.get("revision"),
        "health_status": health_status,
        "message": health.get("message"),
    }
