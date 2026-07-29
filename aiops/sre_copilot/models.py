from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class IncidentRequest(BaseModel):
    alert: str = Field(..., examples=["OOMKilled"])
    namespace: str = Field(default="default")
    pod: str = Field(default="unknown")
    logs: list[str] = Field(default_factory=list)
    events: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    restart_count: int | None = None


class WorkflowResponse(BaseModel):
    incident: dict[str, Any]
    investigation: dict[str, Any] | None = None
    analysis: str | None = None
    remediation: str | None = None
    validation: str | None = None
    policy_violations: list[str] = Field(default_factory=list)
    approval_status: str
    retry_count: int = 0
    report: str | None = None