from __future__ import annotations

from pydantic import BaseModel, Field


class ApprovalDecisionRequest(BaseModel):
    reviewer: str = Field(..., min_length=1, max_length=120)
    comment: str = Field(default="", max_length=2000)


class ApprovalDecisionResponse(BaseModel):
    incident_id: int
    decision: str
    approval_status: str
    reviewer: str
    comment: str
    created_at: str
    downstream: dict
