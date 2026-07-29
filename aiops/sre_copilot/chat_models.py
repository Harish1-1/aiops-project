from __future__ import annotations

from pydantic import BaseModel, Field


class IncidentChatRequest(BaseModel):
    question: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description=(
            "A question about the selected stored incident."
        ),
        examples=[
            "Why was this alert not confirmed?",
            "What was the highest memory usage?",
            "Did Loki show any errors?",
        ],
    )


class IncidentChatResponse(BaseModel):
    incident_id: int
    answer: str
    mode: str