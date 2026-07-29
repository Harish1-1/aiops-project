from pydantic import BaseModel


class Alert(BaseModel):
    status: str
    labels: dict
    annotations: dict
    startsAt: str | None = None
    endsAt: str | None = None


class AlertManagerPayload(BaseModel):
    receiver: str
    status: str
    alerts: list[Alert]