from __future__ import annotations

from .models import RootCause
from .policy_parser import Policy


def select_policy(root_cause: RootCause, policies: dict[str, Policy]) -> Policy | None:
    return policies.get(root_cause.name)
