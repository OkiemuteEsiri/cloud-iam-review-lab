from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class Principal:
    principal_id: str
    principal_type: str
    display_name: str
    provider: str
    enabled: bool = True
    mfa_enabled: bool | None = None
    last_used_days: int | None = None
    credential_age_days: int | None = None
    owner: str | None = None
    external: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.principal_id.strip():
            raise ValueError("principal_id is required")
        if self.principal_type not in {"user", "service_account", "role", "group"}:
            raise ValueError(f"unsupported principal_type: {self.principal_type}")
        if self.provider not in {"aws", "azure", "gcp"}:
            raise ValueError(f"unsupported provider: {self.provider}")
        if self.last_used_days is not None and self.last_used_days < 0:
            raise ValueError("last_used_days must be non-negative")
        if self.credential_age_days is not None and self.credential_age_days < 0:
            raise ValueError("credential_age_days must be non-negative")


@dataclass(frozen=True)
class Grant:
    grant_id: str
    principal_id: str
    resource: str
    permission: str
    scope: str
    privileged: bool = False
    wildcard: bool = False
    standing_access: bool = True

    def validate(self) -> None:
        if not self.grant_id.strip() or not self.principal_id.strip():
            raise ValueError("grant_id and principal_id are required")
        if not self.resource.strip() or not self.permission.strip():
            raise ValueError("resource and permission are required")
        if self.scope not in {"tenant", "organization", "subscription", "project", "account", "resource"}:
            raise ValueError(f"unsupported scope: {self.scope}")


@dataclass(frozen=True)
class Finding:
    control_id: str
    principal_id: str
    severity: str
    title: str
    rationale: str
    remediation: str
    attack_ids: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()

    def validate(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"unsupported severity: {self.severity}")
