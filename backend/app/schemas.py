from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["Information", "Faible", "Moyen", "Élevé"]
AuditStatus = Literal["aucun_indicateur", "a_verifier", "a_risque"]


class Check(BaseModel):
    id: str = Field(min_length=1, max_length=50)
    status: Literal["ok", "unavailable"]
    data: dict = Field(default_factory=dict)
    error: str | None = Field(default=None, max_length=300)


class OsInfo(BaseModel):
    name: str = Field(min_length=1, max_length=50)
    version: str = Field(min_length=1, max_length=100)


class AuditRequest(BaseModel):
    device_name: str = Field(min_length=1, max_length=255)
    os: OsInfo
    duration_seconds: float = Field(ge=0, le=3600)
    checks: list[Check] = Field(max_length=50)


class Alert(BaseModel):
    rule_id: str
    rule_version: str
    title: str
    category: str
    severity: Severity
    detected_at: datetime
    subject: str
    explanation: str
    recommendation: str
    limits: str


class AuditResult(BaseModel):
    audit_id: str
    audited_at: datetime
    device_name: str
    os: OsInfo
    duration_seconds: float
    status: AuditStatus
    summary: str
    alerts: list[Alert]
    checks_performed: list[str]
    unavailable_checks: list[str]
    ruleset_version: str
