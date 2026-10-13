from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))


class Audit(Base):
    __tablename__ = "audits"

    id: Mapped[int] = mapped_column(primary_key=True)
    audit_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    device_name: Mapped[str] = mapped_column(String(255))
    os_name: Mapped[str] = mapped_column(String(50))
    os_version: Mapped[str] = mapped_column(String(100))
    duration_seconds: Mapped[float] = mapped_column(Float)
    audited_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(30))
    summary: Mapped[str] = mapped_column(String(500))
    ruleset_version: Mapped[str] = mapped_column(String(20))
    checks: Mapped[list] = mapped_column(JSON)
    alerts: Mapped[list] = mapped_column(JSON)
    unavailable_checks: Mapped[list] = mapped_column(JSON)
