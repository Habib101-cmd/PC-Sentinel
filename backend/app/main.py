import logging
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import (
    DUMMY_HASH,
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from .database import get_db
from .log import log_event
from .models import Audit, User
from .ratelimit import login_ip_limiter, login_user_limiter, register_ip_limiter
from .report import render_report
from .rules import RULESET_VERSION, evaluate, global_status
from .schemas import Alert, AuditRequest, AuditResult, OsInfo

app = FastAPI(title="PC Sentinel API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(max_length=50)
    password: str = Field(max_length=128)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "inconnu"


def too_many_requests(wait: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"Trop de tentatives. Réessayez dans {wait} secondes.",
        headers={"Retry-After": str(wait)},
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    wait = register_ip_limiter.retry_after(ip)
    if wait:
        log_event("register_blocked", level=logging.WARNING, ip=ip, retry_after=wait)
        raise too_many_requests(wait)
    register_ip_limiter.add(ip)

    user = User(username=data.username, password_hash=hash_password(data.password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        log_event("register_conflict", ip=ip)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ce nom d'utilisateur existe déjà.",
        )
    log_event("register_ok", ip=ip, user_id=user.id)
    return {"message": "Compte créé avec succès."}


@app.post("/auth/login", response_model=Token)
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    user_key = f"{ip}|{data.username.lower()}"

    wait = max(login_user_limiter.retry_after(user_key), login_ip_limiter.retry_after(ip))
    if wait:
        log_event("login_blocked", level=logging.WARNING, ip=ip, retry_after=wait)
        raise too_many_requests(wait)

    user = db.scalar(select(User).where(User.username == data.username))
    stored_hash = user.password_hash if user else DUMMY_HASH
    valid = verify_password(data.password, stored_hash)

    if user is None or not valid:
        login_user_limiter.add(user_key)
        login_ip_limiter.add(ip)
        log_event(
            "login_failed",
            level=logging.WARNING,
            ip=ip,
            user_id=user.id if user else "inconnu",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nom d'utilisateur ou mot de passe incorrect.",
        )

    login_user_limiter.clear(user_key)
    log_event("login_ok", ip=ip, user_id=user.id)
    return Token(access_token=create_access_token(user.id))


@app.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username}


def audit_to_result(audit: Audit) -> AuditResult:
    return AuditResult(
        audit_id=audit.audit_id,
        audited_at=audit.audited_at,
        device_name=audit.device_name,
        os=OsInfo(name=audit.os_name, version=audit.os_version),
        duration_seconds=audit.duration_seconds,
        status=audit.status,
        summary=audit.summary,
        alerts=[Alert(**a) for a in audit.alerts],
        checks_performed=[c["id"] for c in audit.checks if c["status"] == "ok"],
        unavailable_checks=audit.unavailable_checks,
        ruleset_version=audit.ruleset_version,
    )


def find_own_audit(db: Session, audit_id: str, user: User) -> Audit:
    audit = db.scalar(
        select(Audit).where(Audit.audit_id == audit_id, Audit.user_id == user.id)
    )
    if audit is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Audit introuvable."
        )
    return audit


@app.post("/audits", response_model=AuditResult, status_code=status.HTTP_201_CREATED)
def create_audit(
    data: AuditRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    raw_alerts, unavailable = evaluate([c.model_dump() for c in data.checks])
    alerts = [Alert(**a) for a in raw_alerts]
    risk_status, summary = global_status(raw_alerts, unavailable)

    audit = Audit(
        audit_id=str(uuid4()),
        user_id=current_user.id,
        device_name=data.device_name,
        os_name=data.os.name,
        os_version=data.os.version,
        duration_seconds=data.duration_seconds,
        audited_at=datetime.now(timezone.utc),
        status=risk_status,
        summary=summary,
        ruleset_version=RULESET_VERSION,
        checks=[c.model_dump(mode="json") for c in data.checks],
        alerts=[a.model_dump(mode="json") for a in alerts],
        unavailable_checks=unavailable,
    )
    db.add(audit)
    db.commit()
    log_event(
        "audit_created",
        user_id=current_user.id,
        audit_id=audit.audit_id,
        status=risk_status,
        alerts=len(alerts),
        unavailable=len(unavailable),
    )
    return audit_to_result(audit)


@app.get("/audits", response_model=list[AuditResult])
def list_audits(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    audits = db.scalars(
        select(Audit)
        .where(Audit.user_id == current_user.id)
        .order_by(Audit.audited_at.desc())
    ).all()
    return [audit_to_result(a) for a in audits]


@app.get("/audits/{audit_id}", response_model=AuditResult)
def get_audit(
    audit_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return audit_to_result(find_own_audit(db, audit_id, current_user))


@app.get("/audits/{audit_id}/report", response_class=HTMLResponse)
def get_report(
    audit_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    audit = find_own_audit(db, audit_id, current_user)
    html = render_report(audit_to_result(audit), audit.checks)
    log_event("report_generated", user_id=current_user.id, audit_id=audit.audit_id)
    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": f'attachment; filename="rapport-pc-sentinel-{audit.audit_id}.html"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.delete("/audits/{audit_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_audit(
    audit_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    audit = find_own_audit(db, audit_id, current_user)
    db.delete(audit)
    db.commit()
    log_event("audit_deleted", user_id=current_user.id, audit_id=audit_id)


@app.delete("/users/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    user_id = current_user.id
    db.execute(delete(Audit).where(Audit.user_id == user_id))
    db.execute(delete(User).where(User.id == user_id))
    db.commit()
    log_event("account_deleted", user_id=user_id)
