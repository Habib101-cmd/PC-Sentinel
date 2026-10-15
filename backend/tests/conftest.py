"""Configuration commune des tests."""
import os

# Ces variables doivent être définies AVANT d'importer l'application.
# SQLite est forcé : les tests ne touchent jamais à la vraie base PostgreSQL.
os.environ["DATABASE_URL"] = "sqlite:///./test_pcsentinel.db"
os.environ["JWT_SECRET"] = "secret-de-test-uniquement-0123456789-abcdefghijklmnop"

import logging  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import ratelimit  # noqa: E402
from app.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402

PASSWORD = "motdepasse-solide-123"


def full_checks() -> list[dict]:
    """Six contrôles réalisés, sans aucun indicateur."""
    recent = (datetime.now(timezone.utc).date() - timedelta(days=5)).isoformat()
    return [
        {"id": "firewall", "status": "ok",
         "data": {"profiles": {"Domain": "True", "Private": "True", "Public": "True"}}},
        {"id": "antivirus", "status": "ok",
         "data": {"products": [{"name": "Windows Defender", "enabled": True}]}},
        {"id": "updates", "status": "ok",
         "data": {"hotfix_id": "KB5000000", "last_update_date": recent}},
        {"id": "startup", "status": "ok",
         "data": {"entries": [{
             "name": "OneDrive", "location": "Startup",
             "path": "%USERPROFILE%\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
             "signature": "Valid", "publisher": "Microsoft Corporation"}]}},
        {"id": "processes", "status": "ok",
         "data": {"paths": ["%USERPROFILE%\\AppData\\Local\\Programs\\App\\app.exe"],
                  "total_distinct": 60, "sent": 1}},
        {"id": "failed_logons", "status": "ok",
         "data": {"count": 0, "period_hours": 24}},
    ]


@pytest.fixture(autouse=True)
def clean_state():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    ratelimit.reset_all()
    yield


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def password():
    return PASSWORD


@pytest.fixture
def new_user(client):
    """Crée un compte, se connecte et renvoie l'en-tête d'authentification."""
    def create(name: str) -> dict:
        creds = {"username": name, "password": PASSWORD}
        assert client.post("/auth/register", json=creds).status_code == 201
        token = client.post("/auth/login", json=creds).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    return create


@pytest.fixture
def payload():
    def build(**overrides) -> dict:
        data = {
            "device_name": "PC-TEST",
            "os": {"name": "Windows 11", "version": "10.0.22631"},
            "duration_seconds": 2.5,
            "checks": full_checks(),
        }
        data.update(overrides)
        return data
    return build


@pytest.fixture
def checks_with():
    """checks_with(firewall={...}) remplace un contrôle ; checks_with(firewall=None) le retire."""
    def build(**replacements) -> list[dict]:
        result = []
        for check in full_checks():
            if check["id"] in replacements:
                if replacements[check["id"]] is not None:
                    result.append(replacements[check["id"]])
            else:
                result.append(check)
        return result
    return build


class _Collector(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@pytest.fixture
def log_messages():
    handler = _Collector()
    logger = logging.getLogger("pcsentinel")
    logger.addHandler(handler)
    yield handler.messages
    logger.removeHandler(handler)
