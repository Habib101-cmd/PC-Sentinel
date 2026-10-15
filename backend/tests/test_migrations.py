from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from app.models import Audit, User


def test_les_migrations_creent_le_schema_des_modeles(tmp_path, monkeypatch):
    backend = Path(__file__).resolve().parents[1]
    url = f"sqlite:///{(tmp_path / 'migration.db').as_posix()}"
    monkeypatch.setenv("DATABASE_URL", url)

    config = Config(str(backend / "alembic.ini"))
    config.set_main_option("script_location", str(backend / "alembic"))
    command.upgrade(config, "head")

    inspector = inspect(create_engine(url))
    assert {"users", "audits", "alembic_version"} <= set(inspector.get_table_names())
    for model in (User, Audit):
        in_db = {c["name"] for c in inspector.get_columns(model.__tablename__)}
        in_models = {c.name for c in model.__table__.columns}
        assert in_db == in_models, (
            f"{model.__tablename__} : migration et modèle diffèrent. "
            "Générez une migration : alembic revision --autogenerate"
        )
