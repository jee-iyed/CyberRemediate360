"""Test fixtures: an isolated temporary SQLite database, never data/cyberremediate.db."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_TMP = Path(tempfile.mkdtemp(prefix="cr360-tests-"))
TEST_DB = _TMP / "test.db"
os.environ["CR360_DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"
os.environ["CR360_APP_ENV"] = "demo"
os.environ.pop("CR360_API_KEY", None)
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import delete  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.core.database import SessionLocal  # noqa: E402
from app.models import (  # noqa: E402
    Asset,
    AuditEvent,
    Finding,
    ImportJob,
    Remediation,
    Vulnerability,
)

SAMPLES = ROOT / "data" / "samples"


@pytest.fixture(scope="session", autouse=True)
def _migrated_database():
    from init_db import init_database

    init_database(os.environ["CR360_DATABASE_URL"])
    yield


@pytest.fixture(autouse=True)
def _clean_tables():
    with SessionLocal() as db:
        for model in (AuditEvent, Remediation, Finding, Vulnerability, Asset, ImportJob):
            db.execute(delete(model))
        db.commit()
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def sample_bytes():
    return lambda name: (SAMPLES / name).read_bytes()


CSV_HEADER = "asset_id,hostname,ip_address,cve_id,cvss_score,exposure,business_criticality,status"


def make_csv(*rows: str, header: str = CSV_HEADER) -> bytes:
    return ("\n".join([header, *rows]) + "\n").encode("utf-8")
