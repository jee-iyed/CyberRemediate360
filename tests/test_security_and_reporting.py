import shutil
import sqlite3
import tempfile
from pathlib import Path

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from conftest import ROOT
from sqlalchemy import create_engine

from app.core.config import get_settings
from app.core.security import sanitize_actor
from app.services.reporting import _csv_safe, render_csv


def test_write_requires_api_key_when_configured(client, monkeypatch):
    monkeypatch.setenv("CR360_API_KEY", "test-key-not-a-secret")
    get_settings.cache_clear()
    body = {"asset_key": "A1", "hostname": "h1", "ip_address": "192.0.2.1"}
    assert client.post("/api/v1/assets", json=body).status_code == 401
    assert (
        client.post("/api/v1/assets", json=body, headers={"X-API-Key": "wrong"}).status_code == 401
    )
    assert (
        client.post(
            "/api/v1/assets", json=body, headers={"X-API-Key": "test-key-not-a-secret"}
        ).status_code
        == 201
    )
    assert client.get("/api/v1/assets").status_code == 200  # reads stay open
    health = client.get("/api/v1/health").json()
    assert health["write_auth"] == "api-key" and "test-key" not in str(health)


def test_production_without_key_fails_closed(client, monkeypatch):
    monkeypatch.setenv("CR360_APP_ENV", "production")
    get_settings.cache_clear()
    r = client.post(
        "/api/v1/assets", json={"asset_key": "A1", "hostname": "h", "ip_address": "192.0.2.1"}
    )
    assert r.status_code == 503


def test_cors_is_restrictive(client):
    allowed = client.options(
        "/api/v1/assets",
        headers={"Origin": "http://localhost:8501", "Access-Control-Request-Method": "GET"},
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:8501"
    denied = client.options(
        "/api/v1/assets",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in denied.headers


def test_sql_injection_attempt_is_inert(client):
    r = client.get("/api/v1/findings", params={"q": "' OR 1=1 --"})
    assert r.status_code == 200 and r.json()["total"] == 0
    r = client.get("/api/v1/assets", params={"q": "%"})
    assert r.status_code == 200 and r.json()["total"] == 0  # wildcard escaped


def test_actor_sanitised():
    assert sanitize_actor("<img src=x onerror=alert(1)>") == "img srcx onerroralert1"
    assert sanitize_actor(None) == "anonymous-demo-user"
    assert len(sanitize_actor("a" * 500)) == 64


def test_csv_formula_injection_neutralised():
    assert _csv_safe('=HYPERLINK("http://x")') == '\'=HYPERLINK("http://x")'
    assert _csv_safe("@SUM(1)") == "'@SUM(1)"
    assert _csv_safe("normal") == "normal" and _csv_safe(5) == 5
    out = render_csv({"findings": [{"title": "=cmd|' /C calc'!A0"}]}).decode("utf-8-sig")
    assert "'=cmd" in out


def test_legacy_database_migration_preserves_data():
    tmp = Path(tempfile.mkdtemp())
    legacy = tmp / "legacy.db"
    con = sqlite3.connect(legacy)
    legacy_sql = (ROOT / "scripts" / "legacy" / "legacy_database.py").read_text(encoding="utf-8")
    script = legacy_sql.split('cursor.executescript("""')[1].split('""")')[0]
    con.executescript(script)
    con.executemany(
        "INSERT INTO assets VALUES (?,?,?,?,?)",
        [
            ("AST-001", "web-server-01", "192.0.2.10", "internet", "critical"),
            ("AST-002", "db-server-01", "192.0.2.20", "internal", "critical"),
        ],
    )
    con.executemany(
        "INSERT INTO vulnerabilities VALUES (?,?)",
        [("CVE-DEMO-001", 9.8), ("CVE-2021-44228", 10.0)],
    )
    con.executemany(
        "INSERT INTO findings (asset_id, vulnerability_id, status) VALUES (?,?,?)",
        [("AST-001", "CVE-DEMO-001", "open"), ("AST-002", "CVE-2021-44228", "in_progress")],
    )
    con.commit()
    con.close()

    from init_db import init_database

    url = f"sqlite:///{legacy.as_posix()}"
    init_database(url)
    assert list((tmp / "backups").glob("legacy-*.db")), "a backup must be written"
    con = sqlite3.connect(legacy)
    rows = con.execute(
        "SELECT a.asset_key, v.cve_id, f.status, v.is_demo FROM findings f "
        "JOIN assets a ON a.id=f.asset_id JOIN vulnerabilities v ON v.id=f.vulnerability_id "
        "ORDER BY a.asset_key"
    ).fetchall()
    con.close()
    assert rows == [
        ("AST-001", "CVE-DEMO-001", "open", 1),
        ("AST-002", "CVE-2021-44228", "in_progress", 0),
    ]

    # The migrated schema must match the ORM models (no drift).
    from app.core.database import Base

    engine = create_engine(url)
    with engine.connect() as conn:
        diffs = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    engine.dispose()
    significant = [d for d in diffs if d[0] not in ("add_constraint", "remove_constraint")]
    assert significant == [], significant
    shutil.rmtree(tmp, ignore_errors=True)
