"""Initialise or upgrade the database (safe to run repeatedly).

1. If a SQLite database already exists and is not at the latest Alembic revision, a
   timestamped file backup is written to ``data/backups/`` first.
2. ``alembic upgrade head`` is applied (the legacy schema is migrated without data loss).
3. Findings without a risk score (e.g. migrated legacy rows) are scored.

Usage (project root):  python scripts/init_db.py
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from alembic.runtime.migration import MigrationContext  # noqa: E402
from alembic.script import ScriptDirectory  # noqa: E402
from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.core.timeutils import utcnow  # noqa: E402


def alembic_config(url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "backend" / "migrations"))
    cfg.attributes["database_url"] = url
    return cfg


def backup_if_needed(url: str, cfg: Config) -> Path | None:
    parsed = make_url(url)
    if not parsed.drivername.startswith("sqlite") or not parsed.database:
        return None
    db_file = Path(parsed.database)
    if not db_file.exists() or db_file.stat().st_size == 0:
        return None
    engine = create_engine(url)
    with engine.connect() as conn:
        current = MigrationContext.configure(conn).get_current_revision()
    engine.dispose()
    head = ScriptDirectory.from_config(cfg).get_current_head()
    if current == head:
        return None
    backup_dir = db_file.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    target = backup_dir / f"{db_file.stem}-{utcnow().strftime('%Y%m%dT%H%M%SZ')}.db"
    shutil.copy2(db_file, target)
    return target


def init_database(url: str | None = None) -> None:
    url = url or get_settings().database_url
    parsed = make_url(url)
    if parsed.drivername.startswith("sqlite") and parsed.database:
        Path(parsed.database).parent.mkdir(parents=True, exist_ok=True)
    cfg = alembic_config(url)
    backup = backup_if_needed(url, cfg)
    if backup:
        print(
            f"Backup written: {backup.relative_to(ROOT) if backup.is_relative_to(ROOT) else backup}"
        )
    command.upgrade(cfg, "head")

    from sqlalchemy.orm import Session

    from app.core.database import build_engine
    from app.models import Finding
    from app.services.risk import rescore_findings

    engine = build_engine(url)
    with Session(engine) as db:
        ids = list(db.scalars(select(Finding.id).where(Finding.risk_score.is_(None))))
        if ids:
            rescore_findings(db, ids, actor="system-init")
            db.commit()
        print(f"Database ready at revision head; {len(ids)} finding(s) scored.")
    engine.dispose()


if __name__ == "__main__":
    init_database()
