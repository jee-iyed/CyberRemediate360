"""Legacy baseline: the schema created by the original ``database.py`` script.

Uses ``CREATE TABLE IF NOT EXISTS`` so that ``alembic upgrade head`` works both on the
pre-existing ``data/cyberremediate.db`` (created before Alembic was introduced) and on an
empty database.

Revision ID: 0001_legacy_baseline
Revises:
Create Date: 2026-11-09
"""

from alembic import op

revision = "0001_legacy_baseline"
down_revision = None
branch_labels = None
depends_on = None

LEGACY_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        hostname TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        exposure TEXT NOT NULL,
        business_criticality TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        cvss_score REAL NOT NULL CHECK (cvss_score BETWEEN 0 AND 10)
    )""",
    """CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id TEXT NOT NULL,
        vulnerability_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        FOREIGN KEY (asset_id) REFERENCES assets(id),
        FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id),
        UNIQUE (asset_id, vulnerability_id)
    )""",
    """CREATE TABLE IF NOT EXISTS remediations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL,
        assigned_to TEXT,
        action TEXT NOT NULL,
        due_date TEXT,
        status TEXT NOT NULL DEFAULT 'planned',
        FOREIGN KEY (finding_id) REFERENCES findings(id)
    )""",
]


def upgrade() -> None:
    for statement in LEGACY_SCHEMA:
        op.execute(statement)


def downgrade() -> None:
    for table in ("remediations", "findings", "vulnerabilities", "assets"):
        op.execute(f"DROP TABLE IF EXISTS {table}")
