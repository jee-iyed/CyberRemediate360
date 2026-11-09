"""Platform schema: surrogate keys, metadata, scoring, workflow, audit and import jobs.

Data-preserving migration of the legacy tables:

1. legacy tables are renamed to ``legacy_*``;
2. the new tables are created;
3. rows are copied (legacy text ids become business keys: ``assets.asset_key`` and
   ``vulnerabilities.cve_id``);
4. legacy tables are dropped once the copy succeeded (same transaction).

Unknown legacy values are NOT invented: ``first_seen``/``last_seen`` stay NULL, CVSS
version/vector stay NULL, owner/environment stay NULL/'unknown'. ``created_at`` is the
migration time (the moment the record entered the new schema). Risk scores are computed
by the application afterwards (``scripts/init_db.py``).

A file backup of the database must be taken before running this migration on real data
(``scripts/init_db.py`` does it automatically).

Revision ID: 0002_platform_schema
Revises: 0001_legacy_baseline
Create Date: 2026-11-09
"""

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0002_platform_schema"
down_revision = "0001_legacy_baseline"
branch_labels = None
depends_on = None

WORKFLOW = "'open', 'in_progress', 'mitigated', 'resolved', 'accepted', 'false_positive'"
VERIFICATION = "'not_verified', 'pending', 'verified', 'failed'"
CRITICALITY = "'critical', 'high', 'medium', 'low', 'unknown'"
EXPOSURE = "'internet', 'internal', 'isolated', 'unknown'"


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    ]


def upgrade() -> None:
    for table in ("assets", "vulnerabilities", "findings", "remediations"):
        op.rename_table(table, f"legacy_{table}")

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_key", sa.String(64), nullable=False),
        sa.Column("hostname", sa.String(253), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("owner", sa.String(120)),
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("business_criticality", sa.String(16), nullable=False),
        sa.Column("exposure", sa.String(16), nullable=False),
        sa.Column("is_demo", sa.Boolean(), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint("asset_key", name="uq_assets_asset_key"),
        sa.CheckConstraint(
            f"business_criticality IN ({CRITICALITY})", name="ck_assets_criticality"
        ),
        sa.CheckConstraint(f"exposure IN ({EXPOSURE})", name="ck_assets_exposure"),
    )
    op.create_index("ix_assets_hostname", "assets", ["hostname"])
    op.create_index("ix_assets_ip_address", "assets", ["ip_address"])

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("title", sa.String(300)),
        sa.Column("description", sa.Text()),
        sa.Column("cwe_id", sa.String(16)),
        sa.Column("cvss_version", sa.String(8)),
        sa.Column("cvss_score", sa.Float()),
        sa.Column("cvss_vector", sa.String(200)),
        sa.Column("reference_links", sa.JSON()),
        sa.Column("epss_score", sa.Float()),
        sa.Column("kev", sa.Boolean()),
        sa.Column("threat_source", sa.String(120)),
        sa.Column("is_demo", sa.Boolean(), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint("cve_id", name="uq_vulnerabilities_cve_id"),
        sa.CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
            name="ck_vuln_cvss_range",
        ),
        sa.CheckConstraint(
            "epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)",
            name="ck_vuln_epss_range",
        ),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "asset_id",
            sa.Integer(),
            sa.ForeignKey("assets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "vulnerability_id",
            sa.Integer(),
            sa.ForeignKey("vulnerabilities.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("scanner_source", sa.String(64)),
        sa.Column("service", sa.String(64)),
        sa.Column("port", sa.Integer()),
        sa.Column("protocol", sa.String(8)),
        sa.Column("location_key", sa.String(32), nullable=False),
        sa.Column("first_seen", sa.DateTime()),
        sa.Column("last_seen", sa.DateTime()),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("risk_score", sa.Float()),
        sa.Column("priority", sa.String(4)),
        sa.Column("risk_explanation", sa.JSON()),
        sa.Column("evidence", sa.Text()),
        sa.Column("is_demo", sa.Boolean(), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint(
            "asset_id", "vulnerability_id", "location_key", name="uq_findings_business_key"
        ),
        sa.CheckConstraint(f"status IN ({WORKFLOW})", name="ck_findings_status"),
        sa.CheckConstraint(
            "port IS NULL OR (port >= 0 AND port <= 65535)", name="ck_findings_port"
        ),
        sa.CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)",
            name="ck_findings_risk_range",
        ),
    )
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_vulnerability_id", "findings", ["vulnerability_id"])
    op.create_index("ix_findings_status_priority", "findings", ["status", "priority"])
    op.create_index("ix_findings_risk_score", "findings", ["risk_score"])

    op.create_table(
        "remediations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("findings.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("owner", sa.String(120), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("proposed_solution", sa.Text()),
        sa.Column("notes", sa.Text()),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("due_date", sa.DateTime()),
        sa.Column("completed_at", sa.DateTime()),
        sa.Column("verification_status", sa.String(16), nullable=False),
        sa.Column("evidence", sa.Text()),
        sa.Column("justification", sa.Text()),
        sa.Column("risk_acceptance_expires_at", sa.DateTime()),
        *_timestamps(),
        sa.UniqueConstraint("finding_id", name="uq_remediations_finding_id"),
        sa.CheckConstraint(f"status IN ({WORKFLOW})", name="ck_remediations_status"),
        sa.CheckConstraint(
            f"verification_status IN ({VERIFICATION})", name="ck_remediations_verification"
        ),
    )
    op.create_index("ix_remediations_due_date", "remediations", ["due_date"])
    op.create_index("ix_remediations_status", "remediations", ["status"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", sa.String(64), nullable=False),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("previous_value", sa.JSON()),
        sa.Column("new_value", sa.JSON()),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
    )
    op.create_index("ix_audit_entity", "audit_events", ["entity_type", "entity_id"])
    op.create_index("ix_audit_timestamp", "audit_events", ["timestamp"])

    op.create_table(
        "import_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("file_sha256", sa.String(64)),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("total_rows", sa.Integer(), nullable=False),
        sa.Column("imported", sa.Integer(), nullable=False),
        sa.Column("updated", sa.Integer(), nullable=False),
        sa.Column("rejected", sa.Integer(), nullable=False),
        sa.Column("duplicates", sa.Integer(), nullable=False),
        sa.Column("errors", sa.JSON()),
        sa.Column("warnings", sa.JSON()),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
    )

    # ---- data copy -------------------------------------------------------------------
    now = datetime.now(UTC).replace(microsecond=0, tzinfo=None).isoformat(sep=" ")
    bind = op.get_bind()
    params = {"now": now}
    bind.execute(
        sa.text(
            """
            INSERT INTO vulnerabilities (cve_id, cvss_score, is_demo, created_at, updated_at)
            SELECT id, cvss_score, CASE WHEN id LIKE 'CVE-DEMO-%' THEN 1 ELSE 0 END, :now, :now
            FROM legacy_vulnerabilities
            """
        ),
        params,
    )
    bind.execute(
        sa.text(
            f"""
            INSERT INTO assets (asset_key, hostname, ip_address, owner, environment,
                                business_criticality, exposure, is_demo, created_at, updated_at)
            SELECT la.id, lower(la.hostname), la.ip_address, NULL, 'unknown',
                   CASE WHEN lower(la.business_criticality) IN ({CRITICALITY})
                        THEN lower(la.business_criticality) ELSE 'unknown' END,
                   CASE WHEN lower(la.exposure) IN ({EXPOSURE})
                        THEN lower(la.exposure) ELSE 'unknown' END,
                   CASE WHEN EXISTS (SELECT 1 FROM legacy_findings lf
                                     WHERE lf.asset_id = la.id
                                       AND lf.vulnerability_id LIKE 'CVE-DEMO-%')
                        THEN 1 ELSE 0 END,
                   :now, :now
            FROM legacy_assets la
            """
        ),
        params,
    )
    bind.execute(
        sa.text(
            f"""
            INSERT INTO findings (id, asset_id, vulnerability_id, scanner_source, location_key,
                                  status, is_demo, created_at, updated_at)
            SELECT lf.id, a.id, v.id, 'legacy-import', '',
                   CASE WHEN lf.status IN ({WORKFLOW}) THEN lf.status ELSE 'open' END,
                   v.is_demo, :now, :now
            FROM legacy_findings lf
            JOIN assets a ON a.asset_key = lf.asset_id
            JOIN vulnerabilities v ON v.cve_id = lf.vulnerability_id
            """
        ),
        params,
    )
    bind.execute(
        sa.text(
            """
            INSERT INTO remediations (id, finding_id, owner, action, status, due_date,
                                      verification_status, created_at, updated_at)
            SELECT lr.id, lr.finding_id, COALESCE(lr.assigned_to, 'unassigned'), lr.action,
                   'open', lr.due_date, 'not_verified', :now, :now
            FROM legacy_remediations lr
            """
        ),
        params,
    )
    legacy = bind.execute(sa.text("SELECT COUNT(*) FROM legacy_findings")).scalar_one()
    migrated = bind.execute(sa.text("SELECT COUNT(*) FROM findings")).scalar_one()
    if legacy != migrated:
        raise RuntimeError(f"Migration aborted: {legacy} legacy findings but {migrated} migrated")
    bind.execute(
        sa.text(
            """
            INSERT INTO audit_events (entity_type, entity_id, action, previous_value,
                                      new_value, timestamp, actor)
            VALUES ('system', 'database', 'schema_migrated', NULL,
                    json_object('revision', '0002_platform_schema', 'findings', :n),
                    :now, 'alembic-migration')
            """
        ),
        {"now": now, "n": migrated},
    )

    for table in (
        "legacy_remediations",
        "legacy_findings",
        "legacy_vulnerabilities",
        "legacy_assets",
    ):
        op.drop_table(table)


def downgrade() -> None:
    raise NotImplementedError(
        "Downgrade to the legacy schema is not supported; restore the file backup "
        "taken by scripts/init_db.py (data/backups/) instead."
    )
