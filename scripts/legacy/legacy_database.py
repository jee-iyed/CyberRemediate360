import sqlite3
from pathlib import Path

DB_PATH = Path("data/cyberremediate.db")


def create_database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.execute("PRAGMA foreign_keys = ON")

    cursor = connection.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        hostname TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        exposure TEXT NOT NULL,
        business_criticality TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        cvss_score REAL NOT NULL
            CHECK (cvss_score BETWEEN 0 AND 10)
    );

    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id TEXT NOT NULL,
        vulnerability_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        FOREIGN KEY (asset_id) REFERENCES assets(id),
        FOREIGN KEY (vulnerability_id)
            REFERENCES vulnerabilities(id),
        UNIQUE (asset_id, vulnerability_id)
    );

    CREATE TABLE IF NOT EXISTS remediations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL,
        assigned_to TEXT,
        action TEXT NOT NULL,
        due_date TEXT,
        status TEXT NOT NULL DEFAULT 'planned',
        FOREIGN KEY (finding_id) REFERENCES findings(id)
    );
    """)

    connection.commit()
    connection.close()

    print("CyberRemediate 360 — Database initialized")


if __name__ == "__main__":
    create_database()