import csv
import sqlite3
from pathlib import Path

from validate_csv import normalize, validate

CSV_PATH = Path("data/samples/vulnerabilities.csv")
DB_PATH = Path("data/cyberremediate.db")


def import_vulnerabilities():
    imported = 0
    rejected = 0
    duplicates = 0

    connection = sqlite3.connect(DB_PATH)
    connection.execute("PRAGMA foreign_keys = ON")

    try:
        with CSV_PATH.open(
            "r", encoding="utf-8-sig", newline=""
        ) as file:

            reader = csv.DictReader(file)

            for line_number, raw_row in enumerate(
                reader, start=2
            ):
                row = normalize(raw_row)
                errors = validate(row)

                if errors:
                    rejected += 1
                    print(
                        f"Line {line_number} rejected: "
                        f"{', '.join(errors)}"
                    )
                    continue

                # Each observation is stored atomically
                # using a SQLite savepoint.
                connection.execute("SAVEPOINT import_row")

                try:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO assets
                        (id, hostname, ip_address,
                         exposure, business_criticality)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            row["asset_id"],
                            row["hostname"],
                            row["ip_address"],
                            row["exposure"],
                            row["business_criticality"],
                        ),
                    )

                    connection.execute(
                        """
                        INSERT OR IGNORE INTO vulnerabilities
                        (id, cvss_score)
                        VALUES (?, ?)
                        """,
                        (
                            row["cve_id"],
                            float(row["cvss_score"]),
                        ),
                    )

                    cursor = connection.execute(
                        """
                        INSERT OR IGNORE INTO findings
                        (asset_id, vulnerability_id, status)
                        VALUES (?, ?, ?)
                        """,
                        (
                            row["asset_id"],
                            row["cve_id"],
                            row["status"],
                        ),
                    )

                    if cursor.rowcount == 0:
                        duplicates += 1
                    else:
                        imported += 1

                    connection.execute(
                        "RELEASE SAVEPOINT import_row"
                    )

                except sqlite3.Error as error:
                    connection.execute(
                        "ROLLBACK TO SAVEPOINT import_row"
                    )
                    connection.execute(
                        "RELEASE SAVEPOINT import_row"
                    )
                    rejected += 1
                    print(
                        f"Line {line_number} database error: "
                        f"{error}"
                    )

        connection.commit()

    finally:
        connection.close()

    print("\n=== CyberRemediate 360 — SQL Import ===")
    print(f"New findings: {imported}")
    print(f"Rejected rows: {rejected}")
    print(f"Duplicate findings: {duplicates}")


if __name__ == "__main__":
    import_vulnerabilities()