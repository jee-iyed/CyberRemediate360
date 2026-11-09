import csv
import re
from pathlib import Path

CSV_PATH = Path("data/samples/vulnerabilities.csv")

VALID_EXPOSURES = {"internet", "internal", "isolated"}
VALID_CRITICALITIES = {"low", "medium", "high", "critical"}
VALID_STATUSES = {"open", "in_progress", "resolved"}

DEMO_CVE_PATTERN = re.compile(r"^CVE-DEMO-\d{3}$")


def normalize(row):
    """Remove whitespace and normalize selected fields."""
    cleaned = {}

    for key, value in row.items():
        if key is None:
            continue

        cleaned[key] = str(value or "").strip()

    for field in ("hostname", "exposure", "business_criticality", "status"):
        cleaned[field] = cleaned.get(field, "").lower()

    cleaned["cve_id"] = cleaned.get("cve_id", "").upper()

    return cleaned


def validate(row):
    """Return a list of validation errors."""
    errors = []

    required_fields = [
        "asset_id",
        "hostname",
        "ip_address",
        "cve_id",
        "cvss_score",
        "exposure",
        "business_criticality",
        "status",
    ]

    for field in required_fields:
        if not row.get(field):
            errors.append(f"Missing field: {field}")

    try:
        score = float(row.get("cvss_score", ""))
        if not 0 <= score <= 10:
            errors.append("CVSS must be between 0 and 10")
    except ValueError:
        errors.append("Invalid CVSS score")

    if row.get("exposure") not in VALID_EXPOSURES:
        errors.append("Invalid exposure")

    if row.get("business_criticality") not in VALID_CRITICALITIES:
        errors.append("Invalid business criticality")

    if row.get("status") not in VALID_STATUSES:
        errors.append("Invalid status")

    cve_id = row.get("cve_id", "")
    if not DEMO_CVE_PATTERN.fullmatch(cve_id):
        errors.append("Invalid demo CVE identifier")

    return errors


def main():
    valid_rows = []
    rejected_rows = []
    seen = set()
    duplicates = 0

    with CSV_PATH.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        for line_number, raw_row in enumerate(reader, start=2):
            row = normalize(raw_row)
            errors = validate(row)

            if errors:
                rejected_rows.append((line_number, errors))
                continue

            key = (row["asset_id"], row["cve_id"])

            if key in seen:
                duplicates += 1
                continue

            seen.add(key)
            valid_rows.append(row)

    print("=== CyberRemediate 360 — Data Validation ===")
    print(f"Valid observations: {len(valid_rows)}")
    print(f"Rejected observations: {len(rejected_rows)}")
    print(f"Duplicates: {duplicates}")

    for line_number, errors in rejected_rows:
        print(f"Line {line_number}: {', '.join(errors)}")


if __name__ == "__main__":
    main()