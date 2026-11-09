import pytest

from app.core.domain import ImportMode
from app.core.errors import ImportRejectedError
from app.services.parsers import (
    decode,
    parse_nessus_csv,
    parse_normalized_csv,
    parse_normalized_json,
    safe_filename,
)
from app.services.validation import validate_row

BASE = {
    "asset_id": "ast-001",
    "hostname": " Web-01.Example.TEST ",
    "ip_address": "192.0.2.10",
    "cve_id": "cve-2021-44228",
    "cvss_score": "9,8",
    "exposure": "Internet",
    "business_criticality": "CRITICAL",
}


def errors_for(**overrides):
    record, errors = validate_row({**BASE, **overrides}, ImportMode.PRODUCTION)
    return record, " | ".join(errors)


def test_valid_row_is_normalised():
    record, errors = errors_for()
    assert errors == ""
    assert record.asset_id == "AST-001"
    assert record.hostname == "web-01.example.test"
    assert record.cve_id == "CVE-2021-44228"
    assert record.cvss_score == 9.8 and isinstance(record.cvss_score, float)
    assert record.exposure == "internet" and record.business_criticality == "critical"


@pytest.mark.parametrize("value", ["15.0", "-1", "abc", "nan", "inf"])
def test_invalid_cvss(value):
    record, errors = errors_for(cvss_score=value)
    assert record is None and "cvss_score" in errors


@pytest.mark.parametrize("value", ["999.1.1.1", "192.0.2", "not-an-ip", "192.0.2.10/24"])
def test_invalid_ip(value):
    record, errors = errors_for(ip_address=value)
    assert record is None and "ip_address" in errors


def test_ipv6_accepted():
    record, _ = errors_for(ip_address="2001:DB8::1")
    assert record.ip_address == "2001:db8::1"


@pytest.mark.parametrize("value", ["CVE-21-1", "CVE-2021-12", "2021-44228", "CVE_2021_44228"])
def test_malformed_cve(value):
    record, errors = errors_for(cve_id=value)
    assert record is None and "cve_id" in errors


def test_demo_cve_only_in_demo_mode():
    row = {**BASE, "cve_id": "CVE-DEMO-001"}
    assert validate_row(row, ImportMode.PRODUCTION)[0] is None
    assert validate_row(row, ImportMode.DEMO)[0].cve_id == "CVE-DEMO-001"


@pytest.mark.parametrize("field", ["asset_id", "hostname", "ip_address", "cve_id"])
def test_missing_required_fields(field):
    record, errors = errors_for(**{field: ""})
    assert record is None and field in errors


def test_enum_and_status_rules():
    assert "exposure" in errors_for(exposure="everywhere")[1]
    assert "status" in errors_for(status="resolved")[1]
    assert errors_for(status="In_Progress")[0].status == "in_progress"


def test_threat_signal_requires_source():
    assert "threat_source" in errors_for(kev="true")[1]
    record, _ = errors_for(kev="yes", epss_score="0.4", threat_source="CISA KEV 2026-11-01")
    assert record.kev is True and record.epss_score == 0.4


def test_vector_sets_version_and_location_key():
    record, _ = errors_for(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", port="443")
    assert record.cvss_version == "3.1"
    assert record.location_key == "tcp/443"
    assert "cvss_vector" in errors_for(cvss_vector="garbage")[1]


def test_dates_and_port_bounds():
    assert (
        "last_seen" in errors_for(first_seen="2026-10-02", last_seen="2026-10-01")[1]
        or "after first_seen" in errors_for(first_seen="2026-10-02", last_seen="2026-10-01")[1]
    )
    assert "port" in errors_for(port="70000")[1]
    assert "port" in errors_for(port="80; rm -rf /")[1]


def test_decode_rejects_empty_and_binary():
    with pytest.raises(ImportRejectedError):
        decode(b"")
    with pytest.raises(ImportRejectedError):
        decode(b"   \n ")
    with pytest.raises(ImportRejectedError):
        decode(b"PK\x03\x04\x00\x00binary")


def test_decode_cp1252_fallback():
    text, warnings = decode("asset_id,hostname\nA,caf\xe9".encode("cp1252"))
    assert "café" in text and warnings


def test_csv_header_checks_and_semicolon():
    with pytest.raises(ImportRejectedError) as exc:
        parse_normalized_csv("foo,bar\n1,2\n", 100)
    assert "missing_columns" in exc.value.details
    parsed = parse_normalized_csv(
        "asset_id;hostname;ip_address;cve_id\nA;h;192.0.2.1;CVE-2020-1234\n", 100
    )
    assert parsed.rows[0][1]["hostname"] == "h"


def test_csv_row_limit_and_extra_columns():
    text = "asset_id,hostname,ip_address,cve_id\n" + "A,h,192.0.2.1,CVE-2020-1234\n" * 3
    with pytest.raises(ImportRejectedError):
        parse_normalized_csv(text, 2)
    parsed = parse_normalized_csv("asset_id,hostname,ip_address,cve_id\nA,h,1.1.1.1,C,extra\n", 9)
    assert parsed.pre_rejected and not parsed.rows


def test_json_parsing():
    with pytest.raises(ImportRejectedError):
        parse_normalized_json("{not json", 10)
    with pytest.raises(ImportRejectedError):
        parse_normalized_json('{"findings": []}', 10)
    parsed = parse_normalized_json('[{"asset_id": "A"}, 5, {"x": {"nested": 1}}]', 10)
    assert len(parsed.rows) == 1 and len(parsed.pre_rejected) == 2


def test_nessus_adapter(sample_bytes):
    text, _ = decode(sample_bytes("nessus_export_sample.csv"))
    parsed = parse_nessus_csv(text, 100)
    assert len(parsed.rows) == 3 and len(parsed.pre_rejected) == 1
    row = parsed.rows[0][1]
    assert row["cve_id"] == "CVE-2021-44228" and row["cvss_score"] == "10.0"
    assert row["cvss_version"] == "3.0" and row["port"] == "8080"
    with pytest.raises(ImportRejectedError):
        parse_nessus_csv("a,b\n1,2\n", 10)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("../../etc/passwd", "passwd"),
        ("C:\\Windows\\evil.csv", "evil.csv"),
        ("..hidden.csv", "hidden.csv"),
        ("rapport été.csv", "rapport__t_.csv"),
        ("", "upload"),
    ],
)
def test_safe_filename(raw, expected):
    assert safe_filename(raw) == expected
