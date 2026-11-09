"""File decoding and parsing for the supported import formats.

Parsers never execute anything from the file: CSV and JSON are parsed as data only, no
formula is evaluated, no path from the file is opened.

Supported sources:

* ``normalized_csv``  - CyberRemediate 360 normalised CSV (comma, semicolon or tab).
* ``normalized_json`` - list of objects, or ``{"findings": [...]}``.
* ``nessus_csv``      - adapter for the column layout of a Tenable Nessus "CSV" export.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field

from app.core.domain import ImportSource
from app.core.errors import ImportRejectedError

csv.field_size_limit(1_000_000)

REQUIRED_NORMALIZED_COLUMNS = {"asset_id", "hostname", "ip_address", "cve_id"}
NESSUS_REQUIRED_COLUMNS = {"plugin id", "cve", "host", "name"}
ALLOWED_EXTENSIONS = {
    ImportSource.NORMALIZED_CSV: {".csv"},
    ImportSource.NESSUS_CSV: {".csv"},
    ImportSource.NORMALIZED_JSON: {".json"},
}


@dataclass
class ParsedFile:
    rows: list[tuple[int, dict]]  # (line / item number, raw row)
    warnings: list[str] = field(default_factory=list)
    pre_rejected: list[dict] = field(default_factory=list)  # rows rejected while parsing


def safe_filename(name: str | None) -> str:
    """Keep only the base name and a conservative character set (no path traversal)."""
    base = re.split(r"[\\/]", name or "")[-1]
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")
    return base[:120] or "upload"


def check_extension(filename: str, source: ImportSource) -> None:
    lower = filename.lower()
    allowed = ALLOWED_EXTENSIONS[source]
    if not any(lower.endswith(ext) for ext in allowed):
        raise ImportRejectedError(
            f"File extension not allowed for source '{source.value}'",
            {"allowed_extensions": sorted(allowed)},
        )


def decode(content: bytes) -> tuple[str, list[str]]:
    warnings: list[str] = []
    if not content or not content.strip():
        raise ImportRejectedError("File is empty")
    if b"\x00" in content[:4096]:
        raise ImportRejectedError("Binary content detected: only UTF-8 text CSV/JSON is accepted")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = content.decode("cp1252")
        except UnicodeDecodeError as exc:
            raise ImportRejectedError("Unsupported text encoding (use UTF-8)") from exc
        warnings.append("File is not valid UTF-8: decoded as Windows-1252 (cp1252)")
    return text, warnings


def _normalize_header(name: str | None) -> str:
    return re.sub(r"\s+", "_", (name or "").strip().lower())


def _reader(text: str) -> csv.DictReader:
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    return csv.DictReader(io.StringIO(text, newline=""), dialect=dialect)


def _iter_csv(text: str, normalize_headers=_normalize_header):
    reader = _reader(text)
    if not reader.fieldnames:
        raise ImportRejectedError("CSV file has no header row")
    reader.fieldnames = [normalize_headers(h) for h in reader.fieldnames]
    if len(set(reader.fieldnames)) != len(reader.fieldnames):
        raise ImportRejectedError("CSV header contains duplicate column names")
    try:
        for row in reader:
            yield reader.line_num, reader.fieldnames, row
    except csv.Error as exc:
        raise ImportRejectedError(f"Malformed CSV near line {reader.line_num}: {exc}") from exc


def parse_normalized_csv(text: str, max_rows: int) -> ParsedFile:
    parsed = ParsedFile(rows=[])
    header_checked = False
    for line, headers, row in _iter_csv(text):
        if not header_checked:
            missing = REQUIRED_NORMALIZED_COLUMNS - set(headers)
            if missing:
                raise ImportRejectedError(
                    "CSV is missing required columns", {"missing_columns": sorted(missing)}
                )
            header_checked = True
        if None in row:  # more values than headers
            parsed.pre_rejected.append({"line": line, "reasons": ["too many columns in row"]})
            continue
        if all((v or "").strip() == "" for v in row.values()):
            continue  # skip blank lines silently
        parsed.rows.append((line, dict(row)))
        if len(parsed.rows) + len(parsed.pre_rejected) > max_rows:
            raise ImportRejectedError(f"File exceeds the maximum of {max_rows} rows")
    if not header_checked:
        raise ImportRejectedError("CSV contains a header but no data rows")
    return parsed


def parse_normalized_json(text: str, max_rows: int) -> ParsedFile:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ImportRejectedError(f"Malformed JSON: {exc.msg} (line {exc.lineno})") from exc
    if isinstance(data, dict):
        data = data.get("findings")
    if not isinstance(data, list):
        raise ImportRejectedError('JSON must be a list of objects or {"findings": [...]}')
    if not data:
        raise ImportRejectedError("JSON contains no findings")
    if len(data) > max_rows:
        raise ImportRejectedError(f"File exceeds the maximum of {max_rows} rows")
    parsed = ParsedFile(rows=[])
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            parsed.pre_rejected.append({"line": index, "reasons": ["item is not a JSON object"]})
            continue
        bad = [
            k
            for k, v in item.items()
            if isinstance(v, dict) or (isinstance(v, list) and k != "references")
        ]
        if bad:
            parsed.pre_rejected.append(
                {"line": index, "reasons": [f"nested values not allowed for: {', '.join(bad)}"]}
            )
            continue
        parsed.rows.append((index, {str(k).strip().lower(): v for k, v in item.items()}))
    return parsed


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_nessus_csv(text: str, max_rows: int) -> ParsedFile:
    """Adapter: map a Nessus CSV export to the normalised format.

    Expected columns (Nessus "CSV" export): Plugin ID, CVE, CVSS v3.0 Base Score,
    CVSS v2.0 Base Score, Risk, Host, Protocol, Port, Name, Synopsis, Description,
    Solution, See Also, Plugin Output. Optional: IP Address, FQDN, DNS Name, NetBIOS Name.
    Rows without CVE (informational plugins) are rejected with an explicit reason.
    Asset context (exposure, criticality, owner) is not in scanner output and is kept
    from the inventory when the asset already exists.
    """
    parsed = ParsedFile(rows=[])
    checked = False
    for line, headers, row in _iter_csv(
        text, normalize_headers=lambda h: (h or "").strip().lower()
    ):
        if not checked:
            missing = NESSUS_REQUIRED_COLUMNS - set(headers)
            if missing:
                raise ImportRejectedError(
                    "File does not look like a Nessus CSV export",
                    {"missing_columns": sorted(missing)},
                )
            checked = True
        if None in row:
            parsed.pre_rejected.append({"line": line, "reasons": ["too many columns in row"]})
            continue
        get = lambda k, r=row: (r.get(k) or "").strip()  # noqa: E731
        cve = get("cve")
        if not cve:
            parsed.pre_rejected.append(
                {"line": line, "reasons": [f"no CVE for plugin {get('plugin id')} (informational)"]}
            )
            continue
        host = get("host")
        ip = get("ip address") or (host if _is_ip(host) else "")
        hostname = (
            get("fqdn")
            or get("dns name")
            or get("netbios name")
            or (host if not _is_ip(host) else "")
            or (ip.replace(".", "-").replace(":", "-") if ip else "")
        )
        v3, v2 = get("cvss v3.0 base score"), get("cvss v2.0 base score")
        port = get("port")
        parsed.rows.append(
            (
                line,
                {
                    "asset_id": f"NES-{(ip or host).replace(':', '-')}"[:64],
                    "hostname": hostname,
                    "ip_address": ip,
                    "cve_id": cve,
                    "cvss_score": v3 or v2 or None,
                    "cvss_version": "3.0" if v3 else ("2.0" if v2 else None),
                    "title": get("name")[:300] or None,
                    "description": (get("synopsis") or get("description"))[:4000] or None,
                    "references": " ".join(
                        u for u in get("see also").split() if u.startswith(("http://", "https://"))
                    )
                    or None,
                    "scanner_source": f"nessus:plugin-{get('plugin id')}"[:64],
                    "port": port if port and port != "0" else None,
                    "protocol": get("protocol") or None,
                    "service": None,
                    "evidence": get("plugin output")[:4000] or None,
                },
            )
        )
        if len(parsed.rows) + len(parsed.pre_rejected) > max_rows:
            raise ImportRejectedError(f"File exceeds the maximum of {max_rows} rows")
    if not checked:
        raise ImportRejectedError("CSV contains a header but no data rows")
    parsed.warnings.append(
        "Nessus adapter: exposure/criticality are not provided by the scanner; existing "
        "inventory values are kept, new assets are created with 'unknown' context"
    )
    return parsed


PARSERS = {
    ImportSource.NORMALIZED_CSV: parse_normalized_csv,
    ImportSource.NORMALIZED_JSON: parse_normalized_json,
    ImportSource.NESSUS_CSV: parse_nessus_csv,
}
