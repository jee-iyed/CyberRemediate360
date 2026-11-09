"""Validation & normalisation of one scanner observation (one input row).

The normalised format is documented in docs/api.md ("Import formats"). Every row is
validated with a Pydantic v2 model; errors are reported per field and the row is
rejected, never silently fixed (except harmless normalisation such as trimming spaces,
lower-casing enums, upper-casing CVE ids or accepting ``9,8`` as a decimal).
"""

from __future__ import annotations

import ipaddress
import math
import re
from datetime import datetime, timedelta
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from app.core.domain import Criticality, Environment, Exposure, ImportMode
from app.core.timeutils import ensure_utc, utcnow

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
DEMO_CVE_RE = re.compile(r"^CVE-DEMO-\d{3,6}$")
CWE_RE = re.compile(r"^(CWE-\d{1,5}|NVD-CWE-Other|NVD-CWE-noinfo)$")
ASSET_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)
CVSS3_VECTOR_RE = re.compile(
    r"^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH](/.*)?$"
)
CVSS4_VECTOR_RE = re.compile(r"^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/.+$")
CVSS2_VECTOR_RE = re.compile(r"^\(?AV:[LAN]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]\)?$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9._/+-]{1,64}$")
IMPORTABLE_STATUSES = {"open", "in_progress"}
TRUE_VALUES = {"true", "yes", "1", "y"}
FALSE_VALUES = {"false", "no", "0", "n"}
MAX_TEXT = 4000


class FindingRecord(BaseModel):
    """One normalised observation: asset + vulnerability + finding context."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")

    asset_id: str = Field(min_length=1, max_length=64)
    hostname: str = Field(min_length=1, max_length=253)
    ip_address: str
    cve_id: str
    cvss_score: float | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = Field(default=None, max_length=200)
    title: str | None = Field(default=None, max_length=300)
    description: str | None = Field(default=None, max_length=MAX_TEXT)
    cwe_id: str | None = None
    references: list[str] | None = None
    exposure: Exposure | None = None
    business_criticality: Criticality | None = None
    owner: str | None = Field(default=None, max_length=120)
    environment: Environment | None = None
    status: str | None = None
    scanner_source: str | None = Field(default=None, max_length=64)
    service: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence: str | None = Field(default=None, max_length=MAX_TEXT)
    epss_score: float | None = Field(default=None, ge=0, le=1)
    kev: bool | None = None
    threat_source: str | None = Field(default=None, max_length=120)

    # ---- pre-processing --------------------------------------------------------------
    @model_validator(mode="before")
    @classmethod
    def _blank_to_none(cls, data: Any) -> Any:
        if isinstance(data, dict):
            cleaned = {}
            for key, value in data.items():
                if isinstance(value, str):
                    value = value.strip()
                    if value == "":
                        continue  # blank = absent: required fields report "Field required"
                if value is None:
                    continue
                cleaned[key] = value
            return cleaned
        return data

    @field_validator("asset_id")
    @classmethod
    def _asset_key(cls, v: str) -> str:
        if not ASSET_KEY_RE.fullmatch(v):
            raise ValueError("asset_id must be 1-64 chars of letters, digits, . _ : -")
        return v.upper()

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, v: str) -> str:
        v = v.lower().rstrip(".")
        if not HOSTNAME_RE.fullmatch(v):
            raise ValueError("invalid hostname (RFC 1123 labels expected)")
        return v

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v))
        except ValueError as exc:
            raise ValueError(f"invalid IP address '{v[:45]}'") from exc

    @field_validator("cve_id")
    @classmethod
    def _cve(cls, v: str, info: ValidationInfo) -> str:
        v = v.upper()
        mode = (info.context or {}).get("mode", ImportMode.PRODUCTION)
        if CVE_RE.fullmatch(v):
            return v
        if DEMO_CVE_RE.fullmatch(v):
            if mode == ImportMode.DEMO:
                return v
            raise ValueError("fictional CVE-DEMO identifiers are only accepted in demo mode")
        raise ValueError("malformed CVE identifier (expected CVE-YYYY-NNNN)")

    @field_validator("cvss_score", "epss_score", mode="before")
    @classmethod
    def _decimal(cls, v: Any) -> Any:
        if isinstance(v, bool):
            raise ValueError("must be a number")
        if isinstance(v, str):
            v = v.replace(",", ".")
            try:
                v = float(v)
            except ValueError as exc:
                raise ValueError("must be a number") from exc
        if isinstance(v, float) and not math.isfinite(v):
            raise ValueError("must be a finite number")
        return v

    @field_validator("cvss_score")
    @classmethod
    def _cvss_range(cls, v: float | None) -> float | None:
        if v is not None and not 0 <= v <= 10:
            raise ValueError("CVSS score must be between 0.0 and 10.0")
        return round(v, 1) if v is not None else None

    @field_validator("cvss_version", mode="before")
    @classmethod
    def _cvss_version(cls, v: Any) -> Any:
        if v is None:
            return None
        v = str(v).strip()
        if v not in {"2.0", "3.0", "3.1", "4.0"}:
            raise ValueError("cvss_version must be one of 2.0, 3.0, 3.1, 4.0")
        return v

    @field_validator("cwe_id")
    @classmethod
    def _cwe(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = (
            v.upper()
            .replace("NVD-CWE-OTHER", "NVD-CWE-Other")
            .replace("NVD-CWE-NOINFO", "NVD-CWE-noinfo")
        )
        if v.isdigit():
            v = f"CWE-{v}"
        if not CWE_RE.fullmatch(v):
            raise ValueError("cwe_id must look like CWE-79")
        return v

    @field_validator("references", mode="before")
    @classmethod
    def _references(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, str):
            v = [part.strip() for part in re.split(r"[;\s]+", v) if part.strip()]
        if not isinstance(v, list) or len(v) > 20:
            raise ValueError("references must be a list of at most 20 URLs")
        for url in v:
            if not isinstance(url, str) or not re.fullmatch(r"https?://[^\s\"'<>]{3,500}", url):
                raise ValueError("references must be http(s) URLs")
        return v

    @field_validator("exposure", "business_criticality", "environment", mode="before")
    @classmethod
    def _lower_enum(cls, v: Any) -> Any:
        return v.lower() if isinstance(v, str) else v

    @field_validator("status", mode="before")
    @classmethod
    def _status(cls, v: Any) -> Any:
        if v is None:
            return None
        v = str(v).strip().lower()
        if v not in IMPORTABLE_STATUSES:
            raise ValueError(
                "status on import must be 'open' or 'in_progress'; closure states are "
                "managed through the remediation workflow"
            )
        return v

    @field_validator("service")
    @classmethod
    def _service(cls, v: str | None) -> str | None:
        if v is not None and not SERVICE_RE.fullmatch(v):
            raise ValueError("service contains unsupported characters")
        return v.lower() if v else v

    @field_validator("protocol")
    @classmethod
    def _protocol(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.lower()
        if v not in {"tcp", "udp", "icmp"}:
            raise ValueError("protocol must be tcp, udp or icmp")
        return v

    @field_validator("port", mode="before")
    @classmethod
    def _port(cls, v: Any) -> Any:
        if isinstance(v, str):
            if not v.isdigit():
                raise ValueError("port must be an integer between 0 and 65535")
            return int(v)
        return v

    @field_validator("kev", mode="before")
    @classmethod
    def _bool(cls, v: Any) -> Any:
        if isinstance(v, str):
            low = v.lower()
            if low in TRUE_VALUES:
                return True
            if low in FALSE_VALUES:
                return False
            raise ValueError("kev must be true/false")
        return v

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _utc(cls, v: datetime | None) -> datetime | None:
        v = ensure_utc(v)
        if v is not None and v > utcnow() + timedelta(days=1):
            raise ValueError("date cannot be in the future")
        return v

    @model_validator(mode="after")
    def _cross_checks(self) -> FindingRecord:
        if self.first_seen and self.last_seen and self.last_seen < self.first_seen:
            raise ValueError("last_seen must be after first_seen")
        if (self.kev is not None or self.epss_score is not None) and not self.threat_source:
            raise ValueError(
                "threat_source is required when kev or epss_score is provided "
                "(threat signals must come from a documented source)"
            )
        if self.cvss_vector:
            ok = (
                CVSS3_VECTOR_RE.fullmatch(self.cvss_vector)
                or CVSS4_VECTOR_RE.fullmatch(self.cvss_vector)
                or CVSS2_VECTOR_RE.fullmatch(self.cvss_vector)
            )
            if not ok:
                raise ValueError("cvss_vector is not a valid CVSS v2/v3.x/v4.0 vector")
            if self.cvss_version is None:
                if self.cvss_vector.startswith("CVSS:"):
                    self.cvss_version = self.cvss_vector[5:8]
                else:
                    self.cvss_version = "2.0"
        if self.port is not None and self.protocol is None:
            self.protocol = "tcp"
        return self

    @property
    def location_key(self) -> str:
        return f"{self.protocol}/{self.port}" if self.port is not None else ""

    @property
    def business_key(self) -> tuple[str, str, str]:
        return (self.asset_id, self.cve_id, self.location_key)


def validate_row(raw: dict, mode: ImportMode) -> tuple[FindingRecord | None, list[str]]:
    """Return (record, []) or (None, [error messages])."""
    try:
        return FindingRecord.model_validate(raw, context={"mode": mode}), []
    except ValidationError as exc:
        messages = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err.get("loc", ()))
            msg = err.get("msg", "invalid value").removeprefix("Value error, ")
            messages.append(f"{loc}: {msg}" if loc else msg)
        return None, messages
