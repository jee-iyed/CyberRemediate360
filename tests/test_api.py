import json

from conftest import make_csv

ROWS = make_csv(
    "AST-001,web-01,192.0.2.10,CVE-2021-44228,10.0,internet,critical,open",
    "AST-002,db-01,192.0.2.20,CVE-2014-0160,7.5,internal,high,open",
    "AST-003,lab-01,192.0.2.30,CVE-2021-44228,10.0,isolated,low,open",
)


def upload(
    client, content=ROWS, name="scan.csv", source="normalized_csv", mode="production", headers=None
):
    return client.post(
        "/api/v1/imports",
        files={"file": (name, content, "text/csv")},
        data={"source": source, "mode": mode},
        headers=headers or {},
    )


def test_health_and_docs(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200 and r.json()["database"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/docs").status_code == 200
    paths = client.get("/openapi.json").json()["paths"]
    for p in [
        "/api/v1/assets",
        "/api/v1/findings/{finding_id}",
        "/api/v1/imports",
        "/api/v1/dashboard/summary",
        "/api/v1/dashboard/trends",
        "/api/v1/remediations",
        "/api/v1/remediations/{remediation_id}",
        "/api/v1/audit-events",
        "/api/v1/reports/export",
        "/api/v1/vulnerabilities",
        "/api/v1/assets/{asset_id}",
    ]:
        assert p in paths


def test_import_then_query_flow(client):
    r = upload(client)
    assert r.status_code == 201, r.text
    assert r.json()["imported"] == 3
    assert client.get("/api/v1/imports").json()["total"] == 1

    findings = client.get("/api/v1/findings").json()
    assert findings["total"] == 3
    scores = [f["risk_score"] for f in findings["items"]]
    assert scores == sorted(scores, reverse=True)  # default sort: risk desc
    top = findings["items"][0]
    assert top["hostname"] == "web-01" and top["priority"] == "P1"

    detail = client.get(f"/api/v1/findings/{top['id']}").json()
    assert detail["risk_explanation"]["components"]["exposure"] == 20
    assert detail["vulnerability"]["cve_id"] == "CVE-2021-44228"

    assert client.get("/api/v1/findings", params={"q": "lab"}).json()["total"] == 1
    assert client.get("/api/v1/findings", params={"priority": ["P1"]}).json()["total"] == 1
    page = client.get("/api/v1/findings", params={"page_size": 2, "page": 2}).json()
    assert len(page["items"]) == 1 and page["total"] == 3
    assert client.get("/api/v1/findings", params={"sort": "-cvss_score"}).status_code == 200
    bad = client.get("/api/v1/findings", params={"sort": "password"})
    assert bad.status_code == 400 and bad.json()["error"]["code"] == "bad_request"

    vulns = client.get("/api/v1/vulnerabilities", params={"min_cvss": 9}).json()
    assert vulns["total"] == 1


def test_asset_crud_and_validation(client):
    r = client.post(
        "/api/v1/assets",
        json={
            "asset_key": "srv-9",
            "hostname": "srv-9.example.test",
            "ip_address": "198.51.100.9",
            "exposure": "internal",
            "business_criticality": "high",
        },
    )
    assert r.status_code == 201 and r.json()["asset_key"] == "SRV-9"
    asset_id = r.json()["id"]
    assert (
        client.post(
            "/api/v1/assets",
            json={"asset_key": "SRV-9", "hostname": "x", "ip_address": "198.51.100.9"},
        ).status_code
        == 409
    )
    bad = client.post(
        "/api/v1/assets",
        json={"asset_key": "x", "hostname": "x", "ip_address": "300.1.1.1", "role": "admin"},
    )
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "validation_error"
    assert client.get(f"/api/v1/assets/{asset_id}").json()["open_findings"] == 0
    assert client.get("/api/v1/assets/9999").status_code == 404
    assert client.get("/api/v1/assets", params={"q": "srv"}).json()["total"] == 1


def test_asset_patch_rescores(client):
    upload(client)
    assets = client.get("/api/v1/assets", params={"q": "AST-003"}).json()["items"]
    lab = assets[0]
    before = client.get("/api/v1/findings", params={"asset_id": lab["id"]}).json()["items"][0]
    r = client.patch(f"/api/v1/assets/{lab['id']}", json={"exposure": "internet"})
    assert r.status_code == 200
    after = client.get("/api/v1/findings", params={"asset_id": lab["id"]}).json()["items"][0]
    assert after["risk_score"] > before["risk_score"]


def test_remediation_api_workflow(client):
    upload(client)
    fid = client.get("/api/v1/findings").json()["items"][0]["id"]
    r = client.post(
        "/api/v1/remediations",
        json={"finding_id": fid, "owner": "Ops", "action": "Upgrade log4j"},
        headers={"X-Actor": "alice<script>"},
    )
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    bad = client.patch(f"/api/v1/remediations/{rid}", json={"status": "resolved"})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "invalid_transition"
    ok = client.patch(
        f"/api/v1/remediations/{rid}", json={"status": "resolved", "evidence": "rescan clean"}
    )
    assert ok.status_code == 200 and ok.json()["completed_at"]
    assert client.get(f"/api/v1/findings/{fid}").json()["status"] == "resolved"
    assert client.patch(f"/api/v1/remediations/{rid}", json={"bogus": 1}).status_code == 422
    events = client.get("/api/v1/audit-events", params={"entity_type": "remediation"}).json()
    assert events["total"] == 2
    assert {e["actor"] for e in events["items"]} >= {"alicescript"}
    summary = client.get("/api/v1/dashboard/summary").json()
    assert summary["resolved_findings"] == 1 and summary["open_findings"] == 2


def test_dashboard_values_come_from_data(client):
    empty = client.get("/api/v1/dashboard/summary").json()
    assert empty["total_findings"] == 0 and empty["top_assets"] == []
    upload(client)
    s = client.get("/api/v1/dashboard/summary").json()
    assert s["total_assets"] == 3 and s["open_findings"] == 3 and s["high_critical_open"] == 3
    assert s["by_severity"] == {"critical": 2, "high": 1}
    assert s["top_assets"][0]["hostname"] == "web-01"
    t = client.get("/api/v1/dashboard/trends").json()
    assert sum(w["new_findings"] for w in t["series"]) == 3


def test_reports_export(client):
    upload(client)
    pdf = client.get("/api/v1/reports/export", params={"format": "pdf"})
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert pdf.headers["content-type"] == "application/pdf"
    csv_r = client.get("/api/v1/reports/export", params={"format": "csv"})
    assert csv_r.status_code == 200 and "CVE-2021-44228" in csv_r.text
    data = json.loads(client.get("/api/v1/reports/export", params={"format": "json"}).content)
    assert data["summary"]["open_findings"] == 3 and len(data["findings"]) == 3
    assert client.get("/api/v1/reports/export", params={"format": "exe"}).status_code == 422


def test_import_errors_via_api(client):
    r = upload(client, content=b"", name="empty.csv")
    assert r.status_code == 422 and r.json()["error"]["details"]["import_job_id"]
    r = upload(client, name="evil.php")
    assert r.status_code == 422
    r = upload(client, content=b"x" * (5 * 1024 * 1024 + 10), name="big.csv")
    assert r.status_code == 413
    r = upload(client, mode="root")
    assert r.status_code == 422
