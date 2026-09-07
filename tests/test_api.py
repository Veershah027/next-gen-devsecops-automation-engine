"""HTTP surface via FastAPI TestClient."""

from __future__ import annotations

from conftest import CLEAN_SOURCE, VULNERABLE_SOURCE


def test_health_ok(client) -> None:
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["service"] == "devsecops-automation-engine"
    assert body["environment"] == "test"
    assert body["llm_live"] is False
    assert body["webhook_enabled"] is True
    assert body["persistence_enabled"] is False


def test_analyze_happy_path(client) -> None:
    r = client.post("/api/v1/analyze", json={"filename": "svc.py", "source_code": VULNERABLE_SOURCE})
    assert r.status_code == 200
    body = r.json()
    assert body["gate_passed"] is False
    assert body["metrics"]["total_findings"] > 0
    assert body["remediation_mode"] == "template"
    assert body["patches"]
    for patch in body["patches"]:
        assert "validation" in patch and "status" in patch["validation"]


def test_analyze_clean_source(client) -> None:
    r = client.post("/api/v1/analyze", json={"source_code": CLEAN_SOURCE})
    assert r.status_code == 200
    assert r.json()["gate_passed"] is True


def test_analyze_rejects_non_python(client) -> None:
    r = client.post("/api/v1/analyze", json={"source_code": "x=1", "language": "ruby"})
    assert r.status_code == 422
    assert r.json()["error"] == "invalid_submission"


def test_analyze_rejects_empty(client) -> None:
    assert client.post("/api/v1/analyze", json={"source_code": ""}).status_code == 422


def test_analyze_rejects_unknown_field(client) -> None:
    r = client.post("/api/v1/analyze", json={"source_code": "x=1", "bogus": 1})
    assert r.status_code == 422
    assert r.json()["error"] == "validation_error"


def test_analyze_rejects_oversized_body(client) -> None:
    r = client.post(
        "/api/v1/analyze",
        content=b"{}",
        headers={"content-type": "application/json", "content-length": str(5 * 1024 * 1024)},
    )
    assert r.status_code == 413


def test_security_headers_present(client) -> None:
    h = client.get("/health").headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert "default-src 'none'" in h["content-security-policy"]
    assert "x-request-id" in {k.lower() for k in h}


def test_request_id_is_echoed_when_supplied(client) -> None:
    r = client.get("/health", headers={"X-Request-ID": "abc-123"})
    assert r.headers["x-request-id"] == "abc-123"


def test_stream_logs_route_registered(client) -> None:
    schema = client.get("/openapi.json").json()
    assert "/api/v1/stream-logs" in schema["paths"]
    assert "get" in schema["paths"]["/api/v1/stream-logs"]


def test_webhook_deliveries_starts_empty(client) -> None:
    body = client.get("/api/v1/webhook/deliveries").json()
    assert body == {"count": 0, "deliveries": []}


def test_analyses_list_empty_without_persistence(client) -> None:
    assert client.get("/api/v1/analyses").json() == {"count": 0, "analyses": []}


def test_analysis_report_404_without_persistence(client) -> None:
    assert client.get("/api/v1/analyses/whatever").status_code == 404


def test_dashboard_served(client) -> None:
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert "<!DOCTYPE html>" in r.text or "<!doctype html>" in r.text.lower()


def test_openapi_lists_every_documented_endpoint(client) -> None:
    paths = set(client.get("/openapi.json").json()["paths"])
    for expected in (
        "/health",
        "/api/v1/analyze",
        "/api/v1/stream-logs",
        "/api/v1/analyses",
        "/api/v1/analyses/{analysis_id}",
        "/api/v1/analyses/{analysis_id}/report",
        "/api/v1/webhook",
        "/api/v1/webhook/deliveries",
    ):
        assert expected in paths, expected


def test_root_index(client) -> None:
    body = client.get("/").json()
    assert body["service"] == "devsecops-automation-engine"
    assert body["endpoints"]["analyze"] == "/api/v1/analyze"


def test_docs_disabled_in_production(app_factory) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_factory(environment="production")) as c:
        assert c.get("/docs").status_code == 404
        assert c.get("/openapi.json").status_code == 404
