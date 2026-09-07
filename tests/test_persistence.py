"""Optional SQLite analysis history."""

from __future__ import annotations

import pytest
from conftest import CLEAN_SOURCE
from fastapi.testclient import TestClient

from persistence import NullAnalysisStore, build_store


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "analyses.db")


def test_null_store_when_disabled() -> None:
    store = build_store(enabled=False, database_path="unused.db")
    assert isinstance(store, NullAnalysisStore)
    assert store.enabled is False


@pytest.mark.asyncio
async def test_null_store_is_inert() -> None:
    store = NullAnalysisStore()
    assert await store.save(None) is False  # type: ignore[arg-type]
    assert await store.list_recent() == []
    assert await store.get_report("x") is None


def test_sqlite_round_trip_via_api(app_factory, db_path) -> None:
    app = app_factory(persistence_enabled=True, database_path=db_path)
    with TestClient(app) as c:
        r = c.post("/api/v1/analyze", json={"filename": "a.py", "source_code": CLEAN_SOURCE})
        analysis_id = r.json()["analysis_id"]
        assert r.json()["stored"] is True

        listing = c.get("/api/v1/analyses").json()
        assert listing["count"] == 1
        assert listing["analyses"][0]["analysis_id"] == analysis_id

        summary = c.get(f"/api/v1/analyses/{analysis_id}")
        assert summary.status_code == 200
        assert summary.json()["filename"] == "a.py"

        report = c.get(f"/api/v1/analyses/{analysis_id}/report")
        assert report.status_code == 200
        assert report.json()["analysis_id"] == analysis_id

        assert c.get("/api/v1/analyses/missing-id").status_code == 404


def test_health_reports_persistence_enabled(app_factory, db_path) -> None:
    app = app_factory(persistence_enabled=True, database_path=db_path)
    with TestClient(app) as c:
        assert c.get("/health").json()["persistence_enabled"] is True


def test_pipeline_still_works_if_store_write_fails(app_factory, db_path, monkeypatch) -> None:
    app = app_factory(persistence_enabled=True, database_path=db_path)
    with TestClient(app) as c:
        store = app.state.store

        async def boom(_response):  # type: ignore[no-untyped-def]
            raise RuntimeError("disk full")

        monkeypatch.setattr(store, "_insert", _raise)
        r = c.post("/api/v1/analyze", json={"source_code": CLEAN_SOURCE})
        assert r.status_code == 200
        assert r.json()["stored"] is False


def _raise(*_a: object, **_k: object) -> None:
    raise RuntimeError("disk full")
