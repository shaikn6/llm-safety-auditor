"""
test_api_smoke.py — smoke tests for the FastAPI layer (api/main.py, api/database.py,
api/models.py).

These endpoints were previously excluded from coverage measurement because nothing
imported them during a test run. This suite exercises: session CRUD (run an audit,
fetch it back, list sessions, fetch its results), input validation errors, and rate
limiting behavior.
"""

from __future__ import annotations

import os
import tempfile

import pytest

# Point the API at an isolated, throwaway SQLite file before api.database is
# imported anywhere (it reads DATABASE_URL at import time).
_tmp_db_fd, _tmp_db_path = tempfile.mkstemp(suffix=".db")
os.close(_tmp_db_fd)
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp_db_path}"

from fastapi.testclient import TestClient

from api.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "llm-safety-auditor"}


def test_list_attacks(client):
    resp = client.get("/attacks")
    assert resp.status_code == 200
    attacks = resp.json()
    assert len(attacks) > 0
    assert "id" in attacks[0]


def test_list_attacks_invalid_category(client):
    resp = client.get("/attacks", params={"category": "not-a-real-category"})
    assert resp.status_code == 422


def test_get_attack_not_found(client):
    resp = client.get("/attacks/does-not-exist")
    assert resp.status_code == 404


def test_detect_safe_text(client):
    resp = client.post("/detect", json={"text": "The weather is nice today."})
    assert resp.status_code == 200
    body = resp.json()
    assert "is_safe" in body
    assert "confidence" in body


def test_detect_rejects_oversized_text(client):
    resp = client.post("/detect", json={"text": "a" * 32_001})
    assert resp.status_code == 422


def test_detect_requires_text_field(client):
    resp = client.post("/detect", json={})
    assert resp.status_code == 422


def test_audit_run_rejects_out_of_range_limit(client):
    resp = client.post("/audit/run", json={"limit": 0})
    assert resp.status_code == 422

    resp = client.post("/audit/run", json={"limit": 500})
    assert resp.status_code == 422


def test_audit_run_rejects_invalid_category(client):
    resp = client.post("/audit/run", json={"categories": ["not-a-real-category"]})
    assert resp.status_code == 422


def test_audit_run_rejects_oversized_session_id(client):
    resp = client.post("/audit/run", json={"session_id": "x" * 200})
    assert resp.status_code == 422


def test_audit_session_crud_roundtrip(client):
    session_id = "smoke-test-session-1"
    run_resp = client.post("/audit/run", json={"session_id": session_id, "limit": 1})
    assert run_resp.status_code == 200
    body = run_resp.json()
    assert body["session_id"] == session_id
    assert body["total_attacks"] == 1

    get_resp = client.get(f"/audit/{session_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["session_id"] == session_id

    results_resp = client.get(f"/audit/{session_id}/results")
    assert results_resp.status_code == 200
    results = results_resp.json()
    assert len(results) == 1
    assert "attack_id" in results[0]

    list_resp = client.get("/audit/sessions/list")
    assert list_resp.status_code == 200
    session_ids = [s["session_id"] for s in list_resp.json()]
    assert session_id in session_ids


def test_get_session_not_found(client):
    resp = client.get("/audit/does-not-exist-session")
    assert resp.status_code == 404


def test_detect_rate_limit_enforced(client):
    """The /detect endpoint is limited to 30/minute; the 31st request in the
    same window should be rejected with 429."""
    responses = [client.post("/detect", json={"text": "hello"}) for _ in range(31)]
    statuses = [r.status_code for r in responses]
    assert 429 in statuses, f"expected a 429 among responses, got {statuses}"
