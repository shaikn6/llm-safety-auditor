"""
test_api_hardening.py — duplicate session handling, API-key auth on mutating
routes, and provider selection for /audit/run. No network: real providers are
replaced with fakes.
"""

from __future__ import annotations

import os
import tempfile

import pytest

# api.database reads DATABASE_URL at import time; make sure it never points at
# the developer's real database, whichever API test module is imported first.
if "DATABASE_URL" not in os.environ:
    _tmp_db_fd, _tmp_db_path = tempfile.mkstemp(suffix=".db")
    os.close(_tmp_db_fd)
    os.environ["DATABASE_URL"] = f"sqlite:///{_tmp_db_path}"

from fastapi.testclient import TestClient

import api.main as api_main
from api.main import app, limiter
from auditor.mock_llm import LLMResponse
from auditor.providers import ProviderConfigError, ProviderError


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    """Each test starts with an empty rate-limit window and default env."""
    limiter.reset()
    for var in ("APP_ENV", "API_KEYS", "LLM_PROVIDER", "LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)
    yield
    limiter.reset()


# ---------------------------------------------------------------------------
# Duplicate session ids
# ---------------------------------------------------------------------------


def test_duplicate_session_id_returns_409(client):
    payload = {"session_id": "hardening-dup-1", "limit": 2}
    first = client.post("/audit/run", json=payload)
    assert first.status_code == 200

    second = client.post("/audit/run", json=payload)
    assert second.status_code == 409
    assert "hardening-dup-1" in second.json()["detail"]
    assert "already exists" in second.json()["detail"]

    # The first run is untouched.
    results = client.get("/audit/hardening-dup-1/results").json()
    assert len(results) == 2


def test_omitted_session_id_gets_unique_id_each_run(client):
    a = client.post("/audit/run", json={"limit": 1})
    b = client.post("/audit/run", json={"limit": 1})
    assert a.status_code == b.status_code == 200
    assert a.json()["session_id"] != b.json()["session_id"]


def test_session_id_longer_than_column_is_rejected(client):
    resp = client.post("/audit/run", json={"session_id": "x" * 65, "limit": 1})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# API-key auth on mutating routes
# ---------------------------------------------------------------------------


def test_dev_mode_without_keys_is_open(client):
    resp = client.post("/detect", json={"text": "hello"})
    assert resp.status_code == 200


def test_configured_key_is_required(client, monkeypatch):
    monkeypatch.setenv("API_KEYS", "key-one, key-two")

    assert client.post("/detect", json={"text": "hello"}).status_code == 401
    wrong = client.post("/detect", json={"text": "hi"}, headers={"X-API-Key": "nope"})
    assert wrong.status_code == 401
    assert client.post("/audit/run", json={"limit": 1}).status_code == 401

    for key in ("key-one", "key-two"):
        ok = client.post("/detect", json={"text": "hi"}, headers={"X-API-Key": key})
        assert ok.status_code == 200
    run = client.post("/audit/run", json={"limit": 1}, headers={"X-API-Key": "key-two"})
    assert run.status_code == 200


def test_non_ascii_key_is_rejected_not_crashing(client, monkeypatch):
    monkeypatch.setenv("API_KEYS", "key-one")
    resp = client.post(
        "/detect", json={"text": "hi"}, headers={"X-API-Key": "kéy".encode()}
    )
    assert resp.status_code == 401


def test_production_without_keys_fails_closed(client, monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    resp = client.post("/detect", json={"text": "hello"})
    assert resp.status_code == 503
    assert "API_KEYS" in resp.json()["detail"]
    assert client.post("/audit/run", json={"limit": 1}).status_code == 503


def test_production_with_key_works(client, monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("API_KEYS", "prod-key")
    resp = client.post(
        "/detect", json={"text": "hello"}, headers={"X-API-Key": "prod-key"}
    )
    assert resp.status_code == 200


def test_read_routes_do_not_need_a_key(client, monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("API_KEYS", "prod-key")
    assert client.get("/health").status_code == 200
    assert client.get("/attacks").status_code == 200


def test_session_read_routes_require_a_key(client, monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("API_KEYS", "prod-key")
    # Stored audit sessions and their results are not public.
    for path in ("/audit/sessions/list", "/audit/sid/", "/audit/sid/results"):
        url = path.rstrip("/") if path != "/audit/sid/" else "/audit/sid"
        assert client.get(url).status_code == 401
        assert client.get(url, headers={"X-API-Key": "prod-key"}).status_code != 401


# ---------------------------------------------------------------------------
# Detector context on /detect
# ---------------------------------------------------------------------------


def test_detect_accepts_attack_category(client):
    text = "In Okafor v. Ministry of Transport (2021), the court ruled 5-4."
    plain = client.post("/detect", json={"text": text}).json()
    assert plain["is_safe"] is True

    ctx = client.post(
        "/detect", json={"text": text, "attack_category": "HALLUCINATION_TRIGGER"}
    ).json()
    assert ctx["is_safe"] is False
    assert ctx["category"] == "hallucination"


def test_detect_rejects_unknown_attack_category(client):
    resp = client.post("/detect", json={"text": "hi", "attack_category": "NOPE"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Provider selection
# ---------------------------------------------------------------------------


class _FakeProvider:
    def __init__(self, text: str = "I can't help with that."):
        self.text = text
        self.calls = 0

    def complete(self, attack):
        self.calls += 1
        return LLMResponse(
            prompt=attack.template,
            response_text=self.text,
            is_simulated_failure=False,
            model_name="fake-model-1",
        )


def test_audit_run_uses_the_configured_provider(client, monkeypatch):
    fake = _FakeProvider()
    seen = {}

    def fake_build(seed):
        seen["seed"] = seed
        return fake

    monkeypatch.setattr(api_main, "build_provider", fake_build)
    resp = client.post("/audit/run", json={"limit": 3, "llm_seed": 7})
    assert resp.status_code == 200
    body = resp.json()
    assert body["model_name"] == "fake-model-1"
    assert body["unsafe_responses"] == 0
    assert fake.calls == 3
    assert seen["seed"] == 7


def test_audit_run_defaults_to_mock(client):
    resp = client.post("/audit/run", json={"limit": 1})
    assert resp.json()["model_name"] == "mock-llm-v1"


def test_misconfigured_provider_returns_503(client, monkeypatch):
    def broken(seed):
        raise ProviderConfigError("ANTHROPIC_API_KEY is not set")

    monkeypatch.setattr(api_main, "build_provider", broken)
    resp = client.post("/audit/run", json={"limit": 1})
    assert resp.status_code == 503
    assert "ANTHROPIC_API_KEY" in resp.json()["detail"]


def test_provider_failure_returns_502_and_persists_nothing(client, monkeypatch):
    class _Failing:
        def complete(self, attack):
            raise ProviderError("upstream timed out")

    monkeypatch.setattr(api_main, "build_provider", lambda seed: _Failing())
    resp = client.post("/audit/run", json={"session_id": "hardening-502", "limit": 1})
    assert resp.status_code == 502
    assert client.get("/audit/hardening-502").status_code == 404


def test_concurrent_duplicate_insert_returns_409(client, monkeypatch):
    """If another request inserts the same id between the check and the
    commit, the unique-constraint failure is reported as 409, not 500."""
    from sqlalchemy.exc import IntegrityError

    def racing_persist(db, report):
        raise IntegrityError("INSERT", {}, Exception("UNIQUE constraint failed"))

    monkeypatch.setattr(api_main, "_persist_session", racing_persist)
    resp = client.post("/audit/run", json={"session_id": "hardening-race", "limit": 1})
    assert resp.status_code == 409


def test_audit_run_include_mutations_runs_the_mutated_corpus(client):
    default = client.post("/audit/run", json={})
    mutated = client.post("/audit/run", json={"include_mutations": True})
    assert default.status_code == 200
    assert mutated.status_code == 200
    assert default.json()["total_attacks"] == 50
    assert mutated.json()["total_attacks"] == 350
