"""gate:health — the production gateway exposes a conforming liveness /health.

A pure liveness probe (process-up): no auth (mirrors a real load-balancer health check), no
downstream call. 200 + {status:"ok", service:"gateway"} means the gateway process is up.
gate:health discovers this package (it builds a FastAPI app) and runs this eval.
"""
from fastapi.testclient import TestClient

from gateway import create_app
from conftest import FakeAuthorizer, FakeDownstream, FakeRedis


def _app():
    return create_app(FakeAuthorizer(), FakeDownstream(), FakeRedis())


def test_health_ok():
    client = TestClient(_app())
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "gateway"


def test_health_needs_no_api_key():
    """Health must be reachable WITHOUT an x-api-key — it is not a client route."""
    client = TestClient(_app())
    assert client.get("/health").status_code == 200


def test_health_advertises_signed_stt_only_when_configured(monkeypatch):
    monkeypatch.delenv("VEXA_STT_OVERRIDE_SECRET", raising=False)
    assert TestClient(_app()).get("/health").json()["features"]["signed_stt_override"] is False
    monkeypatch.setenv("VEXA_STT_OVERRIDE_SECRET", "test-only")
    assert TestClient(_app()).get("/health").json()["features"]["signed_stt_override"] is True
