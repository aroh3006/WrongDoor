"""End-to-end test for the ``oauth2`` auth type (§5.5 bonus).

Identities authenticate through the demo's real OAuth2 token endpoint (a real
form-encoded token request, a real issued bearer token), seed an order each
against the token-protected ``orders`` resource, and the differential sweep
reports the planted orders BOLA. This is where the genuine integration risk
lives (the token endpoint parsing form data and a real token working), so it is
tested end to end for both non-interactive grants.

The 401->refresh->retry trigger is pure plugin logic and is covered
deterministically by MockTransport unit tests (test_identity.py), not here.
"""

import asyncio

import httpx

from app import app as vulnerable_app

from wrongdoor.cli import _run_pipeline
from wrongdoor.config.schema import Config
from wrongdoor.report.finding import build_findings
from wrongdoor.safety.guard import SafetyGuard
from wrongdoor.spec.openapi import _operations_from_resolved

_ORDER_SPEC = {
    "paths": {
        "/orders": {"post": {"operationId": "createOrder", "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"item": {"type": "string"}}}}}}, "responses": {}}},
        "/orders/{order_id}": {"get": {"operationId": "getOrder", "parameters": [{"name": "order_id", "in": "path", "required": True, "schema": {"type": "integer"}}], "responses": {}}},
    }
}


def _run(cfg: Config):
    guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=True)
    ops = _operations_from_resolved(_ORDER_SPEC)
    transport = httpx.ASGITransport(app=vulnerable_app)
    judgments, _ = asyncio.run(_run_pipeline(cfg, ops, guard, transport=transport))
    return build_findings(judgments, cfg)


def test_oauth2_password_grant_finds_orders_bola(monkeypatch):
    monkeypatch.setenv("ALICE_PW", "alice-pw")
    monkeypatch.setenv("BOB_PW", "bob-pw")
    cfg = Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [
                {"id": "alice", "attributes": {"tenant": "A"}, "auth": {"type": "oauth2", "token_url": "/oauth/token", "grant": "password", "username": "alice", "password_env": "ALICE_PW"}},
                {"id": "bob", "attributes": {"tenant": "B"}, "auth": {"type": "oauth2", "token_url": "/oauth/token", "grant": "password", "username": "bob", "password_env": "BOB_PW"}},
            ],
            "resources": {"orders": {"sensitivity": "high"}},
        }
    )
    fs = _run(cfg)
    assert len(fs) == 2
    assert all(f.finding_type == "BOLA" and f.resource_type == "orders" for f in fs)
    assert {f.actor for f in fs} == {"alice", "bob"}  # each identity attacks once


def test_oauth2_client_credentials_grant_finds_orders_bola(monkeypatch):
    monkeypatch.setenv("ALICE_SECRET", "alice-secret")
    monkeypatch.setenv("BOB_SECRET", "bob-secret")
    cfg = Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [
                {"id": "alice", "attributes": {"tenant": "A"}, "auth": {"type": "oauth2", "token_url": "/oauth/token", "grant": "client_credentials", "client_id": "alice-client", "client_secret_env": "ALICE_SECRET"}},
                {"id": "bob", "attributes": {"tenant": "B"}, "auth": {"type": "oauth2", "token_url": "/oauth/token", "grant": "client_credentials", "client_id": "bob-client", "client_secret_env": "BOB_SECRET"}},
            ],
            "resources": {"orders": {"sensitivity": "high"}},
        }
    )
    fs = _run(cfg)
    assert len(fs) == 2
    assert all(f.finding_type == "BOLA" and f.resource_type == "orders" for f in fs)
    assert {f.actor for f in fs} == {"alice", "bob"}
