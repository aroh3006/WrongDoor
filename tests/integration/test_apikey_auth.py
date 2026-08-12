"""End-to-end test for the ``api_key`` auth type (§5.5 bonus).

Two identities authenticate with an X-API-Key header (no bearer / no login), seed
a widget each against the demo API's key-protected resource, and the differential
sweep reports the planted widgets BOLA. This proves the whole pipeline — manager
-> api-key plugin -> seeder -> planner -> executor -> verdict -> findings — works
end to end with key auth, not just the plugin in isolation.

Kept off the main golden spec on purpose: widgets is a key-only resource, so a
tiny inline spec here keeps the 10-finding known-answer test untouched.
"""

import asyncio

import httpx

from app import app as vulnerable_app

from wrongdoor.cli import _run_pipeline
from wrongdoor.config.schema import Config
from wrongdoor.engine.verdict import Verdict
from wrongdoor.report.finding import build_findings
from wrongdoor.safety.guard import SafetyGuard
from wrongdoor.spec.openapi import _operations_from_resolved

_WIDGET_SPEC = {
    "paths": {
        "/widgets": {"post": {"operationId": "createWidget", "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"name": {"type": "string"}}}}}}, "responses": {}}},
        "/widgets/{widget_id}": {"get": {"operationId": "getWidget", "parameters": [{"name": "widget_id", "in": "path", "required": True, "schema": {"type": "integer"}}], "responses": {}}},
    }
}


def test_api_key_identities_find_the_widgets_bola(monkeypatch):
    monkeypatch.setenv("ALICE_KEY", "alice-key")
    monkeypatch.setenv("BOB_KEY", "bob-key")

    cfg = Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [
                {"id": "alice", "attributes": {"tenant": "A"}, "auth": {"type": "api_key", "key_env": "ALICE_KEY"}},
                {"id": "bob", "attributes": {"tenant": "B"}, "auth": {"type": "api_key", "key_env": "BOB_KEY"}},
            ],
            "resources": {"widgets": {"sensitivity": "high"}},
        }
    )
    ops = _operations_from_resolved(_WIDGET_SPEC)
    guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=True)
    transport = httpx.ASGITransport(app=vulnerable_app)

    judgments, _ = asyncio.run(_run_pipeline(cfg, ops, guard, transport=transport))
    fs = build_findings(judgments, cfg)

    # One widget seeded per identity; each is leaked to the other -> 2 BOLA findings.
    assert len(fs) == 2
    assert all(f.finding_type == "BOLA" and f.resource_type == "widgets" for f in fs)
    assert {f.actor for f in fs} == {"alice", "bob"}  # each identity is the attacker once

    # Control: an unauthenticated read (no API key) gets 401 -> PASS, not a finding.
    anon = [j for j in judgments if j.request.check == "unauth"]
    assert anon and all(j.verdict is Verdict.PASS for j in anon)
