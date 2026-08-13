"""End-to-end test for the mass-assignment detector (D4) against the demo API.

Two users each seed a profile, then the update-based prober PATCHes each owner's
own profile injecting the declared protected fields. The demo blindly binds `role`
(the planted bug) but ignores `locked` (the control), so WrongDoor must report a
VIOLATION on `role` and a PASS on `locked` — proving both branches end to end
(manager -> seeder -> prober -> judge_injection -> findings) through the real ASGI
app, not just the pure oracle.

Kept off the main golden spec on purpose (a tiny inline spec here), so the
10-finding known-answer test stays untouched.
"""

import asyncio

import httpx

from app import app as vulnerable_app

from wrongdoor.cli import _run_pipeline
from wrongdoor.config.schema import Config
from wrongdoor.engine.verdict import Verdict
from wrongdoor.report.finding import build_findings
from wrongdoor.risk import Severity
from wrongdoor.safety.guard import SafetyGuard
from wrongdoor.spec.openapi import _operations_from_resolved

_SPEC = {
    "paths": {
        "/profiles": {"post": {"operationId": "createProfile", "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"bio": {"type": "string"}}}}}}, "responses": {}}},
        "/profiles/{profile_id}": {
            "get": {"operationId": "getProfile", "parameters": [{"name": "profile_id", "in": "path", "required": True, "schema": {"type": "integer"}}], "responses": {}},
            "patch": {"operationId": "updateProfile", "parameters": [{"name": "profile_id", "in": "path", "required": True, "schema": {"type": "integer"}}], "responses": {}},
        },
    }
}


def _config() -> Config:
    return Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [
                {"id": "alice", "attributes": {"tenant": "A"}, "auth": {"type": "login", "url": "/login", "username": "alice", "password_env": "ALICE_PW"}},
                {"id": "bob", "attributes": {"tenant": "B"}, "auth": {"type": "login", "url": "/login", "username": "bob", "password_env": "BOB_PW"}},
            ],
            "resources": {"profiles": {"sensitivity": "high", "protected_fields": {"role": "admin", "locked": True}}},
        }
    )


def test_mass_assignment_detected_on_role_not_on_locked(monkeypatch):
    monkeypatch.setenv("ALICE_PW", "alice-pw")
    monkeypatch.setenv("BOB_PW", "bob-pw")

    cfg = _config()
    ops = _operations_from_resolved(_SPEC)
    guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=True)
    transport = httpx.ASGITransport(app=vulnerable_app)

    judgments, _ = asyncio.run(_run_pipeline(cfg, ops, guard, transport=transport, include_mutations=True))
    fs = build_findings(judgments, cfg)

    # Both users' profiles let `role` stick -> exactly 2 mass-assignment findings.
    assert len(fs) == 2
    assert all(f.finding_type == "MASS_ASSIGNMENT" and f.matched_fields == ("role",) for f in fs)
    assert {f.owner for f in fs} == {"alice", "bob"}  # each self-escalated once
    assert all(f.severity is Severity.CRITICAL for f in fs)  # high sensitivity + mutation + massassign
    assert all("allowlist" in f.remediation.lower() for f in fs)

    # `locked` was injected too, but the server ignored it -> PASS, never a finding.
    locked = [j for j in judgments if j.request.check == "massassign" and "locked" in j.reason]
    assert len(locked) == 2 and all(j.verdict is Verdict.PASS for j in locked)

    # Profiles GET/PATCH are owner-checked, so the cross-identity sweep finds nothing.
    assert not any(f.finding_type in ("BOLA", "MISSING_AUTH") for f in fs)


def test_no_mass_assignment_without_include_mutations(monkeypatch):
    monkeypatch.setenv("ALICE_PW", "alice-pw")
    monkeypatch.setenv("BOB_PW", "bob-pw")

    cfg = _config()
    ops = _operations_from_resolved(_SPEC)
    guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=True)
    transport = httpx.ASGITransport(app=vulnerable_app)

    # Default (reads-only): the D4 prober never runs, so no mass-assignment at all.
    judgments, _ = asyncio.run(_run_pipeline(cfg, ops, guard, transport=transport))

    assert not any(j.request.check == "massassign" for j in judgments)
    assert build_findings(judgments, cfg) == []
