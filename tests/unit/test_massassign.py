"""Unit tests for the mass-assignment prober (D4), driven through httpx.MockTransport.

A profiles API where PATCH only honours a whitelist of fields (role, name): setting
``role`` sticks (the planted bug), setting ``locked`` is silently ignored (correct).
The prober must report a VIOLATION for the field that stuck and a PASS for the one
that didn't, proving both branches without a real server.
"""

import asyncio
import json
import re

import httpx

from wrongdoor.config.schema import Config
from wrongdoor.engine.massassign import probe_mass_assignment
from wrongdoor.engine.ledger import OwnershipLedger
from wrongdoor.engine.verdict import Verdict
from wrongdoor.identity.base import AuthedClient
from wrongdoor.safety.guard import SafetyGuard
from wrongdoor.spec.openapi import _operations_from_resolved

_SPEC = {
    "paths": {
        "/profiles/{profile_id}": {
            "get": {"operationId": "getProfile", "parameters": [{"name": "profile_id", "in": "path", "required": True, "schema": {"type": "integer"}}], "responses": {}},
            "patch": {"operationId": "updateProfile", "parameters": [{"name": "profile_id", "in": "path", "required": True, "schema": {"type": "integer"}}], "responses": {}},
        }
    }
}
_OPS = _operations_from_resolved(_SPEC)


def _profiles_handler(store: dict[int, dict], allowed=("role", "name")):
    """PATCH binds only whitelisted fields; anything else in the body is ignored."""

    def handler(req: httpx.Request) -> httpx.Response:
        m = re.fullmatch(r"/profiles/(\d+)", req.url.path)
        if not m:
            return httpx.Response(404, json={})
        pid = int(m.group(1))
        prof = store.get(pid)
        if prof is None:
            return httpx.Response(404, json={})
        if req.method == "PATCH":
            body = json.loads(req.content) if req.content else {}
            for k, v in body.items():
                if k in allowed:  # mass-assignment bug: `role` is bindable from the body
                    prof[k] = v
            return httpx.Response(200, json=prof)
        if req.method == "GET":
            return httpx.Response(200, json=prof)
        return httpx.Response(404, json={})

    return handler


def _authed(user: str, handler) -> AuthedClient:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://t")
    client.headers["Authorization"] = f"Bearer {user}"
    return AuthedClient(identity_id=user, client=client, attributes={})


def _config(protected_fields: dict) -> Config:
    return Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [{"id": "alice", "auth": {"type": "bearer", "token_env": "A"}}],
            "resources": {"profiles": {"sensitivity": "high", "protected_fields": protected_fields}},
        }
    )


def _ledger(canonical: dict) -> OwnershipLedger:
    led = OwnershipLedger()
    led.record("profiles", 1000, owner="alice", canonical_body=canonical)
    return led


async def _run(cfg, registry, ops, guard, ledger):
    try:
        return await probe_mass_assignment(cfg, registry, ops, guard, ledger)
    finally:
        for ac in registry.values():
            await ac.client.aclose()


def test_probe_reports_violation_for_field_that_sticks_and_pass_for_protected():
    store = {1000: {"id": 1000, "owner": "alice", "role": "user", "locked": False}}
    registry = {"alice": _authed("alice", _profiles_handler(store))}
    guard = SafetyGuard(allow=["t"], confirm_own_target=True)
    cfg = _config({"role": "admin", "locked": True})

    judgments = asyncio.run(_run(cfg, registry, _OPS, guard, _ledger(dict(store[1000]))))

    role_j = next(j for j in judgments if j.request.check == "massassign" and "role" in j.reason)
    locked_j = next(j for j in judgments if "locked" in j.reason)
    assert role_j.verdict is Verdict.VIOLATION and role_j.matched_fields == ("role",)
    assert role_j.owner == "alice"  # the injector owns the object it mutated
    assert locked_j.verdict is Verdict.PASS  # the server ignored the injected `locked`


def test_probe_skips_field_whose_value_equals_current_without_writing():
    calls = {"n": 0}
    store = {1000: {"id": 1000, "owner": "alice", "role": "user"}}
    base = _profiles_handler(store)

    def counting(req):
        calls["n"] += 1
        return base(req)

    registry = {"alice": _authed("alice", counting)}
    guard = SafetyGuard(allow=["t"], confirm_own_target=True)
    cfg = _config({"role": "user"})  # probe value already equals the current value

    judgments = asyncio.run(_run(cfg, registry, _OPS, guard, _ledger(dict(store[1000]))))

    assert len(judgments) == 1 and judgments[0].verdict is Verdict.INCONCLUSIVE
    assert calls["n"] == 0  # nothing was sent: the injection would have tested nothing


def test_probe_skips_resource_with_no_update_op():
    # A GET-only spec: no PUT/PATCH to inject through -> the prober does nothing.
    get_only = _operations_from_resolved(
        {"paths": {"/profiles/{profile_id}": {"get": {"operationId": "getProfile", "parameters": [{"name": "profile_id", "in": "path", "required": True, "schema": {"type": "integer"}}], "responses": {}}}}}
    )
    store = {1000: {"id": 1000, "owner": "alice", "role": "user"}}
    registry = {"alice": _authed("alice", _profiles_handler(store))}
    guard = SafetyGuard(allow=["t"], confirm_own_target=True)
    cfg = _config({"role": "admin"})

    judgments = asyncio.run(_run(cfg, registry, get_only, guard, _ledger(dict(store[1000]))))

    assert judgments == []


def test_probe_skips_resource_without_protected_fields():
    store = {1000: {"id": 1000, "owner": "alice", "role": "user"}}
    registry = {"alice": _authed("alice", _profiles_handler(store))}
    guard = SafetyGuard(allow=["t"], confirm_own_target=True)
    cfg = _config({})  # no protected_fields declared

    judgments = asyncio.run(_run(cfg, registry, _OPS, guard, _ledger(dict(store[1000]))))

    assert judgments == []
