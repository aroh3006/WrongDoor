"""Unit tests for the seeder (§5.6), driven through httpx.MockTransport."""

import asyncio
import json
import re

import httpx
import pytest

from wrongdoor.config.schema import Config
from wrongdoor.engine.seeder import seed
from wrongdoor.identity.base import AuthedClient
from wrongdoor.safety.guard import SafetyError, SafetyGuard
from wrongdoor.spec.openapi import _operations_from_resolved

_SPEC = {
    "paths": {
        "/invoices": {
            "post": {
                "operationId": "createInvoice",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"amount": {"type": "number"}, "memo": {"type": "string"}},
                                "required": ["amount"],
                            }
                        }
                    }
                },
                "responses": {},
            }
        },
        "/invoices/{invoice_id}": {
            "get": {
                "operationId": "getInvoice",
                "parameters": [{"name": "invoice_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                "responses": {},
            }
        },
    }
}
_OPS = _operations_from_resolved(_SPEC)


def _invoice_handler():
    """A MockTransport handler behaving like a correct invoices API."""
    store: dict[int, dict] = {}
    counter = {"n": 1000}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST" and req.url.path == "/invoices":
            user = req.headers.get("authorization", "").removeprefix("Bearer ")
            body = json.loads(req.content) if req.content else {}
            iid = counter["n"]
            counter["n"] += 1
            store[iid] = {"id": iid, "owner": user, "amount": body.get("amount"), "memo": body.get("memo", "")}
            return httpx.Response(201, json=store[iid])
        m = re.fullmatch(r"/invoices/(\d+)", req.url.path)
        if req.method == "GET" and m:
            inv = store.get(int(m.group(1)))
            return httpx.Response(200, json=inv) if inv else httpx.Response(404, json={})
        return httpx.Response(404, json={})

    return handler


def _authed(user: str, handler) -> AuthedClient:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://t")
    client.headers["Authorization"] = f"Bearer {user}"  # simulate a completed auth
    return AuthedClient(identity_id=user, client=client, attributes={})


def _config(max_objects: int = 100) -> Config:
    return Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [
                {"id": "alice", "auth": {"type": "bearer", "token_env": "A"}},
                {"id": "bob", "auth": {"type": "bearer", "token_env": "B"}},
            ],
            "seeding": {"max_objects": max_objects},
        }
    )


async def _run_seed(config, registry, ops, guard):
    try:
        return await seed(config, registry, ops, guard)
    finally:
        for ac in registry.values():
            await ac.client.aclose()


def test_seed_records_ownership_and_canonical_body():
    handler = _invoice_handler()
    registry = {"alice": _authed("alice", handler), "bob": _authed("bob", handler)}
    guard = SafetyGuard(allow=["t"], confirm_own_target=True)

    outcome = asyncio.run(_run_seed(_config(), registry, _OPS, guard))

    assert outcome.failures == []
    assert len(outcome.ledger) == 2
    alice_objs = outcome.ledger.objects_owned_by("alice")
    assert len(alice_objs) == 1
    inv = alice_objs[0]
    assert inv.resource_type == "invoices"
    assert inv.canonical_body["owner"] == "alice"  # captured via the owner GET
    assert inv.canonical_body["amount"] == 1.0  # from the synthesized body
    assert len(outcome.ledger.objects_owned_by("bob")) == 1
    # alice and bob got distinct object ids
    assert len({e.object_id for e in outcome.ledger}) == 2


def test_seed_respects_max_objects_cap():
    handler = _invoice_handler()
    registry = {"alice": _authed("alice", handler), "bob": _authed("bob", handler)}
    guard = SafetyGuard(allow=["t"], confirm_own_target=True)

    outcome = asyncio.run(_run_seed(_config(max_objects=1), registry, _OPS, guard))

    assert outcome.capped is True
    assert len(outcome.ledger) == 1


def test_seed_collects_failures_for_non_2xx_create():
    base = _invoice_handler()

    def handler(req):
        if req.method == "POST" and req.url.path == "/invoices":
            if req.headers.get("authorization", "").removeprefix("Bearer ") == "mallory":
                return httpx.Response(403, json={"detail": "nope"})
        return base(req)

    registry = {"alice": _authed("alice", handler), "mallory": _authed("mallory", handler)}
    guard = SafetyGuard(allow=["t"], confirm_own_target=True)

    outcome = asyncio.run(_run_seed(_config(), registry, _OPS, guard))

    assert {e.owner for e in outcome.ledger} == {"alice"}  # mallory's create failed
    assert any("mallory" in f and "403" in f for f in outcome.failures)


def test_seed_propagates_guard_refusal():
    handler = _invoice_handler()
    registry = {"alice": _authed("alice", handler)}
    guard = SafetyGuard(allow=["t"], confirm_own_target=False)  # not confirmed

    with pytest.raises(SafetyError):
        asyncio.run(_run_seed(_config(), registry, _OPS, guard))
