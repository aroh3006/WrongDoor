"""Unit tests for the Async Executor (§5.9), via httpx.MockTransport."""

import asyncio

import httpx

from wrongdoor.engine.executor import ObservedResponse, execute
from wrongdoor.engine.ledger import ObjectRef
from wrongdoor.engine.planner import Expectation, PlannedRequest
from wrongdoor.identity.base import AuthedClient


def _registry(handler, *identities):
    reg = {}
    for ident in identities:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://t")
        client.headers["Authorization"] = f"Bearer {ident}"
        reg[ident] = AuthedClient(identity_id=ident, client=client, attributes={})
    return reg


def _req(actor, path):
    return PlannedRequest(
        acting_identity=actor,
        method="GET",
        path=path,
        operation_id="getInvoice",
        target=ObjectRef("invoices", path.rsplit("/", 1)[-1]),
        expected=Expectation.DENY,
        is_mutation=False,
    )


async def _drive(planned, reg, **kw):
    try:
        return await execute(planned, reg, **kw)
    finally:
        for ac in reg.values():
            await ac.client.aclose()


def test_executes_and_captures_status_and_body():
    def handler(req):
        # echo who asked and what path
        return httpx.Response(200, json={"path": req.url.path, "seen_auth": req.headers.get("authorization")})

    reg = _registry(handler, "alice", "bob")
    planned = [_req("bob", "/invoices/1000"), _req("alice", "/invoices/1001")]
    results = asyncio.run(_drive(planned, reg))

    assert [r.acting_identity for r, _ in results] == ["bob", "alice"]  # order preserved
    (req0, obs0) = results[0]
    assert obs0.status == 200
    assert obs0.body == {"path": "/invoices/1000", "seen_auth": "Bearer bob"}


def test_non_json_body_captured_as_text():
    def handler(req):
        return httpx.Response(403, text="Forbidden")

    reg = _registry(handler, "bob")
    results = asyncio.run(_drive([_req("bob", "/invoices/1000")], reg))
    obs = results[0][1]
    assert obs.status == 403 and obs.body == "Forbidden"


def test_network_error_becomes_status_zero():
    def handler(req):
        raise httpx.ConnectError("boom")

    reg = _registry(handler, "bob")
    results = asyncio.run(_drive([_req("bob", "/invoices/1000")], reg))
    assert results[0][1].status == 0


def test_all_requests_run_under_low_concurrency():
    def handler(req):
        return httpx.Response(200, json={})

    reg = _registry(handler, "alice", "bob")
    planned = [_req("alice", f"/invoices/{i}") for i in range(20)] + [_req("bob", "/invoices/x")]
    results = asyncio.run(_drive(planned, reg, concurrency=2))
    assert len(results) == 21
    assert all(isinstance(obs, ObservedResponse) and obs.status == 200 for _, obs in results)
