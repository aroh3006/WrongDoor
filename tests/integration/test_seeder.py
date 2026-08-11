"""Integration: seed the real toy FastAPI app and check the ledger's ground truth.

Runs the toy in-process via ASGI: authenticate -> seed -> assert the ledger says
each identity owns exactly the invoice it created, with the owner's canonical body.
"""

import asyncio
from pathlib import Path

import httpx

from toy_api import app as toy_app

from wrongdoor.config.loader import load_config
from wrongdoor.engine.seeder import seed
from wrongdoor.identity.manager import aclose_all, authenticate_identities
from wrongdoor.safety.guard import SafetyGuard
from wrongdoor.spec.openapi import load_operations

_ROOT = Path(__file__).resolve().parents[2]


def test_seed_builds_correct_ledger_against_toy_api(monkeypatch):
    monkeypatch.setenv("ALICE_PW", "alice-pw")
    monkeypatch.setenv("BOB_PW", "bob-pw")

    cfg = load_config(_ROOT / "examples" / "scratch" / "toy_config.yaml")
    ops = load_operations(_ROOT / "examples" / "scratch" / "toy_openapi.yaml")
    guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=True)
    transport = httpx.ASGITransport(app=toy_app)

    async def run():
        registry = await authenticate_identities(cfg, guard, transport=transport)
        try:
            return await seed(cfg, registry, ops, guard)
        finally:
            await aclose_all(registry)

    outcome = asyncio.run(run())

    assert outcome.failures == []
    assert len(outcome.ledger) == 2
    for identity in ("alice", "bob"):
        objs = outcome.ledger.objects_owned_by(identity)
        assert len(objs) == 1
        entry = objs[0]
        assert entry.resource_type == "invoices"
        assert entry.canonical_body["owner"] == identity  # ground truth by construction
        assert entry.canonical_body["amount"] == 1.0
