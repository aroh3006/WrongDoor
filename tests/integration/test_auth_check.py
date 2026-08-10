"""Integration: authenticate both identities against the real toy FastAPI app.

Runs the toy app in-process via httpx.ASGITransport (no socket), exercising the
full config -> guard -> identity-manager path against real endpoint logic.
"""

import asyncio
from pathlib import Path

import httpx

from toy_api import app as toy_app

from wrongdoor.config.loader import load_config
from wrongdoor.identity.manager import aclose_all, authenticate_identities
from wrongdoor.safety.guard import SafetyGuard

_TOY_CONFIG = Path(__file__).resolve().parents[2] / "examples" / "scratch" / "toy_config.yaml"


def test_auth_check_against_toy_api(monkeypatch):
    monkeypatch.setenv("ALICE_PW", "alice-pw")
    monkeypatch.setenv("BOB_PW", "bob-pw")

    cfg = load_config(_TOY_CONFIG)
    guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=True)
    transport = httpx.ASGITransport(app=toy_app)

    async def run():
        registry = await authenticate_identities(cfg, guard, transport=transport)
        try:
            return {i: (await ac.client.get("/me")).json() for i, ac in registry.items()}
        finally:
            await aclose_all(registry)

    out = asyncio.run(run())
    assert out["alice"] == {"username": "alice", "email": "alice@example.com", "tenant": "A"}
    assert out["bob"] == {"username": "bob", "email": "bob@example.com", "tenant": "B"}
