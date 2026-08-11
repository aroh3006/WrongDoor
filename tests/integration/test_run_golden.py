"""Golden known-answer test (§16): run the full WrongDoor pipeline against the
vulnerable demo API and assert it reports EXACTLY the planted BOLA and nothing on
the secured control. This is the test that proves the whole engine works.

Runs the demo in-process via ASGI (no Docker); a Testcontainers/real-socket
variant can be added in Phase 4 when the demo is containerized for the Action.
"""

import asyncio
from pathlib import Path

import httpx

from app import app as vulnerable_app

from wrongdoor.cli import _run_pipeline
from wrongdoor.config.loader import load_config
from wrongdoor.engine.verdict import Verdict, findings
from wrongdoor.safety.guard import SafetyGuard
from wrongdoor.spec.openapi import load_operations

_VULN = Path(__file__).resolve().parents[2] / "examples" / "vulnerable-api"


def test_run_reports_exactly_the_planted_bola(monkeypatch):
    monkeypatch.setenv("ALICE_PW", "alice-pw")
    monkeypatch.setenv("BOB_PW", "bob-pw")

    cfg = load_config(_VULN / "config.yaml")
    ops = load_operations(_VULN / "openapi.yaml")
    guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=True)
    transport = httpx.ASGITransport(app=vulnerable_app)

    judgments = asyncio.run(_run_pipeline(cfg, ops, guard, transport=transport))
    found = findings(judgments)

    # The invoice BOLA leaks in both directions (alice<->bob) -> exactly 2 findings,
    # all on getInvoice, each confirmed by the owner's data appearing in the response.
    assert len(found) == 2
    assert all(f.request.operation_id == "getInvoice" for f in found)
    assert all(f.request.target.resource_type == "invoices" for f in found)
    assert {f.request.acting_identity for f in found} == {"alice", "bob"}
    assert {f.owner for f in found} == {"alice", "bob"}
    assert all("owner" in f.matched_fields and "amount" in f.matched_fields for f in found)

    # The documents control was swept and produced ZERO findings — all correctly denied.
    docs = [j for j in judgments if j.request.target.resource_type == "documents"]
    assert len(docs) == 2
    assert all(j.verdict is Verdict.PASS for j in docs)
