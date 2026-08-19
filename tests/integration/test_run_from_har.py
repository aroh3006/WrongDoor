"""End-to-end test: run the whole pipeline off a HAR-derived catalog (§14 Phase 5).

Loads operations from the committed HAR fixture (via the same dispatcher the CLI
uses), then runs _run_pipeline against the demo API and asserts it reports the
planted invoice BOLA and nothing on the secured documents control: the same
known answer as the OpenAPI golden test, proving a HAR-sourced catalog is a
drop-in for the spec-sourced one. Auth is config-based, as designed.
"""

import asyncio
from pathlib import Path

import httpx

from app import app as vulnerable_app

from wrongdoor.cli import _run_pipeline
from wrongdoor.config.schema import Config
from wrongdoor.engine.verdict import Verdict
from wrongdoor.report.finding import build_findings
from wrongdoor.safety.guard import SafetyGuard
from wrongdoor.spec.loader import load_operations

_FIXTURE = Path(__file__).resolve().parents[2] / "examples" / "har" / "demo.har"


def test_run_from_har_finds_the_invoice_bola(monkeypatch):
    monkeypatch.setenv("ALICE_PW", "alice-pw")
    monkeypatch.setenv("BOB_PW", "bob-pw")

    ops = load_operations(_FIXTURE)  # .har -> HAR importer, identical Operation list
    cfg = Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [
                {"id": "alice", "attributes": {"tenant": "A"}, "auth": {"type": "login", "url": "/login", "username": "alice", "password_env": "ALICE_PW"}},
                {"id": "bob", "attributes": {"tenant": "B"}, "auth": {"type": "login", "url": "/login", "username": "bob", "password_env": "BOB_PW"}},
            ],
            "resources": {"invoices": {"sensitivity": "high"}, "documents": {"sensitivity": "low"}},
        }
    )
    guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=True)
    transport = httpx.ASGITransport(app=vulnerable_app)

    judgments, _ = asyncio.run(_run_pipeline(cfg, ops, guard, transport=transport))
    fs = build_findings(judgments, cfg)

    # Invoices GET has no ownership check -> BOLA leaked both ways (2 findings).
    assert len(fs) == 2
    assert all(f.finding_type == "BOLA" and f.resource_type == "invoices" for f in fs)
    assert {f.actor for f in fs} == {"alice", "bob"}

    # Documents GET DOES check ownership -> swept from the same HAR catalog, zero findings.
    docs = [j for j in judgments if j.request.target.resource_type == "documents"]
    assert docs and all(j.verdict is Verdict.PASS for j in docs)
