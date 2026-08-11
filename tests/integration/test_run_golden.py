"""Golden known-answer test (§16): run the full WrongDoor pipeline against the
vulnerable demo API and assert it reports EXACTLY the planted BOLA and nothing on
the secured control. This is the test that proves the whole engine works.

Runs the demo in-process via ASGI (no Docker); a Testcontainers/real-socket
variant can be added in Phase 4 when the demo is containerized for the Action.
"""

import asyncio
from collections import Counter
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

    # Known answer: BOLA on invoices AND notes, MISSING_AUTH on notes, and BFLA on
    # the unprotected admin endpoint. 8 confirmed in all.
    assert len(found) == 8
    assert Counter(f.request.check for f in found) == {"bola": 4, "unauth": 2, "bfla": 2}
    bola_resources = Counter(f.request.target.resource_type for f in found if f.request.check == "bola")
    assert bola_resources == {"invoices": 2, "notes": 2}
    assert {f.request.target.resource_type for f in found if f.request.check == "unauth"} == {"notes"}
    assert {f.request.operation_id for f in found if f.request.check == "bfla"} == {"getAllInvoices"}

    # Controls swept, ZERO findings: documents (BOLA/unauth) and getAllUsers (BFLA).
    docs = [j for j in judgments if j.request.target.resource_type == "documents"]
    assert len(docs) == 4 and all(j.verdict is Verdict.PASS for j in docs)
    admin_control = [j for j in judgments if j.request.operation_id == "getAllUsers"]
    assert len(admin_control) == 2 and all(j.verdict is Verdict.PASS for j in admin_control)


def test_golden_findings_render_in_all_formats(monkeypatch):
    import json as _json

    from wrongdoor.report import html, json_report, junit, sarif
    from wrongdoor.report.finding import build_findings
    from wrongdoor.risk import Severity

    monkeypatch.setenv("ALICE_PW", "alice-pw")
    monkeypatch.setenv("BOB_PW", "bob-pw")
    cfg = load_config(_VULN / "config.yaml")
    ops = load_operations(_VULN / "openapi.yaml")
    guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=True)
    transport = httpx.ASGITransport(app=vulnerable_app)

    judgments = asyncio.run(_run_pipeline(cfg, ops, guard, transport=transport))
    fs = build_findings(judgments, cfg)
    assert len(fs) == 8
    assert Counter(f.finding_type for f in fs) == {"BOLA": 4, "MISSING_AUTH": 2, "BFLA": 2}
    assert Counter(f.severity.name for f in fs) == {"CRITICAL": 2, "HIGH": 6}

    doc = _json.loads(json_report.render(fs))
    assert doc["summary"]["findings"] == 8

    s = _json.loads(sarif.render(fs, spec_uri="examples/vulnerable-api/openapi.yaml"))
    assert len(s["runs"][0]["results"]) == 8

    assert 'failures="8"' in junit.render(fs, total_checks=len(judgments))
    assert "BFLA" in html.render(fs) and "getAllInvoices" in html.render(fs)
