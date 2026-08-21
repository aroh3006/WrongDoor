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

    judgments, _ = asyncio.run(_run_pipeline(cfg, ops, guard, transport=transport))
    found = findings(judgments)

    # Known answer: BOLA on invoices, notes AND projects (the chained resource),
    # MISSING_AUTH on notes, and BFLA on the unprotected admin endpoint. 10 in all.
    assert len(found) == 10
    assert Counter(f.request.check for f in found) == {"bola": 6, "unauth": 2, "bfla": 2}
    bola_resources = Counter(f.request.target.resource_type for f in found if f.request.check == "bola")
    # projects appearing here proves the create-chain worked (a project needs an org).
    assert bola_resources == {"invoices": 2, "notes": 2, "projects": 2}
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

    judgments, _ = asyncio.run(_run_pipeline(cfg, ops, guard, transport=transport))
    fs = build_findings(judgments, cfg)
    assert len(fs) == 10
    assert Counter(f.finding_type for f in fs) == {"BOLA": 6, "MISSING_AUTH": 2, "BFLA": 2}
    assert Counter(f.severity.name for f in fs) == {"CRITICAL": 2, "HIGH": 8}

    doc = _json.loads(json_report.render(fs))
    assert doc["summary"]["findings"] == 10

    s = _json.loads(sarif.render(fs, spec_uri="examples/vulnerable-api/openapi.yaml"))
    assert len(s["runs"][0]["results"]) == 10

    assert 'failures="10"' in junit.render(fs, total_checks=len(judgments))
    assert "BFLA" in html.render(fs) and "getAllInvoices" in html.render(fs)


def test_cleanup_removes_only_the_seeded_objects(monkeypatch):
    """--cleanup deletes exactly what the run created, children before parents, and
    reports (never deletes) resources the spec has no DELETE op for."""
    monkeypatch.setenv("ALICE_PW", "alice-pw")
    monkeypatch.setenv("BOB_PW", "bob-pw")

    cfg = load_config(_VULN / "config.yaml")
    ops = load_operations(_VULN / "openapi.yaml")
    guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=True)
    transport = httpx.ASGITransport(app=vulnerable_app)

    _, cleanup = asyncio.run(_run_pipeline(cfg, ops, guard, transport=transport, cleanup=True))

    assert cleanup is not None
    assert cleanup.total == 12  # 6 resources x 2 identities seeded this run
    # invoices/notes/orgs/projects/profiles each have a DELETE op (2 each) -> 10 deleted.
    assert cleanup.deleted == 10
    # documents has NO DELETE op in the spec -> its 2 objects are reported, not deleted.
    assert len(cleanup.left_behind) == 2
    assert all("documents/" in n and "no delete operation" in n for n in cleanup.left_behind)
    # orgs deleted cleanly (never a 409) -> proves projects were removed BEFORE their org.
    assert not any("orgs/" in n for n in cleanup.left_behind)


def test_shipped_demo_config_demonstrates_mass_assignment(monkeypatch):
    """The demo config ships protected_fields, so --include-mutations shows D4.

    This is the path a reader follows from the README quickstart. It must flag
    the bindable `role` and stay quiet about the correctly-ignored `locked`.
    """
    monkeypatch.setenv("ALICE_PW", "alice-pw")
    monkeypatch.setenv("BOB_PW", "bob-pw")

    cfg = load_config(_VULN / "config.yaml")
    ops = load_operations(_VULN / "openapi.yaml")
    guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=True)
    transport = httpx.ASGITransport(app=vulnerable_app)

    judgments, _ = asyncio.run(
        _run_pipeline(cfg, ops, guard, transport=transport, include_mutations=True)
    )
    ma = [j for j in judgments if j.request.check == "massassign"]

    # role sticks (the planted bug) for both identities; locked is ignored.
    violations = [j for j in ma if j.verdict is Verdict.VIOLATION]
    assert len(violations) == 2
    assert all(j.matched_fields == ("role",) for j in violations)
    assert {j.owner for j in violations} == {"alice", "bob"}
    locked = [j for j in ma if "locked" in j.reason]
    assert len(locked) == 2 and all(j.verdict is Verdict.PASS for j in locked)
