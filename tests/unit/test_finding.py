"""Unit tests for the Finding model + builder (§5.11, §11, §13)."""

from wrongdoor.config.schema import Config
from wrongdoor.engine.executor import ObservedResponse
from wrongdoor.engine.ledger import ObjectRef
from wrongdoor.engine.planner import Expectation, PlannedRequest
from wrongdoor.engine.verdict import Judgment, Verdict
from wrongdoor.report.finding import build_findings, max_severity
from wrongdoor.risk import Severity


def _config():
    return Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [
                {"id": "alice", "attributes": {"tenant": "A"}, "auth": {"type": "bearer", "token_env": "A"}},
                {"id": "bob", "attributes": {"tenant": "B"}, "auth": {"type": "bearer", "token_env": "B"}},
            ],
            "resources": {"invoices": {"sensitivity": "high"}},
        }
    )


def _violation(body=None):
    req = PlannedRequest(
        acting_identity="bob",
        method="GET",
        path="/invoices/1000",
        operation_id="getInvoice",
        target=ObjectRef("invoices", "1000"),
        expected=Expectation.DENY,
        is_mutation=False,
    )
    return Judgment(
        verdict=Verdict.VIOLATION,
        reason="confirmed",
        request=req,
        observed=ObservedResponse(status=200, body=body or {"id": 1000, "owner": "alice", "secret": "hush"}),
        owner="alice",
        matched_fields=("id", "owner"),
    )


def test_build_findings_enriches_violation():
    f = build_findings([_violation()], _config())[0]
    assert f.severity is Severity.CRITICAL  # high sensitivity + cross-tenant
    assert f.finding_type == "BOLA"
    assert f.fingerprint == "WD-BOLA-getInvoice-invoices-cross-tenant"
    assert "'bob'" in f.explanation and "'alice'" in f.explanation
    assert "ownership" in f.remediation.lower()
    assert f.canonical_request() == "GET /invoices/1000 (as alice) -> 200"
    assert f.attack_request() == "GET /invoices/1000 (as bob) -> 200"


def test_findings_exclude_non_violations():
    passing = Judgment(
        verdict=Verdict.PASS,
        reason="ok",
        request=_violation().request,
        observed=ObservedResponse(status=403, body=None),
        owner="alice",
        matched_fields=(),
    )
    assert build_findings([passing], _config()) == []


def test_to_dict_redacts_by_default_and_can_include_bodies():
    f = build_findings([_violation()], _config())[0]
    d = f.to_dict()
    assert d["evidence"]["body_match"] == ["id", "owner"]  # field names only
    assert "hush" not in repr(d)  # the sensitive VALUE is not in the default output
    assert "observed_body" not in d["evidence"]

    d2 = f.to_dict(include_bodies=True)
    assert d2["evidence"]["observed_body"]["secret"] == "hush"


def test_max_severity():
    assert max_severity(build_findings([_violation()], _config())) is Severity.CRITICAL
    assert max_severity([]) is None
