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
            "resources": {"invoices": {"sensitivity": "high"}, "notes": {"sensitivity": "medium"}},
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


def test_findings_are_sorted_most_severe_first():
    invoice = _violation()  # invoices, high + cross-tenant -> CRITICAL
    note_req = PlannedRequest(
        acting_identity="bob",
        method="GET",
        path="/notes/9",
        operation_id="getNote",
        target=ObjectRef("notes", "9"),
        expected=Expectation.DENY,
        is_mutation=False,
        check="bola",
    )
    note = Judgment(
        verdict=Verdict.VIOLATION,
        reason="x",
        request=note_req,
        observed=ObservedResponse(status=200, body={"id": 9, "owner": "alice"}),
        owner="alice",
        matched_fields=("id", "owner"),
    )
    # note (HIGH) given first, invoice (CRITICAL) second -> output must lead with CRITICAL
    fs = build_findings([note, invoice], _config())
    assert [int(f.severity) for f in fs] == sorted([int(f.severity) for f in fs], reverse=True)
    assert fs[0].severity is Severity.CRITICAL


def test_unauthenticated_violation_becomes_missing_auth_finding():
    from wrongdoor.engine.planner import ANONYMOUS_ID

    req = PlannedRequest(
        acting_identity=ANONYMOUS_ID,
        method="GET",
        path="/notes/5",
        operation_id="getNote",
        target=ObjectRef("notes", "5"),
        expected=Expectation.DENY,
        is_mutation=False,
        check="unauth",
    )
    j = Judgment(
        verdict=Verdict.VIOLATION,
        reason="x",
        request=req,
        observed=ObservedResponse(status=200, body={"id": 5, "owner": "alice"}),
        owner="alice",
        matched_fields=("id", "owner"),
    )
    f = build_findings([j], _config())[0]
    assert f.finding_type == "MISSING_AUTH"
    assert f.actor == "anonymous"
    assert f.severity is Severity.HIGH  # medium sensitivity + unauthenticated bump
    assert f.fingerprint == "WD-MISSING_AUTH-getNote-notes"
    assert "unauthenticated" in f.explanation.lower()


def test_mass_assignment_violation_becomes_finding():
    req = PlannedRequest(
        acting_identity="alice",
        method="PATCH",
        path="/profiles/1000",
        operation_id="updateProfile",
        target=ObjectRef("profiles", "1000"),
        expected=Expectation.DENY,
        is_mutation=True,
        check="massassign",
    )
    j = Judgment(
        verdict=Verdict.VIOLATION,
        reason="confirmed mass-assignment",
        request=req,
        observed=ObservedResponse(status=200, body={"id": 1000, "role": "admin"}),
        owner="alice",  # the injector owns the object
        matched_fields=("role",),
    )
    cfg = Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [{"id": "alice", "attributes": {"tenant": "A"}, "auth": {"type": "bearer", "token_env": "A"}}],
            "resources": {"profiles": {"sensitivity": "high", "protected_fields": {"role": "admin"}}},
        }
    )
    f = build_findings([j], cfg)[0]
    assert f.finding_type == "MASS_ASSIGNMENT"
    assert f.actor == "alice" and f.owner == "alice"  # self-escalation
    assert f.fingerprint == "WD-MASSASSIGN-updateProfile-profiles-role"
    # high sensitivity -> mutation bump -> massassign bump, clamped at CRITICAL
    assert f.severity is Severity.CRITICAL
    assert "'role'" in f.explanation and "mass-assignment" in f.explanation.lower()
    assert "allowlist" in f.remediation.lower()


def test_mass_assignment_low_sensitivity_is_high():
    req = PlannedRequest(
        acting_identity="alice",
        method="PATCH",
        path="/prefs/1",
        operation_id="updatePrefs",
        target=ObjectRef("prefs", "1"),
        expected=Expectation.DENY,
        is_mutation=True,
        check="massassign",
    )
    j = Judgment(
        verdict=Verdict.VIOLATION, reason="x", request=req,
        observed=ObservedResponse(status=200, body={"id": 1, "theme": "x"}),
        owner="alice", matched_fields=("theme",),
    )
    cfg = Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [{"id": "alice", "auth": {"type": "bearer", "token_env": "A"}}],
            "resources": {"prefs": {"sensitivity": "low", "protected_fields": {"theme": "x"}}},
        }
    )
    f = build_findings([j], cfg)[0]
    # low(1) + mutation bump(2) + massassign bump(3) = HIGH
    assert f.severity is Severity.HIGH


def test_bfla_finding_never_renders_a_none_owner():
    # A function-level finding has no owning identity. The request pair must not
    # print "(as None)", which reads like a bug in the report.
    req = PlannedRequest(
        acting_identity="bob",
        method="GET",
        path="/admin/all-invoices",
        operation_id="getAllInvoices",
        target=ObjectRef("all-invoices", "*"),
        expected=Expectation.DENY,
        is_mutation=False,
        check="bfla",
    )
    j = Judgment(
        verdict=Verdict.VIOLATION, reason="x", request=req,
        observed=ObservedResponse(status=200, body={"invoices": []}),
        owner=None, matched_fields=(),
    )
    f = build_findings([j], _config())[0]
    assert "None" not in f.canonical_request()
    assert "privileged role" in f.canonical_request()
    assert f.attack_request() == "GET /admin/all-invoices (as bob) -> 200"


def test_bfla_violation_becomes_bfla_finding():
    req = PlannedRequest(
        acting_identity="bob",
        method="GET",
        path="/admin/all-invoices",
        operation_id="getAllInvoices",
        target=ObjectRef("all-invoices", "*"),
        expected=Expectation.DENY,
        is_mutation=False,
        check="bfla",
    )
    j = Judgment(
        verdict=Verdict.VIOLATION,
        reason="x",
        request=req,
        observed=ObservedResponse(status=200, body={"invoices": []}),
        owner=None,
        matched_fields=(),
    )
    f = build_findings([j], _config())[0]
    assert f.finding_type == "BFLA"
    assert f.actor == "bob"
    assert f.fingerprint == "WD-BFLA-getAllInvoices-all-invoices"
    assert f.severity is Severity.HIGH  # default medium + BFLA bump
    assert "privileged" in f.explanation.lower()
