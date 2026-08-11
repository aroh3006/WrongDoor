"""Unit tests for the verdict oracle (§9, §16) — synthetic (request, response, ledger)
triples, no network. This is the four-state logic nailed in isolation."""

from wrongdoor.engine.executor import ObservedResponse
from wrongdoor.engine.ledger import ObjectRef, OwnershipLedger
from wrongdoor.engine.planner import Expectation, PlannedRequest
from wrongdoor.engine.verdict import Verdict, findings, judge, judge_all

_CANON = {"id": 1000, "owner": "alice", "amount": 500}


def _ledger(canonical=None):
    led = OwnershipLedger()
    led.record("invoices", 1000, owner="alice", canonical_body=canonical or dict(_CANON))
    return led


def _req(expected=Expectation.DENY, actor="bob"):
    return PlannedRequest(
        acting_identity=actor,
        method="GET",
        path="/invoices/1000",
        operation_id="getInvoice",
        target=ObjectRef("invoices", "1000"),
        expected=expected,
        is_mutation=False,
    )


def _obs(status, body=None):
    return ObservedResponse(status=status, body=body)


def test_non_owner_2xx_with_body_match_is_violation():
    j = judge(_req(), _obs(200, dict(_CANON)), _ledger())
    assert j.verdict is Verdict.VIOLATION
    assert set(j.matched_fields) == {"id", "owner", "amount"}
    assert j.owner == "alice"


def test_non_owner_2xx_without_body_match_is_inconclusive():
    other = {"id": 1001, "owner": "bob", "amount": 999}
    j = judge(_req(), _obs(200, other), _ledger())
    assert j.verdict is Verdict.INCONCLUSIVE


def test_non_owner_403_is_pass():
    assert judge(_req(), _obs(403, "Forbidden"), _ledger()).verdict is Verdict.PASS


def test_non_owner_404_is_pass_info_hiding():
    assert judge(_req(), _obs(404, {}), _ledger()).verdict is Verdict.PASS


def test_non_owner_401_is_pass():
    assert judge(_req(), _obs(401), _ledger()).verdict is Verdict.PASS


def test_5xx_is_inconclusive_even_when_body_would_match():
    j = judge(_req(), _obs(500, dict(_CANON)), _ledger())
    assert j.verdict is Verdict.INCONCLUSIVE


def test_owner_allow_denied_is_broken():
    j = judge(_req(expected=Expectation.ALLOW, actor="alice"), _obs(403), _ledger())
    assert j.verdict is Verdict.BROKEN


def test_owner_allow_success_is_pass():
    j = judge(_req(expected=Expectation.ALLOW, actor="alice"), _obs(200, dict(_CANON)), _ledger())
    assert j.verdict is Verdict.PASS


def test_unexpected_status_is_inconclusive():
    assert judge(_req(), _obs(302), _ledger()).verdict is Verdict.INCONCLUSIVE


def test_target_not_in_ledger_is_inconclusive():
    assert judge(_req(), _obs(200, dict(_CANON)), OwnershipLedger()).verdict is Verdict.INCONCLUSIVE


def _bfla_req():
    return PlannedRequest(
        acting_identity="bob",
        method="GET",
        path="/admin/all-invoices",
        operation_id="getAllInvoices",
        target=ObjectRef("all-invoices", "*"),
        expected=Expectation.DENY,
        is_mutation=False,
        check="bfla",
    )


def test_bfla_success_is_violation_without_a_ledger_object():
    # BFLA is status-based and needs no ledger entry.
    j = judge(_bfla_req(), _obs(200, {"invoices": []}), OwnershipLedger())
    assert j.verdict is Verdict.VIOLATION


def test_bfla_denied_is_pass():
    assert judge(_bfla_req(), _obs(403), OwnershipLedger()).verdict is Verdict.PASS


def test_judge_all_and_findings():
    led = _ledger()
    results = [
        (_req(), _obs(403)),  # PASS
        (_req(actor="carol"), _obs(200, dict(_CANON))),  # VIOLATION
    ]
    judgments = judge_all(results, led)
    assert [j.verdict for j in judgments] == [Verdict.PASS, Verdict.VIOLATION]
    fs = findings(judgments)
    assert len(fs) == 1 and fs[0].request.acting_identity == "carol"
