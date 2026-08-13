"""Unit tests for the verdict oracle (§9, §16) — synthetic (request, response, ledger)
triples, no network. This is the four-state logic nailed in isolation."""

from wrongdoor.engine.executor import ObservedResponse
from wrongdoor.engine.ledger import ObjectRef, OwnershipLedger
from wrongdoor.engine.planner import Expectation, PlannedRequest
from wrongdoor.engine.verdict import (
    Verdict,
    findings,
    judge,
    judge_all,
    judge_injection,
)

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


# --- mass-assignment oracle (D4) -------------------------------------------
def _massassign_req(actor="alice"):
    return PlannedRequest(
        acting_identity=actor,
        method="PATCH",
        path="/profiles/1000",
        operation_id="updateProfile",
        target=ObjectRef("profiles", "1000"),
        expected=Expectation.DENY,
        is_mutation=True,
        check="massassign",
    )


def test_massassign_field_stuck_is_violation():
    j = judge_injection(
        _massassign_req(), "role", "admin",
        readback_body={"id": 1000, "role": "admin"}, baseline_value="user", update_status=200,
    )
    assert j.verdict is Verdict.VIOLATION
    assert j.matched_fields == ("role",)
    assert j.owner == "alice"  # the injector owns the object it mutated


def test_massassign_field_stripped_is_pass():
    j = judge_injection(
        _massassign_req(), "role", "admin",
        readback_body={"id": 1000, "role": "user"}, baseline_value="user", update_status=200,
    )
    assert j.verdict is Verdict.PASS


def test_massassign_rejected_update_but_field_unchanged_is_pass():
    # The update returned 4xx AND the re-read shows the field never changed -> PASS.
    j = judge_injection(
        _massassign_req(), "role", "admin",
        readback_body={"id": 1000, "role": "user"}, baseline_value="user", update_status=403,
    )
    assert j.verdict is Verdict.PASS


def test_massassign_value_equals_baseline_is_inconclusive():
    j = judge_injection(
        _massassign_req(), "verified", True,
        readback_body={"id": 1000, "verified": True}, baseline_value=True, update_status=200,
    )
    assert j.verdict is Verdict.INCONCLUSIVE


def test_massassign_unreadable_object_is_inconclusive():
    j = judge_injection(
        _massassign_req(), "role", "admin",
        readback_body="Forbidden", baseline_value="user", update_status=200,
    )
    assert j.verdict is Verdict.INCONCLUSIVE


def test_massassign_server_error_is_inconclusive():
    j = judge_injection(
        _massassign_req(), "role", "admin",
        readback_body={"id": 1000, "role": "admin"}, baseline_value="user", update_status=500,
    )
    assert j.verdict is Verdict.INCONCLUSIVE


def test_massassign_confirmed_without_a_baseline():
    # No baseline known (field was absent before) but the client introduced it.
    j = judge_injection(
        _massassign_req(), "role", "admin",
        readback_body={"id": 1000, "role": "admin"}, update_status=200,
    )
    assert j.verdict is Verdict.VIOLATION


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
