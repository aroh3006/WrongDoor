"""Unit tests for the deterministic risk scorer (§9)."""

import pytest

from wrongdoor.config.schema import ResourceConfig
from wrongdoor.engine.executor import ObservedResponse
from wrongdoor.engine.ledger import ObjectRef
from wrongdoor.engine.planner import Expectation, PlannedRequest
from wrongdoor.engine.verdict import Judgment, Verdict
from wrongdoor.risk import Severity, parse_severity, score

_CROSS = {"alice": {"tenant": "A"}, "bob": {"tenant": "B"}}
_SAME = {"alice": {"tenant": "A"}, "bob": {"tenant": "A"}}
_HIGH = {"invoices": ResourceConfig(sensitivity="high")}
_LOW = {"invoices": ResourceConfig(sensitivity="low")}


def _judgment(actor="bob", owner="alice", is_mutation=False, resource="invoices"):
    req = PlannedRequest(
        acting_identity=actor,
        method="DELETE" if is_mutation else "GET",
        path=f"/{resource}/1",
        operation_id="op",
        target=ObjectRef(resource, "1"),
        expected=Expectation.DENY,
        is_mutation=is_mutation,
    )
    return Judgment(
        verdict=Verdict.VIOLATION,
        reason="x",
        request=req,
        observed=ObservedResponse(status=200, body={}),
        owner=owner,
        matched_fields=("id",),
    )


def test_cross_tenant_read_of_high_is_critical():
    assert score(_judgment(), _CROSS, _HIGH) is Severity.CRITICAL


def test_same_tenant_read_of_high_is_high():
    assert score(_judgment(), _SAME, _HIGH) is Severity.HIGH


def test_default_sensitivity_is_medium():
    assert score(_judgment(), _SAME, {}) is Severity.MEDIUM


def test_low_sensitivity_read_is_low():
    assert score(_judgment(), _SAME, _LOW) is Severity.LOW


def test_mutation_bumps_one_band():
    assert score(_judgment(is_mutation=True), _SAME, {}) is Severity.HIGH  # medium -> high


def test_bumps_clamp_at_critical():
    # high + cross-tenant + mutation would be band 5; clamp to CRITICAL (4).
    assert score(_judgment(is_mutation=True), _CROSS, _HIGH) is Severity.CRITICAL


def test_massassign_gets_mutation_and_massassign_bumps():
    req = PlannedRequest(
        acting_identity="alice",
        method="PATCH",
        path="/invoices/1",
        operation_id="op",
        target=ObjectRef("invoices", "1"),
        expected=Expectation.DENY,
        is_mutation=True,
        check="massassign",
    )
    j = Judgment(verdict=Verdict.VIOLATION, reason="x", request=req,
                 observed=ObservedResponse(status=200, body={}), owner="alice", matched_fields=("role",))
    # low(1) + mutation(2) + massassign(3) = HIGH; self-escalation so no cross-tenant bump.
    assert score(j, _SAME, _LOW) is Severity.HIGH
    # high(3) + mutation(4) + massassign -> clamp CRITICAL.
    assert score(j, _SAME, _HIGH) is Severity.CRITICAL


def test_severity_is_ordered():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW


def test_parse_severity():
    assert parse_severity("High") is Severity.HIGH
    with pytest.raises(ValueError):
        parse_severity("catastrophic")
