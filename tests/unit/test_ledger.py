"""Unit tests for the Ownership Ledger (§5.7): integrity is the whole point."""

import pytest

from wrongdoor.engine.ledger import LedgerError, ObjectRef, OwnershipLedger


def test_record_then_lookup():
    led = OwnershipLedger()
    led.record("invoices", 1001, owner="alice", canonical_body={"id": 1001, "amount": 500})
    assert led.owner_of(ObjectRef("invoices", "1001")) == "alice"
    assert led.get_by("invoices", 1001).canonical_body["amount"] == 500
    assert len(led) == 1


def test_id_is_normalized_to_string():
    led = OwnershipLedger()
    led.record("invoices", 1001, owner="alice", canonical_body={})
    # Recorded with int 1001; must be findable by "1001" and by 1001.
    assert led.get_by("invoices", "1001") is not None
    assert led.get_by("invoices", 1001) is not None
    assert ObjectRef("invoices", "1001") in led


def test_same_id_different_resource_types_do_not_collide():
    led = OwnershipLedger()
    led.record("invoices", 1, owner="alice", canonical_body={"kind": "invoice"})
    led.record("users", 1, owner="bob", canonical_body={"kind": "user"})
    assert led.owner_of(ObjectRef("invoices", "1")) == "alice"
    assert led.owner_of(ObjectRef("users", "1")) == "bob"
    assert len(led) == 2


def test_conflicting_ownership_raises():
    led = OwnershipLedger()
    led.record("invoices", 1, owner="alice", canonical_body={})
    with pytest.raises(LedgerError):
        led.record("invoices", 1, owner="bob", canonical_body={})


def test_rerecording_same_owner_is_idempotent_update():
    led = OwnershipLedger()
    led.record("invoices", 1, owner="alice", canonical_body={"amount": 1})
    led.record("invoices", 1, owner="alice", canonical_body={"amount": 2})  # refresh
    assert len(led) == 1
    assert led.get_by("invoices", 1).canonical_body["amount"] == 2


def test_empty_id_raises():
    led = OwnershipLedger()
    with pytest.raises(LedgerError):
        led.record("invoices", None, owner="alice", canonical_body={})
    with pytest.raises(LedgerError):
        led.record("invoices", "", owner="alice", canonical_body={})


def test_objects_owned_by():
    led = OwnershipLedger()
    led.record("invoices", 1, owner="alice", canonical_body={})
    led.record("invoices", 2, owner="bob", canonical_body={})
    led.record("invoices", 3, owner="alice", canonical_body={})
    assert {e.object_id for e in led.objects_owned_by("alice")} == {"1", "3"}


def test_redacted_summary_shows_field_names_not_values():
    led = OwnershipLedger()
    led.record("invoices", 1, owner="alice", canonical_body={"amount": 500, "secret_memo": "hush"})
    summary = led.redacted_summary()
    assert summary == [
        {
            "resource_type": "invoices",
            "object_id": "1",
            "owner": "alice",
            "canonical_fields": ["amount", "secret_memo"],
        }
    ]
    # The sensitive VALUES must never appear in the summary.
    blob = repr(summary)
    assert "500" not in blob and "hush" not in blob
