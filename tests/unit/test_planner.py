"""Unit tests for the Matrix Planner (§5.8)."""

from wrongdoor.engine.ledger import ObjectRef, OwnershipLedger
from wrongdoor.engine.planner import ANONYMOUS_ID, Expectation, plan_matrix
from wrongdoor.spec.openapi import _operations_from_resolved

_SPEC = {
    "paths": {
        "/invoices/{invoice_id}": {
            "parameters": [{"name": "invoice_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
            "get": {"operationId": "getInvoice", "responses": {}},
            "delete": {"operationId": "deleteInvoice", "responses": {}},
        }
    }
}
_OPS = _operations_from_resolved(_SPEC)  # one GET (access), one DELETE (access, mutation)


def _ledger():
    led = OwnershipLedger()
    led.record("invoices", 1000, owner="alice", canonical_body={"id": 1000})
    led.record("invoices", 1001, owner="bob", canonical_body={"id": 1001})
    return led


def test_plans_non_owner_reads_and_excludes_self():
    planned = plan_matrix(_ledger(), _OPS, identities=["alice", "bob"])
    # Only GET (reads); default excludes the DELETE mutation.
    cells = {(p.acting_identity, p.path) for p in planned}
    assert cells == {("bob", "/invoices/1000"), ("alice", "/invoices/1001")}
    assert all(p.method == "GET" for p in planned)
    assert all(p.expected is Expectation.DENY for p in planned)


def test_target_and_metadata_are_correct():
    planned = plan_matrix(_ledger(), _OPS, identities=["alice", "bob"])
    bob_hits_alice = next(p for p in planned if p.acting_identity == "bob")
    assert bob_hits_alice.target == ObjectRef("invoices", "1000")
    assert bob_hits_alice.operation_id == "getInvoice"
    assert bob_hits_alice.is_mutation is False


def test_mutations_excluded_by_default_and_included_on_demand():
    default = plan_matrix(_ledger(), _OPS, identities=["alice", "bob"])
    assert all(not p.is_mutation for p in default)

    with_mut = plan_matrix(_ledger(), _OPS, identities=["alice", "bob"], include_mutations=True)
    methods = {p.method for p in with_mut}
    assert methods == {"GET", "DELETE"}
    # reads must be ordered before mutations
    first_mutation = next(i for i, p in enumerate(with_mut) if p.is_mutation)
    assert all(not p.is_mutation for p in with_mut[:first_mutation])


def test_third_identity_gets_planned_against_both_objects():
    planned = plan_matrix(_ledger(), _OPS, identities=["alice", "bob", "carol"])
    carol = {p.path for p in planned if p.acting_identity == "carol"}
    assert carol == {"/invoices/1000", "/invoices/1001"}  # non-owner of both


def test_include_unauth_adds_anonymous_read_rows():
    planned = plan_matrix(_ledger(), _OPS, identities=["alice", "bob"], include_unauth=True)
    unauth = [p for p in planned if p.check == "unauth"]
    # one anonymous GET per object (reads only; the DELETE is excluded)
    assert {(p.acting_identity, p.path) for p in unauth} == {
        (ANONYMOUS_ID, "/invoices/1000"),
        (ANONYMOUS_ID, "/invoices/1001"),
    }
    assert all(p.method == "GET" and p.expected is Expectation.DENY for p in unauth)
    assert any(p.check == "bola" for p in planned)  # BOLA rows still present


def test_plan_bfla_tests_only_under_privileged_identities():
    from wrongdoor.config.schema import OperationConfig
    from wrongdoor.engine.planner import plan_bfla

    spec = {"paths": {"/admin/all-invoices": {"get": {"operationId": "getAllInvoices", "responses": {}}}}}
    ops = _operations_from_resolved(spec)
    rows = plan_bfla(
        ops,
        {"alice": {}, "bob": {"role": "admin"}},  # bob legitimately holds the role
        {"getAllInvoices": OperationConfig(privileged=True, requires_role="admin")},
    )
    assert [r.acting_identity for r in rows] == ["alice"]  # only the non-admin is tested
    assert rows[0].check == "bfla" and rows[0].path == "/admin/all-invoices"


def test_no_plans_when_resource_type_has_no_access_ops():
    # ledger has invoices, but the only op is for documents -> nothing to plan
    spec = {
        "paths": {
            "/documents/{id}": {
                "parameters": [{"name": "id", "in": "path"}],
                "get": {"operationId": "getDoc", "responses": {}},
            }
        }
    }
    ops = _operations_from_resolved(spec)
    assert plan_matrix(_ledger(), ops, identities=["alice", "bob"]) == []
