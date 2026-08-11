"""Matrix Planner (§5.8) — build the list of cross-identity requests to try.

OWN THIS FILE. The planner decides *what gets tested*: for every object whose
owner we know (from the ledger), it schedules an access attempt by every identity
that should NOT be allowed. Get this wrong and you either miss leaks (too few
cells) or waste requests / create noise (too many).

Design (defensible):

* Owner-only policy (Phase 3): a non-owner accessing an object is expected to be
  DENIED. Self-owned cells are excluded — the owner using their own object is
  authorized, not a test.
* Mutations (PUT/PATCH/DELETE) are OFF by default (§13). The flagship is BOLA via
  GET; enabling writes against a live target is opt-in (``include_mutations``),
  and even then reads are ordered before mutations (§5.8).
* Only single-object-id access-ops are planned (one ``{id}`` to substitute).
  Nested/multi-id paths are skipped for now (documented limitation).
* ``expected`` comes from a tiny policy hook so tenant/role rules slot in later.
"""

from dataclasses import dataclass
from enum import Enum

from ..spec.openapi import Operation, access_operations
from .ledger import ObjectRef, OwnershipLedger

_MUTATION_METHODS = {"PUT", "PATCH", "DELETE"}

# Reserved actor id for the unauthenticated (D3) rows — a client with no auth.
ANONYMOUS_ID = "__anonymous__"


class Expectation(Enum):
    """What the policy says *should* happen for a planned (actor, object, op)."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class PlannedRequest:
    acting_identity: str
    method: str
    path: str  # concrete path with the object id substituted, e.g. /invoices/1000
    operation_id: str
    target: ObjectRef
    expected: Expectation
    is_mutation: bool
    check: str = "bola"  # which detector this row belongs to: bola | unauth | bfla


def plan_matrix(
    ledger: OwnershipLedger,
    operations: list[Operation],
    identities: list[str],
    *,
    policy: str = "owner_only",
    include_mutations: bool = False,
    include_unauth: bool = False,
) -> list[PlannedRequest]:
    accesses = access_operations(operations)
    planned: list[PlannedRequest] = []

    for entry in ledger.entries():
        for op in accesses:
            if op.resource_type != entry.resource_type:
                continue
            if len(op.object_id_params) != 1:
                continue  # single-id resources only (Phase 3)
            is_mutation = op.method in _MUTATION_METHODS
            if is_mutation and not include_mutations:
                continue  # mutations off by default (§13)

            param = op.object_id_params[0]
            concrete_path = op.path_template.replace("{" + param.name + "}", entry.object_id)

            # BOLA (D1): every non-owner identity should be denied.
            for actor in identities:
                if actor == entry.owner:
                    continue  # self-owned cell: authorized, not a test
                planned.append(
                    PlannedRequest(
                        acting_identity=actor,
                        method=op.method,
                        path=concrete_path,
                        operation_id=op.operation_id,
                        target=entry.ref,
                        expected=_expected(policy, actor, entry.owner),
                        is_mutation=is_mutation,
                        check="bola",
                    )
                )

            # Missing auth (D3): one row from an unauthenticated caller. Reads only —
            # we never fire unauthenticated writes at a target.
            if include_unauth and not is_mutation:
                planned.append(
                    PlannedRequest(
                        acting_identity=ANONYMOUS_ID,
                        method=op.method,
                        path=concrete_path,
                        operation_id=op.operation_id,
                        target=entry.ref,
                        expected=Expectation.DENY,
                        is_mutation=is_mutation,
                        check="unauth",
                    )
                )

    # Reads before mutations (§5.8) — stable sort keeps per-object order otherwise.
    planned.sort(key=lambda r: r.is_mutation)
    return planned


def _expected(policy: str, actor: str, owner: str) -> Expectation:
    # owner_only: only the owner may access; every non-owner cell we plan is DENY.
    # (Structured as a hook so tenant/role policies can return ALLOW for some cells.)
    if policy == "owner_only":
        return Expectation.DENY
    raise ValueError(f"unknown policy: {policy!r}")
