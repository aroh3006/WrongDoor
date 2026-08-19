"""Seeder (§5.6): ground truth by construction.

Critical security boundary: the seeder creates real objects as each identity and
records who owns what into the ledger. That recorded ownership is the fact every
later verdict depends on, and this phase *writes real data*, so safety and
correctness both live here. Review carefully before modifying.

Algorithm, for each create-op x each identity:
  1. synthesize a valid body from the op's schema;
  2. gate the write through the Safety Guard (LIVE WRITE);
  3. POST as that identity;
  4. extract the new object id (configured field / "id" / Location header);
  5. capture the owner's canonical view (create body, then an authoritative
     owner GET if the resource has one);
  6. record (resource_type, id) -> owner + canonical_body in the ledger.

Safety posture:
  * Sequential, not concurrent: these are writes; §13 wants conservative behavior.
  * Bounded by ``seeding.max_objects``: never create a runaway amount of data.
  * Skips create-ops whose path is a configured login URL (don't "seed" auth).
  * Per-object failures (non-2xx, no id) are collected and the loop continues;
    but a guard refusal (SafetyError) or a ledger conflict (LedgerError) propagate,
    because continuing past those would be unsafe or would forge ground truth.
"""

from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config.schema import Config, LoginAuthConfig
from ..identity.base import AuthedClient
from ..safety.guard import SafetyError, SafetyGuard
from ..spec.openapi import (
    Operation,
    access_operations,
    create_operations,
    synthesize_body,
)
from .ledger import LedgerEntry, OwnershipLedger


class SeederError(Exception):
    """Raised on an unseedable configuration (e.g. a dependency cycle)."""


@dataclass
class SeedOutcome:
    ledger: OwnershipLedger
    failures: list[str] = field(default_factory=list)  # human-readable per-object notes
    capped: bool = False  # True if max_objects stopped seeding early


@dataclass
class CleanupOutcome:
    """Result of a teardown pass: how many ledger objects were deleted, and which
    were left behind (with the reason). ``total == deleted + len(left_behind)``."""

    deleted: int = 0
    left_behind: list[str] = field(default_factory=list)  # "resource/id (reason)" per object

    @property
    def total(self) -> int:
        return self.deleted + len(self.left_behind)

    @property
    def ok(self) -> bool:
        return not self.left_behind


async def seed(
    config: Config,
    registry: dict[str, AuthedClient],
    operations: list[Operation],
    guard: SafetyGuard,
    *,
    ledger: OwnershipLedger | None = None,
) -> SeedOutcome:
    ledger = ledger if ledger is not None else OwnershipLedger()
    base_url = config.target.base_url
    max_objects = config.seeding.max_objects
    id_field = config.seeding.id_field
    login_paths = _login_paths(config)

    creates = [o for o in create_operations(operations) if o.path_template not in login_paths]
    deps = {d.resource: d for d in config.seeding.dependencies}
    creates = _order_by_dependency(creates, deps)  # parents before children (cycle -> SeederError)
    accesses = access_operations(operations)

    outcome = SeedOutcome(ledger=ledger)
    seeded = 0

    for op in creates:
        for identity_id, authed in registry.items():
            if seeded >= max_objects:
                outcome.capped = True
                break

            body = synthesize_body(op.request_schema)

            # Dependency chain: attach this child to a parent object the SAME
            # identity owns, so ownership chains cleanly (alice's org -> project).
            dep = deps.get(op.resource_type)
            if dep is not None:
                parent = _first_owned(ledger, dep.parent, identity_id)
                if parent is None:
                    outcome.failures.append(
                        f"{op.operation_id} as {identity_id}: no {dep.parent!r} parent object to attach to"
                    )
                    continue
                if isinstance(body, dict):
                    pid = parent.object_id
                    body[dep.body_field] = int(pid) if pid.isdigit() else pid

            create_url = _join(base_url, op.path_template)
            guard.assert_allowed(create_url)  # LIVE WRITE, gate first

            try:
                resp = await authed.client.request(op.method, op.path_template, json=body)
            except httpx.HTTPError as e:
                outcome.failures.append(f"{op.operation_id} as {identity_id}: request error: {e}")
                continue
            if resp.status_code // 100 != 2:
                outcome.failures.append(f"{op.operation_id} as {identity_id}: HTTP {resp.status_code}")
                continue

            object_id = _extract_object_id(resp, id_field)
            if object_id is None:
                outcome.failures.append(f"{op.operation_id} as {identity_id}: could not extract object id")
                continue

            canonical = await _capture_canonical(
                authed, op, object_id, resp, accesses, guard, base_url
            )
            # record() raises LedgerError on an ownership conflict, we let it.
            ledger.record(op.resource_type, object_id, owner=identity_id, canonical_body=canonical)
            seeded += 1

        if outcome.capped:
            break

    if outcome.capped:
        outcome.failures.append(f"reached max_objects cap ({max_objects}); stopped seeding")
    return outcome


async def cleanup(
    config: Config,
    registry: dict[str, AuthedClient],
    operations: list[Operation],
    guard: SafetyGuard,
    ledger: OwnershipLedger,
) -> CleanupOutcome:
    """Delete every object recorded in the ledger, and ONLY those objects.

    This is teardown for the data ``seed()`` created; the ledger is an exact
    manifest of what WrongDoor made this run, so nothing else on the target is
    ever touched. Each delete is sent via the resource's ``DELETE`` access-op
    from the spec, as the object's OWNER (who has legitimate delete rights), and
    gated by the Safety Guard first.

    Ordering: child-before-parent (the reverse of the seeder's create order), so
    a parent delete isn't blocked by a still-present child (e.g. an org that
    still has projects).

    Failure posture: deliberately the OPPOSITE of ``seed()``. Seeding aborts on
    a guard refusal or a bad create (a partial/forged ground truth is dangerous),
    but cleanup is best-effort and NEVER aborts on a single failure. It attempts
    a delete for every ledger object, treats 404 as success (already gone == the
    goal, idempotent), and collects every other outcome into ``left_behind`` so
    the target is left in a known, reported state rather than a silent half-clean.
    """
    base_url = config.target.base_url
    deps = {d.resource: d for d in config.seeding.dependencies}
    accesses = access_operations(operations)

    by_resource: dict[str, list[LedgerEntry]] = {}
    for entry in ledger.entries():
        by_resource.setdefault(entry.resource_type, []).append(entry)

    outcome = CleanupOutcome()
    for resource_type in _delete_order(list(by_resource), deps):  # children first
        delete_op = _matching_delete(accesses, resource_type)
        for entry in by_resource[resource_type]:
            note = await _delete_one(entry, delete_op, registry, guard, base_url)
            if note is None:
                outcome.deleted += 1
            else:
                outcome.left_behind.append(note)
    return outcome


async def _delete_one(
    entry: LedgerEntry,
    delete_op: Operation | None,
    registry: dict[str, AuthedClient],
    guard: SafetyGuard,
    base_url: str,
) -> str | None:
    """Delete one ledger object. Return None on success, else a left-behind note.

    A guard refusal here is recorded and skipped (not raised); cleanup must stay
    non-fatal, but the request is still never sent, so the safety boundary holds.
    """
    ref = f"{entry.resource_type}/{entry.object_id}"
    if delete_op is None:
        return f"{ref} (no delete operation in spec)"
    authed = registry.get(entry.owner)
    if authed is None:
        return f"{ref} (owner {entry.owner!r} has no live session)"

    param = delete_op.object_id_params[0]
    path = delete_op.path_template.replace("{" + param.name + "}", entry.object_id)
    try:
        guard.assert_allowed(_join(base_url, path))  # LIVE DELETE, gate first
    except SafetyError as e:
        return f"{ref} (refused by safety guard: {e})"

    try:
        resp = await authed.client.request("DELETE", path)
    except httpx.HTTPError as e:
        return f"{ref} (request error: {e})"
    if resp.status_code // 100 == 2 or resp.status_code == 404:
        return None  # 2xx deleted, or 404 already gone: both mean the object is gone
    return f"{ref} (HTTP {resp.status_code})"


# --- helpers ---------------------------------------------------------------
def _order_by_dependency(creates: list[Operation], deps: dict) -> list[Operation]:
    """Order create-ops so a parent resource is always seeded before its children."""
    by_resource: dict[str, list[Operation]] = {}
    for op in creates:
        by_resource.setdefault(op.resource_type, []).append(op)
    # Only keep edges whose parent is actually being created here.
    parent_of = {
        r: deps[r].parent for r in by_resource if r in deps and deps[r].parent in by_resource
    }
    ordered: list[Operation] = []
    for resource in _toposort(list(by_resource), parent_of):
        ordered.extend(by_resource[resource])
    return ordered


def _delete_order(resource_types: list[str], deps: dict) -> list[str]:
    """Resource types in child-before-parent order: the reverse of create order.

    Reuses the seeder's topological sort (parents first) and reverses it. A cycle
    is impossible here (seeding would already have raised), but we stay non-fatal
    and fall back to the given order if one somehow appears."""
    unique = list(dict.fromkeys(resource_types))  # dedupe, keep ledger order
    parent_of = {
        r: deps[r].parent for r in unique if r in deps and deps[r].parent in unique
    }
    try:
        parents_first = _toposort(unique, parent_of)
    except SeederError:
        parents_first = unique
    parents_first.reverse()
    return parents_first


def _matching_delete(accesses: list[Operation], resource_type: str) -> Operation | None:
    for op in accesses:
        if (
            op.method == "DELETE"
            and op.resource_type == resource_type
            and len(op.object_id_params) == 1
        ):
            return op
    return None


def _toposort(resources: list[str], parent_of: dict[str, str]) -> list[str]:
    order: list[str] = []
    state: dict[str, str] = {}

    def visit(resource: str, stack: list[str]) -> None:
        if state.get(resource) == "done":
            return
        if state.get(resource) == "visiting":
            cycle = stack[stack.index(resource):] + [resource]
            raise SeederError("resource dependency cycle: " + " -> ".join(cycle))
        state[resource] = "visiting"
        parent = parent_of.get(resource)
        if parent is not None:
            visit(parent, stack + [resource])
        state[resource] = "done"
        order.append(resource)  # parent already appended -> parents come first

    for resource in resources:
        visit(resource, [])
    return order


def _first_owned(ledger: OwnershipLedger, resource_type: str, identity: str):
    for entry in ledger.objects_owned_by(identity):
        if entry.resource_type == resource_type:
            return entry
    return None


def _login_paths(config: Config) -> set[str]:
    """Paths that are login endpoints: never seed these even if the spec lists them."""
    return {
        i.auth.url for i in config.identities if isinstance(i.auth, LoginAuthConfig)
    }


def _join(base_url: str, path: str) -> str:
    return str(httpx.URL(base_url).join(path))


def _json_or_none(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return None


def _extract_object_id(resp: httpx.Response, id_field: str | None) -> str | None:
    body = _json_or_none(resp)
    if isinstance(body, dict):
        # Configured field first, then the conventional "id".
        for key in ([id_field] if id_field else []) + ["id"]:
            if key and body.get(key) is not None:
                return str(body[key])
    # Fall back to the Location header's last path segment (common for 201s).
    location = resp.headers.get("location")
    if location:
        segment = location.rstrip("/").rsplit("/", 1)[-1]
        if segment:
            return segment
    return None


def _matching_get(accesses: list[Operation], resource_type: str) -> Operation | None:
    for op in accesses:
        if (
            op.method == "GET"
            and op.resource_type == resource_type
            and len(op.object_id_params) == 1
        ):
            return op
    return None


async def _capture_canonical(
    authed: AuthedClient,
    create_op: Operation,
    object_id: str,
    create_resp: httpx.Response,
    accesses: list[Operation],
    guard: SafetyGuard,
    base_url: str,
) -> Any:
    """The owner's canonical view: an owner GET if available, else the create body."""
    canonical = _json_or_none(create_resp)  # baseline: what the create returned

    get_op = _matching_get(accesses, create_op.resource_type)
    if get_op is not None:
        param = get_op.object_id_params[0]
        concrete_path = get_op.path_template.replace("{" + param.name + "}", object_id)
        guard.assert_allowed(_join(base_url, concrete_path))  # LIVE read, gate it
        resp = await authed.client.get(concrete_path)
        if resp.status_code // 100 == 2:
            body = _json_or_none(resp)
            if body is not None:
                canonical = body  # authoritative owner view wins
    return canonical
