"""Seeder (§5.6) — ground truth by construction.

OWN THIS FILE. The seeder creates real objects as each identity and records who
owns what into the ledger. That recorded ownership is the fact every later
verdict depends on, and this phase *writes real data*, so safety and correctness
both live here.

Algorithm, for each create-op x each identity:
  1. synthesize a valid body from the op's schema;
  2. gate the write through the Safety Guard (LIVE WRITE);
  3. POST as that identity;
  4. extract the new object id (configured field / "id" / Location header);
  5. capture the owner's canonical view (create body, then an authoritative
     owner GET if the resource has one);
  6. record (resource_type, id) -> owner + canonical_body in the ledger.

Safety posture:
  * Sequential, not concurrent — these are writes; §13 wants conservative behavior.
  * Bounded by ``seeding.max_objects`` — never create a runaway amount of data.
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
from ..safety.guard import SafetyGuard
from ..spec.openapi import (
    Operation,
    access_operations,
    create_operations,
    synthesize_body,
)
from .ledger import OwnershipLedger


@dataclass
class SeedOutcome:
    ledger: OwnershipLedger
    failures: list[str] = field(default_factory=list)  # human-readable per-object notes
    capped: bool = False  # True if max_objects stopped seeding early


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
    accesses = access_operations(operations)

    outcome = SeedOutcome(ledger=ledger)
    seeded = 0

    for op in creates:
        for identity_id, authed in registry.items():
            if seeded >= max_objects:
                outcome.capped = True
                break

            body = synthesize_body(op.request_schema)
            create_url = _join(base_url, op.path_template)
            guard.assert_allowed(create_url)  # LIVE WRITE — gate first

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
            # record() raises LedgerError on an ownership conflict — we let it.
            ledger.record(op.resource_type, object_id, owner=identity_id, canonical_body=canonical)
            seeded += 1

        if outcome.capped:
            break

    if outcome.capped:
        outcome.failures.append(f"reached max_objects cap ({max_objects}); stopped seeding")
    return outcome


# --- helpers ---------------------------------------------------------------
def _login_paths(config: Config) -> set[str]:
    """Paths that are login endpoints — never seed these even if the spec lists them."""
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
        guard.assert_allowed(_join(base_url, concrete_path))  # LIVE read — gate it
        resp = await authed.client.get(concrete_path)
        if resp.status_code // 100 == 2:
            body = _json_or_none(resp)
            if body is not None:
                canonical = body  # authoritative owner view wins
    return canonical
