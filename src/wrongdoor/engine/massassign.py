"""Mass-assignment prober (D4): reuses the ledger's before/after ground-truth
trick, pointed at a new question.

Critical security boundary, since it writes: BOLA asks "can a non-owner READ my
object?"; mass-assignment (OWASP API3 / BOPLA) asks "can the owner SET a field
they shouldn't control?" (e.g. PATCH your own profile with ``{"role": "admin"}``
and have it stick). This prober tests the update vector, reusing the ledger the
seeder already built:

  * the ledger's ``canonical_body`` is the owner's view of the object *before* any
    attack, so it is a free, ground-truth BASELINE: we know exactly what ``role``
    was before we try to change it;
  * we PATCH/PUT the object AS ITS OWNER (legitimate rights to call update; the
    question is only whether the body may set a protected field), injecting one
    declared ``protected_fields`` value chosen to differ from that baseline;
  * we RE-READ the object as the owner and let the pure ``judge_injection`` oracle
    decide from the persisted state (a 2xx on the update proves nothing: the field
    may have been silently stripped).

So confirmation stays at BOLA's evidentiary bar (a before/after differential on an
object with known ground truth); only "which fields are protected" is config, since
that is policy the tool cannot infer.

Safety posture (mirrors the seeder, since this writes):
  * runs ONLY under ``--include-mutations`` (the caller gates it) AND only for
    resources that declare ``protected_fields`` (a double opt-in);
  * sequential, and every update/read is gated by the Safety Guard first;
  * bounded by the already-capped ledger (no new writes are invented: it mutates
    objects the seeder already created, which ``--cleanup`` already tears down).
Review carefully before modifying.
"""

import httpx

from ..config.schema import Config
from ..identity.base import AuthedClient
from ..safety.guard import SafetyGuard
from ..spec.openapi import Operation, access_operations
from .diff import normalize
from .ledger import OwnershipLedger
from .planner import Expectation, PlannedRequest
from .seeder import _join, _matching_get
from .verdict import Judgment, judge_injection


async def probe_mass_assignment(
    config: Config,
    registry: dict[str, AuthedClient],
    operations: list[Operation],
    guard: SafetyGuard,
    ledger: OwnershipLedger,
) -> list[Judgment]:
    """Attempt a mass-assignment on every seeded object whose resource declares
    ``protected_fields`` and has a single-id update op. Returns one Judgment per
    (object, field): VIOLATION if the field took our value, PASS if it was
    stripped, INCONCLUSIVE if we couldn't test or confirm."""
    base_url = config.target.base_url
    id_field = config.seeding.id_field
    accesses = access_operations(operations)
    judgments: list[Judgment] = []

    for entry in ledger.entries():
        resource_cfg = config.resources.get(entry.resource_type)
        if resource_cfg is None or not resource_cfg.protected_fields:
            continue  # nothing declared protected here -> nothing to test
        update_op = _matching_update(accesses, entry.resource_type)
        if update_op is None:
            continue  # no PUT/PATCH to attempt the injection through (create-based D4 is deferred)
        authed = registry.get(entry.owner)
        if authed is None:
            continue  # owner has no live session (shouldn't happen mid-run)
        get_op = _matching_get(accesses, entry.resource_type)
        update_path = _concrete(update_op, entry.object_id)
        canonical = entry.canonical_body

        for field, value in resource_cfg.protected_fields.items():
            req = PlannedRequest(
                acting_identity=entry.owner,
                method=update_op.method,
                path=update_path,
                operation_id=update_op.operation_id,
                target=entry.ref,
                expected=Expectation.DENY,  # setting a protected field should be refused
                is_mutation=True,
                check="massassign",
            )
            known_baseline = isinstance(canonical, dict) and field in canonical
            baseline = canonical[field] if known_baseline else None

            if known_baseline and value == baseline:
                # Our probe value already equals the current value, sending would
                # test nothing. Record INCONCLUSIVE without a write.
                judgments.append(
                    judge_injection(req, field, value, None, baseline_value=baseline, update_status=0)
                )
                continue

            status, readback = await _attempt_injection(
                authed, update_op, get_op, entry, field, value, canonical, id_field, guard, base_url
            )
            if known_baseline:
                judgments.append(
                    judge_injection(req, field, value, readback, baseline_value=baseline, update_status=status)
                )
            else:
                judgments.append(judge_injection(req, field, value, readback, update_status=status))

    return judgments


async def _attempt_injection(
    authed: AuthedClient,
    update_op: Operation,
    get_op: Operation | None,
    entry,
    field: str,
    value,
    canonical,
    id_field: str | None,
    guard: SafetyGuard,
    base_url: str,
) -> tuple[int, object]:
    """Send the injected update as the owner, then re-read the object as the owner.
    Returns (update_status, readback_body). update_status 0 == the request never
    completed; readback_body None == the object couldn't be re-read (-> INCONCLUSIVE)."""
    body = _update_body(canonical, id_field, field, value)
    update_path = _concrete(update_op, entry.object_id)
    guard.assert_allowed(_join(base_url, update_path))  # LIVE WRITE, gate first
    try:
        resp = await authed.client.request(update_op.method, update_path, json=body)
    except httpx.HTTPError:
        return 0, None
    return resp.status_code, await _read_back(authed, get_op, entry, guard, base_url)


async def _read_back(
    authed: AuthedClient, get_op: Operation | None, entry, guard: SafetyGuard, base_url: str
) -> object:
    """The owner's authoritative re-read: the confirming evidence. None if there's
    no GET op or the read didn't return a usable body."""
    if get_op is None:
        return None
    path = _concrete(get_op, entry.object_id)
    guard.assert_allowed(_join(base_url, path))  # LIVE read, gate it
    try:
        resp = await authed.client.get(path)
    except httpx.HTTPError:
        return None
    if resp.status_code // 100 != 2:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


# --- helpers ---------------------------------------------------------------
def _matching_update(accesses: list[Operation], resource_type: str) -> Operation | None:
    """The single-id update op for a resource: PATCH preferred (partial), else PUT."""
    for method in ("PATCH", "PUT"):
        for op in accesses:
            if (
                op.method == method
                and op.resource_type == resource_type
                and len(op.object_id_params) == 1
            ):
                return op
    return None


def _update_body(canonical, id_field: str | None, field: str, value) -> dict:
    """Build the update body: the object's own (non-volatile, id-stripped) fields
    plus the one injected field. Re-sending the canonical fields keeps a full PUT
    from wiping required data; ``normalize`` (reused from diff) drops volatile
    fields; the id lives in the URL, so we drop it from the body."""
    body: dict = {}
    if isinstance(canonical, dict):
        drop = {"id"}
        if id_field:
            drop.add(id_field)
        drop_lower = {d.lower() for d in drop}
        body = {k: v for k, v in normalize(canonical).items() if str(k).lower() not in drop_lower}
    body[field] = value  # the injection, set last so it wins even if it was present
    return body


def _concrete(op: Operation, object_id: str) -> str:
    param = op.object_id_params[0]
    return op.path_template.replace("{" + param.name + "}", object_id)
