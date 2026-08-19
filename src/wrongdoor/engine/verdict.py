"""Verdict Engine (§5.10, §9): the oracle. The single most critical file in the
tool, since every finding traces back to it.

A leaked object returns a perfectly valid 200 OK, so authorization can't be judged
from a response in isolation. This function decides it *with* ground truth (the
ledger): it knows who really owns the target and what the owner's object contains.

It is a PURE function of its inputs (no I/O), so it is trivially testable and can
never become an injection vector. Every branch below is a claim you must be able
to defend. Review carefully before modifying.

Four honest states (never collapse them):
  PASS         secure: correctly denied, or an allowed access that succeeded.
  VIOLATION    confirmed leak, with evidence (matched fields + the request pair).
  BROKEN       the app denied LEGITIMATE access (owner denied): a bug, reported
               separately, never counted as a security pass.
  INCONCLUSIVE needs a human: 5xx, 2xx with no body match, or an unexpected status.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .diff import confirm_injection, confirm_leak
from .executor import ObservedResponse
from .ledger import OwnershipLedger
from .planner import Expectation, PlannedRequest

_NO_BASELINE = object()  # sentinel: the field had no known value before the injection


class Verdict(Enum):
    PASS = "pass"
    VIOLATION = "violation"
    BROKEN = "broken"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Judgment:
    verdict: Verdict
    reason: str
    request: PlannedRequest
    observed: ObservedResponse
    owner: str | None  # ground-truth owner of the target (from the ledger)
    matched_fields: tuple[str, ...] = ()  # populated for a VIOLATION: the evidence


def judge(
    request: PlannedRequest, observed: ObservedResponse, ledger: OwnershipLedger
) -> Judgment:
    entry = ledger.get(request.target)
    status = observed.status
    owner = entry.owner if entry else None

    def result(verdict: Verdict, reason: str, matched: tuple[str, ...] = ()) -> Judgment:
        return Judgment(
            verdict=verdict,
            reason=reason,
            request=request,
            observed=observed,
            owner=owner,
            matched_fields=matched,
        )

    # A server error is neither a pass nor a leak, regardless of expectation.
    if 500 <= status < 600:
        return result(Verdict.INCONCLUSIVE, "server error (5xx)")

    if request.expected is Expectation.ALLOW:
        if 200 <= status < 300:
            return result(Verdict.PASS, "authorized access succeeded")
        return result(Verdict.BROKEN, f"legitimate access denied (HTTP {status})")

    # BFLA (D2) is function-level: no object to match, judged on status alone,
    # a non-privileged identity reaching the operation at all is the finding.
    if request.check == "bfla":
        if status in (401, 403):
            return result(Verdict.PASS, "correctly denied (privileged operation)")
        if status == 404:
            return result(Verdict.PASS, "not found")
        if 200 <= status < 300:
            return result(
                Verdict.VIOLATION,
                "confirmed BFLA: privileged operation succeeded for a non-privileged identity",
            )
        return result(Verdict.INCONCLUSIVE, f"unexpected status {status}")

    # BOLA (D1) / missing-auth (D3) need ground truth from the ledger.
    if entry is None:
        return result(Verdict.INCONCLUSIVE, "target object not in ledger")

    # request.expected is DENY (the actor is a non-owner / unauthorized).
    if status in (401, 403):
        return result(Verdict.PASS, "correctly denied")
    if status == 404:
        # We KNOW the object exists (we created it), so a 404 to a non-owner is
        # legitimate deny-by-info-hiding, not a missing object.
        return result(Verdict.PASS, "denied via not-found (info hiding); object known to exist")
    if 200 <= status < 300:
        matched = confirm_leak(observed.body, entry.canonical_body)
        if matched:
            return result(
                Verdict.VIOLATION,
                "confirmed BOLA: response contains the owner's object",
                tuple(matched),
            )
        # A 2xx alone is not a leak: a filtered/empty/generic 200 looks the same.
        return result(Verdict.INCONCLUSIVE, "2xx to non-owner but no body match, needs review")

    return result(Verdict.INCONCLUSIVE, f"unexpected status {status}")


def judge_injection(
    request: PlannedRequest,
    field: str,
    injected_value: Any,
    readback_body: Any,
    baseline_value: Any = _NO_BASELINE,
    *,
    update_status: int,
) -> Judgment:
    """The mass-assignment (D4) oracle: a PURE sibling of ``judge``.

    ``judge`` decides BOLA from (attack response, ledger); this decides
    mass-assignment from (the update's status, the owner's re-read, the field's
    pre-injection baseline). Like ``judge`` it does no I/O: the prober performs
    the update and the re-read, then hands the bodies here, so the decision stays
    trivially testable and can't be an injection vector.

    ``observed`` is recorded as the UPDATE attempt's status paired with the owner's
    re-read body: the status is the attack's HTTP result, the body is the
    confirming evidence (the persisted object), so one object serves both the
    reproducible-attack line and ``--include-bodies``.

    Four honest states, decided by the PERSISTED state (a 2xx on the update alone
    proves nothing, the field may have been silently stripped):
      * value already equalled the baseline, or a 5xx, or the object can't be
        re-read  -> INCONCLUSIVE (nothing was actually tested / can't confirm);
      * the field now holds our injected value (and it changed)  -> VIOLATION;
      * the field was stripped / ignored  -> PASS.
    """
    observed = ObservedResponse(status=update_status, body=readback_body)
    owner = request.acting_identity  # the injector owns the object it is updating

    def result(verdict: Verdict, reason: str, matched: tuple[str, ...] = ()) -> Judgment:
        return Judgment(
            verdict=verdict,
            reason=reason,
            request=request,
            observed=observed,
            owner=owner,
            matched_fields=matched,
        )

    has_baseline = baseline_value is not _NO_BASELINE
    if has_baseline and injected_value == baseline_value:
        return result(
            Verdict.INCONCLUSIVE,
            f"probe value for {field!r} equals its current value, nothing tested",
        )
    if 500 <= update_status < 600:
        return result(Verdict.INCONCLUSIVE, f"server error on update (HTTP {update_status})")
    if not isinstance(readback_body, dict):
        return result(Verdict.INCONCLUSIVE, "could not re-read the object to confirm")

    confirmed = (
        confirm_injection(readback_body, field, injected_value, baseline_value)
        if has_baseline
        else confirm_injection(readback_body, field, injected_value)
    )
    if confirmed:
        return result(
            Verdict.VIOLATION,
            f"confirmed mass-assignment: the client set the protected field {field!r}",
            (field,),
        )
    return result(Verdict.PASS, f"protected field {field!r} was not accepted (stripped/ignored)")


def judge_all(
    results: list[tuple[PlannedRequest, ObservedResponse]], ledger: OwnershipLedger
) -> list[Judgment]:
    return [judge(req, observed, ledger) for req, observed in results]


def findings(judgments: list[Judgment]) -> list[Judgment]:
    """The confirmed leaks: the judgments a report should surface as findings."""
    return [j for j in judgments if j.verdict is Verdict.VIOLATION]
