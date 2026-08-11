"""Verdict Engine (§5.10, §9) — the oracle. OWN THIS FILE COMPLETELY.

A leaked object returns a perfectly valid 200 OK, so authorization can't be judged
from a response in isolation. This function decides it *with* ground truth (the
ledger): it knows who really owns the target and what the owner's object contains.

It is a PURE function of its inputs — no I/O — so it is trivially testable and can
never become an injection vector. Every branch below is a claim you must be able
to defend.

Four honest states (never collapse them):
  PASS         secure — correctly denied, or an allowed access that succeeded.
  VIOLATION    confirmed leak, with evidence (matched fields + the request pair).
  BROKEN       the app denied LEGITIMATE access (owner denied) — a bug, reported
               separately, never counted as a security pass.
  INCONCLUSIVE needs a human — 5xx, 2xx with no body match, or an unexpected status.
"""

from dataclasses import dataclass
from enum import Enum

from .diff import confirm_leak
from .executor import ObservedResponse
from .ledger import OwnershipLedger
from .planner import Expectation, PlannedRequest


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
    matched_fields: tuple[str, ...] = ()  # populated for a VIOLATION — the evidence


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

    # BFLA (D2) is function-level: no object to match, judged on status alone —
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
        # legitimate deny-by-info-hiding — not a missing object.
        return result(Verdict.PASS, "denied via not-found (info hiding); object known to exist")
    if 200 <= status < 300:
        matched = confirm_leak(observed.body, entry.canonical_body)
        if matched:
            return result(
                Verdict.VIOLATION,
                "confirmed BOLA: response contains the owner's object",
                tuple(matched),
            )
        # A 2xx alone is not a leak — a filtered/empty/generic 200 looks the same.
        return result(Verdict.INCONCLUSIVE, "2xx to non-owner but no body match — needs review")

    return result(Verdict.INCONCLUSIVE, f"unexpected status {status}")


def judge_all(
    results: list[tuple[PlannedRequest, ObservedResponse]], ledger: OwnershipLedger
) -> list[Judgment]:
    return [judge(req, observed, ledger) for req, observed in results]


def findings(judgments: list[Judgment]) -> list[Judgment]:
    """The confirmed leaks — the judgments a report should surface as findings."""
    return [j for j in judgments if j.verdict is Verdict.VIOLATION]
