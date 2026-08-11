"""Body-diff (§7) — the leak confirmer.

OWN THIS FILE. A broken-object-authorization leak returns a perfectly valid
200 OK, so a status code alone proves nothing. This module is what turns a
non-owner 2xx into a *confirmed* leak: it checks that the response actually
contains the owner's object. Refusing to confirm without that match is exactly
what keeps false positives near zero (§7).

Rule — containment, not equality:
  1. Normalize both bodies by dropping volatile fields (timestamps, etags,
     last_seen) that legitimately change and shouldn't be required to match.
  2. Confirm a leak iff every non-volatile field of the OWNER's canonical object
     appears, with an equal value, in the observed response
     (canonical_nonvolatile ⊆ observed).

Why:
  * Containment (subset), not equality — a leaked response may carry extra
    server-added fields; we require the owner's data to be present, not identical.
  * The whole (non-volatile) object must be contained — that is what discriminates
    a real leak from a coincidental overlap of a couple of default fields, and a
    near-miss (same shape, different values) fails on some field.
  * Conservative: a non-dict body, or a canonical with nothing but volatile
    fields, yields no confirmation (-> the oracle records INCONCLUSIVE, not a leak).

Phase-3 scope: top-level fields only. Normalizing volatile fields nested inside
sub-objects is a later refinement.
"""

from typing import Any

# Field names that legitimately vary and must not be required to match.
DEFAULT_VOLATILE_FIELDS = frozenset(
    {
        "created_at",
        "updated_at",
        "modified_at",
        "timestamp",
        "etag",
        "last_seen",
        "last_login",
        "last_modified",
        "version",
    }
)

_MISSING = object()  # sentinel: distinguishes an absent key from a present None


def normalize(body: dict, volatile_fields=DEFAULT_VOLATILE_FIELDS) -> dict:
    """Copy of ``body`` with volatile fields removed (case-insensitive keys)."""
    vol = {v.lower() for v in volatile_fields}
    return {k: v for k, v in body.items() if str(k).lower() not in vol}


def confirm_leak(
    observed_body: Any,
    canonical_body: Any,
    *,
    volatile_fields=DEFAULT_VOLATILE_FIELDS,
) -> list[str] | None:
    """Return the matched field names if ``observed_body`` contains the owner's
    object, else ``None`` (not a confirmed leak)."""
    if not isinstance(observed_body, dict) or not isinstance(canonical_body, dict):
        return None  # can only decide containment on object bodies

    canonical = normalize(canonical_body, volatile_fields)
    if not canonical:
        return None  # nothing identifying to match on -> cannot confirm

    for key, value in canonical.items():
        if observed_body.get(key, _MISSING) != value:
            return None  # a field is missing or differs -> containment broken

    return sorted(canonical.keys())  # every owner field matched -> the evidence
