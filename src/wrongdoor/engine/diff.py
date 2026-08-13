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


def confirm_injection(
    readback_body: Any,
    field: str,
    injected_value: Any,
    baseline_value: Any = _MISSING,
) -> bool:
    """Confirm a mass-assignment (D4): did injecting ``field=injected_value`` into an
    update actually take, as seen in the owner's re-read of the object?

    A sibling of ``confirm_leak`` — same dict-only / equality / ``_MISSING``
    discipline — but a *field-level* claim (one field took our value) rather than
    the whole-object containment ``confirm_leak`` proves. Returns ``True`` only
    when we can attribute the change to our injection:

      * the re-read is an object (dict) — else we cannot decide (conservative);
      * ``readback[field] == injected_value`` — the field is present AND holds the
        exact value we tried to set (not stripped, not coerced to something else);
      * when a ground-truth ``baseline_value`` is known (the value the field held
        BEFORE the injection, from the ledger's canonical body), the injected
        value must actually DIFFER from it — otherwise the field would read as our
        value even if the server ignored us and it merely already had that value.
    """
    if not isinstance(readback_body, dict):
        return False  # can only decide on an object body
    present = readback_body.get(field, _MISSING)
    if present is _MISSING or present != injected_value:
        return False  # field absent, or not our value -> the server stripped/ignored it
    if baseline_value is not _MISSING and injected_value == baseline_value:
        return False  # equals the pre-existing value -> can't attribute the change to us
    return True
