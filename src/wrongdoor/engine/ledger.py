"""Ownership Ledger (§5.7) — the one core data structure: ground truth.

OWN THIS FILE. Everything the verdict engine later concludes rests on the ledger
being correct: it is the record of "object X belongs to identity Y, and here is
Y's own copy of X." If this is wrong, every verdict is silently wrong. So this
file is written to make quiet corruption impossible, not to be clever.

Design (each point is defensible in a viva):

* Key by ``(resource_type, object_id)``, never bare ``object_id`` — real APIs
  reuse small ids across types (``invoice/1`` and ``user/1`` both exist), and a
  bare-id key would cross-wire ownership. ``object_id`` is normalized to ``str``
  because JSON returns ``1`` or ``"1"`` inconsistently.
* Ownership is write-once ground truth. Recording the same ref with a *different*
  owner raises ``LedgerError`` — that can only mean the target gave two identities
  the same id (an anomaly) or a seeder bug, and either would poison every verdict.
  Re-recording the *same* owner is allowed (idempotent).
* ``canonical_body`` is the owner's view, stored opaquely; the ledger never
  interprets it (that's diff.py's job in Phase 3).
* Redaction is the default. ``redacted_summary()`` emits field *names*, never
  values (§13). Raw bodies leave only via an explicit getter.
"""

from dataclasses import dataclass
from typing import Any, Iterator


class LedgerError(Exception):
    """Raised on an integrity violation (empty id, conflicting ownership claim)."""


@dataclass(frozen=True)
class ObjectRef:
    """Identifies one object: its collection and its (stringified) id."""

    resource_type: str
    object_id: str


@dataclass
class LedgerEntry:
    ref: ObjectRef
    owner: str  # identity id of the creator == ground-truth owner
    canonical_body: Any  # the owner's own view of the object (possibly sensitive)

    @property
    def resource_type(self) -> str:
        return self.ref.resource_type

    @property
    def object_id(self) -> str:
        return self.ref.object_id


class OwnershipLedger:
    def __init__(self) -> None:
        self._entries: dict[ObjectRef, LedgerEntry] = {}

    # --- the one write path -------------------------------------------------
    def record(
        self, resource_type: str, object_id: Any, owner: str, canonical_body: Any
    ) -> LedgerEntry:
        """Record ground truth for one created object. Write-once per owner."""
        if object_id is None or str(object_id) == "":
            raise LedgerError(
                f"cannot record {resource_type!r} object with an empty id "
                f"(owner {owner!r}) — the create response had no usable id"
            )
        ref = ObjectRef(resource_type=resource_type, object_id=str(object_id))

        existing = self._entries.get(ref)
        if existing is not None and existing.owner != owner:
            # Two identities cannot both own the same object. This is either a
            # target anomaly or a seeder bug — fail loud, don't corrupt truth.
            raise LedgerError(
                f"ownership conflict for {ref}: already owned by "
                f"{existing.owner!r}, now claimed by {owner!r}"
            )

        entry = LedgerEntry(ref=ref, owner=owner, canonical_body=canonical_body)
        self._entries[ref] = entry
        return entry

    # --- reads (total: never raise) ----------------------------------------
    def get(self, ref: ObjectRef) -> LedgerEntry | None:
        return self._entries.get(ref)

    def get_by(self, resource_type: str, object_id: Any) -> LedgerEntry | None:
        return self._entries.get(ObjectRef(resource_type, str(object_id)))

    def owner_of(self, ref: ObjectRef) -> str | None:
        entry = self._entries.get(ref)
        return entry.owner if entry else None

    def entries(self) -> list[LedgerEntry]:
        return list(self._entries.values())

    def objects_owned_by(self, identity: str) -> list[LedgerEntry]:
        return [e for e in self._entries.values() if e.owner == identity]

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[LedgerEntry]:
        return iter(self._entries.values())

    def __contains__(self, ref: object) -> bool:
        return ref in self._entries

    # --- safe-by-default view (§13) ----------------------------------------
    def redacted_summary(self) -> list[dict]:
        """Printable summary with canonical-body field NAMES only, no values."""
        return [
            {
                "resource_type": e.ref.resource_type,
                "object_id": e.ref.object_id,
                "owner": e.owner,
                "canonical_fields": _field_names(e.canonical_body),
            }
            for e in self._entries.values()
        ]


def _field_names(body: Any) -> list[str] | str:
    if isinstance(body, dict):
        return sorted(str(k) for k in body.keys())
    return f"<{type(body).__name__}>"
