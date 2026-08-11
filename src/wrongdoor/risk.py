"""Risk Scorer (§9) — deterministic, hand-reconstructable severity.

No model, no score-of-0.87: a finding's severity is a small function of factors
you can recite. severity = f(resource_sensitivity, cross_tenant, is_mutation):

  * base band from the resource's configured sensitivity (low/medium/high);
  * a cross-tenant access (actor's tenant != owner's tenant) bumps up one band;
  * a mutation (PUT/PATCH/DELETE) bumps up one band;
  * clamp at CRITICAL.

So a cross-tenant read of a high-sensitivity object is Critical; a same-tenant
read of a high object is High; a low-sensitivity read is Low (§12).
"""

from enum import IntEnum

from .config.schema import ResourceConfig
from .engine.verdict import Judgment


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


_SENSITIVITY_BAND = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
}


def _bump(band: Severity) -> Severity:
    return Severity(min(int(band) + 1, int(Severity.CRITICAL)))


def score(
    judgment: Judgment,
    id_attributes: dict[str, dict[str, str]],
    resources: dict[str, ResourceConfig],
) -> Severity:
    resource_type = judgment.request.target.resource_type
    resource_cfg = resources.get(resource_type)
    sensitivity = resource_cfg.sensitivity if resource_cfg else "medium"
    band = _SENSITIVITY_BAND[sensitivity]

    actor_tenant = id_attributes.get(judgment.request.acting_identity, {}).get("tenant")
    owner_tenant = id_attributes.get(judgment.owner or "", {}).get("tenant")
    if actor_tenant is not None and owner_tenant is not None and actor_tenant != owner_tenant:
        band = _bump(band)  # cross-tenant boundary break

    if judgment.request.is_mutation:
        band = _bump(band)  # a write/delete is worse than the equivalent read

    if judgment.request.check == "unauth":
        band = _bump(band)  # exposed to any anonymous caller — worse than a cross-identity leak

    if judgment.request.check == "bfla":
        band = _bump(band)  # a privileged function reachable by the under-privileged

    return band


def parse_severity(name: str) -> Severity:
    """Parse a --fail-on value like 'high' into a Severity (case-insensitive)."""
    try:
        return Severity[name.strip().upper()]
    except KeyError as e:
        valid = ", ".join(s.name.lower() for s in Severity)
        raise ValueError(f"unknown severity {name!r}; choose one of: {valid}") from e
