"""Finding model + builder (§5.11, §11): judgments enriched for reporting.

A ``Finding`` is a confirmed VIOLATION judgment plus its deterministic severity,
explanation, remediation, a stable fingerprint, and the reproducible request pair.
Redaction is the default: ``to_dict`` emits matched field NAMES only; raw response
bodies appear solely when ``include_bodies=True`` (§13).
"""

from dataclasses import dataclass

from ..config.schema import Config
from ..engine.planner import ANONYMOUS_ID
from ..engine.verdict import Judgment, Verdict
from ..explain import (
    explain_bfla,
    explain_bola,
    explain_mass_assignment,
    explain_missing_auth,
    remediate_bfla,
    remediate_bola,
    remediate_mass_assignment,
    remediate_missing_auth,
)
from ..risk import Severity, score


@dataclass
class Finding:
    fingerprint: str
    finding_type: str  # "BOLA"
    severity: Severity
    actor: str
    actor_tenant: str | None
    owner: str | None
    owner_tenant: str | None
    resource_type: str
    object_id: str
    method: str
    operation_id: str
    path: str
    status: int
    matched_fields: tuple[str, ...]
    explanation: str
    remediation: str
    judgment: Judgment  # retained for optional --include-bodies; never serialized by default

    def canonical_request(self) -> str:
        # A function-level (BFLA) finding has no owning identity, so there is no
        # "the owner's own legitimate request" to show. Say that plainly rather
        # than printing "(as None)".
        if self.owner is None:
            return f"{self.method} {self.path} (requires a privileged role)"
        return f"{self.method} {self.path} (as {self.owner}) -> 200"

    def attack_request(self) -> str:
        return f"{self.method} {self.path} (as {self.actor}) -> {self.status}"

    def to_dict(self, *, include_bodies: bool = False) -> dict:
        d = {
            "id": self.fingerprint,
            "type": self.finding_type,
            "severity": self.severity.name,
            "actor": {"identity": self.actor, "tenant": self.actor_tenant},
            "victim": {
                "owner": self.owner,
                "tenant": self.owner_tenant,
                "object": f"{self.resource_type}/{self.object_id}",
            },
            "operation": f"{self.method} {self.operation_id}",
            "evidence": {
                "canonical_request": self.canonical_request(),
                "attack_request": self.attack_request(),
                "body_match": list(self.matched_fields),  # field names only (§13)
            },
            "explanation": self.explanation,
            "remediation": self.remediation,
        }
        if include_bodies:
            # Opt-in: real response body, which may contain sensitive values.
            d["evidence"]["observed_body"] = self.judgment.observed.body
        return d


def build_findings(judgments: list[Judgment], config: Config) -> list[Finding]:
    id_attrs = {i.id: dict(i.attributes) for i in config.identities}
    resources = config.resources
    findings: list[Finding] = []

    for j in judgments:
        if j.verdict is not Verdict.VIOLATION:
            continue
        req = j.request
        owner_tenant = id_attrs.get(j.owner or "", {}).get("tenant")
        rt, oid = req.target.resource_type, req.target.object_id
        matched = tuple(j.matched_fields)

        if req.check == "bfla":
            finding_type = "BFLA"
            actor = req.acting_identity
            actor_tenant = id_attrs.get(actor, {}).get("tenant")
            fingerprint = f"WD-BFLA-{req.operation_id}-{rt}"
            explanation = explain_bfla(actor, actor_tenant, req.method, req.operation_id)
            remediation = remediate_bfla(req.method, req.operation_id)
        elif req.check == "massassign":
            finding_type = "MASS_ASSIGNMENT"
            actor = req.acting_identity  # the injector is also the object's owner
            actor_tenant = id_attrs.get(actor, {}).get("tenant")
            field = matched[0] if matched else "?"  # judge_injection records the confirmed field
            fingerprint = f"WD-MASSASSIGN-{req.operation_id}-{rt}-{field}"
            explanation = explain_mass_assignment(actor, actor_tenant, rt, oid, req.method, req.operation_id, field)
            remediation = remediate_mass_assignment(rt, req.method, req.operation_id, field)
        elif req.check == "unauth" or req.acting_identity == ANONYMOUS_ID:
            finding_type = "MISSING_AUTH"
            actor, actor_tenant = "anonymous", None
            fingerprint = f"WD-MISSING_AUTH-{req.operation_id}-{rt}"
            explanation = explain_missing_auth(j.owner, owner_tenant, rt, oid, req.method, req.operation_id, matched)
            remediation = remediate_missing_auth(rt, req.method, req.operation_id)
        else:
            finding_type = "BOLA"
            actor = req.acting_identity
            actor_tenant = id_attrs.get(actor, {}).get("tenant")
            cross = actor_tenant is not None and owner_tenant is not None and actor_tenant != owner_tenant
            fingerprint = f"WD-BOLA-{req.operation_id}-{rt}-{'cross-tenant' if cross else 'same-tenant'}"
            explanation = explain_bola(actor, actor_tenant, j.owner, owner_tenant, rt, oid, req.method, req.operation_id, matched)
            remediation = remediate_bola(rt, req.method, req.operation_id)

        findings.append(
            Finding(
                fingerprint=fingerprint,
                finding_type=finding_type,
                severity=score(j, id_attrs, resources),
                actor=actor,
                actor_tenant=actor_tenant,
                owner=j.owner,
                owner_tenant=owner_tenant,
                resource_type=rt,
                object_id=oid,
                method=req.method,
                operation_id=req.operation_id,
                path=req.path,
                status=j.observed.status,
                matched_fields=matched,
                explanation=explanation,
                remediation=remediation,
                judgment=j,
            )
        )
    # Most severe first, with a deterministic tiebreak, so every report leads with
    # the worst finding rather than plan order.
    findings.sort(key=lambda f: (-int(f.severity), f.finding_type, f.resource_type, f.object_id))
    return findings


def max_severity(findings: list[Finding]) -> Severity | None:
    return max((f.severity for f in findings), default=None)
