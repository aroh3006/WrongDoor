"""Explainer (§5.11, §10) — deterministic template prose for a finding.

The LLM is OFF and out of scope here (Phase 6, cosmetic only). These functions
turn already-final finding facts into a sentence and a remediation; disabling any
future LLM must leave the finding, verdict, score, and evidence byte-identical —
only the wording could change. So the truth lives in the templates below.

Templates use field NAMES, never values (§13).
"""


def explain_bola(
    actor: str,
    actor_tenant: str | None,
    owner: str | None,
    owner_tenant: str | None,
    resource_type: str,
    object_id: str,
    method: str,
    operation_id: str,
    matched_fields: tuple[str, ...],
) -> str:
    who = f"identity {actor!r}" + (f" (tenant {actor_tenant})" if actor_tenant else "")
    whose = f"{owner!r}" + (f" (tenant {owner_tenant})" if owner_tenant else "")
    fields = ", ".join(matched_fields) if matched_fields else "the object"
    return (
        f"{who} successfully accessed {resource_type}/{object_id}, owned by {whose}, "
        f"via {method} {operation_id}. The response contained the owner's data "
        f"({fields}), confirming a Broken Object Level Authorization leak."
    )


def remediate_bola(resource_type: str, method: str, operation_id: str) -> str:
    return (
        f"Enforce an ownership/tenancy check on {method} {operation_id} before returning "
        f"the object: verify the {resource_type} belongs to the caller "
        f"(e.g. WHERE id = :id AND owner = current_user) and return 403/404 otherwise."
    )
