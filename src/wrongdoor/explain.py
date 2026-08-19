"""Explainer (§5.11, §10): deterministic template prose for a finding.

The LLM is OFF and out of scope here (Phase 6, cosmetic only). These functions
turn already-final finding facts into a sentence and a remediation; disabling any
future LLM must leave the finding, verdict, score, and evidence byte-identical.
Only the wording could change. So the truth lives in the templates below.

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


def explain_missing_auth(
    owner: str | None,
    owner_tenant: str | None,
    resource_type: str,
    object_id: str,
    method: str,
    operation_id: str,
    matched_fields: tuple[str, ...],
) -> str:
    whose = f"{owner!r}" + (f" (tenant {owner_tenant})" if owner_tenant else "")
    fields = ", ".join(matched_fields) if matched_fields else "the object"
    return (
        f"An unauthenticated caller accessed {resource_type}/{object_id}, owned by {whose}, "
        f"via {method} {operation_id}. The response contained the owner's data ({fields}), "
        f"confirming the endpoint serves protected data without authentication."
    )


def remediate_missing_auth(resource_type: str, method: str, operation_id: str) -> str:
    return (
        f"Require authentication on {method} {operation_id}: reject requests without a valid "
        f"token (401) before returning any {resource_type}, then enforce an ownership check."
    )


def explain_bfla(actor: str, actor_tenant: str | None, method: str, operation_id: str) -> str:
    who = f"identity {actor!r}" + (f" (tenant {actor_tenant})" if actor_tenant else "")
    return (
        f"{who} successfully invoked the privileged operation {method} {operation_id}, "
        f"which should require elevated privileges — a Broken Function Level Authorization flaw."
    )


def remediate_bfla(method: str, operation_id: str) -> str:
    return (
        f"Enforce a role/privilege check on {method} {operation_id}: verify the caller holds the "
        f"required role and return 403 otherwise."
    )


def explain_mass_assignment(
    actor: str,
    actor_tenant: str | None,
    resource_type: str,
    object_id: str,
    method: str,
    operation_id: str,
    field: str,
) -> str:
    who = f"identity {actor!r}" + (f" (tenant {actor_tenant})" if actor_tenant else "")
    return (
        f"{who} set the protected field {field!r} on their own {resource_type}/{object_id} "
        f"via {method} {operation_id} — a field a client should not control. A re-read as the "
        f"owner confirmed the value persisted, confirming a mass-assignment (Broken Object "
        f"Property Level Authorization) flaw."
    )


def remediate_mass_assignment(resource_type: str, method: str, operation_id: str, field: str) -> str:
    return (
        f"Do not bind the whole request body to the {resource_type} model on {method} "
        f"{operation_id}: allowlist only client-settable fields and reject or ignore "
        f"{field!r} from the body (e.g. a write-DTO / explicit field mapping), so a client "
        f"cannot assign server-controlled fields."
    )
