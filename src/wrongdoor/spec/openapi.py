"""Spec importer (§5.4): OpenAPI document -> operation catalog.

We lean on prance to load + resolve internal ``$ref``s (don't reimplement that —
§4), then walk the resolved spec ourselves to build a small, typed ``Operation``
list. The walk is a pure function of a resolved dict, so it's testable without
prance touching a file.

Scope note: only internal (``#/components/...``) refs are supported — the spec is
passed to prance as a string with no base path, so external/remote refs won't
resolve. That's intentional for a single-file spec.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import prance

# Bound the catalog so a huge/hostile spec can't blow up a run (§5.4).
MAX_OPERATIONS = 500
# HTTP methods we look at (in OpenAPI these are lowercase keys under a path).
_HTTP_METHODS = ("get", "post", "put", "patch", "delete")
_MAX_SYNTH_DEPTH = 6

_STRING_FORMAT_SAMPLES = {
    "date-time": "2020-01-01T00:00:00Z",
    "date": "2020-01-01",
    "email": "user@example.com",
    "uuid": "00000000-0000-0000-0000-000000000000",
}


class SpecError(Exception):
    """Raised when the OpenAPI spec cannot be parsed or is too large."""


@dataclass(frozen=True)
class Parameter:
    name: str
    location: str  # "path" | "query" | "header" | ...
    is_object_id: bool  # True for path params — the things a BOLA test swaps


@dataclass
class Operation:
    operation_id: str
    method: str  # upper-case: GET, POST, ...
    path_template: str  # e.g. /invoices/{invoice_id}
    kind: str  # "create" | "access"
    resource_type: str  # e.g. "invoices" — ties a create op to its access ops
    parameters: tuple[Parameter, ...] = ()
    request_schema: dict | None = None  # resolved JSON schema for the body (create ops)

    @property
    def object_id_params(self) -> tuple[Parameter, ...]:
        return tuple(p for p in self.parameters if p.is_object_id)


def load_operations(path: str | Path) -> list[Operation]:
    """Load an OpenAPI file (JSON or YAML) into an operation catalog."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise SpecError(f"cannot read spec file {path}: {e}") from e
    return load_operations_from_string(text)


def load_operations_from_string(text: str) -> list[Operation]:
    try:
        parser = prance.ResolvingParser(spec_string=text, strict=False)
    except Exception as e:  # prance raises various types; normalize to SpecError
        raise SpecError(f"failed to parse OpenAPI spec: {e}") from e
    return _operations_from_resolved(parser.specification)


# --- the pure walk (no prance, no I/O) ------------------------------------
def _operations_from_resolved(spec: dict) -> list[Operation]:
    paths = spec.get("paths") or {}
    operations: list[Operation] = []
    seen = 0
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in _HTTP_METHODS:
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            seen += 1
            if seen > MAX_OPERATIONS:
                raise SpecError(
                    f"spec declares more than {MAX_OPERATIONS} operations; refusing"
                )
            params = _collect_params(path_item, op)
            has_path_id = any(p.is_object_id for p in params)
            kind = _classify(method, has_path_id)
            operations.append(
                Operation(
                    operation_id=op.get("operationId") or f"{method.upper()} {path}",
                    method=method.upper(),
                    path_template=path,
                    kind=kind,
                    resource_type=_resource_type(path),
                    parameters=params,
                    request_schema=_request_schema(op) if kind == "create" else None,
                )
            )
    return operations


def _classify(method: str, has_path_id: bool) -> str:
    if method == "post" and not has_path_id:
        return "create"  # POST /invoices -> makes a new object
    if method in ("get", "put", "patch", "delete") and has_path_id:
        return "access"  # GET/PUT/DELETE /invoices/{id} -> touches an existing object
    return "other"  # e.g. an admin/collection endpoint — inert unless marked privileged


def _resource_type(path: str) -> str:
    # The object's collection = the last path segment that isn't a {param}.
    # /invoices -> invoices ; /invoices/{id} -> invoices ; /orgs/{o}/invoices/{id} -> invoices
    segments = [s for s in path.split("/") if s and not _is_template(s)]
    return segments[-1] if segments else path


def _is_template(segment: str) -> bool:
    return segment.startswith("{") and segment.endswith("}")


def _collect_params(path_item: dict, op: dict) -> tuple[Parameter, ...]:
    # Path-level params are shared; operation-level params override by (name, in).
    merged: dict[tuple[str, str], Parameter] = {}
    for raw in list(path_item.get("parameters") or []) + list(op.get("parameters") or []):
        if not isinstance(raw, dict):
            continue
        name, location = raw.get("name"), raw.get("in")
        if name and location:
            merged[(name, location)] = Parameter(
                name=name, location=location, is_object_id=(location == "path")
            )
    return tuple(merged.values())


def _request_schema(op: dict) -> dict | None:
    body = op.get("requestBody")
    if not isinstance(body, dict):
        return None
    content = body.get("content") or {}
    media = content.get("application/json")
    if isinstance(media, dict) and isinstance(media.get("schema"), dict):
        return media["schema"]
    # fall back to the first content type that carries a schema
    for media in content.values():
        if isinstance(media, dict) and isinstance(media.get("schema"), dict):
            return media["schema"]
    return None


def create_operations(operations: list[Operation]) -> list[Operation]:
    return [o for o in operations if o.kind == "create"]


def access_operations(operations: list[Operation]) -> list[Operation]:
    return [o for o in operations if o.kind == "access"]


# --- sample-body synthesis (input generation, not a security decision, §10) --
def synthesize_body(schema: dict | None, _depth: int = 0) -> Any:
    """Build a plausible, deterministic request body from a JSON schema."""
    if schema is None:
        return {}
    if not isinstance(schema, dict) or _depth > _MAX_SYNTH_DEPTH:
        return None

    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if schema.get("enum"):
        return schema["enum"][0]
    for combiner in ("allOf", "oneOf", "anyOf"):
        if schema.get(combiner):
            return synthesize_body(schema[combiner][0], _depth + 1)

    t = schema.get("type")
    if t == "object" or (t is None and "properties" in schema):
        props = schema.get("properties") or {}
        return {name: synthesize_body(sub, _depth + 1) for name, sub in props.items()}
    if t == "array":
        items = schema.get("items")
        return [synthesize_body(items, _depth + 1)] if items else []
    if t == "string":
        return _STRING_FORMAT_SAMPLES.get(schema.get("format"), "example")
    if t == "integer":
        return 1
    if t == "number":
        return 1.0
    if t == "boolean":
        return True
    if t == "null":
        return None
    return {}  # no/unknown type -> an empty object is a safe default
