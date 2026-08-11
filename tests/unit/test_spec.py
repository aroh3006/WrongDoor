"""Unit tests for the OpenAPI importer (§5.4)."""

import pytest

from wrongdoor.spec import openapi
from wrongdoor.spec.openapi import (
    SpecError,
    access_operations,
    create_operations,
    load_operations_from_string,
    synthesize_body,
    _operations_from_resolved,
)

# An already-resolved spec (no $ref) so the walk is tested without prance.
_RESOLVED = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1"},
    "paths": {
        "/invoices": {
            "post": {
                "operationId": "createInvoice",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"amount": {"type": "number"}},
                                "required": ["amount"],
                            }
                        }
                    }
                },
                "responses": {},
            },
            "get": {"operationId": "listInvoices", "responses": {}},  # collection GET -> skipped
        },
        "/invoices/{invoice_id}": {
            "parameters": [
                {"name": "invoice_id", "in": "path", "required": True, "schema": {"type": "integer"}}
            ],
            "get": {"operationId": "getInvoice", "responses": {}},
            "delete": {"operationId": "deleteInvoice", "responses": {}},
        },
        "/health": {"get": {"operationId": "health", "responses": {}}},  # skipped
    },
}


def test_classifies_create_and_access_and_skips_the_rest():
    ops = _operations_from_resolved(_RESOLVED)
    by_id = {o.operation_id: o for o in ops}
    assert set(by_id) == {"createInvoice", "getInvoice", "deleteInvoice"}
    assert by_id["createInvoice"].kind == "create"
    assert by_id["getInvoice"].kind == "access"
    assert by_id["deleteInvoice"].kind == "access"
    assert all(o.resource_type == "invoices" for o in ops)


def test_object_id_param_tagged():
    ops = _operations_from_resolved(_RESOLVED)
    get = next(o for o in ops if o.operation_id == "getInvoice")
    assert [p.name for p in get.object_id_params] == ["invoice_id"]
    assert get.object_id_params[0].is_object_id is True


def test_create_op_carries_request_schema_access_op_does_not():
    ops = _operations_from_resolved(_RESOLVED)
    create = next(o for o in ops if o.kind == "create")
    access = next(o for o in ops if o.kind == "access")
    assert "amount" in create.request_schema["properties"]
    assert access.request_schema is None


def test_resource_type_uses_last_non_param_segment():
    spec = {
        "paths": {
            "/orgs/{oid}/invoices/{id}": {
                "parameters": [
                    {"name": "oid", "in": "path"},
                    {"name": "id", "in": "path"},
                ],
                "get": {"responses": {}},
            }
        }
    }
    op = _operations_from_resolved(spec)[0]
    assert op.resource_type == "invoices"
    assert {p.name for p in op.object_id_params} == {"oid", "id"}


def test_operation_cap_enforced(monkeypatch):
    monkeypatch.setattr(openapi, "MAX_OPERATIONS", 2)
    spec = {
        "paths": {
            "/a": {"get": {"responses": {}}},
            "/b": {"get": {"responses": {}}},
            "/c": {"get": {"responses": {}}},
        }
    }
    with pytest.raises(SpecError):
        _operations_from_resolved(spec)


def test_filters():
    ops = _operations_from_resolved(_RESOLVED)
    assert [o.operation_id for o in create_operations(ops)] == ["createInvoice"]
    assert {o.operation_id for o in access_operations(ops)} == {"getInvoice", "deleteInvoice"}


# --- synthesize_body -------------------------------------------------------
def test_synthesize_object_body():
    schema = {"type": "object", "properties": {"amount": {"type": "number"}, "memo": {"type": "string"}}}
    assert synthesize_body(schema) == {"amount": 1.0, "memo": "example"}


def test_synthesize_uses_example_enum_and_format():
    assert synthesize_body({"type": "string", "example": "fixed"}) == "fixed"
    assert synthesize_body({"type": "string", "enum": ["a", "b"]}) == "a"
    assert synthesize_body({"type": "string", "format": "email"}) == "user@example.com"


def test_synthesize_array_and_none():
    assert synthesize_body({"type": "array", "items": {"type": "integer"}}) == [1]
    assert synthesize_body(None) == {}


# --- prance path ($ref resolution) -----------------------------------------
_WITH_REF = """
openapi: "3.0.0"
info: {title: t, version: "1"}
paths:
  /invoices:
    post:
      operationId: createInvoice
      requestBody:
        content:
          application/json:
            schema: {$ref: "#/components/schemas/InvoiceIn"}
      responses: {"201": {description: ok}}
  /invoices/{invoice_id}:
    get:
      operationId: getInvoice
      parameters:
        - {name: invoice_id, in: path, required: true, schema: {type: integer}}
      responses: {"200": {description: ok}}
components:
  schemas:
    InvoiceIn:
      type: object
      properties: {amount: {type: number}}
      required: [amount]
"""


def test_load_from_string_resolves_refs():
    ops = load_operations_from_string(_WITH_REF)
    create = next(o for o in ops if o.kind == "create")
    # The $ref must have been resolved into the actual object schema.
    assert create.request_schema["properties"]["amount"]["type"] == "number"


def test_invalid_spec_raises_spec_error():
    with pytest.raises(SpecError):
        load_operations_from_string('{"not": "a valid openapi document"}')
