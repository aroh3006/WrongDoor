"""Unit tests for the HAR importer (§5.4, §14 Phase 5).

Drives the importer with inline HAR docs so each inference is checked in
isolation, plus one parse of the real committed fixture.
"""

import json
from pathlib import Path

import pytest

from wrongdoor.spec.har import load_har, load_har_from_string
from wrongdoor.spec.openapi import SpecError

_FIXTURE = Path(__file__).resolve().parents[2] / "examples" / "har" / "demo.har"


def _entry(method, path, *, status=200, body=None, mime="application/json"):
    request = {"method": method, "url": "http://t" + path, "headers": []}
    if body is not None:
        request["postData"] = {"mimeType": mime, "text": json.dumps(body) if mime.endswith("json") else body}
    return {"request": request, "response": {"status": status}}


def _har(*entries) -> str:
    return json.dumps({"log": {"entries": list(entries)}})


def test_literal_ids_collapse_to_one_access_template():
    ops = load_har_from_string(
        _har(
            _entry("GET", "/invoices/1000"),
            _entry("GET", "/invoices/1001"),  # same op as 1000, different literal id
            _entry("GET", "/invoices/2999"),
        )
    )
    assert len(ops) == 1
    op = ops[0]
    assert op.kind == "access"
    assert op.path_template == "/invoices/{invoice_id}"
    assert op.resource_type == "invoices"
    assert [p.name for p in op.object_id_params] == ["invoice_id"]


def test_operation_id_reads_like_a_name_not_a_doubled_method():
    ops = load_har_from_string(_har(_entry("GET", "/invoices/1000")))
    op = ops[0]
    # Reports render "<METHOD> <operation_id>", so the id must not start with the
    # method (else you get "GET GET /invoices/{id}").
    assert op.operation_id == "get_invoices_invoice_id"
    assert not op.operation_id.upper().startswith(op.method + " ")


def test_post_is_a_create_and_captures_the_body_as_example():
    ops = load_har_from_string(_har(_entry("POST", "/invoices", status=201, body={"amount": 5, "memo": "x"})))
    assert len(ops) == 1
    op = ops[0]
    assert op.kind == "create" and op.resource_type == "invoices"
    assert op.object_id_params == ()  # a create has no path id
    # The recorded body is wrapped as an example, which synthesize_body replays.
    assert op.request_schema == {"example": {"amount": 5, "memo": "x"}}


def test_uuid_segment_is_treated_as_an_id():
    ops = load_har_from_string(
        _har(_entry("GET", "/users/550e8400-e29b-41d4-a716-446655440000/profile"))
    )
    # /users/{user_id}/profile -> resource is the last static segment, "profile".
    assert ops[0].path_template == "/users/{user_id}/profile"
    assert [p.name for p in ops[0].object_id_params] == ["user_id"]


def test_collection_get_and_post_with_id_are_not_testable_ops():
    ops = load_har_from_string(
        _har(
            _entry("GET", "/invoices"),         # collection GET (no id) -> "other"
            _entry("POST", "/invoices/1000"),   # POST with an id -> "other"
        )
    )
    assert ops == []


def test_non_2xx_and_static_noise_are_filtered():
    ops = load_har_from_string(
        _har(
            _entry("GET", "/invoices/1000", status=404),  # a probe, not a real resource
            _entry("GET", "/app.js"),                      # static asset
            _entry("GET", "/favicon.ico"),
        )
    )
    assert ops == []


def test_duplicate_op_dedupes_but_keeps_the_one_with_a_body():
    ops = load_har_from_string(
        _har(
            _entry("POST", "/invoices", status=201),                        # no body
            _entry("POST", "/invoices", status=201, body={"amount": 9}),    # has body
        )
    )
    assert len(ops) == 1
    assert ops[0].request_schema == {"example": {"amount": 9}}


def test_malformed_har_raises_spec_error():
    with pytest.raises(SpecError):
        load_har_from_string("not json at all")
    with pytest.raises(SpecError):
        load_har_from_string(json.dumps({"log": {}}))  # no entries array


def test_fixture_parses_to_the_expected_catalog():
    ops = load_har(_FIXTURE)
    by_key = {(o.method, o.path_template) for o in ops}
    assert by_key == {
        ("POST", "/invoices"),
        ("GET", "/invoices/{invoice_id}"),
        ("POST", "/documents"),
        ("GET", "/documents/{document_id}"),
    }
