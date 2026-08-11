"""Unit tests for the HTML reporter (§11), including the XSS autoescape guard (§13)."""

from wrongdoor.config.schema import Config
from wrongdoor.engine.executor import ObservedResponse
from wrongdoor.engine.ledger import ObjectRef
from wrongdoor.engine.planner import Expectation, PlannedRequest
from wrongdoor.engine.verdict import Judgment, Verdict
from wrongdoor.report import html
from wrongdoor.report.finding import build_findings


def _config():
    return Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [
                {"id": "alice", "attributes": {"tenant": "A"}, "auth": {"type": "bearer", "token_env": "A"}},
                {"id": "bob", "attributes": {"tenant": "B"}, "auth": {"type": "bearer", "token_env": "B"}},
            ],
            "resources": {"invoices": {"sensitivity": "high"}},
        }
    )


def _finding(operation_id="getInvoice", body=None):
    req = PlannedRequest(
        acting_identity="bob",
        method="GET",
        path="/invoices/1000",
        operation_id=operation_id,
        target=ObjectRef("invoices", "1000"),
        expected=Expectation.DENY,
        is_mutation=False,
    )
    j = Judgment(
        verdict=Verdict.VIOLATION,
        reason="x",
        request=req,
        observed=ObservedResponse(status=200, body=body or {"id": 1000, "owner": "alice"}),
        owner="alice",
        matched_fields=("id", "owner"),
    )
    return build_findings([j], _config())


def test_html_renders_a_finding():
    out = html.render(_finding())
    assert "WrongDoor Report" in out
    assert "CRITICAL" in out
    assert "getInvoice" in out
    assert "Remediation" in out
    assert "/invoices/1000 (as alice) -&gt; 200" in out  # request pair (escaped '>')


def test_html_autoescapes_untrusted_operation_id():
    out = html.render(_finding(operation_id="<script>alert(1)</script>"))
    assert "<script>alert(1)</script>" not in out  # never emitted raw
    assert "&lt;script&gt;" in out  # escaped instead


def test_html_autoescapes_body_values_with_include_bodies():
    out = html.render(
        _finding(body={"id": 1000, "owner": "alice", "x": "<img src=x onerror=alert(1)>"}),
        include_bodies=True,
    )
    assert "<img src=x onerror=alert(1)>" not in out
    assert "&lt;img" in out
