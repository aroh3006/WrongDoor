"""Unit tests for the JSON / SARIF / JUnit reporters (§11, §13)."""

import json
import xml.etree.ElementTree as ET

from wrongdoor.config.schema import Config
from wrongdoor.engine.executor import ObservedResponse
from wrongdoor.engine.ledger import ObjectRef
from wrongdoor.engine.planner import Expectation, PlannedRequest
from wrongdoor.engine.verdict import Judgment, Verdict
from wrongdoor.report import json_report, junit, sarif
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


def _findings():
    req = PlannedRequest(
        acting_identity="bob",
        method="GET",
        path="/invoices/1000",
        operation_id="getInvoice",
        target=ObjectRef("invoices", "1000"),
        expected=Expectation.DENY,
        is_mutation=False,
    )
    j = Judgment(
        verdict=Verdict.VIOLATION,
        reason="confirmed",
        request=req,
        observed=ObservedResponse(status=200, body={"id": 1000, "owner": "alice", "secret": "hush"}),
        owner="alice",
        matched_fields=("id", "owner"),
    )
    return build_findings([j], _config())


def test_json_report_shape_and_redaction():
    doc = json.loads(json_report.render(_findings()))
    assert doc["tool"] == "wrongdoor"
    assert doc["summary"]["findings"] == 1
    assert doc["summary"]["by_severity"]["CRITICAL"] == 1
    assert doc["summary"]["by_type"] == {"BOLA": 1}
    assert doc["findings"][0]["type"] == "BOLA"
    assert "hush" not in json_report.render(_findings())  # value redacted by default


def test_json_report_include_bodies():
    doc = json.loads(json_report.render(_findings(), include_bodies=True))
    assert doc["findings"][0]["evidence"]["observed_body"]["secret"] == "hush"


def test_sarif_is_valid_and_maps_severity_to_error():
    doc = json.loads(sarif.render(_findings(), spec_uri="examples/vulnerable-api/openapi.yaml"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "WrongDoor"
    result = run["results"][0]
    assert result["ruleId"] == "WD-BOLA-getInvoice-invoices-cross-tenant"
    assert result["level"] == "error"  # CRITICAL -> error
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("openapi.yaml")


def test_junit_counts_and_escapes():
    xml = junit.render(_findings(), total_checks=4)
    root = ET.fromstring(xml)
    assert root.attrib["tests"] == "4" and root.attrib["failures"] == "1"
    case = root.find("testcase")
    assert case.attrib["classname"] == "invoices"
    assert case.find("failure").attrib["type"] == "BOLA"
