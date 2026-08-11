"""SARIF 2.1.0 reporter — GitHub/IDE-native security format (run -> results).

API findings have no source line, so results anchor to the OpenAPI spec file
(``spec_uri``) — enough for GitHub to surface them; precise inline regions are a
later refinement.
"""

import json

from .finding import Finding
from ..risk import Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def render(findings: list[Finding], *, spec_uri: str = "openapi.yaml") -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rules.setdefault(
            f.fingerprint,
            {
                "id": f.fingerprint,
                "name": f.finding_type,
                "shortDescription": {"text": f"{f.finding_type} on {f.operation_id}"},
            },
        )
        results.append(
            {
                "ruleId": f.fingerprint,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.explanation},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": spec_uri}}}
                ],
                "properties": {
                    "severity": f.severity.name,
                    "actor": f.actor,
                    "owner": f.owner,
                    "object": f"{f.resource_type}/{f.object_id}",
                    "attack_request": f.attack_request(),
                },
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "WrongDoor",
                        "informationUri": "https://github.com/aroh3006/wrongdoor",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
