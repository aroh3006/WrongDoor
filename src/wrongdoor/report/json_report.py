"""JSON reporter — the findings as structured data (stdlib json)."""

import json

from .. import __version__
from ..risk import Severity
from .finding import Finding


def render(findings: list[Finding], *, include_bodies: bool = False) -> str:
    by_severity = {s.name: 0 for s in Severity}
    for f in findings:
        by_severity[f.severity.name] += 1
    doc = {
        "tool": "wrongdoor",
        "version": __version__,
        "summary": {"findings": len(findings), "by_severity": by_severity},
        "findings": [f.to_dict(include_bodies=include_bodies) for f in findings],
    }
    return json.dumps(doc, indent=2)
