"""JUnit XML reporter — authorization as a test suite (§11).

Each confirmed leak is a failing testcase; ``tests`` reflects the whole sweep so
CI shows "N checks, M failures". ElementTree escapes all text (safe XML).
"""

import xml.etree.ElementTree as ET

from .finding import Finding


def render(findings: list[Finding], *, total_checks: int = 0) -> str:
    tests = total_checks if total_checks else len(findings)
    suite = ET.Element(
        "testsuite",
        name="wrongdoor",
        tests=str(tests),
        failures=str(len(findings)),
    )
    for f in findings:
        case = ET.SubElement(
            suite,
            "testcase",
            classname=f.resource_type,
            name=f"{f.method} {f.operation_id} [{f.actor} -> {f.owner}]",
        )
        failure = ET.SubElement(
            case, "failure", message=f"{f.finding_type} ({f.severity.name})", type=f.finding_type
        )
        failure.text = f"{f.explanation}\n{f.attack_request()}"
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(suite, encoding="unicode")
