"""HTML reporter (§11) — one self-contained file via Jinja2.

Autoescaping is forced ON: response/spec-derived strings (operation ids, field
names, bodies) are untrusted, so a value like ``<script>`` must render inert, not
execute (§13). Redaction is still the default — bodies appear only with
``include_bodies``.
"""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .. import __version__
from ..risk import Severity
from .finding import Finding

_TEMPLATES = Path(__file__).resolve().parent / "templates"


def render(findings: list[Finding], *, include_bodies: bool = False) -> str:
    env = Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True)
    template = env.get_template("report.html.j2")
    by_severity = {s.name: sum(1 for f in findings if f.severity is s) for s in sorted(Severity, reverse=True)}
    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f.finding_type] = by_type.get(f.finding_type, 0) + 1
    return template.render(
        findings=findings,
        by_severity=by_severity,
        by_type=by_type,
        total=len(findings),
        version=__version__,
        include_bodies=include_bodies,
    )
