"""Terminal reporter (Rich): the human-readable default for `wrongdoor run`."""

from collections import Counter

from rich.console import Console
from rich.panel import Panel

from ..engine.verdict import Judgment, Verdict
from ..risk import Severity
from .finding import Finding


def render(console: Console, judgments: list[Judgment], findings: list[Finding]) -> None:
    counts = Counter(j.verdict for j in judgments)
    console.print(
        f"\nchecks: {len(judgments)}   "
        f"[red]violations={counts[Verdict.VIOLATION]}[/red]   "
        f"pass={counts[Verdict.PASS]}   broken={counts[Verdict.BROKEN]}   "
        f"inconclusive={counts[Verdict.INCONCLUSIVE]}\n"
    )
    if findings:
        by_sev = Counter(f.severity for f in findings)
        by_type = Counter(f.finding_type for f in findings)
        sev_line = "   ".join(f"{s.name}={by_sev[s]}" for s in sorted(Severity, reverse=True) if by_sev[s])
        type_line = "   ".join(f"{t}={n}" for t, n in sorted(by_type.items()))
        console.print(f"by severity: {sev_line}")
        console.print(f"by type:     {type_line}\n")
    for f in findings:
        lines = [
            f"severity:  {f.severity.name}",
            f"actor:     {f.actor}" + (f" (tenant {f.actor_tenant})" if f.actor_tenant else ""),
            f"victim:    {_victim_line(f)}",
            f"operation: {f.method} {f.operation_id}",
            "",
            "reproducible request pair:",
            f"  canonical: {f.canonical_request()}",
            f"  attack:    {f.attack_request()}",
        ]
        # A function-level (BFLA) finding matches no object, so there are no
        # field names to show. Printing an empty "body match:" line just looks
        # like something failed to render.
        if f.matched_fields:
            lines += ["", f"body match: {', '.join(f.matched_fields)}"]
        lines += ["", f"fix: {f.remediation}"]
        console.print(
            Panel(
                "\n".join(lines),
                # ASCII separators only: the default Windows console codepage
                # mangles characters like the middle dot.
                title=f"{f.severity.name} | {f.finding_type} | {f.operation_id}",
                border_style="red",
            )
        )


def _victim_line(f: Finding) -> str:
    """Who was harmed. A BFLA finding is function-level, so it has no owning
    identity and no object to name."""
    if f.owner is None:
        return f"n/a (function-level: {f.resource_type})"
    tenant = f" (tenant {f.owner_tenant})" if f.owner_tenant else ""
    return f"{f.owner}{tenant} owns {f.resource_type}/{f.object_id}"
