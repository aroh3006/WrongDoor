"""Terminal reporter (Rich) — the human-readable default for `wrongdoor run`."""

from collections import Counter

from rich.console import Console
from rich.panel import Panel

from ..engine.verdict import Judgment, Verdict
from .finding import Finding


def render(console: Console, judgments: list[Judgment], findings: list[Finding]) -> None:
    counts = Counter(j.verdict for j in judgments)
    console.print(
        f"\nchecks: {len(judgments)}   "
        f"[red]violations={counts[Verdict.VIOLATION]}[/red]   "
        f"pass={counts[Verdict.PASS]}   broken={counts[Verdict.BROKEN]}   "
        f"inconclusive={counts[Verdict.INCONCLUSIVE]}\n"
    )
    for f in findings:
        lines = [
            f"severity:  {f.severity.name}",
            f"actor:     {f.actor}" + (f" (tenant {f.actor_tenant})" if f.actor_tenant else ""),
            f"victim:    {f.owner}"
            + (f" (tenant {f.owner_tenant})" if f.owner_tenant else "")
            + f" owns {f.resource_type}/{f.object_id}",
            f"operation: {f.method} {f.operation_id}",
            "",
            "reproducible request pair:",
            f"  canonical: {f.canonical_request()}",
            f"  attack:    {f.attack_request()}",
            "",
            f"body match: {', '.join(f.matched_fields)}",
            "",
            f"fix: {f.remediation}",
        ]
        console.print(
            Panel(
                "\n".join(lines),
                title=f"{f.severity.name} · {f.finding_type} · {f.operation_id}",
                border_style="red",
            )
        )
