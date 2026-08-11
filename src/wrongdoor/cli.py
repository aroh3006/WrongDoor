"""WrongDoor CLI (§5.1) — Phase 1 slice.

Wires ConfigLoader -> SafetyGuard -> IdentityManager and prints each identity's
response to a probe endpoint. No analysis here; that arrives in later phases.

Exit codes (so CI can distinguish failure modes later):
  0 ok · 2 config error · 3 safety refusal · 4 authentication failure
"""

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .banner import print_banner
from .config.loader import ConfigError, load_config
from .config.schema import Config
from .engine.executor import execute
from .engine.planner import plan_matrix
from .engine.seeder import SeedOutcome
from .engine.seeder import seed as seed_objects
from .engine.verdict import Judgment, judge_all
from .identity.base import AuthError
from .identity.manager import aclose_all, authenticate_identities
from .report import html, json_report, junit, sarif, terminal
from .report.finding import build_findings, max_severity
from .risk import parse_severity
from .safety.guard import SafetyError, SafetyGuard
from .spec.openapi import (
    Operation,
    SpecError,
    access_operations,
    create_operations,
    load_operations,
)

app = typer.Typer(add_completion=False, help="WrongDoor — dynamic authorization tester.")
_out = Console()
_err = Console(stderr=True)


@app.callback()
def _startup() -> None:
    """Runs before any subcommand — print the banner."""
    print_banner(__version__)


@app.command("auth-check")
def auth_check(
    config: Path = typer.Option(..., "--config", "-c", help="Path to config.yaml"),
    confirm_own_target: bool = typer.Option(
        False,
        "--confirm-own-target",
        help="Confirm you own / are authorized to test this target",
    ),
    probe: str = typer.Option("/me", "--probe", help="Path to GET as each identity"),
) -> None:
    """Authenticate every identity and print its response to ``probe``."""
    try:
        cfg = load_config(config)
    except ConfigError as e:
        _err.print(f"[red]config error:[/red] {e}")
        raise typer.Exit(code=2)

    guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=confirm_own_target)

    try:
        asyncio.run(_run(cfg, guard, probe))
    except SafetyError as e:
        _err.print(f"[red]refused:[/red] {e}")
        raise typer.Exit(code=3)
    except AuthError as e:
        _err.print(f"[red]auth failed:[/red] {e}")
        raise typer.Exit(code=4)


async def _run(cfg: Config, guard: SafetyGuard, probe: str) -> None:
    registry = await authenticate_identities(cfg, guard)
    try:
        table = Table(title=f"GET {probe} as each identity")
        table.add_column("identity")
        table.add_column("status", justify="right")
        table.add_column("response")
        for identity_id, authed in registry.items():
            resp = await authed.client.get(probe)
            table.add_row(identity_id, str(resp.status_code), _short(resp.text))
        _out.print(table)
    finally:
        await aclose_all(registry)  # always close the sessions


def _short(text: str, limit: int = 200) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "…"


@app.command("seed")
def seed_cmd(
    config: Path = typer.Option(..., "--config", "-c", help="Path to config.yaml"),
    spec: Path = typer.Option(..., "--spec", "-s", help="Path to the OpenAPI spec"),
    confirm_own_target: bool = typer.Option(
        False,
        "--confirm-own-target",
        help="Confirm you own / are authorized to test this target",
    ),
) -> None:
    """Authenticate, seed an object as each identity, and print the ownership ledger."""
    try:
        cfg = load_config(config)
    except ConfigError as e:
        _err.print(f"[red]config error:[/red] {e}")
        raise typer.Exit(code=2)
    try:
        operations = load_operations(spec)
    except SpecError as e:
        _err.print(f"[red]spec error:[/red] {e}")
        raise typer.Exit(code=5)

    guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=confirm_own_target)
    try:
        asyncio.run(_run_seed(cfg, operations, guard))
    except SafetyError as e:
        _err.print(f"[red]refused:[/red] {e}")
        raise typer.Exit(code=3)
    except AuthError as e:
        _err.print(f"[red]auth failed:[/red] {e}")
        raise typer.Exit(code=4)


async def _run_seed(cfg: Config, operations: list[Operation], guard: SafetyGuard) -> None:
    registry = await authenticate_identities(cfg, guard)  # outside try: no client to close if this raises
    try:
        outcome = await seed_objects(cfg, registry, operations, guard)
    finally:
        await aclose_all(registry)
    _print_ledger(outcome)


def _print_ledger(outcome: SeedOutcome) -> None:
    ledger = outcome.ledger
    table = Table(title=f"Ownership ledger — {len(ledger)} object(s)")
    table.add_column("resource")
    table.add_column("object_id", justify="right")
    table.add_column("owner")
    table.add_column("canonical fields (values redacted)")
    for row in ledger.redacted_summary():  # redacted by default — no values printed (§13)
        fields = row["canonical_fields"]
        fields_str = ", ".join(fields) if isinstance(fields, list) else str(fields)
        table.add_row(row["resource_type"], row["object_id"], row["owner"], fields_str)
    _out.print(table)
    for note in outcome.failures:
        _err.print(f"[yellow]note:[/yellow] {note}")


@app.command("run")
def run_cmd(
    config: Path = typer.Option(..., "--config", "-c", help="Path to config.yaml"),
    spec: Path = typer.Option(..., "--spec", "-s", help="Path to the OpenAPI spec"),
    confirm_own_target: bool = typer.Option(
        False, "--confirm-own-target", help="Confirm you own / are authorized to test this target"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview scope offline; send no requests"),
    include_mutations: bool = typer.Option(
        False, "--include-mutations", help="Also test PUT/PATCH/DELETE (writes to the target!)"
    ),
    report_format: str = typer.Option("terminal", "--format", "-f", help="terminal | json | sarif | junit | html"),
    output: Path = typer.Option(None, "--output", "-o", help="Write the report to a file (machine formats)"),
    fail_on: str = typer.Option("low", "--fail-on", help="Exit non-zero if any finding is >= this severity"),
    include_bodies: bool = typer.Option(
        False, "--include-bodies", help="Include response bodies (sensitive) in the report"
    ),
) -> None:
    """Full pipeline: authenticate, seed, sweep cross-identity access, and report findings."""
    try:
        cfg = load_config(config)
    except ConfigError as e:
        _err.print(f"[red]config error:[/red] {e}")
        raise typer.Exit(code=2)
    try:
        operations = load_operations(spec)
    except SpecError as e:
        _err.print(f"[red]spec error:[/red] {e}")
        raise typer.Exit(code=5)

    if dry_run:
        _print_dry_run(cfg, operations)  # offline: no auth, no seed, no requests
        return

    try:
        threshold = parse_severity(fail_on)
    except ValueError as e:
        _err.print(f"[red]bad --fail-on:[/red] {e}")
        raise typer.Exit(code=2)

    guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=confirm_own_target)
    try:
        judgments = asyncio.run(
            _run_pipeline(cfg, operations, guard, include_mutations=include_mutations)
        )
    except SafetyError as e:
        _err.print(f"[red]refused:[/red] {e}")
        raise typer.Exit(code=3)
    except AuthError as e:
        _err.print(f"[red]auth failed:[/red] {e}")
        raise typer.Exit(code=4)

    finding_list = build_findings(judgments, cfg)
    _emit_report(report_format, finding_list, judgments, output, include_bodies, spec)

    top = max_severity(finding_list)
    if top is not None and top >= threshold:
        raise typer.Exit(code=1)  # a finding at/above --fail-on -> fail CI


async def _run_pipeline(
    cfg: Config,
    operations: list[Operation],
    guard: SafetyGuard,
    *,
    transport=None,
    include_mutations: bool = False,
) -> list[Judgment]:
    # transport is injectable so tests can drive the whole pipeline against an
    # in-process ASGI app; production passes None (real network).
    registry = await authenticate_identities(cfg, guard, transport=transport)
    try:
        outcome = await seed_objects(cfg, registry, operations, guard)
        planned = plan_matrix(
            outcome.ledger,
            operations,
            list(registry.keys()),
            policy=cfg.policy.rule,
            include_mutations=include_mutations,
        )
        results = await execute(planned, registry)
        judgments = judge_all(results, outcome.ledger)
    finally:
        await aclose_all(registry)
    return judgments


def _print_dry_run(cfg: Config, operations: list[Operation]) -> None:
    _out.print(f"[bold]dry run[/bold] — target {cfg.target.base_url} (no requests will be sent)")
    _out.print("identities: " + ", ".join(i.id for i in cfg.identities))
    creates = ", ".join(f"{o.method} {o.path_template}" for o in create_operations(operations)) or "(none)"
    accesses = ", ".join(f"{o.method} {o.path_template}" for o in access_operations(operations)) or "(none)"
    _out.print(f"would seed (create-ops): {creates}")
    _out.print(f"would sweep (access-ops): {accesses}")


def _emit_report(
    report_format: str,
    finding_list: list,
    judgments: list[Judgment],
    output: Path | None,
    include_bodies: bool,
    spec_path: Path,
) -> None:
    if report_format == "terminal":
        terminal.render(_out, judgments, finding_list)
        return
    if report_format == "json":
        text = json_report.render(finding_list, include_bodies=include_bodies)
    elif report_format == "sarif":
        text = sarif.render(finding_list, spec_uri=str(spec_path))
    elif report_format == "junit":
        text = junit.render(finding_list, total_checks=len(judgments))
    elif report_format == "html":
        text = html.render(finding_list, include_bodies=include_bodies)
    else:
        _err.print(f"[red]unknown --format:[/red] {report_format} (use terminal|json|sarif|junit|html)")
        raise typer.Exit(code=2)

    if output is not None:
        Path(output).write_text(text, encoding="utf-8")
        _out.print(f"wrote {report_format} report to {output}")
    else:
        print(text)  # raw stdout so machine output stays valid
