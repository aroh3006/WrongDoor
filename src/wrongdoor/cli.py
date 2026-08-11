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
from .engine.seeder import SeedOutcome
from .engine.seeder import seed as seed_objects
from .identity.base import AuthError
from .identity.manager import aclose_all, authenticate_identities
from .safety.guard import SafetyError, SafetyGuard
from .spec.openapi import Operation, SpecError, load_operations

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
