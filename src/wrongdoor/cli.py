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
from .identity.base import AuthError
from .identity.manager import aclose_all, authenticate_identities
from .safety.guard import SafetyError, SafetyGuard

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
