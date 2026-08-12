"""Identity plumbing shared by the auth plugins and the manager (§5.5).

Secrets live in this package and only here: ``resolve_secret`` is the single
door credentials come through (always from the environment), and ``redacted``
keeps them out of any diagnostic output.
"""

import os
from dataclasses import dataclass, field
from typing import Iterable, Protocol

import httpx


class AuthError(Exception):
    """Raised when an identity cannot be authenticated (bad creds, missing secret…)."""


@dataclass
class AuthedClient:
    """A live authenticated session for one identity.

    The credentials live *on* the httpx client (as a header, or in its cookie
    jar), so downstream code just uses ``client`` — it never re-handles secrets.
    """

    identity_id: str
    client: httpx.AsyncClient
    attributes: dict[str, str] = field(default_factory=dict)
    # Header names (lowercased) carrying THIS identity's secret beyond the
    # always-sensitive defaults — e.g. a configured api-key header. Travels with
    # the client so any diagnostic can redact exactly what this identity sends.
    sensitive_headers: frozenset[str] = frozenset()


class AuthPlugin(Protocol):
    """One auth method. Given a client, make it authenticated for its identity.

    A plugin that puts a secret in a NON-default header (i.e. not authorization/
    cookie) should also expose ``sensitive_headers`` — a frozenset of the
    lowercased header names it fills — so ``redacted`` masks them. The manager
    reads it defensively, so plugins that only use default headers can omit it.
    """

    async def authenticate(self, client: httpx.AsyncClient) -> None: ...


def resolve_secret(env_name: str) -> str:
    """Read a secret from the environment by variable name (§13).

    The name is referenced in the config (e.g. ``password_env: ALICE_PW``); the
    value never appears in the config file. Errors name the *variable*, never the
    value.
    """
    value = os.environ.get(env_name)
    if not value:
        raise AuthError(f"missing or empty secret env var: {env_name}")
    return value


# Header names whose values must never be printed/logged. This is the baseline;
# a plugin using a custom secret header (e.g. api-key) passes it via
# ``extra_sensitive`` so the CONFIGURED header is masked too, not just these.
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization"}


def redacted(headers, extra_sensitive: Iterable[str] = ()) -> dict[str, str]:
    """Copy of ``headers`` with sensitive values masked, for safe diagnostics.

    ``extra_sensitive`` adds identity-specific secret headers (e.g. the api-key
    header a given identity was configured with) on top of the always-sensitive
    defaults. Case-insensitive."""
    sensitive = _SENSITIVE_HEADERS | {h.lower() for h in extra_sensitive}
    return {
        k: ("<redacted>" if k.lower() in sensitive else v)
        for k, v in dict(headers).items()
    }
