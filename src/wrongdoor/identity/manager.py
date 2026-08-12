"""Identity manager (§5.5): authenticate every identity, one session each.

Returns ``{identity_id -> AuthedClient}``. Authentication happens concurrently
(the Phase 0 asyncio pattern); if any identity fails, the clients already opened
are closed before the error propagates, so we never leak sockets.
"""

import asyncio

import httpx

from ..config.schema import (
    ApiKeyAuthConfig,
    BearerAuthConfig,
    Config,
    LoginAuthConfig,
)
from ..safety.guard import SafetyGuard
from .apikey import ApiKeyAuth
from .base import AuthedClient, AuthError, AuthPlugin
from .bearer import BearerAuth
from .cookie import LoginAuth

# Conservative timeout so a hung target can't stall a run indefinitely (§5.9).
_DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


def _build_plugin(auth) -> AuthPlugin:
    if isinstance(auth, BearerAuthConfig):
        return BearerAuth.from_config(auth)
    if isinstance(auth, LoginAuthConfig):
        return LoginAuth.from_config(auth)
    if isinstance(auth, ApiKeyAuthConfig):
        return ApiKeyAuth.from_config(auth)
    raise AuthError(f"unsupported auth type: {getattr(auth, 'type', auth)!r}")


async def authenticate_identities(
    config: Config,
    guard: SafetyGuard,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, AuthedClient]:
    base_url = config.target.base_url
    # Gate BEFORE opening any client or sending any request.
    guard.assert_allowed(base_url)

    async def _one(identity) -> AuthedClient:
        plugin = _build_plugin(identity.auth)  # resolves secrets (may raise AuthError)
        client = httpx.AsyncClient(
            base_url=base_url,
            transport=transport,
            follow_redirects=False,  # a redirect must not bounce us off the allowlist
            timeout=_DEFAULT_TIMEOUT,
        )
        try:
            await plugin.authenticate(client)
        except BaseException:
            await client.aclose()  # don't leak the socket on failure
            raise
        # Record any custom secret header this plugin set (e.g. api-key) so it
        # travels with the client and diagnostics redact the CONFIGURED header.
        sensitive = frozenset(getattr(plugin, "sensitive_headers", frozenset()))
        return AuthedClient(
            identity_id=identity.id,
            client=client,
            attributes=dict(identity.attributes),
            sensitive_headers=sensitive,
        )

    results = await asyncio.gather(
        *(_one(i) for i in config.identities), return_exceptions=True
    )

    registry: dict[str, AuthedClient] = {}
    first_error: BaseException | None = None
    for identity, result in zip(config.identities, results):
        if isinstance(result, BaseException):
            first_error = first_error or result
        else:
            registry[identity.id] = result

    if first_error is not None:
        await aclose_all(registry)  # tidy up the ones that DID succeed
        raise first_error
    return registry


async def aclose_all(registry: dict[str, AuthedClient]) -> None:
    """Close every authenticated client (call in the CLI's finally)."""
    for authed in registry.values():
        await authed.client.aclose()


def make_anonymous_client(identity_id: str, base_url: str, *, transport=None) -> AuthedClient:
    """An unauthenticated client (no auth headers) for the D3 (missing-auth) detector."""
    client = httpx.AsyncClient(
        base_url=base_url, transport=transport, follow_redirects=False, timeout=_DEFAULT_TIMEOUT
    )
    return AuthedClient(identity_id=identity_id, client=client, attributes={})
