"""Bearer-token auth: attach a pre-issued token as an Authorization header."""

import httpx

from ..config.schema import BearerAuthConfig
from .base import resolve_secret


class BearerAuth:
    def __init__(self, token: str) -> None:
        self._token = token  # resolved secret; never logged

    @classmethod
    def from_config(cls, cfg: BearerAuthConfig) -> "BearerAuth":
        return cls(token=resolve_secret(cfg.token_env))

    async def authenticate(self, client: httpx.AsyncClient) -> None:
        # No login round-trip: the token is pre-issued, so we just set the header
        # on the client. Every subsequent request the client makes carries it.
        client.headers["Authorization"] = f"Bearer {self._token}"
