"""API-key auth (config type ``api_key``): attach a pre-issued key as a header.

Same no-round-trip shape as ``bearer``: the key is pre-issued, so we just set
the header on the client and every later request carries it. The header name is
configurable (APIs disagree), and the plugin reports that header as sensitive so
diagnostics redact it, whatever it was named.
"""

import httpx

from ..config.schema import ApiKeyAuthConfig
from .base import resolve_secret


class ApiKeyAuth:
    def __init__(self, key: str, header: str) -> None:
        self._key = key  # resolved secret; never logged
        self._header = header

    @classmethod
    def from_config(cls, cfg: ApiKeyAuthConfig) -> "ApiKeyAuth":
        return cls(key=resolve_secret(cfg.key_env), header=cfg.header)

    @property
    def sensitive_headers(self) -> frozenset[str]:
        """The (lowercased) header this plugin fills with a secret, so ``redacted``
        masks the *configured* header, not just the hardcoded defaults."""
        return frozenset({self._header.lower()})

    async def authenticate(self, client: httpx.AsyncClient) -> None:
        # No login round-trip: set the key header on the client once.
        client.headers[self._header] = self._key
