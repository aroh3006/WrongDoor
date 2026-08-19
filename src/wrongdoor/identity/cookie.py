"""Session-login auth (config type ``login``).

Handles both shapes of login endpoint:
  * returns a token in the JSON body -> we set ``Authorization: Bearer <token>``;
  * sets a session cookie -> httpx's cookie jar on the client persists it, and we
    do nothing extra.
"""

import httpx

from ..config.schema import LoginAuthConfig
from .base import AuthError, resolve_secret

# If the config doesn't say which JSON field holds the token, try these names.
_DEFAULT_TOKEN_FIELDS = ("access_token", "token")


class LoginAuth:
    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        token_field: str | None = None,
    ) -> None:
        self._url = url
        self._username = username
        self._password = password  # resolved secret; never logged
        self._token_field = token_field

    @classmethod
    def from_config(cls, cfg: LoginAuthConfig) -> "LoginAuth":
        return cls(
            url=cfg.url,
            username=cfg.username,
            password=resolve_secret(cfg.password_env),
            token_field=cfg.token_field,
        )

    @property
    def auth_urls(self) -> tuple[str, ...]:
        """The URL this plugin POSTs credentials to: the manager gates it against
        the allowlist before we send, same as any other live request."""
        return (self._url,)

    async def authenticate(self, client: httpx.AsyncClient) -> None:
        resp = await client.post(
            self._url, json={"username": self._username, "password": self._password}
        )
        if resp.status_code // 100 != 2:
            # Report the status only, never the response body or the credentials.
            raise AuthError(
                f"login failed for {self._username!r}: HTTP {resp.status_code}"
            )

        token = self._extract_token(resp)
        if token:
            client.headers["Authorization"] = f"Bearer {token}"
            return

        # No token in the body: did the endpoint set a session cookie instead?
        if len(client.cookies) > 0:
            return  # cookie-based session; the jar carries it from here

        raise AuthError(
            f"login for {self._username!r} returned {resp.status_code} but no token "
            "or cookie was found (check the auth type / token_field)"
        )

    def _extract_token(self, resp: httpx.Response) -> str | None:
        try:
            data = resp.json()
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        fields = (self._token_field,) if self._token_field else _DEFAULT_TOKEN_FIELDS
        for f in fields:
            value = data.get(f) if f else None
            if isinstance(value, str) and value:
                return value
        return None
