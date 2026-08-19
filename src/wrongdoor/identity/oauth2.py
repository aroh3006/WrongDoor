"""OAuth2 auth (config type ``oauth2``) — the one plugin that participates in
every request's lifecycle instead of setting a header once.

OWN THIS FILE. A bearer token can expire mid-run, so correct behavior is to see
the 401 and re-issue the request with a fresh token. httpx's own extension point
for that is ``httpx.Auth.async_auth_flow`` — a generator that yields a request,
receives the response, and may yield again to retry. So this plugin *is* an
``httpx.Auth``:

  * ``authenticate`` fetches an initial token up front (failing fast on bad
    credentials, like ``login``) and installs itself as ``client.auth``;
  * ``async_auth_flow`` attaches the token to every request and, on a 401,
    refreshes once and retries once.

Refresh is serialized behind a lock with a staleness check: the executor is
concurrent, so a just-expired token can 401 many in-flight requests at once.
Without the lock every one of them would refresh independently and hammer the
token endpoint (a "stampede"). With it, the first request to notice the stale
token refreshes; the rest find the token already changed and reuse it.

Grants: ``client_credentials`` and resource-owner ``password`` (the two
non-interactive grants). Refresh uses ``grant_type=refresh_token`` when the
server issued a refresh token, otherwise it re-runs the original grant — which
is the right fallback for client-credentials, which typically issues none.
"""

import asyncio

import httpx

from ..config.schema import OAuth2AuthConfig
from .base import AuthError, resolve_secret


class OAuth2Auth(httpx.Auth):
    def __init__(
        self,
        token_url: str,
        grant: str,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        username: str | None = None,
        password: str | None = None,
        scope: str | None = None,
        token_field: str = "access_token",
    ) -> None:
        self._token_url = token_url
        self._grant = grant
        self._client_id = client_id
        self._client_secret = client_secret  # resolved secret; never logged
        self._username = username
        self._password = password  # resolved secret; never logged
        self._scope = scope
        self._token_field = token_field
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._lock = asyncio.Lock()  # serializes refresh across concurrent 401s

    @classmethod
    def from_config(cls, cfg: OAuth2AuthConfig) -> "OAuth2Auth":
        return cls(
            token_url=cfg.token_url,
            grant=cfg.grant,
            client_id=cfg.client_id,
            client_secret=resolve_secret(cfg.client_secret_env) if cfg.client_secret_env else None,
            username=cfg.username,
            password=resolve_secret(cfg.password_env) if cfg.password_env else None,
            scope=cfg.scope,
            token_field=cfg.token_field,
        )

    @property
    def auth_urls(self) -> tuple[str, ...]:
        """The token endpoint we POST credentials to (initial fetch AND refresh).
        The manager gates it against the allowlist before we send."""
        return (self._token_url,)

    # --- AuthPlugin ---------------------------------------------------------
    async def authenticate(self, client: httpx.AsyncClient) -> None:
        # Eager initial fetch BEFORE installing ourselves as client.auth, so this
        # request carries no auth and can't recurse through the flow. Fails fast
        # on bad credentials (AuthError -> exit 4), like login.
        resp = await client.post(self._token_url, data=self._grant_params())
        self._apply_token_response(resp, context="oauth2 token request")
        client.auth = self  # every later request now runs through async_auth_flow

    # --- httpx.Auth ---------------------------------------------------------
    async def async_auth_flow(self, request):
        token = self._access_token
        request.headers["Authorization"] = f"Bearer {token}"
        response = yield request
        if response.status_code != 401:
            return  # happy path: leave the body unread for the caller to consume

        # Token rejected. Read the 401 body to release the connection before we
        # re-issue anything on it.
        await response.aread()
        async with self._lock:
            # Only the first arrival (token still the one that just failed) does
            # the refresh; concurrent 401s fall through and reuse the new token.
            if self._access_token == token:
                try:
                    refresh_resp = yield self._build_refresh_request(request)
                    await refresh_resp.aread()
                    self._apply_token_response(refresh_resp, context="oauth2 token refresh")
                except (httpx.HTTPError, AuthError):
                    pass  # refresh failed: retry re-presents and 401s -> recorded normally
        request.headers["Authorization"] = f"Bearer {self._access_token}"
        yield request  # single retry with whatever token we now hold

    # --- token requests -----------------------------------------------------
    def _grant_params(self) -> dict[str, str]:
        if self._grant == "client_credentials":
            params = {"grant_type": "client_credentials"}
        else:  # password
            params = {"grant_type": "password", "username": self._username or "", "password": self._password or ""}
        return self._with_client_and_scope(params)

    def _refresh_params(self) -> dict[str, str]:
        # Prefer a real refresh token; otherwise re-run the initial grant (the
        # correct fallback for client-credentials, which issues no refresh token).
        if self._refresh_token:
            return self._with_client_and_scope(
                {"grant_type": "refresh_token", "refresh_token": self._refresh_token}
            )
        return self._grant_params()

    def _with_client_and_scope(self, params: dict[str, str]) -> dict[str, str]:
        if self._client_id:
            params["client_id"] = self._client_id
        if self._client_secret:
            params["client_secret"] = self._client_secret
        if self._scope:
            params["scope"] = self._scope
        return params

    def _build_refresh_request(self, request: httpx.Request) -> httpx.Request:
        # Resolve token_url against the failed request's absolute URL, so a
        # relative token_url lands on the same (already-allowlisted) host.
        url = request.url.join(self._token_url)
        return httpx.Request("POST", url, data=self._refresh_params())

    def _apply_token_response(self, resp: httpx.Response, *, context: str) -> None:
        # Status only, never the body or the credentials, in any error.
        if resp.status_code // 100 != 2:
            raise AuthError(f"{context} failed: HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError:
            data = None
        token = data.get(self._token_field) if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise AuthError(f"{context}: no {self._token_field!r} in the token response")
        self._access_token = token
        refresh = data.get("refresh_token") if isinstance(data, dict) else None
        if isinstance(refresh, str) and refresh:
            self._refresh_token = refresh  # rotate if the server sent a new one
