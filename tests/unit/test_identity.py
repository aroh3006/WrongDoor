"""Unit tests for the identity manager and auth plugins (§5.5).

Everything runs through httpx.MockTransport, so there is no real network: the
handler stands in for the target's /login and /me endpoints.
"""

import asyncio
import json
from urllib.parse import parse_qs

import httpx
import pytest

from wrongdoor.config.schema import ApiKeyAuthConfig, BearerAuthConfig, Config
from wrongdoor.identity.apikey import ApiKeyAuth
from wrongdoor.identity.base import AuthError, redacted, resolve_secret
from wrongdoor.identity.bearer import BearerAuth
from wrongdoor.identity.cookie import LoginAuth
from wrongdoor.identity.manager import aclose_all, authenticate_identities
from wrongdoor.identity.oauth2 import OAuth2Auth
from wrongdoor.safety.guard import SafetyError, SafetyGuard


def _client(handler):
    return httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://t"
    )


# --- resolve_secret / redacted --------------------------------------------
def test_resolve_secret_present(monkeypatch):
    monkeypatch.setenv("WD_TEST_SECRET", "s3cr3t")
    assert resolve_secret("WD_TEST_SECRET") == "s3cr3t"


def test_resolve_secret_missing(monkeypatch):
    monkeypatch.delenv("WD_MISSING", raising=False)
    with pytest.raises(AuthError):
        resolve_secret("WD_MISSING")


def test_redacted_masks_sensitive():
    out = redacted(
        {"Authorization": "Bearer x", "Cookie": "a=b", "Accept": "application/json"}
    )
    assert out["Authorization"] == "<redacted>"
    assert out["Cookie"] == "<redacted>"
    assert out["Accept"] == "application/json"


def test_redacted_masks_configured_extra_header_case_insensitively():
    # A custom (non-default) secret header is masked only when threaded through.
    headers = {"X-Company-Token": "sekret", "Accept": "application/json"}
    assert redacted(headers)["X-Company-Token"] == "sekret"  # not a default -> visible
    out = redacted(headers, extra_sensitive={"x-company-token"})
    assert out["X-Company-Token"] == "<redacted>"  # configured header masked
    assert out["Accept"] == "application/json"


# --- api key ---------------------------------------------------------------
def test_api_key_sets_configured_header_and_reports_it_sensitive():
    plugin = ApiKeyAuth(key="k3y", header="X-API-Key")
    assert plugin.sensitive_headers == frozenset({"x-api-key"})  # lowercased

    def handler(req):
        return httpx.Response(200, json={"key": req.headers.get("x-api-key")})

    async def run():
        async with _client(handler) as c:
            await plugin.authenticate(c)
            return (await c.get("/x")).json()["key"]

    assert asyncio.run(run()) == "k3y"


def test_api_key_from_config_resolves_env_and_custom_header(monkeypatch):
    monkeypatch.setenv("WIDGET_KEY", "alice-key")
    plugin = ApiKeyAuth.from_config(
        ApiKeyAuthConfig(type="api_key", key_env="WIDGET_KEY", header="X-Company-Token")
    )
    assert plugin.sensitive_headers == frozenset({"x-company-token"})

    def handler(req):
        return httpx.Response(200, json={"key": req.headers.get("x-company-token")})

    async def run():
        async with _client(handler) as c:
            await plugin.authenticate(c)
            return (await c.get("/x")).json()["key"]

    assert asyncio.run(run()) == "alice-key"


def test_api_key_from_config_missing_env_raises(monkeypatch):
    monkeypatch.delenv("NO_SUCH_KEY", raising=False)
    with pytest.raises(AuthError):
        ApiKeyAuth.from_config(ApiKeyAuthConfig(type="api_key", key_env="NO_SUCH_KEY"))


# --- oauth2 ----------------------------------------------------------------
def test_oauth2_client_credentials_fetches_and_attaches_bearer():
    def handler(req):
        if req.url.path == "/oauth/token":
            form = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
            assert form["grant_type"] == "client_credentials"
            assert form["client_id"] == "svc" and form["client_secret"] == "s3cr"
            return httpx.Response(200, json={"access_token": "AT", "token_type": "bearer"})
        return httpx.Response(200, json={"auth": req.headers.get("authorization")})

    plugin = OAuth2Auth(token_url="/oauth/token", grant="client_credentials", client_id="svc", client_secret="s3cr")

    async def run():
        async with _client(handler) as c:
            await plugin.authenticate(c)
            return (await c.get("/x")).json()["auth"]

    assert asyncio.run(run()) == "Bearer AT"


def test_oauth2_password_grant_fetches_bearer():
    def handler(req):
        if req.url.path == "/oauth/token":
            form = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
            assert form["grant_type"] == "password"
            assert form["username"] == "bob" and form["password"] == "pw"
            return httpx.Response(200, json={"access_token": "PT", "token_type": "bearer"})
        return httpx.Response(200, json={"auth": req.headers.get("authorization")})

    plugin = OAuth2Auth(token_url="/oauth/token", grant="password", username="bob", password="pw")

    async def run():
        async with _client(handler) as c:
            await plugin.authenticate(c)
            return (await c.get("/x")).json()["auth"]

    assert asyncio.run(run()) == "Bearer PT"


def _oauth_refresh_handler(*, issue_refresh=True):
    """Token endpoint + protected resource where the FIRST-issued access token is
    dead on arrival (401), forcing exactly one refresh; the refreshed token works.
    Records each token request's grant_type in ``state['grants']``."""
    state = {"n": 0, "grants": [], "expired": set()}

    def handler(req):
        if req.url.path == "/oauth/token":
            form = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
            state["grants"].append(form.get("grant_type"))
            state["n"] += 1
            access = f"access-{state['n']}"
            if state["n"] == 1:
                state["expired"].add(access)  # first token pre-expired -> one refresh
            body = {"access_token": access, "token_type": "bearer"}
            if issue_refresh:
                body["refresh_token"] = f"refresh-{state['n']}"
            return httpx.Response(200, json=body)
        if req.url.path == "/orders/1":
            presented = req.headers.get("authorization", "").removeprefix("Bearer ")
            if not presented or presented in state["expired"]:
                return httpx.Response(401, json={"detail": "expired"})
            return httpx.Response(200, json={"ok": True, "token": presented})
        return httpx.Response(404, json={})

    return handler, state


def test_oauth2_refreshes_and_retries_once_on_401():
    handler, state = _oauth_refresh_handler(issue_refresh=True)
    plugin = OAuth2Auth(token_url="/oauth/token", grant="client_credentials", client_id="svc", client_secret="s")

    async def run():
        async with _client(handler) as c:
            await plugin.authenticate(c)  # fetches access-1 (pre-expired)
            return (await c.get("/orders/1")).json()

    body = asyncio.run(run())
    assert body == {"ok": True, "token": "access-2"}  # retried with the refreshed token
    assert state["grants"] == ["client_credentials", "refresh_token"]  # grant, then refresh


def test_oauth2_reauths_when_no_refresh_token():
    handler, state = _oauth_refresh_handler(issue_refresh=False)
    plugin = OAuth2Auth(token_url="/oauth/token", grant="client_credentials", client_id="svc", client_secret="s")

    async def run():
        async with _client(handler) as c:
            await plugin.authenticate(c)
            return (await c.get("/orders/1")).json()

    body = asyncio.run(run())
    assert body["ok"] and body["token"] == "access-2"
    # No refresh token was issued -> the refresh falls back to re-running the grant.
    assert state["grants"] == ["client_credentials", "client_credentials"]


def test_oauth2_bad_credentials_raises_autherror():
    def handler(req):
        return httpx.Response(401, json={"detail": "nope"})  # token endpoint rejects

    plugin = OAuth2Auth(token_url="/oauth/token", grant="client_credentials", client_id="svc", client_secret="bad")

    async def run():
        async with _client(handler) as c:
            await plugin.authenticate(c)

    with pytest.raises(AuthError):
        asyncio.run(run())


# --- bearer ----------------------------------------------------------------
def test_bearer_sets_authorization_header():
    def handler(req):
        return httpx.Response(200, json={"auth": req.headers.get("authorization")})

    async def run():
        async with _client(handler) as c:
            await BearerAuth(token="secret-token").authenticate(c)
            return (await c.get("/x")).json()["auth"]

    assert asyncio.run(run()) == "Bearer secret-token"


def test_bearer_from_config_resolves_env(monkeypatch):
    monkeypatch.setenv("TOK", "abc")
    plugin = BearerAuth.from_config(BearerAuthConfig(type="bearer", token_env="TOK"))

    def handler(req):
        return httpx.Response(200, json={"auth": req.headers.get("authorization")})

    async def run():
        async with _client(handler) as c:
            await plugin.authenticate(c)
            return (await c.get("/x")).json()["auth"]

    assert asyncio.run(run()) == "Bearer abc"


# --- login -----------------------------------------------------------------
def test_login_extracts_token_and_sets_bearer():
    def handler(req):
        if req.url.path == "/login":
            return httpx.Response(200, json={"access_token": "tok-xyz", "token_type": "bearer"})
        return httpx.Response(200, json={"auth": req.headers.get("authorization")})

    async def run():
        async with _client(handler) as c:
            await LoginAuth(url="/login", username="u", password="p").authenticate(c)
            return (await c.get("/me")).json()["auth"]

    assert asyncio.run(run()) == "Bearer tok-xyz"


def test_login_falls_back_to_cookie_session():
    def handler(req):
        if req.url.path == "/login":
            return httpx.Response(200, headers={"set-cookie": "session=abc; Path=/"}, json={})
        return httpx.Response(200, json={"cookie": req.headers.get("cookie")})

    async def run():
        async with _client(handler) as c:
            await LoginAuth(url="/login", username="u", password="p").authenticate(c)
            return (await c.get("/me")).json()["cookie"]

    assert "session=abc" in asyncio.run(run())


def test_login_raises_on_bad_status():
    def handler(req):
        return httpx.Response(401, json={"detail": "nope"})

    async def run():
        async with _client(handler) as c:
            await LoginAuth(url="/login", username="u", password="p").authenticate(c)

    with pytest.raises(AuthError):
        asyncio.run(run())


def test_login_raises_when_2xx_but_no_session():
    def handler(req):
        return httpx.Response(200, json={"unrelated": "value"})

    async def run():
        async with _client(handler) as c:
            await LoginAuth(url="/login", username="u", password="p").authenticate(c)

    with pytest.raises(AuthError):
        asyncio.run(run())


# --- manager ---------------------------------------------------------------
def _toy_handler():
    """A MockTransport handler that behaves like the toy API (login + /me)."""
    valid = {"alice": "alice-pw", "bob": "bob-pw"}
    tokens: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/login":
            body = json.loads(req.content)
            if valid.get(body["username"]) != body["password"]:
                return httpx.Response(401, json={"detail": "bad creds"})
            token = f"tok-{body['username']}"
            tokens[token] = body["username"]
            return httpx.Response(200, json={"access_token": token, "token_type": "bearer"})
        if req.url.path == "/me":
            user = tokens.get(req.headers.get("authorization", "").removeprefix("Bearer "))
            if not user:
                return httpx.Response(401, json={})
            return httpx.Response(200, json={"username": user})
        return httpx.Response(404, json={})

    return handler


def _two_identity_config():
    return Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [
                {
                    "id": "alice",
                    "attributes": {"tenant": "A"},
                    "auth": {"type": "login", "url": "/login", "username": "alice", "password_env": "ALICE_PW"},
                },
                {
                    "id": "bob",
                    "attributes": {"tenant": "B"},
                    "auth": {"type": "login", "url": "/login", "username": "bob", "password_env": "BOB_PW"},
                },
            ],
        }
    )


def test_manager_authenticates_all_identities(monkeypatch):
    monkeypatch.setenv("ALICE_PW", "alice-pw")
    monkeypatch.setenv("BOB_PW", "bob-pw")
    cfg = _two_identity_config()
    guard = SafetyGuard(allow=["t"], confirm_own_target=True)

    async def run():
        reg = await authenticate_identities(cfg, guard, transport=httpx.MockTransport(_toy_handler()))
        try:
            return {i: (await ac.client.get("/me")).json()["username"] for i, ac in reg.items()}
        finally:
            await aclose_all(reg)

    assert asyncio.run(run()) == {"alice": "alice", "bob": "bob"}


def test_manager_raises_on_bad_credentials(monkeypatch):
    monkeypatch.setenv("ALICE_PW", "alice-pw")
    monkeypatch.setenv("BOB_PW", "WRONG")
    cfg = _two_identity_config()
    guard = SafetyGuard(allow=["t"], confirm_own_target=True)

    with pytest.raises(AuthError):
        asyncio.run(
            authenticate_identities(cfg, guard, transport=httpx.MockTransport(_toy_handler()))
        )


def test_manager_refuses_when_guard_denies(monkeypatch):
    monkeypatch.setenv("ALICE_PW", "alice-pw")
    monkeypatch.setenv("BOB_PW", "bob-pw")
    cfg = _two_identity_config()
    guard = SafetyGuard(allow=["t"], confirm_own_target=False)  # not confirmed

    with pytest.raises(SafetyError):
        asyncio.run(
            authenticate_identities(cfg, guard, transport=httpx.MockTransport(_toy_handler()))
        )


def _ok_token_handler(req):
    # A permissive handler: if the guard fails to fire, auth would SUCCEED here,
    # so a SafetyError in these tests can only come from the allowlist check.
    return httpx.Response(200, json={"access_token": "x", "token_type": "bearer"})


def test_manager_refuses_off_allowlist_oauth2_token_url(monkeypatch):
    monkeypatch.setenv("SVC_SECRET", "s")
    cfg = Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [
                {"id": "svc", "auth": {"type": "oauth2", "token_url": "http://evil.test/token", "grant": "client_credentials", "client_id": "svc", "client_secret_env": "SVC_SECRET"}}
            ],
        }
    )
    guard = SafetyGuard(allow=["t"], confirm_own_target=True)
    with pytest.raises(SafetyError):  # credentials must not be POSTed off-allowlist
        asyncio.run(authenticate_identities(cfg, guard, transport=httpx.MockTransport(_ok_token_handler)))


def test_manager_refuses_off_allowlist_login_url(monkeypatch):
    monkeypatch.setenv("PW", "p")
    cfg = Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [
                {"id": "alice", "auth": {"type": "login", "url": "http://evil.test/login", "username": "alice", "password_env": "PW"}}
            ],
        }
    )
    guard = SafetyGuard(allow=["t"], confirm_own_target=True)
    with pytest.raises(SafetyError):
        asyncio.run(authenticate_identities(cfg, guard, transport=httpx.MockTransport(_ok_token_handler)))


def test_manager_records_api_key_sensitive_header(monkeypatch):
    monkeypatch.setenv("ALICE_KEY", "alice-key")
    cfg = Config.model_validate(
        {
            "target": {"base_url": "http://t", "allow": ["t"]},
            "identities": [
                {"id": "alice", "auth": {"type": "api_key", "key_env": "ALICE_KEY", "header": "X-API-Key"}}
            ],
        }
    )
    guard = SafetyGuard(allow=["t"], confirm_own_target=True)

    def handler(req):
        return httpx.Response(200, json={"key": req.headers.get("x-api-key")})

    async def run():
        reg = await authenticate_identities(cfg, guard, transport=httpx.MockTransport(handler))
        try:
            sent = (await reg["alice"].client.get("/x")).json()["key"]
            return sent, reg["alice"].sensitive_headers
        finally:
            await aclose_all(reg)

    sent, sensitive = asyncio.run(run())
    assert sent == "alice-key"  # the key rode in the configured header
    # The configured header travels with the client, so diagnostics can redact it.
    assert sensitive == frozenset({"x-api-key"})
    assert redacted({"X-API-Key": "alice-key"}, sensitive)["X-API-Key"] == "<redacted>"
