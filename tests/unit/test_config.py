"""Unit tests for the config schema + loader (§5.2)."""

import pytest
import yaml
from pydantic import ValidationError

from wrongdoor.config.loader import ConfigError, load_config
from wrongdoor.config.schema import (
    MAX_IDENTITIES,
    ApiKeyAuthConfig,
    BearerAuthConfig,
    Config,
    LoginAuthConfig,
    OAuth2AuthConfig,
)


def _valid_dict() -> dict:
    return {
        "target": {"base_url": "http://127.0.0.1:8000", "allow": ["127.0.0.1"]},
        "identities": [
            {
                "id": "alice",
                "attributes": {"tenant": "A"},
                "auth": {
                    "type": "login",
                    "url": "/login",
                    "username": "alice",
                    "password_env": "ALICE_PW",
                },
            },
            {"id": "bob", "auth": {"type": "bearer", "token_env": "BOB_TOKEN"}},
        ],
    }


def test_valid_config_parses_and_discriminates_auth():
    cfg = Config.model_validate(_valid_dict())
    assert [i.id for i in cfg.identities] == ["alice", "bob"]
    assert isinstance(cfg.identities[0].auth, LoginAuthConfig)
    assert isinstance(cfg.identities[1].auth, BearerAuthConfig)
    assert cfg.policy.rule == "owner_only"  # default applied


def test_api_key_auth_parses_with_default_and_custom_header():
    d = _valid_dict()
    d["identities"][1]["auth"] = {"type": "api_key", "key_env": "BOB_KEY"}
    cfg = Config.model_validate(d)
    auth = cfg.identities[1].auth
    assert isinstance(auth, ApiKeyAuthConfig)
    assert auth.key_env == "BOB_KEY" and auth.header == "X-API-Key"  # default header

    d["identities"][1]["auth"]["header"] = "X-Company-Token"
    cfg2 = Config.model_validate(d)
    assert cfg2.identities[1].auth.header == "X-Company-Token"


def test_api_key_inline_key_rejected():
    d = _valid_dict()
    d["identities"][1]["auth"] = {"type": "api_key", "key_env": "BOB_KEY", "key": "raw-secret"}
    with pytest.raises(ValidationError):  # inline secret = extra field, forbidden
        Config.model_validate(d)


def test_oauth2_client_credentials_and_password_grants_parse():
    d = _valid_dict()
    d["identities"][1]["auth"] = {
        "type": "oauth2",
        "token_url": "/oauth/token",
        "grant": "client_credentials",
        "client_id": "svc",
        "client_secret_env": "SVC_SECRET",
    }
    cfg = Config.model_validate(d)
    assert isinstance(cfg.identities[1].auth, OAuth2AuthConfig)
    assert cfg.identities[1].auth.token_field == "access_token"  # default

    d["identities"][1]["auth"] = {
        "type": "oauth2",
        "token_url": "/oauth/token",
        "grant": "password",
        "username": "bob",
        "password_env": "BOB_PW",
    }
    assert Config.model_validate(d).identities[1].auth.grant == "password"


def test_oauth2_missing_grant_fields_rejected():
    d = _valid_dict()
    # client_credentials grant without the client secret -> validation error
    d["identities"][1]["auth"] = {"type": "oauth2", "token_url": "/t", "grant": "client_credentials", "client_id": "svc"}
    with pytest.raises(ValidationError):
        Config.model_validate(d)
    # password grant without the password env -> validation error
    d["identities"][1]["auth"] = {"type": "oauth2", "token_url": "/t", "grant": "password", "username": "bob"}
    with pytest.raises(ValidationError):
        Config.model_validate(d)


def test_oauth2_inline_secret_rejected():
    d = _valid_dict()
    d["identities"][1]["auth"] = {
        "type": "oauth2", "token_url": "/t", "grant": "client_credentials",
        "client_id": "svc", "client_secret_env": "SVC_SECRET", "client_secret": "raw",
    }
    with pytest.raises(ValidationError):  # inline secret = extra field, forbidden
        Config.model_validate(d)


def test_inline_secret_is_rejected():
    d = _valid_dict()
    d["identities"][0]["auth"]["password"] = "hunter2"  # inline secret = extra field
    with pytest.raises(ValidationError):
        Config.model_validate(d)


def test_unknown_top_level_key_rejected():
    d = _valid_dict()
    d["surprise"] = 1
    with pytest.raises(ValidationError):
        Config.model_validate(d)


def test_unknown_auth_type_rejected():
    d = _valid_dict()
    d["identities"][1]["auth"] = {"type": "magic", "token_env": "X"}
    with pytest.raises(ValidationError):
        Config.model_validate(d)


def test_duplicate_identity_ids_rejected():
    d = _valid_dict()
    d["identities"][1]["id"] = "alice"
    with pytest.raises(ValidationError):
        Config.model_validate(d)


def test_non_http_base_url_rejected():
    d = _valid_dict()
    d["target"]["base_url"] = "ftp://example.test/x"
    with pytest.raises(ValidationError):
        Config.model_validate(d)


def test_empty_allowlist_rejected():
    d = _valid_dict()
    d["target"]["allow"] = []
    with pytest.raises(ValidationError):
        Config.model_validate(d)


def test_identity_cap_enforced():
    d = _valid_dict()
    d["identities"] = [
        {"id": f"u{n}", "auth": {"type": "bearer", "token_env": f"T{n}"}}
        for n in range(MAX_IDENTITIES + 1)
    ]
    with pytest.raises(ValidationError):
        Config.model_validate(d)


def test_loader_roundtrip(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(_valid_dict()), encoding="utf-8")
    cfg = load_config(p)
    assert cfg.target.base_url == "http://127.0.0.1:8000"
    assert cfg.identities[0].auth.type == "login"


def test_config_error_never_echoes_an_inline_secret(tmp_path):
    # extra="forbid" rejects an inline secret — but the error output must NOT
    # contain the secret value (§13). Permanent regression guard.
    p = tmp_path / "config.yaml"
    p.write_text(
        "target: {base_url: 'http://127.0.0.1:8000', allow: ['127.0.0.1']}\n"
        "identities:\n"
        "  - id: alice\n"
        "    auth: {type: bearer, token_env: ALICE_TOKEN, token: SUPERSECRET-INLINE-VALUE}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as ei:
        load_config(p)
    msg = str(ei.value)
    assert "SUPERSECRET-INLINE-VALUE" not in msg  # the secret value is gone
    assert "token" in msg  # but the offending field is still named, so it's actionable


def test_loader_missing_file():
    with pytest.raises(ConfigError):
        load_config("does-not-exist.yaml")


def test_loader_non_mapping_root(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(p)


def test_loader_invalid_yaml(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("target: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(p)


def test_protected_fields_parse_and_default_empty():
    cfg = Config.model_validate(_valid_dict())
    # A resource not listed (or listed without protected_fields) defaults to none.
    assert cfg.resources == {}

    d = _valid_dict()
    d["resources"] = {"profiles": {"sensitivity": "high", "protected_fields": {"role": "admin", "is_verified": True}}}
    cfg2 = Config.model_validate(d)
    pf = cfg2.resources["profiles"].protected_fields
    assert pf == {"role": "admin", "is_verified": True}  # values keep their JSON type


def test_protected_fields_reject_unknown_resource_key():
    d = _valid_dict()
    d["resources"] = {"profiles": {"protected_feilds": {"role": "admin"}}}  # typo'd key
    with pytest.raises(ValidationError):  # extra="forbid" catches the typo
        Config.model_validate(d)


def test_seeding_defaults_and_override():
    cfg = Config.model_validate(_valid_dict())
    assert cfg.seeding.max_objects == 100 and cfg.seeding.id_field is None
    d = _valid_dict()
    d["seeding"] = {"id_field": "invoice_id", "max_objects": 5}
    cfg2 = Config.model_validate(d)
    assert cfg2.seeding.id_field == "invoice_id" and cfg2.seeding.max_objects == 5
