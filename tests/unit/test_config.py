"""Unit tests for the config schema + loader (§5.2)."""

import pytest
import yaml
from pydantic import ValidationError

from wrongdoor.config.loader import ConfigError, load_config
from wrongdoor.config.schema import (
    MAX_IDENTITIES,
    BearerAuthConfig,
    Config,
    LoginAuthConfig,
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


def test_seeding_defaults_and_override():
    cfg = Config.model_validate(_valid_dict())
    assert cfg.seeding.max_objects == 100 and cfg.seeding.id_field is None
    d = _valid_dict()
    d["seeding"] = {"id_field": "invoice_id", "max_objects": 5}
    cfg2 = Config.model_validate(d)
    assert cfg2.seeding.id_field == "invoice_id" and cfg2.seeding.max_objects == 5
