"""Unit tests for the offline static sanity pass (§5.3)."""

from wrongdoor.config.schema import Config
from wrongdoor.lint.sanity import lint
from wrongdoor.spec.openapi import _operations_from_resolved


def _config(base_url="http://127.0.0.1:8000", allow=None, resources=None):
    return Config.model_validate(
        {
            "target": {"base_url": base_url, "allow": allow or ["127.0.0.1"]},
            "identities": [
                {"id": "alice", "auth": {"type": "login", "url": "/login", "username": "alice", "password_env": "ALICE_PW"}}
            ],
            "resources": resources or {},
        }
    )


def test_clean_config_with_env_set_is_ok():
    report = lint(_config(), env={"ALICE_PW": "x"})
    assert report.ok and report.warnings == []


def test_base_url_not_in_allowlist_is_error():
    report = lint(_config(base_url="http://evil.test", allow=["127.0.0.1"]), env={"ALICE_PW": "x"})
    assert not report.ok
    assert any("allow" in e for e in report.errors)


def test_missing_secret_env_is_a_warning_not_an_error():
    report = lint(_config(), env={})
    assert report.ok  # a warning, not a blocking error
    assert any("ALICE_PW" in w for w in report.warnings)


def test_missing_api_key_env_is_warned():
    cfg = Config.model_validate(
        {
            "target": {"base_url": "http://127.0.0.1:8000", "allow": ["127.0.0.1"]},
            "identities": [{"id": "alice", "auth": {"type": "api_key", "key_env": "ALICE_KEY"}}],
        }
    )
    report = lint(cfg, env={})
    assert report.ok  # still just a warning
    assert any("ALICE_KEY" in w for w in report.warnings)


def test_dependency_cycle_is_an_error():
    cfg = Config.model_validate(
        {
            "target": {"base_url": "http://127.0.0.1:8000", "allow": ["127.0.0.1"]},
            "identities": [
                {"id": "alice", "auth": {"type": "login", "url": "/login", "username": "alice", "password_env": "ALICE_PW"}}
            ],
            "seeding": {
                "dependencies": [
                    {"resource": "a", "parent": "b", "body_field": "b_id"},
                    {"resource": "b", "parent": "a", "body_field": "a_id"},
                ]
            },
        }
    )
    report = lint(cfg, env={"ALICE_PW": "x"})
    assert not report.ok
    assert any("cycle" in e for e in report.errors)


def test_spec_aware_mismatch_warnings():
    spec = {
        "paths": {
            "/invoices": {"post": {"operationId": "createInvoice", "responses": {}}},  # create, no access
            "/documents/{id}": {
                "get": {
                    "operationId": "getDoc",
                    "parameters": [{"name": "id", "in": "path"}],
                    "responses": {},
                }
            },  # access, no create
        }
    }
    ops = _operations_from_resolved(spec)
    report = lint(_config(resources={"widgets": {"sensitivity": "low"}}), ops, env={"ALICE_PW": "x"})
    joined = " ".join(report.warnings)
    assert "widgets" in joined  # dangling resource config
    assert "invoices" in joined  # created but not tested
    assert "documents" in joined  # access but no create-op to seed
