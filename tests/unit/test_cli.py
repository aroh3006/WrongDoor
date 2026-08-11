"""CLI wiring: error exit codes (§5.1). Happy path is covered by the integration
test, which can inject a transport; here we only check the failure branches."""

from typer.testing import CliRunner

from wrongdoor.cli import app

runner = CliRunner()

_VALID_CONFIG = """\
target:
  base_url: http://127.0.0.1:9
  allow: [127.0.0.1]
identities:
  - id: alice
    auth: {type: login, url: /login, username: alice, password_env: ALICE_PW}
"""


def test_missing_config_exits_2():
    result = runner.invoke(app, ["auth-check", "--config", "does-not-exist.yaml", "--confirm-own-target"])
    assert result.exit_code == 2


def test_refuses_without_confirm_flag_exits_3(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(_VALID_CONFIG, encoding="utf-8")
    # No --confirm-own-target: the guard refuses before any network call.
    result = runner.invoke(app, ["auth-check", "--config", str(cfg)])
    assert result.exit_code == 3


_MINIMAL_SPEC = """\
openapi: "3.0.0"
info: {title: t, version: "1"}
paths: {}
"""


def test_seed_missing_config_exits_2(tmp_path):
    spec = tmp_path / "s.yaml"
    spec.write_text(_MINIMAL_SPEC, encoding="utf-8")
    result = runner.invoke(app, ["seed", "--config", "nope.yaml", "--spec", str(spec), "--confirm-own-target"])
    assert result.exit_code == 2


def test_seed_missing_spec_exits_5(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(_VALID_CONFIG, encoding="utf-8")
    result = runner.invoke(app, ["seed", "--config", str(cfg), "--spec", "nope.yaml", "--confirm-own-target"])
    assert result.exit_code == 5


def test_seed_refuses_without_confirm_exits_3(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(_VALID_CONFIG, encoding="utf-8")
    spec = tmp_path / "s.yaml"
    spec.write_text(_MINIMAL_SPEC, encoding="utf-8")
    result = runner.invoke(app, ["seed", "--config", str(cfg), "--spec", str(spec)])
    assert result.exit_code == 3
