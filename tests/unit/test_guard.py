"""Unit tests for the Safety Guard mechanics (§5.9)."""

import pytest

from wrongdoor.safety.guard import SafetyError, SafetyGuard


def _guard(allow, confirmed=True):
    return SafetyGuard(allow=allow, confirm_own_target=confirmed)


def test_allows_allowlisted_host_when_confirmed():
    _guard(["127.0.0.1"]).assert_allowed("http://127.0.0.1:8000/login")  # no raise


def test_host_match_is_case_insensitive():
    _guard(["localhost"]).assert_allowed("http://LOCALHOST/me")  # no raise


def test_refuses_when_not_confirmed():
    with pytest.raises(SafetyError):
        _guard(["127.0.0.1"], confirmed=False).assert_allowed("http://127.0.0.1/")


def test_refuses_non_allowlisted_host():
    with pytest.raises(SafetyError):
        _guard(["staging.myapp.test"]).assert_allowed("http://other.host/")


def test_refuses_non_http_scheme():
    with pytest.raises(SafetyError):
        _guard(["etc"]).assert_allowed("file:///etc/passwd")


def test_refuses_url_without_host():
    with pytest.raises(SafetyError):
        _guard(["x"]).assert_allowed("http://")


def test_empty_allowlist_refuses_everything():
    with pytest.raises(SafetyError):
        _guard([]).assert_allowed("http://127.0.0.1/")


def test_port_pinned_entry_matches_only_that_port():
    g = _guard(["127.0.0.1:8000"])
    g.assert_allowed("http://127.0.0.1:8000/")  # no raise
    with pytest.raises(SafetyError):
        g.assert_allowed("http://127.0.0.1:9000/")


def test_host_only_entry_matches_any_port():
    g = _guard(["127.0.0.1"])
    g.assert_allowed("http://127.0.0.1:8000/")
    g.assert_allowed("http://127.0.0.1:9999/")
