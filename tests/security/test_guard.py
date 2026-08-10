"""Security guarantees for the Safety Guard (§13, §16): a non-allowlisted or
look-alike target is refused, and the allowlist can't be bypassed by substrings."""

import pytest

from wrongdoor.safety.guard import SafetyError, SafetyGuard


def _guard():
    return SafetyGuard(allow=["staging.myapp.test"], confirm_own_target=True)


@pytest.mark.parametrize(
    "url",
    [
        "http://staging.myapp.test.evil.com/",  # allowlisted host as a subdomain of attacker
        "http://evil-staging.myapp.test/",      # would pass a naive endswith
        "http://staging.myapp.test.evil/",       # trailing extra label
        "http://myapp.test/",                    # parent domain, not the exact host
    ],
)
def test_lookalike_hosts_are_refused(url):
    with pytest.raises(SafetyError):
        _guard().assert_allowed(url)


def test_unconfirmed_run_refuses_even_allowlisted_host():
    g = SafetyGuard(allow=["staging.myapp.test"], confirm_own_target=False)
    with pytest.raises(SafetyError):
        g.assert_allowed("http://staging.myapp.test/invoices/1")
