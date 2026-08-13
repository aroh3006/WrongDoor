"""Unit tests for the body-diff confirmer (§7). This is the low-false-positive core."""

from wrongdoor.engine.diff import confirm_injection, confirm_leak, normalize


def test_full_containment_confirms_and_returns_matched_fields():
    canonical = {"id": 1000, "owner": "alice", "amount": 500}
    observed = {"id": 1000, "owner": "alice", "amount": 500}
    assert confirm_leak(observed, canonical) == ["amount", "id", "owner"]


def test_extra_fields_in_observed_still_match():
    canonical = {"id": 1000, "amount": 500}
    observed = {"id": 1000, "amount": 500, "served_by": "cache-3"}  # extra field is fine
    assert confirm_leak(observed, canonical) == ["amount", "id"]


def test_near_miss_different_value_does_not_match():
    canonical = {"id": 1000, "owner": "alice", "amount": 500}
    observed = {"id": 1001, "owner": "bob", "amount": 500}  # a DIFFERENT object
    assert confirm_leak(observed, canonical) is None


def test_missing_field_does_not_match():
    canonical = {"id": 1000, "owner": "alice", "amount": 500}
    observed = {"id": 1000, "owner": "alice"}  # amount absent
    assert confirm_leak(observed, canonical) is None


def test_volatile_fields_are_ignored():
    canonical = {"id": 1000, "amount": 500, "created_at": "2020-01-01T00:00:00Z"}
    observed = {"id": 1000, "amount": 500, "created_at": "2026-08-11T12:00:00Z"}
    # created_at differs but is volatile -> still a confirmed match on id/amount
    assert confirm_leak(observed, canonical) == ["amount", "id"]


def test_non_dict_bodies_are_inconclusive():
    assert confirm_leak("Forbidden", {"id": 1}) is None
    assert confirm_leak({"id": 1}, None) is None


def test_canonical_with_only_volatile_fields_cannot_confirm():
    assert confirm_leak({"created_at": "x"}, {"created_at": "x"}) is None


def test_normalize_strips_volatile_case_insensitively():
    body = {"id": 1, "Created_At": "t", "ETag": "abc"}
    assert normalize(body) == {"id": 1}


# --- mass-assignment confirmer (D4) ----------------------------------------
def test_injection_confirmed_when_field_took_our_value():
    # baseline role was "user"; we injected "admin" and the re-read shows "admin".
    assert confirm_injection({"id": 1, "role": "admin"}, "role", "admin", baseline_value="user") is True


def test_injection_not_confirmed_when_field_stripped():
    # server ignored the injection -> re-read still shows the baseline.
    assert confirm_injection({"id": 1, "role": "user"}, "role", "admin", baseline_value="user") is False


def test_injection_not_confirmed_when_field_absent():
    assert confirm_injection({"id": 1}, "role", "admin", baseline_value="user") is False


def test_injection_not_confirmed_when_value_equals_baseline():
    # our chosen value already matches the current value -> can't attribute to us.
    assert confirm_injection({"id": 1, "verified": True}, "verified", True, baseline_value=True) is False


def test_injection_confirmed_without_a_known_baseline():
    # no baseline (field wasn't in the canonical) but the client introduced it as our value.
    assert confirm_injection({"id": 1, "role": "admin"}, "role", "admin") is True


def test_injection_non_dict_body_is_not_confirmed():
    assert confirm_injection("Forbidden", "role", "admin") is False
    assert confirm_injection(None, "role", "admin", baseline_value="user") is False
