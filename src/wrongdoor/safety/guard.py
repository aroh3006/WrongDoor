"""Safety Guard (§5.9, §13) — the single choke point in front of all live I/O.

OWN THIS FILE. Nothing in WrongDoor may send a live request without this guard
saying yes first. Its whole job is to make it hard to point the tool — which
authenticates as real users and (later) creates real data — at something you
don't own or didn't mean to hit.

Phase 1 enforces two gates:
  1. Host allowlist  — the target's host must exactly match an entry in
     ``config.target.allow``. Exact hostname match, never a substring.
  2. Confirmation    — the operator must have passed ``--confirm-own-target``.

Design principles (each is a line you should be able to defend in a viva):

* **Fail closed.** Anything ambiguous — unparseable URL, missing host,
  non-http(s) scheme, empty allowlist, no matching entry — is a refusal, never
  a maybe. The safe default is "no".
* **Exact hostname equality.** Substring / ``endswith`` checks are how allowlists
  get bypassed: ``staging.myapp.test.evil.com`` "contains" ``staging.myapp.test``,
  and ``endswith('myapp.test')`` matches ``evil-myapp.test``. We parse the URL,
  take the lowercased hostname, and compare with ``==``.
* **Raise, don't return a bool.** A forgotten ``if not allowed:`` silently ships
  the request. ``assert_allowed()`` raises ``SafetyError``; the only way past it
  is for it not to throw.

Note on redirects (out of scope for Phase 1, hardened in Phase 6): the guard only
sees the URL it is handed, so a 3xx could in principle bounce a request to an
off-allowlist host. WrongDoor's httpx clients therefore run with
``follow_redirects=False`` (set in the identity manager) as a Phase-1 stopgap;
full redirect-chain re-checking comes later.
"""

from urllib.parse import urlsplit


class SafetyError(Exception):
    """Raised to REFUSE a live request. Fail-closed: refusal is the default."""


def _host_port(authority: str) -> tuple[str | None, int | None]:
    """Split ``host`` / ``host:port`` / ``[::1]:port`` into (lowercased host, port).

    We parse it as the authority part of a URL (``//host:port``) so the stdlib
    handles IPv6 brackets and port validation for us. A non-numeric port makes
    ``.port`` raise ValueError; we treat that (and any parse failure) as "no
    host", which is fail-closed.
    """
    try:
        parts = urlsplit(f"//{authority.strip()}")
        return parts.hostname, parts.port
    except ValueError:
        return None, None


class SafetyGuard:
    """Gate constructed once from the config allowlist + the confirmation flag,
    then consulted (``assert_allowed``) before every live request."""

    def __init__(self, allow: list[str], confirm_own_target: bool) -> None:
        # Normalize the allowlist once into (host, port) pairs. Entries that yield
        # no host are dropped here: they can never match, and dropping them keeps
        # the matching loop simple and fail-closed.
        self._allow: list[tuple[str, int | None]] = []
        for entry in allow:
            host, port = _host_port(entry)
            if host:
                self._allow.append((host, port))
        self._confirmed = confirm_own_target
        self._allow_raw = list(allow)  # kept only for readable error messages

    def assert_allowed(self, url: str) -> None:
        """Return None if ``url`` may be contacted; raise ``SafetyError`` otherwise."""
        # 1. Parse and sanity-check the URL itself. Accessing `.port` is what can
        #    raise ValueError (bad port), so it lives inside the try.
        try:
            parts = urlsplit(url)
            host = parts.hostname
            port = parts.port
        except ValueError as e:
            raise SafetyError(f"refusing malformed target URL {url!r}: {e}") from e

        if parts.scheme not in ("http", "https"):
            raise SafetyError(
                f"refusing non-http(s) target URL {url!r} (scheme {parts.scheme!r})"
            )
        if not host:
            raise SafetyError(f"refusing target URL with no host: {url!r}")

        # 2. Confirmation gate: the operator must assert they own / are authorized
        #    to test this target. No flag, no live requests at all.
        if not self._confirmed:
            raise SafetyError(
                "refusing any live request: pass --confirm-own-target to confirm "
                "you own or are authorized to test this target"
            )

        # 3. Host allowlist: exact host match; if an entry pins a port, match it too.
        for allow_host, allow_port in self._allow:
            if host == allow_host and (allow_port is None or allow_port == port):
                return  # allowed
        raise SafetyError(
            f"refusing target host {host!r}: not in allowlist {self._allow_raw}"
        )
