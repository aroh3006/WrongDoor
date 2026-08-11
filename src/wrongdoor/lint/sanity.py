"""Static Sanity Pass (§5.3) — a cheap, offline lint run BEFORE any live request.

Pure and I/O-free (beyond reading env-var presence): it catches config mistakes
before you waste a live run or create junk data. Errors block a run; warnings
are advisory. Cycle detection over resource-creation dependencies arrives in
Phase 5, when dependency chains exist.
"""

import os
from dataclasses import dataclass, field
from typing import Mapping

from ..config.schema import BearerAuthConfig, Config, LoginAuthConfig
from ..safety.guard import SafetyError, SafetyGuard
from ..spec.openapi import Operation, access_operations, create_operations


@dataclass
class LintReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _secret_vars(auth) -> list[str]:
    if isinstance(auth, BearerAuthConfig):
        return [auth.token_env]
    if isinstance(auth, LoginAuthConfig):
        return [auth.password_env]
    return []


def lint(
    config: Config,
    operations: list[Operation] | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> LintReport:
    env = os.environ if env is None else env
    report = LintReport()

    # ERROR: base_url must be allowlisted, or every live run is refused up front.
    try:
        SafetyGuard(config.target.allow, confirm_own_target=True).assert_allowed(config.target.base_url)
    except SafetyError:
        report.errors.append(
            "target.base_url host is not in target.allow — the run would be refused"
        )

    # WARNING: referenced secret env vars that aren't set (auth will fail at runtime).
    for identity in config.identities:
        for var in _secret_vars(identity.auth):
            if not env.get(var):
                report.warnings.append(
                    f"identity {identity.id!r}: env var {var} is not set (auth will fail)"
                )

    # Spec-aware checks (only when a spec was provided).
    if operations is not None:
        created = {o.resource_type for o in create_operations(operations)}
        accessed = {o.resource_type for o in access_operations(operations)}
        for rt in config.resources:
            if rt not in created | accessed:
                report.warnings.append(
                    f"resources.{rt}: no operation for this resource in the spec (dangling reference)"
                )
        for rt in sorted(created - accessed):
            report.warnings.append(f"resource {rt!r} is created but has no access-op to test")
        for rt in sorted(accessed - created):
            report.warnings.append(f"resource {rt!r} has an access-op but no create-op to seed it")

    return report
