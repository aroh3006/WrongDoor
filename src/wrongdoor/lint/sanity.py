"""Static Sanity Pass (§5.3): a cheap, offline lint run BEFORE any live request.

Pure and I/O-free (beyond reading env-var presence): it catches config mistakes
before you waste a live run or create junk data. Errors block a run; warnings
are advisory. Cycle detection over resource-creation dependencies arrives in
Phase 5, when dependency chains exist.
"""

import os
from dataclasses import dataclass, field
from typing import Mapping

from ..config.schema import (
    ApiKeyAuthConfig,
    BearerAuthConfig,
    Config,
    LoginAuthConfig,
    OAuth2AuthConfig,
)
from ..safety.guard import SafetyError, SafetyGuard
from ..spec.openapi import Operation, access_operations, create_operations


@dataclass
class LintReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _dependency_cycle(dependencies) -> list[str] | None:
    """Return a cycle path in the child->parent dependency graph, or None. This is
    the only graph traversal in the tool (§5.3): a small DFS with a visiting set."""
    parent_of = {d.resource: d.parent for d in dependencies}
    state: dict[str, str] = {}

    def visit(resource: str, stack: list[str]) -> list[str] | None:
        if state.get(resource) == "done":
            return None
        if state.get(resource) == "visiting":
            return stack[stack.index(resource):] + [resource]
        state[resource] = "visiting"
        parent = parent_of.get(resource)
        if parent is not None:
            found = visit(parent, stack + [resource])
            if found:
                return found
        state[resource] = "done"
        return None

    for resource in list(parent_of):
        found = visit(resource, [])
        if found:
            return found
    return None


def _secret_vars(auth) -> list[str]:
    if isinstance(auth, BearerAuthConfig):
        return [auth.token_env]
    if isinstance(auth, LoginAuthConfig):
        return [auth.password_env]
    if isinstance(auth, ApiKeyAuthConfig):
        return [auth.key_env]
    if isinstance(auth, OAuth2AuthConfig):
        return [v for v in (auth.client_secret_env, auth.password_env) if v]
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

    # ERROR: a cycle in the seeding dependency graph can never be ordered (§5.3).
    cycle = _dependency_cycle(config.seeding.dependencies)
    if cycle:
        report.errors.append("resource dependency cycle: " + " -> ".join(cycle))

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
