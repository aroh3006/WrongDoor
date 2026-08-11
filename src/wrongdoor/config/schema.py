"""Pydantic DSL = WrongDoor's input contract (§5.2, §6).

This is the untrusted-input boundary: `config.yaml` is text a user (or a mistake)
authored, so we validate it into typed objects once here and trust it afterward.

Two security properties are worth calling out:

* ``extra="forbid"`` on every model — an unknown or typo'd key is rejected, not
  ignored. Crucially this makes it impossible to smuggle a raw secret inline
  (e.g. ``password: hunter2``): there is no such field, and forbidding extras
  turns the attempt into a loud validation error.
* Secrets are referenced by env-var *name* only (``token_env``, ``password_env``).
  The actual token/password lives in the environment, never in the config file
  (§13). The identity manager resolves these names at auth time.
"""

from typing import Annotated, Literal, Union
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Bound a run so a malformed/hostile config cannot make us authenticate against
# an absurd number of principals. Operations get a similar cap in Phase 2.
MAX_IDENTITIES = 50


class BearerAuthConfig(BaseModel):
    """A pre-issued bearer token, supplied via an env var. No login round-trip."""

    model_config = ConfigDict(extra="forbid")
    type: Literal["bearer"]
    token_env: str = Field(min_length=1)  # NAME of the env var holding the token


class LoginAuthConfig(BaseModel):
    """A session login: POST credentials to ``url``, get back a cookie or a token."""

    model_config = ConfigDict(extra="forbid")
    type: Literal["login"]
    url: str = Field(min_length=1)  # login path (relative to base_url) or absolute
    username: str = Field(min_length=1)
    password_env: str = Field(min_length=1)  # NAME of the env var holding the password
    # Which JSON field carries the token, if the endpoint returns one in the body.
    # None => the plugin tries common names (access_token, token) then falls back
    # to cookie-based session auth.
    token_field: str | None = None


# Discriminated union: Pydantic picks the variant by the `type` value, giving
# precise "unknown auth type 'foo'" style errors instead of a confusing merge.
AuthConfig = Annotated[
    Union[BearerAuthConfig, LoginAuthConfig], Field(discriminator="type")
]


class IdentityConfig(BaseModel):
    """A principal WrongDoor can authenticate as."""

    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1)
    # Free-form trust attributes (e.g. tenant, role). String values — quote them
    # in YAML if they look numeric. Used by the policy/verdict later.
    attributes: dict[str, str] = Field(default_factory=dict)
    auth: AuthConfig


class TargetConfig(BaseModel):
    """The API under test and the host allowlist that gates all live I/O."""

    model_config = ConfigDict(extra="forbid")
    base_url: str
    # The Safety Guard refuses any target whose host is not listed here. Required
    # and non-empty: you must declare where WrongDoor is allowed to point.
    allow: list[str] = Field(min_length=1)

    @field_validator("base_url")
    @classmethod
    def _must_be_http_url_with_host(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("base_url must be an http(s) URL with a host")
        return v


class PolicyConfig(BaseModel):
    """Expected-access policy. Phase 1 only supports owner-only."""

    model_config = ConfigDict(extra="forbid")
    rule: Literal["owner_only"] = "owner_only"


class SeedingConfig(BaseModel):
    """Seeding settings (§5.6). All optional with safe defaults."""

    model_config = ConfigDict(extra="forbid")
    # JSON field holding the created object's id. None => the seeder tries "id"
    # then falls back to the Location header.
    id_field: str | None = None
    # Safety cap: never create more than this many objects in one run.
    max_objects: int = Field(default=100, ge=1)


class Config(BaseModel):
    """The whole validated configuration."""

    model_config = ConfigDict(extra="forbid")
    target: TargetConfig
    identities: list[IdentityConfig] = Field(min_length=1, max_length=MAX_IDENTITIES)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    seeding: SeedingConfig = Field(default_factory=SeedingConfig)

    @model_validator(mode="after")
    def _identity_ids_unique(self) -> "Config":
        ids = [i.id for i in self.identities]
        dupes = sorted({x for x in ids if ids.count(x) > 1})
        if dupes:
            raise ValueError(f"duplicate identity ids: {dupes}")
        return self
