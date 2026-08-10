"""Config loader (§5.2): read a YAML file, validate it into a typed ``Config``.

Fails fast with a readable ``ConfigError`` instead of a raw traceback, so a
mistake in ``config.yaml`` reads like a helpful message, not a crash.

Security: ``yaml.safe_load`` only — never ``yaml.load`` — so a hostile config
cannot construct arbitrary Python objects (the ``!!python/object/...`` tags).
"""

from pathlib import Path

import yaml
from pydantic import ValidationError

from .schema import Config


class ConfigError(Exception):
    """Raised for any problem reading or validating the config file."""


def load_config(path: str | Path) -> Config:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"cannot read config file {p}: {e}") from e

    try:
        raw = yaml.safe_load(text)  # safe_load: no arbitrary object construction
    except yaml.YAMLError as e:
        raise ConfigError(f"invalid YAML in {p}: {e}") from e

    if not isinstance(raw, dict):
        got = type(raw).__name__
        raise ConfigError(f"config root must be a mapping, got {got}")

    try:
        return Config.model_validate(raw)
    except ValidationError as e:
        raise ConfigError(f"config validation failed:\n{e}") from e
