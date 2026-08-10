"""Security: the loader must use yaml.safe_load, so a hostile config cannot
construct arbitrary Python objects (remote-ish code execution via YAML tags)."""

import pytest

from wrongdoor.config.loader import ConfigError, load_config

# With yaml.load this would call os.system; with safe_load it is refused at
# parse time (a ConstructorError, surfaced as ConfigError) and never executes.
_PYTHON_TAG = "!!python/object/apply:os.system ['echo pwned']\n"


def test_python_object_tag_is_refused_not_executed(tmp_path):
    p = tmp_path / "evil.yaml"
    p.write_text(_PYTHON_TAG, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(p)
