"""Shared test setup.

Puts examples/scratch/ on sys.path so tests can `import toy_api` — the toy API
is a throwaway script, not an installed package, so it is not importable by
default.
"""

import sys
from pathlib import Path

_EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
for _sub in ("scratch", "vulnerable-api"):
    _path = str(_EXAMPLES / _sub)
    if _path not in sys.path:
        sys.path.insert(0, _path)
