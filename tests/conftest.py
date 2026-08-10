"""Shared test setup.

Puts examples/scratch/ on sys.path so tests can `import toy_api` — the toy API
is a throwaway script, not an installed package, so it is not importable by
default.
"""

import sys
from pathlib import Path

_SCRATCH = Path(__file__).resolve().parent.parent / "examples" / "scratch"
if str(_SCRATCH) not in sys.path:
    sys.path.insert(0, str(_SCRATCH))
