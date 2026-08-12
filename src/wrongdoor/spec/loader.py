"""Importer dispatch (§5.4): pick the operation-catalog front-end by file type.

Both importers return the identical ``list[Operation]`` and raise the same
``SpecError``, so callers stay importer-agnostic — a ``.har`` capture and an
OpenAPI spec are interchangeable at ``--spec``. A ``.har`` extension routes to
the HAR importer; everything else is treated as OpenAPI (which itself handles
JSON or YAML).
"""

from pathlib import Path

from .har import load_har
from .openapi import Operation
from .openapi import load_operations as _load_openapi


def load_operations(path: str | Path) -> list[Operation]:
    if str(path).lower().endswith(".har"):
        return load_har(path)
    return _load_openapi(path)
