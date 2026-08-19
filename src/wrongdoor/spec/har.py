"""HAR importer (§5.4, §14 Phase 5): recorded traffic -> the SAME operation catalog.

A HAR file is a log of literal HTTP requests/responses: no path templates, no
schema. This importer reconstructs the same ``Operation`` list the OpenAPI
importer produces, so everything downstream (planner/seeder/executor/verdict) is
importer-agnostic: it never learns whether a run came from a spec or a HAR. To
guarantee that, we import the ``Operation``/``Parameter`` types and the
``_classify`` / ``_resource_type`` helpers straight from ``openapi`` and reuse
them unchanged; only the front-end (literal URLs -> templates) is new here.

The one inference not present in the data: turning literal paths like
``/invoices/1000`` and ``/invoices/1001`` into a single templated access-op
``/invoices/{invoice_id}``. We do it by shape: a segment that looks like an
object id (all digits, a UUID, or a long hex token) becomes ``{param}``, then
hand the templated path to the same ``_classify`` used for specs, so create-vs-
access is decided identically.

Auth is deliberately NOT extracted from a HAR (§13). Recorded credentials are
secrets and usually expired; decisively, a HAR captures only ONE identity
while WrongDoor's differential method needs two or more. Auth stays config-based;
recorded ``Authorization``/``Cookie`` headers are never read here.
"""

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .openapi import (
    MAX_OPERATIONS,
    Operation,
    Parameter,
    SpecError,
    _classify,
    _resource_type,
)

# Bound how much recorded traffic we scan, mirroring MAX_OPERATIONS for specs.
_MAX_ENTRIES = 5000

# A path segment we treat as an object id when templatizing a literal URL:
# all-digits, a UUID, or a long hex token (Mongo ObjectId etc.).
_ID_SEGMENT = re.compile(
    r"^(?:"
    r"\d+"
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|[0-9a-fA-F]{16,}"
    r")$"
)

# Obvious non-API noise a real capture is full of: skipped.
_STATIC_SUFFIXES = (
    ".js", ".css", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".map",
)


def load_har(path: str | Path) -> list[Operation]:
    """Load a HAR file into the operation catalog (same output as the OpenAPI importer)."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise SpecError(f"cannot read HAR file {path}: {e}") from e
    return load_har_from_string(text)


def load_har_from_string(text: str) -> list[Operation]:
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise SpecError(f"failed to parse HAR (not valid JSON): {e}") from e

    ops: dict[tuple[str, str], Operation] = {}
    for entry in _entries(doc)[:_MAX_ENTRIES]:
        built = _operation_from_entry(entry)
        if built is None:
            continue
        key = (built.method, built.path_template)
        existing = ops.get(key)
        if existing is None:
            ops[key] = built
        elif existing.request_schema is None and built.request_schema is not None:
            ops[key] = built  # keep the occurrence that carried a body to learn from
        if len(ops) > MAX_OPERATIONS:
            raise SpecError(f"HAR yields more than {MAX_OPERATIONS} operations; refusing")
    return list(ops.values())


# --- the walk (pure; no I/O) ----------------------------------------------
def _entries(doc: Any) -> list:
    log = doc.get("log") if isinstance(doc, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise SpecError("HAR has no log.entries array")
    return entries


def _operation_from_entry(entry: Any) -> Operation | None:
    if not isinstance(entry, dict):
        return None
    request = entry.get("request")
    if not isinstance(request, dict):
        return None
    method, url = request.get("method"), request.get("url")
    if not isinstance(method, str) or not isinstance(url, str):
        return None

    # Only import successful traffic: a 4xx/5xx may be a probe at a non-resource.
    response = entry.get("response")
    status = response.get("status") if isinstance(response, dict) else None
    if not (isinstance(status, int) and 200 <= status < 300):
        return None

    path = _url_path(url)
    if path is None or _is_noise(path):
        return None

    template, params = _templatize(path)
    has_path_id = any(p.is_object_id for p in params)
    kind = _classify(method.lower(), has_path_id)  # SAME classifier as the spec path
    if kind == "other":
        return None  # not a create or single-object access op -> nothing to test

    return Operation(
        operation_id=_synth_operation_id(method, template),
        method=method.upper(),
        path_template=template,
        kind=kind,
        resource_type=_resource_type(template),
        parameters=tuple(params),
        request_schema=_schema_from_body(request) if kind == "create" else None,
    )


def _synth_operation_id(method: str, template: str) -> str:
    """A stable, readable operationId from method+template, e.g.
    ``get_invoices_invoice_id``. Reports prepend the method separately, so (unlike
    a literal ``GET /invoices/{id}``) this reads like a real operationId, not a
    doubled ``GET GET /invoices/{id}``. Unique per (method, template)."""
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", template).strip("_").lower()
    return f"{method.lower()}_{slug}" if slug else method.lower()


def _url_path(url: str) -> str | None:
    try:
        path = urlsplit(url).path  # drops host and query
    except ValueError:
        return None
    if not path:
        return None
    return path.rstrip("/") if len(path) > 1 else path


def _is_noise(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(suffix) for suffix in _STATIC_SUFFIXES)


def _templatize(path: str) -> tuple[str, list[Parameter]]:
    """Replace id-shaped segments with ``{param}`` so two literal ids collapse to
    one template. Params are named after the preceding (singularized) segment."""
    out: list[str] = []
    params: list[Parameter] = []
    used: set[str] = set()
    prev_static = ""
    for seg in path.split("/"):
        if seg and _ID_SEGMENT.match(seg):
            name = _param_name(prev_static, used)
            used.add(name)
            out.append("{" + name + "}")
            params.append(Parameter(name=name, location="path", is_object_id=True))
        else:
            out.append(seg)
            if seg:
                prev_static = seg
    return "/".join(out), params


def _param_name(preceding: str, used: set[str]) -> str:
    base = (_singular(preceding) + "_id") if preceding else "id"
    name, i = base, 2
    while name in used:  # keep names unique within one path (nested ids)
        name, i = f"{base}{i}", i + 1
    return name


def _singular(word: str) -> str:
    return word[:-1] if len(word) > 1 and word.endswith("s") else word


def _schema_from_body(request: dict) -> dict | None:
    """A create-op's body source: wrap the recorded JSON body as ``example`` so
    ``synthesize_body`` replays a body shaped like the real one, no seeder change."""
    post = request.get("postData")
    if not isinstance(post, dict):
        return None
    text, mime = post.get("text"), (post.get("mimeType") or "")
    if not isinstance(text, str) or "json" not in mime.lower():
        return None  # non-JSON body -> no example; seeder falls back to {}
    try:
        body = json.loads(text)
    except ValueError:
        return None
    return {"example": body}
