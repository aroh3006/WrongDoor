"""Deliberately-vulnerable demo API: WrongDoor's known-answer harness (§16).

Two users in two tenants, and two resources built backwards from the finding:

  * invoices  -- PLANTED BUG: GET /invoices/{id} authenticates but does NO
                 ownership check, so any user can read any invoice (BOLA).
  * documents -- CONTROL: GET /documents/{id} DOES check ownership (403 for a
                 non-owner) and must yield ZERO findings (false-positive control).

WrongDoor should report exactly one VIOLATION (the invoice BOLA) and nothing on
documents.
"""

import secrets
from urllib.parse import parse_qs

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

app = FastAPI(title="WrongDoor vulnerable demo API")

_USERS = {
    "alice": {"password": "alice-pw", "tenant": "A"},
    "bob": {"password": "bob-pw", "tenant": "B"},
}
_TOKENS: dict[str, str] = {}
_INVOICES: dict[int, dict] = {}
_DOCUMENTS: dict[int, dict] = {}
_next_id = 1000


class LoginBody(BaseModel):
    username: str
    password: str


class InvoiceIn(BaseModel):
    amount: float
    memo: str = ""


class DocumentIn(BaseModel):
    title: str
    body: str = ""


def _require_user(authorization: str | None) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    user = _TOKENS.get(authorization.removeprefix("Bearer "))
    if user is None:
        raise HTTPException(status_code=401, detail="invalid token")
    return user


@app.post("/login")
def login(body: LoginBody) -> dict:
    user = _USERS.get(body.username)
    if user is None or not secrets.compare_digest(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="invalid credentials")
    token = secrets.token_urlsafe(16)
    _TOKENS[token] = body.username
    return {"access_token": token, "token_type": "bearer"}


@app.get("/me")
def whoami(authorization: str | None = Header(default=None)) -> dict:
    """Who the caller is. This is the default probe for `wrongdoor auth-check`,
    so the identities in the demo config can be verified before a full run."""
    user = _require_user(authorization)
    return {"username": user, "tenant": _USERS[user]["tenant"]}


@app.post("/invoices", status_code=201)
def create_invoice(body: InvoiceIn, authorization: str | None = Header(default=None)) -> dict:
    global _next_id
    user = _require_user(authorization)
    inv = {"id": _next_id, "owner": user, "tenant": _USERS[user]["tenant"], "amount": body.amount, "memo": body.memo}
    _INVOICES[_next_id] = inv
    _next_id += 1
    return inv


@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int, authorization: str | None = Header(default=None)) -> dict:
    _require_user(authorization)  # authenticated, but NO ownership check -> BOLA
    inv = _INVOICES.get(invoice_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="not found")
    return inv  # returns ANY user's invoice -- the planted bug


@app.delete("/invoices/{invoice_id}", status_code=204)
def delete_invoice(invoice_id: int, authorization: str | None = Header(default=None)) -> None:
    user = _require_user(authorization)  # DELETE is owner-only (correct) -> lets cleanup work
    inv = _INVOICES.get(invoice_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="not found")
    if inv["owner"] != user:
        raise HTTPException(status_code=403, detail="forbidden")
    del _INVOICES[invoice_id]


@app.post("/documents", status_code=201)
def create_document(body: DocumentIn, authorization: str | None = Header(default=None)) -> dict:
    global _next_id
    user = _require_user(authorization)
    doc = {"id": _next_id, "owner": user, "tenant": _USERS[user]["tenant"], "title": body.title, "body": body.body}
    _DOCUMENTS[_next_id] = doc
    _next_id += 1
    return doc


@app.get("/documents/{document_id}")
def get_document(document_id: int, authorization: str | None = Header(default=None)) -> dict:
    user = _require_user(authorization)
    doc = _DOCUMENTS.get(document_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="not found")
    if doc["owner"] != user:  # CORRECT ownership check -- the false-positive control
        raise HTTPException(status_code=403, detail="forbidden")
    return doc


# --- notes: PLANTED BUG (D3, missing authentication) -----------------------
# POST requires auth, but GET requires NO token at all -> anyone (unauthenticated)
# can read any note. (This is also a BOLA for an authenticated non-owner.)
_NOTES: dict[int, dict] = {}


class NoteIn(BaseModel):
    title: str
    body: str = ""


@app.post("/notes", status_code=201)
def create_note(body: NoteIn, authorization: str | None = Header(default=None)) -> dict:
    global _next_id
    user = _require_user(authorization)
    note = {"id": _next_id, "owner": user, "tenant": _USERS[user]["tenant"], "title": body.title, "body": body.body}
    _NOTES[_next_id] = note
    _next_id += 1
    return note


@app.get("/notes/{note_id}")
def get_note(note_id: int) -> dict:  # NO auth parameter, NO check -> missing authentication
    note = _NOTES.get(note_id)
    if note is None:
        raise HTTPException(status_code=404, detail="not found")
    return note


@app.delete("/notes/{note_id}", status_code=204)
def delete_note(note_id: int, authorization: str | None = Header(default=None)) -> None:
    user = _require_user(authorization)  # owner-only delete (cleanup uses the owner)
    note = _NOTES.get(note_id)
    if note is None:
        raise HTTPException(status_code=404, detail="not found")
    if note["owner"] != user:
        raise HTTPException(status_code=403, detail="forbidden")
    del _NOTES[note_id]


# --- admin endpoints: PLANTED BFLA (D2) + a secured control ------------------
@app.get("/admin/all-invoices")
def admin_all_invoices(authorization: str | None = Header(default=None)) -> dict:
    _require_user(authorization)  # authenticated, but NO role check -> BFLA
    return {"invoices": list(_INVOICES.values())}


@app.get("/admin/all-users")
def admin_all_users(authorization: str | None = Header(default=None)) -> dict:
    user = _require_user(authorization)
    if _USERS[user].get("role") != "admin":  # CORRECT role check -- the BFLA control
        raise HTTPException(status_code=403, detail="forbidden")
    return {"users": list(_USERS.keys())}


# --- orgs -> projects: a create-CHAIN (a project needs an owned org) ---------
# Creating a project REQUIRES a valid org_id the caller owns, so WrongDoor must
# seed an org first and inject its id. GET /projects/{id} is BOLA (no ownership).
_ORGS: dict[int, dict] = {}
_PROJECTS: dict[int, dict] = {}


class OrgIn(BaseModel):
    name: str = ""


class ProjectIn(BaseModel):
    org_id: int
    name: str = ""


@app.post("/orgs", status_code=201)
def create_org(body: OrgIn, authorization: str | None = Header(default=None)) -> dict:
    global _next_id
    user = _require_user(authorization)
    org = {"id": _next_id, "owner": user, "tenant": _USERS[user]["tenant"], "name": body.name}
    _ORGS[_next_id] = org
    _next_id += 1
    return org


@app.post("/projects", status_code=201)
def create_project(body: ProjectIn, authorization: str | None = Header(default=None)) -> dict:
    global _next_id
    user = _require_user(authorization)
    org = _ORGS.get(body.org_id)
    if org is None or org["owner"] != user:  # must own the parent org
        raise HTTPException(status_code=400, detail="invalid or unowned org_id")
    project = {"id": _next_id, "owner": user, "tenant": _USERS[user]["tenant"], "org_id": body.org_id, "name": body.name}
    _PROJECTS[_next_id] = project
    _next_id += 1
    return project


@app.get("/projects/{project_id}")
def get_project(project_id: int, authorization: str | None = Header(default=None)) -> dict:
    _require_user(authorization)  # authenticated, but NO ownership check -> BOLA
    project = _PROJECTS.get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="not found")
    return project


# --- widgets: API-KEY-authenticated resource (exercises the api_key auth type) --
# Auth here is an X-API-Key header (not a bearer token / cookie), mapping the key
# to a user. GET has NO ownership check -> BOLA, same planted-bug shape as
# invoices but reached through a different auth method end to end.
_WIDGET_KEYS = {"alice-key": "alice", "bob-key": "bob"}  # api key -> user
_WIDGETS: dict[int, dict] = {}


class WidgetIn(BaseModel):
    name: str = ""


def _require_key(x_api_key: str | None) -> str:
    user = _WIDGET_KEYS.get(x_api_key or "")
    if user is None:
        raise HTTPException(status_code=401, detail="missing or invalid API key")
    return user


@app.post("/widgets", status_code=201)
def create_widget(body: WidgetIn, x_api_key: str | None = Header(default=None)) -> dict:
    global _next_id
    user = _require_key(x_api_key)
    widget = {"id": _next_id, "owner": user, "tenant": _USERS[user]["tenant"], "name": body.name}
    _WIDGETS[_next_id] = widget
    _next_id += 1
    return widget


@app.get("/widgets/{widget_id}")
def get_widget(widget_id: int, x_api_key: str | None = Header(default=None)) -> dict:
    _require_key(x_api_key)  # authenticated by key, but NO ownership check -> BOLA
    widget = _WIDGETS.get(widget_id)
    if widget is None:
        raise HTTPException(status_code=404, detail="not found")
    return widget


@app.delete("/projects/{project_id}", status_code=204)
def delete_project(project_id: int, authorization: str | None = Header(default=None)) -> None:
    user = _require_user(authorization)  # owner-only delete
    project = _PROJECTS.get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="not found")
    if project["owner"] != user:
        raise HTTPException(status_code=403, detail="forbidden")
    del _PROJECTS[project_id]


@app.delete("/orgs/{org_id}", status_code=204)
def delete_org(org_id: int, authorization: str | None = Header(default=None)) -> None:
    user = _require_user(authorization)  # owner-only delete
    org = _ORGS.get(org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="not found")
    if org["owner"] != user:
        raise HTTPException(status_code=403, detail="forbidden")
    if any(p["org_id"] == org_id for p in _PROJECTS.values()):
        # FK: an org can't be deleted while a project still references it. This is
        # what forces cleanup to delete children (projects) BEFORE parents (orgs).
        raise HTTPException(status_code=409, detail="org still has projects")
    del _ORGS[org_id]


# --- OAuth2: token endpoint + a protected resource (exercises the oauth2 type) --
# A form-encoded token endpoint (RFC 6749) supporting the two non-interactive
# grants plus refresh_token, and an `orders` resource protected by the bearer
# token it issues. GET /orders/{id} has NO ownership check -> BOLA, reached via
# an OAuth2 access token end to end. Tokens here are multi-use / non-expiring, so
# the grant sweep is deterministic (the refresh path is unit-tested separately).
_OAUTH_CLIENTS = {"alice-client": ("alice-secret", "alice"), "bob-client": ("bob-secret", "bob")}  # id -> (secret, user)
_OAUTH_ACCESS: dict[str, str] = {}  # access_token -> user
_OAUTH_REFRESH: dict[str, str] = {}  # refresh_token -> user
_ORDERS: dict[int, dict] = {}
_oauth_seq = {"n": 0}


class OrderIn(BaseModel):
    item: str = ""


def _issue_tokens(user: str) -> dict:
    _oauth_seq["n"] += 1
    n = _oauth_seq["n"]
    access, refresh = f"access-{user}-{n}", f"refresh-{user}-{n}"
    _OAUTH_ACCESS[access] = user
    _OAUTH_REFRESH[refresh] = user
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer", "expires_in": 3600}


@app.post("/oauth/token")
async def oauth_token(request: Request) -> dict:
    # Parse the x-www-form-urlencoded body ourselves (keeps the demo free of the
    # python-multipart dependency FastAPI's Form() would pull in).
    form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
    grant = form.get("grant_type")
    if grant == "password":
        user = form.get("username", "")
        if _USERS.get(user, {}).get("password") != form.get("password"):
            raise HTTPException(status_code=401, detail="invalid credentials")
    elif grant == "client_credentials":
        cc = _OAUTH_CLIENTS.get(form.get("client_id", ""))
        if cc is None or cc[0] != form.get("client_secret"):
            raise HTTPException(status_code=401, detail="invalid client")
        user = cc[1]
    elif grant == "refresh_token":
        user = _OAUTH_REFRESH.get(form.get("refresh_token", ""))
        if user is None:
            raise HTTPException(status_code=401, detail="invalid refresh token")
    else:
        raise HTTPException(status_code=400, detail="unsupported grant_type")
    return _issue_tokens(user)


def _require_oauth(authorization: str | None) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    user = _OAUTH_ACCESS.get(authorization.removeprefix("Bearer "))
    if user is None:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    return user


@app.post("/orders", status_code=201)
def create_order(body: OrderIn, authorization: str | None = Header(default=None)) -> dict:
    global _next_id
    user = _require_oauth(authorization)
    order = {"id": _next_id, "owner": user, "tenant": _USERS[user]["tenant"], "item": body.item}
    _ORDERS[_next_id] = order
    _next_id += 1
    return order


@app.get("/orders/{order_id}")
def get_order(order_id: int, authorization: str | None = Header(default=None)) -> dict:
    _require_oauth(authorization)  # authenticated via OAuth2, but NO ownership check -> BOLA
    order = _ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="not found")
    return order


# --- profiles: PLANTED MASS-ASSIGNMENT (D4) + a protected control field ------
# A user can update their OWN profile (owner-checked PATCH), but the handler
# blindly binds a whitelist that WRONGLY includes `role`: so PATCHing your own
# profile with {"role": "admin"} escalates you (the planted bug). `locked` is NOT
# bindable from the body (the control): an attempt to set it is silently ignored,
# so WrongDoor must report a VIOLATION on `role` and a PASS on `locked`.
# GET/PATCH are both owner-checked, so profiles yields NO BOLA/unauth findings.
_PROFILES: dict[int, dict] = {}
_PROFILE_BINDABLE = {"role", "bio"}  # role should NOT be here, that's the bug


class ProfileIn(BaseModel):
    bio: str = ""


@app.post("/profiles", status_code=201)
def create_profile(body: ProfileIn, authorization: str | None = Header(default=None)) -> dict:
    global _next_id
    user = _require_user(authorization)
    profile = {
        "id": _next_id,
        "owner": user,
        "tenant": _USERS[user]["tenant"],
        "role": "user",  # server-controlled default; a client must not be able to set it
        "locked": False,  # server-controlled; the protected control field
        "bio": body.bio,  # the one legitimately client-settable field
    }
    _PROFILES[_next_id] = profile
    _next_id += 1
    return profile


@app.get("/profiles/{profile_id}")
def get_profile(profile_id: int, authorization: str | None = Header(default=None)) -> dict:
    user = _require_user(authorization)
    profile = _PROFILES.get(profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="not found")
    if profile["owner"] != user:  # owner-checked read -> no BOLA here
        raise HTTPException(status_code=403, detail="forbidden")
    return profile


@app.patch("/profiles/{profile_id}")
async def update_profile(profile_id: int, request: Request, authorization: str | None = Header(default=None)) -> dict:
    user = _require_user(authorization)
    profile = _PROFILES.get(profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="not found")
    if profile["owner"] != user:  # you may only update your OWN profile
        raise HTTPException(status_code=403, detail="forbidden")
    body = await request.json()
    for key, value in body.items():
        if key in _PROFILE_BINDABLE:  # blind bind: `role` slips through -> mass-assignment
            profile[key] = value
    return profile


@app.delete("/profiles/{profile_id}", status_code=204)
def delete_profile(profile_id: int, authorization: str | None = Header(default=None)) -> None:
    user = _require_user(authorization)  # owner-only delete (cleanup uses the owner)
    profile = _PROFILES.get(profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="not found")
    if profile["owner"] != user:
        raise HTTPException(status_code=403, detail="forbidden")
    del _PROFILES[profile_id]
