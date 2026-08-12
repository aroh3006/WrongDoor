"""Deliberately-vulnerable demo API — WrongDoor's known-answer harness (§16).

Two users in two tenants, and two resources built backwards from the finding:

  * invoices  -- PLANTED BUG: GET /invoices/{id} authenticates but does NO
                 ownership check, so any user can read any invoice (BOLA).
  * documents -- CONTROL: GET /documents/{id} DOES check ownership (403 for a
                 non-owner) and must yield ZERO findings (false-positive control).

WrongDoor should report exactly one VIOLATION (the invoice BOLA) and nothing on
documents.
"""

import secrets

from fastapi import FastAPI, Header, HTTPException
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
