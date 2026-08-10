"""
Phase 1 scratch: a throwaway toy API to authenticate against.

This is NOT the Phase 3 vulnerable demo (that lives in examples/vulnerable-api/
and will have planted bugs). This one has no bugs to find — it is just enough
plumbing to exercise WrongDoor's identity manager end to end:

    POST /login  {username, password}  -> {"access_token": ..., "token_type": "bearer"}
    GET  /me     (Authorization: Bearer <token>) -> the caller's own info

Run it:  uvicorn toy_api:app --port 8000   (from examples/scratch/)
"""

import secrets

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="WrongDoor toy API (scratch)")

# Two hardcoded users with different passwords. email/tenant give /me something
# identity-specific to return, so later we can tell alice's response from bob's.
_USERS = {
    "alice": {"password": "alice-pw", "email": "alice@example.com", "tenant": "A"},
    "bob": {"password": "bob-pw", "email": "bob@example.com", "tenant": "B"},
}

# Opaque bearer tokens minted at login: token -> username. In-memory only; this
# is a toy, so process restart forgets all sessions. That is fine.
_TOKENS: dict[str, str] = {}


class LoginBody(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(body: LoginBody) -> dict:
    user = _USERS.get(body.username)
    # compare_digest even here, so the toy models the right habit (no early-exit
    # password comparison) rather than a naive ==.
    if user is None or not secrets.compare_digest(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="invalid credentials")
    token = secrets.token_urlsafe(16)
    _TOKENS[token] = body.username
    return {"access_token": token, "token_type": "bearer"}


@app.get("/me")
def me(authorization: str | None = Header(default=None)) -> dict:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.removeprefix("Bearer ")
    username = _TOKENS.get(token)
    if username is None:
        raise HTTPException(status_code=401, detail="invalid token")
    user = _USERS[username]
    return {"username": username, "email": user["email"], "tenant": user["tenant"]}
