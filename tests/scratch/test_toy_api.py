"""Smoke test for the throwaway toy API (examples/scratch/toy_api.py)."""

from fastapi.testclient import TestClient

from toy_api import app

client = TestClient(app)


def test_login_returns_bearer_token():
    resp = client.post("/login", json={"username": "alice", "password": "alice-pw"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


def test_login_rejects_wrong_password():
    resp = client.post("/login", json={"username": "alice", "password": "nope"})
    assert resp.status_code == 401


def test_me_returns_own_info_with_token():
    token = client.post(
        "/login", json={"username": "bob", "password": "bob-pw"}
    ).json()["access_token"]
    resp = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == {"username": "bob", "email": "bob@example.com", "tenant": "B"}


def test_me_requires_token():
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers={"Authorization": "Bearer bogus"}).status_code == 401


def _token(user: str, pw: str) -> str:
    return client.post("/login", json={"username": user, "password": pw}).json()["access_token"]


def test_create_and_get_own_invoice():
    h = {"Authorization": f"Bearer {_token('alice', 'alice-pw')}"}
    created = client.post("/invoices", json={"amount": 42.0, "memo": "x"}, headers=h)
    assert created.status_code == 201
    inv = created.json()
    assert inv["owner"] == "alice" and inv["amount"] == 42.0
    got = client.get(f"/invoices/{inv['id']}", headers=h)
    assert got.status_code == 200 and got.json()["id"] == inv["id"]


def test_non_owner_cannot_get_invoice():
    inv = client.post(
        "/invoices", json={"amount": 1.0}, headers={"Authorization": f"Bearer {_token('alice', 'alice-pw')}"}
    ).json()
    resp = client.get(
        f"/invoices/{inv['id']}", headers={"Authorization": f"Bearer {_token('bob', 'bob-pw')}"}
    )
    assert resp.status_code == 403  # correct authorization, no bug here
