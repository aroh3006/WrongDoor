"""Confirm the demo API's KNOWN ANSWER at the HTTP level (§16): the invoices
endpoint really has the planted BOLA, and the documents endpoint really is secure.
If these ever flip, the golden pipeline test would be testing the wrong thing."""

from fastapi.testclient import TestClient

from app import app as vulnerable_app

client = TestClient(vulnerable_app)


def _token(user: str, pw: str) -> str:
    return client.post("/login", json={"username": user, "password": pw}).json()["access_token"]


def test_invoices_has_the_planted_bola():
    alice = {"Authorization": f"Bearer {_token('alice', 'alice-pw')}"}
    bob = {"Authorization": f"Bearer {_token('bob', 'bob-pw')}"}
    inv = client.post("/invoices", json={"amount": 500.0, "memo": "secret"}, headers=alice).json()
    # bob reads ALICE's invoice -> 200 with alice's data: the bug.
    leaked = client.get(f"/invoices/{inv['id']}", headers=bob)
    assert leaked.status_code == 200
    assert leaked.json()["owner"] == "alice"


def test_documents_is_the_secure_control():
    alice = {"Authorization": f"Bearer {_token('alice', 'alice-pw')}"}
    bob = {"Authorization": f"Bearer {_token('bob', 'bob-pw')}"}
    doc = client.post("/documents", json={"title": "t", "body": "b"}, headers=alice).json()
    # bob reads ALICE's document -> 403: the control.
    assert client.get(f"/documents/{doc['id']}", headers=bob).status_code == 403


def test_notes_has_missing_authentication():
    alice = {"Authorization": f"Bearer {_token('alice', 'alice-pw')}"}
    note = client.post("/notes", json={"title": "t", "body": "b"}, headers=alice).json()
    # NO auth header at all -> still returns alice's note: missing authentication.
    resp = client.get(f"/notes/{note['id']}")
    assert resp.status_code == 200
    assert resp.json()["owner"] == "alice"


def test_admin_all_invoices_has_bfla():
    bob = {"Authorization": f"Bearer {_token('bob', 'bob-pw')}"}
    # bob (a normal user) can hit the admin endpoint -> BFLA.
    assert client.get("/admin/all-invoices", headers=bob).status_code == 200


def test_admin_all_users_is_the_bfla_control():
    bob = {"Authorization": f"Bearer {_token('bob', 'bob-pw')}"}
    # this admin endpoint DOES check the role -> 403 for a normal user.
    assert client.get("/admin/all-users", headers=bob).status_code == 403
