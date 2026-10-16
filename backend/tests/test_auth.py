import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.mongodb import db_manager

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

def test_auth_registration_and_login(client):
    test_email = f"analyst_{int(pytest.importorskip('time').time())}@soc-shield.net"
    
    # 1. Register User
    reg_res = client.post("/api/auth/register", json={
        "name": "Jane Analyst",
        "email": test_email,
        "password": "SecurePassword123!"
    })
    assert reg_res.status_code == 201
    data = reg_res.json()
    assert "access_token" in data
    assert "password" not in str(data)
    assert "password_hash" not in str(data)
    user_id = data["user"]["id"]
    token = data["access_token"]

    # 2. Duplicate Registration Rejection
    dup_res = client.post("/api/auth/register", json={
        "name": "Jane Impersonator",
        "email": test_email,
        "password": "AnotherPassword456!"
    })
    assert dup_res.status_code == 400
    assert "already exists" in dup_res.json()["detail"]

    # 3. Current User Profile
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["id"] == user_id
    assert me_data["email"] == test_email.lower()
    assert me_data["role"] == "user"

    # 4. Incorrect Password Rejection
    bad_login = client.post("/api/auth/login", json={
        "email": test_email,
        "password": "WrongPassword999!"
    })
    assert bad_login.status_code == 401
    assert "Invalid email or password" in bad_login.json()["detail"]

    # 5. Successful Login
    login_res = client.post("/api/auth/login", json={
        "email": test_email,
        "password": "SecurePassword123!"
    })
    assert login_res.status_code == 200
    assert "access_token" in login_res.json()

    # 6. Change Password
    pwd_res = client.post(
        "/api/auth/password",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "current_password": "SecurePassword123!",
            "new_password": "UpdatedPassword456!"
        }
    )
    assert pwd_res.status_code == 200

    # 7. Login with New Password
    new_login = client.post("/api/auth/login", json={
        "email": test_email,
        "password": "UpdatedPassword456!"
    })
    assert new_login.status_code == 200

def test_unauthenticated_me_rejection(client):
    res = client.get("/api/auth/me")
    assert res.status_code == 401

def test_multi_tenant_investigation_isolation(client):
    time_stamp = int(pytest.importorskip('time').time())
    
    # 1. Create User A
    email_a = f"usera_{time_stamp}@defense.org"
    reg_a = client.post("/api/auth/register", json={
        "name": "User Alpha",
        "email": email_a,
        "password": "AlphaPassword123!"
    })
    assert reg_a.status_code == 201
    token_a = reg_a.json()["access_token"]

    # 2. Create User B
    email_b = f"userb_{time_stamp}@defense.org"
    reg_b = client.post("/api/auth/register", json={
        "name": "User Beta",
        "email": email_b,
        "password": "BetaPassword123!"
    })
    assert reg_b.status_code == 201
    token_b = reg_b.json()["access_token"]

    # 3. User A creates an investigation
    analyze_res = client.post(
        "/api/analyze",
        headers={"Authorization": f"Bearer {token_a}"},
        data={
            "raw_content": "From: sender@domain.com\nSubject: Top Secret Phish\n\nUrgent please confirm password",
            "input_type": "raw_text",
            "simulate_both_fail": "true"
        }
    )
    assert analyze_res.status_code == 200
    inv_id = analyze_res.json()["id"]

    # 4. User A can retrieve it
    get_a = client.get(f"/api/investigations/{inv_id}", headers={"Authorization": f"Bearer {token_a}"})
    assert get_a.status_code == 200
    assert get_a.json()["id"] == inv_id

    # 5. User B ATTEMPTS to access User A's investigation -> MUST BE BLOCKED WITH 403
    get_b = client.get(f"/api/investigations/{inv_id}", headers={"Authorization": f"Bearer {token_b}"})
    assert get_b.status_code == 403
    assert "Access denied" in get_b.json()["detail"]

    # 6. User B ATTEMPTS to access User A's trace -> MUST BE BLOCKED WITH 403
    trace_b = client.get(f"/api/investigations/{inv_id}/trace", headers={"Authorization": f"Bearer {token_b}"})
    assert trace_b.status_code == 403

    # 7. User B ATTEMPTS to export User A's dossier -> MUST BE BLOCKED WITH 403
    exp_b = client.get(f"/api/investigations/{inv_id}/export?format=csv", headers={"Authorization": f"Bearer {token_b}"})
    assert exp_b.status_code == 403
