import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

def test_api_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["healthy", "degraded"]
    assert "service" in data
    assert "database" in data

def test_api_providers_status(client):
    res = client.get("/api/providers/status")
    assert res.status_code == 200
    data = res.json()
    assert "primary_provider" in data
    assert "gemini_configured" in data
    assert "groq_configured" in data
    assert "fallback_ready" in data
    # Ensure no API keys are returned
    assert "GEMINI_API_KEY" not in str(data)
    assert "GROQ_API_KEY" not in str(data)

def test_api_analyze_plain_text(client):
    response = client.post(
        "/api/analyze",
        data={
            "raw_content": "Urgent alert: Your account has been suspended! Please confirm your password: http://192.168.1.1/login",
            "input_type": "raw_text",
            "simulate_both_fail": "true"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["risk"]["overall_score"] > 50
    assert len(data["evidence"]) >= 2
    assert len(data["trace"]) == 10
    inv_id = data["id"]

    # Verify retrieval
    get_res = client.get(f"/api/investigations/{inv_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == inv_id

    # Verify trace endpoint
    trace_res = client.get(f"/api/investigations/{inv_id}/trace")
    assert trace_res.status_code == 200
    assert len(trace_res.json()["trace"]) == 10

    # Verify export json, csv, markdown
    exp_csv = client.get(f"/api/investigations/{inv_id}/export?format=csv")
    assert exp_csv.status_code == 200
    assert "Investigation ID" in exp_csv.text

    exp_md = client.get(f"/api/investigations/{inv_id}/export?format=markdown")
    assert exp_md.status_code == 200
    assert "PhishGuard AI — Investigation Dossier" in exp_md.text

def test_api_update_review(client):
    # Update seed demo investigation review status
    patch_res = client.patch(
        "/api/investigations/inv-demo-m365-phish/review?status=RESOLVED_MALICIOUS&notes=Confirmed phishing attack"
    )
    assert patch_res.status_code == 200
    data = patch_res.json()
    assert data["review_status"] == "RESOLVED_MALICIOUS"
    assert data["review_notes"] == "Confirmed phishing attack"
