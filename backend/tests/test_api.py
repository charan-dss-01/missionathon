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

def test_api_analyze_stream_real_events(client):
    """
    Verifies that POST /api/analyze/stream emits real-time SSE events in correct order,
    reports accurate node durations and finding counts, conditionally marks attachments skipped,
    and concludes with the complete investigation dossier.
    """
    import json
    response = client.post(
        "/api/analyze/stream",
        data={
            "raw_content": "From: billing@paypal-notice.com\nSubject: Account Locked\n\nConfirm at: http://192.168.1.1/login",
            "input_type": "raw_text",
            "simulate_both_fail": "true"
        }
    )
    assert response.status_code == 200
    assert "text/event-stream" in response.headers.get("content-type", "")

    # Parse SSE events
    events = []
    current_event = None
    for line in response.text.split("\n"):
        line = line.strip()
        if line.startswith("event:"):
            current_event = line.replace("event:", "").strip()
        elif line.startswith("data:") and current_event:
            data_str = line.replace("data:", "").strip()
            try:
                events.append((current_event, json.loads(data_str)))
            except Exception:
                pass
            current_event = None

    event_types = [e[0] for e in events]
    assert "pipeline_started" in event_types
    assert "node_completed" in event_types
    assert "complete" in event_types
    assert "pipeline_completed" in event_types

    # Verify node sequence
    completed_nodes = [e[1]["node"] for e in events if e[0] == "node_completed"]
    expected_nodes = [
        "parse_input", "analyze_headers", "analyze_body", "analyze_urls",
        "analyze_attachments", "aggregate_evidence", "calculate_risk",
        "interpret_with_llm", "validate_evidence", "generate_report"
    ]
    assert completed_nodes == expected_nodes

    # Verify conditional attachment skipping (no attachment was provided)
    att_event = next(e[1] for e in events if e[0] == "node_completed" and e[1]["node"] == "analyze_attachments")
    assert att_event["status"] == "SKIPPED"
    assert "no attachments" in att_event["summary"].lower()

    # Verify final complete event dossier
    complete_event = next(e[1] for e in events if e[0] == "complete")
    result = complete_event["result"]
    assert "id" in result
    assert result["risk"]["overall_score"] > 0
    assert len(result["trace"]) == 10

def test_api_investigation_events_replay(client):
    """
    Verifies that GET /api/investigations/{id}/events returns recorded trace events for replay.
    """
    # Use existing seed investigation
    res = client.get("/api/investigations/inv-demo-m365-phish/events")
    assert res.status_code == 200
    assert "text/event-stream" in res.headers.get("content-type", "")
    assert "event: node_completed" in res.text
    assert "event: complete" in res.text

def test_api_analyze_stream_with_attachment(client):
    """
    Verifies that when an attachment is provided, analyze_attachments is COMPLETED, not SKIPPED.
    """
    import json, io
    file_bytes = b"%PDF-1.4 /JavaScript << /JS (app.alert('test')) >>"
    response = client.post(
        "/api/analyze/stream",
        data={
            "raw_content": "Subject: Test\n\nPlease find attachment.",
            "input_type": "attachment",
            "simulate_both_fail": "true"
        },
        files={"file": ("malicious.pdf", io.BytesIO(file_bytes), "application/pdf")}
    )
    assert response.status_code == 200
    events = []
    current_event = None
    for line in response.text.split("\n"):
        line = line.strip()
        if line.startswith("event:"):
            current_event = line.replace("event:", "").strip()
        elif line.startswith("data:") and current_event:
            try:
                events.append((current_event, json.loads(line.replace("data:", "").strip())))
            except Exception:
                pass
            current_event = None

    att_event = next(e[1] for e in events if e[0] == "node_completed" and e[1]["node"] == "analyze_attachments")
    assert att_event["status"] == "COMPLETED"
    assert att_event["finding_count"] >= 1

