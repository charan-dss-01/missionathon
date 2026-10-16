"""
Tests for Mission 03 Features:
- Feature A: Individual Attachment Risk Report Cards & Independent Scoring
- Feature B: End-User Classification Feedback Workflow & Persistence
- Feature C: Deterministic Rule-Grounded Recommendations
"""

import pytest
import io
import zipfile
from fastapi.testclient import TestClient

from app.main import app
from app.analyzers.attachment_analyzer import AttachmentAnalyzer
from app.models.schemas import RiskRatingEnum, FeedbackCategoryEnum
from app.storage.memory_store import MemoryStore


client = TestClient(app)


# ============================================================================
# Feature A Tests: Independent Attachment Risk Assessment & Recommendations
# ============================================================================

def test_benign_pdf_individual_assessment():
    """A clean benign PDF attachment should receive Low risk and safe preview guidance."""
    clean_pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    attachments_raw = [
        {
            "filename": "annual_report.pdf",
            "content_type": "application/pdf",
            "bytes": clean_pdf_bytes
        }
    ]

    findings, evidence = AttachmentAnalyzer.analyze_attachments(attachments_raw)
    assert len(findings) == 1
    finding = findings[0]

    assert finding.filename == "annual_report.pdf"
    assert "pdf" in finding.detected_type.lower()
    assert finding.risk_score == 0
    assert finding.risk_level == RiskRatingEnum.LOW
    assert "safe" in finding.recommended_action.lower() or "preview" in finding.recommended_action.lower() or "standard" in finding.recommended_action.lower()
    assert "no suspicious" in finding.classification_reason.lower() or "low" in finding.classification_reason.lower() or "complete" in finding.classification_reason.lower()


def test_disguised_executable_attachment():
    """A disguised executable (.pdf containing MZ header) must trigger high individual risk."""
    fake_exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"A" * 100
    attachments_raw = [
        {
            "filename": "fake_invoice.pdf",
            "content_type": "application/pdf",
            "bytes": fake_exe_bytes
        }
    ]

    findings, evidence = AttachmentAnalyzer.analyze_attachments(attachments_raw)
    assert len(findings) == 1
    finding = findings[0]

    assert finding.filename == "fake_invoice.pdf"
    assert "exe" in finding.detected_type.lower() or "mz" in finding.detected_type.lower() or "pe" in finding.detected_type.lower()
    assert finding.risk_score >= 50
    assert finding.risk_level in (RiskRatingEnum.HIGH, RiskRatingEnum.MEDIUM)
    assert "quarantine" in finding.recommended_action.lower() or "block" in finding.recommended_action.lower()
    assert len(finding.evidence_records) >= 1
    assert any("ATT_MIME_MISMATCH" in r.rule_id or "ATT_MAGIC_EXE" in r.rule_id for r in finding.evidence_records)


def test_independent_scoring_for_multiple_attachments():
    """Two attachments in one message must be scored independently without cross-contamination."""
    clean_png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
    malicious_scr_bytes = b"MZ\x90\x00" + b"\x00" * 60

    attachments_raw = [
        {
            "filename": "company_logo.png",
            "content_type": "image/png",
            "bytes": clean_png_bytes
        },
        {
            "filename": "urgent_screensaver.scr",
            "content_type": "application/octet-stream",
            "bytes": malicious_scr_bytes
        }
    ]

    findings, evidence = AttachmentAnalyzer.analyze_attachments(attachments_raw)
    assert len(findings) == 2

    clean_finding = next(f for f in findings if f.filename == "company_logo.png")
    evil_finding = next(f for f in findings if f.filename == "urgent_screensaver.scr")

    # Clean PNG must remain LOW risk (score 0)
    assert clean_finding.risk_score == 0
    assert clean_finding.risk_level == RiskRatingEnum.LOW

    # Malicious .scr must have elevated risk (score >= 40)
    assert evil_finding.risk_score >= 40
    assert evil_finding.risk_level in (RiskRatingEnum.HIGH, RiskRatingEnum.MEDIUM)
    assert evil_finding.dangerous_extension is True


def test_password_protected_archive_recommendation():
    """Password-protected zip must trigger encrypted warning and out-of-band verification guidance."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("secret_document.txt", b"encrypted content payload")
    
    raw = bytearray(zip_buffer.getvalue())
    cd_idx = raw.find(b"PK\x01\x02")
    raw[6] |= 1
    if cd_idx != -1:
        raw[cd_idx + 8] |= 1
    zip_bytes = bytes(raw)

    attachments_raw = [
        {
            "filename": "confidential.zip",
            "content_type": "application/zip",
            "bytes": zip_bytes
        }
    ]

    findings, evidence = AttachmentAnalyzer.analyze_attachments(attachments_raw)
    assert len(findings) == 1
    finding = findings[0]

    assert finding.encrypted is True
    assert "ATT_ARCHIVE_ENCRYPTED" in finding.matched_rules
    assert finding.risk_level in (RiskRatingEnum.MEDIUM, RiskRatingEnum.HIGH)
    assert "password" in finding.recommended_action.lower() or "verify" in finding.recommended_action.lower()


# ============================================================================
# Feature B Tests: End-User Classification Feedback Workflow & Persistence
# ============================================================================

@pytest.fixture
def sample_investigation_id():
    """Create a sample investigation with an attachment and return its ID."""
    raw_eml = (
        "From: billing@trusted-vendor.com\n"
        "To: employee@victim.corp\n"
        "Subject: Monthly Vendor Invoice Attached\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\n\n"
        "--BOUNDARY\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "Please find your monthly invoice attached.\n\n"
        "--BOUNDARY\n"
        "Content-Type: application/pdf\n"
        "Content-Disposition: attachment; filename=\"invoice_102.pdf\"\n\n"
        "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
        "--BOUNDARY--\n"
    )
    resp = client.post(
        "/api/analyze",
        data={"input_type": "eml", "simulate_both_fail": "true"},
        files={"file": ("vendor_invoice.eml", raw_eml.encode("utf-8"), "message/rfc822")}
    )
    assert resp.status_code == 200
    return resp.json()["id"]


def test_submit_valid_investigation_feedback(sample_investigation_id):
    """User can submit feedback for an investigation and receive persisted feedback record."""
    inv_id = sample_investigation_id

    feedback_payload = {
        "category": "FALSE_POSITIVE",
        "attachment_filename": "invoice_102.pdf",
        "explanation": "This invoice is from our known recurring office supplies supplier."
    }

    resp = client.post(f"/api/investigations/{inv_id}/feedback", json=feedback_payload)
    assert resp.status_code in (200, 201)
    data = resp.json()

    assert data["investigation_id"] == inv_id
    assert data["category"] == "FALSE_POSITIVE"
    assert data["attachment_filename"] == "invoice_102.pdf"
    assert data["explanation"] == feedback_payload["explanation"]
    assert "original_prediction_snapshot" in data
    assert "overall_score" in data["original_prediction_snapshot"]
    assert "overall_rating" in data["original_prediction_snapshot"]


def test_retrieve_feedback_history(sample_investigation_id):
    """GET /api/investigations/{id}/feedback returns list of recorded feedback."""
    inv_id = sample_investigation_id

    # Post initial feedback
    client.post(
        f"/api/investigations/{inv_id}/feedback",
        json={
            "category": "INCORRECT_RISK_LEVEL",
            "attachment_filename": "invoice_102.pdf",
            "explanation": "Risk score seems slightly elevated for an authentic vendor.",
        }
    )

    # Retrieve feedback list
    get_resp = client.get(f"/api/investigations/{inv_id}/feedback")
    assert get_resp.status_code == 200
    feedback_list = get_resp.json()
    assert isinstance(feedback_list, list)
    assert len(feedback_list) >= 1
    assert any(fb["category"] == "INCORRECT_RISK_LEVEL" for fb in feedback_list)


def test_feedback_target_attachment_validation(sample_investigation_id):
    """Submitting feedback for an attachment filename that does not exist in the dossier returns 400."""
    inv_id = sample_investigation_id

    invalid_payload = {
        "category": "FALSE_POSITIVE",
        "attachment_filename": "non_existent_file.exe",
        "explanation": "This file was not in the email."
    }

    resp = client.post(f"/api/investigations/{inv_id}/feedback", json=invalid_payload)
    assert resp.status_code == 400
    assert "not found in investigation" in resp.json()["detail"].lower()


def test_feedback_anti_duplicate_protection(sample_investigation_id):
    """Submitting identical feedback within 60s returns existing record rather than duplicating."""
    inv_id = sample_investigation_id

    payload = {
        "category": "OTHER",
        "attachment_filename": None,
        "explanation": "Evaluating tone of urgency in the subject line.",
    }

    resp1 = client.post(f"/api/investigations/{inv_id}/feedback", json=payload)
    assert resp1.status_code in (200, 201)
    id1 = resp1.json()["id"]

    resp2 = client.post(f"/api/investigations/{inv_id}/feedback", json=payload)
    assert resp2.status_code in (200, 201)
    id2 = resp2.json()["id"]

    assert id1 == id2, "Duplicate feedback within 60s should return the existing feedback record ID"


def test_feedback_nonexistent_investigation():
    """Feedback for non-existent investigation ID returns 404."""
    resp = client.post(
        "/api/investigations/nonexistent-id-9999/feedback",
        json={
            "category": "FALSE_POSITIVE",
            "explanation": "Does not exist"
        }
    )
    assert resp.status_code == 404


# ============================================================================
# Deliverable 1 Tests: Granular 4-Way Risk Breakdown End-to-End
# ============================================================================

def test_granular_4_way_breakdown_end_to_end():
    """
    Scans a composite email triggering all 4 threat vectors:
    - Sender (DMARC fail / Reply-to mismatch)
    - Body (Urgency & Credential harvesting)
    - URL (IP-literal URL)
    - Attachment (Disguised executable with MZ header)
    Verifies that the API returns distinct, non-zero scores for all 4 vectors,
    and that CSV/Markdown exports correctly reflect the 4-way attribution.
    """
    raw_eml = (
        "From: admin@company-notice.com\n"
        "Reply-To: evil@external-drop.ru\n"
        "To: victim@company.com\n"
        "Subject: Urgent: Security Alert - Password Expiration\n"
        "MIME-Version: 1.0\n"
        "Authentication-Results: mx.company.com; dmarc=fail\n"
        "Content-Type: multipart/mixed; boundary=\"MULTIPART_BOUNDARY\"\n\n"
        "--MULTIPART_BOUNDARY\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "Your account will be suspended immediately. Please confirm your password at http://192.168.1.50/login.\n\n"
        "--MULTIPART_BOUNDARY\n"
        "Content-Type: application/pdf\n"
        "Content-Disposition: attachment; filename=\"security_notice.pdf\"\n\n"
        "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00FAKE_EXECUTABLE_PAYLOAD\n"
        "--MULTIPART_BOUNDARY--\n"
    )

    resp = client.post(
        "/api/analyze",
        data={"input_type": "eml", "simulate_both_fail": "true"},
        files={"file": ("composite_threat.eml", raw_eml.encode("utf-8"), "message/rfc822")}
    )
    assert resp.status_code == 200
    data = resp.json()
    inv_id = data["id"]
    risk = data["risk"]

    # Verify all 4 granular vectors are populated and non-zero
    assert risk["sender_score"] >= 20, f"Expected sender_score >= 20, got {risk['sender_score']}"
    assert risk["body_score"] >= 15, f"Expected body_score >= 15, got {risk['body_score']}"
    assert risk["url_score"] >= 25, f"Expected url_score >= 25, got {risk['url_score']}"
    assert risk["attachment_score"] >= 30, f"Expected attachment_score >= 30, got {risk['attachment_score']}"
    assert risk["overall_score"] >= 60
    assert risk["overall_rating"] == "HIGH"

    # Verify CSV export reflects the 4-way breakdown columns
    csv_resp = client.get(f"/api/investigations/{inv_id}/export?format=csv")
    assert csv_resp.status_code == 200
    csv_text = csv_resp.text
    assert "Sender Score" in csv_text
    assert "Body Score" in csv_text
    assert "URL Score" in csv_text
    assert "Attachment Score" in csv_text

    # Verify Markdown export reflects the 4-way breakdown
    md_resp = client.get(f"/api/investigations/{inv_id}/export?format=markdown")
    assert md_resp.status_code == 200
    md_text = md_resp.text
    assert "4-Way Risk Breakdown:" in md_text
    assert "Sender:" in md_text
    assert "Body:" in md_text
    assert "URLs:" in md_text
    assert "Attachments:" in md_text

