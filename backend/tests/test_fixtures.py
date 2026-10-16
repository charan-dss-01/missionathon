import os
from pathlib import Path
import pytest
from app.workflow.graph import investigation_graph
from app.models.schemas import RiskRatingEnum
from app.analyzers.attachment_analyzer import AttachmentAnalyzer

FIXTURES_DIR = Path(__file__).parent / "fixtures"

@pytest.mark.asyncio
async def test_fixture_benign_email():
    with open(FIXTURES_DIR / "benign.eml", "rb") as f:
        raw_bytes = f.read()
    
    state = {
        "raw_bytes": raw_bytes,
        "input_type": "eml",
        "file_name": "benign.eml",
        "simulate_both_fail": True,
        "trace": []
    }
    result_state = await investigation_graph.ainvoke(state)
    result = result_state["final_result"]

    assert result.status == "COMPLETED"
    assert result.risk.overall_rating == RiskRatingEnum.LOW
    assert len(result.evidence) == 0
    assert result.risk.overall_score < 30

@pytest.mark.asyncio
async def test_fixture_reply_to_mismatch():
    with open(FIXTURES_DIR / "reply_to_mismatch.eml", "rb") as f:
        raw_bytes = f.read()

    state = {
        "raw_bytes": raw_bytes,
        "input_type": "eml",
        "file_name": "reply_to_mismatch.eml",
        "simulate_both_fail": True,
        "trace": []
    }
    result_state = await investigation_graph.ainvoke(state)
    result = result_state["final_result"]

    rule_ids = [e.rule_id for e in result.evidence]
    assert "HDR_REPLYTO_MISMATCH" in rule_ids

@pytest.mark.asyncio
async def test_fixture_auth_failure():
    with open(FIXTURES_DIR / "auth_failure.eml", "rb") as f:
        raw_bytes = f.read()

    state = {
        "raw_bytes": raw_bytes,
        "input_type": "eml",
        "file_name": "auth_failure.eml",
        "simulate_both_fail": True,
        "trace": []
    }
    result_state = await investigation_graph.ainvoke(state)
    result = result_state["final_result"]

    rule_ids = [e.rule_id for e in result.evidence]
    assert "AUTH_SPF_FAIL" in rule_ids
    assert "AUTH_DMARC_FAIL" in rule_ids
    assert result.risk.overall_score >= 50

@pytest.mark.asyncio
async def test_fixture_url_mismatch():
    with open(FIXTURES_DIR / "url_mismatch.eml", "rb") as f:
        raw_bytes = f.read()

    state = {
        "raw_bytes": raw_bytes,
        "input_type": "eml",
        "file_name": "url_mismatch.eml",
        "simulate_both_fail": True,
        "trace": []
    }
    result_state = await investigation_graph.ainvoke(state)
    result = result_state["final_result"]

    rule_ids = [e.rule_id for e in result.evidence]
    assert "URL_TEXT_HREF_MISMATCH" in rule_ids
    assert result.risk.overall_score >= 35

def test_fixture_mime_signature_mismatch():
    # PDF extension with Windows PE executable magic bytes
    fake_exe_pdf = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 128
    findings, evidence = AttachmentAnalyzer.analyze_attachments([{
        "filename": "Payroll_Update.pdf",
        "bytes": fake_exe_pdf,
        "content_type": "application/pdf"
    }])
    assert len(findings) == 1
    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_MIME_MISMATCH" in rule_ids

def test_fixture_oversized_input_bounded():
    # File exceeding 5MB limit
    oversized_data = b"0" * (6 * 1024 * 1024)
    findings, evidence = AttachmentAnalyzer.analyze_attachments([{
        "filename": "huge_dump.iso",
        "bytes": oversized_data,
        "content_type": "application/octet-stream"
    }])
    assert findings[0].coverage_status == "OVERSIZED"
    assert findings[0].detected_type == "OVERSIZED"


@pytest.mark.asyncio
async def test_baseline_snapshot():
    """Confirms score snapshot baseline is completely unchanged for existing fixtures."""
    expected_snapshots = {
        "benign.eml": {"overall_score": 0, "rating": RiskRatingEnum.LOW, "rules": []},
        "reply_to_mismatch.eml": {"overall_score": 20, "rating": RiskRatingEnum.LOW, "rules": ["HDR_REPLYTO_MISMATCH"]},
        "auth_failure.eml": {"overall_score": 95, "rating": RiskRatingEnum.HIGH, "rules": ["AUTH_SPF_FAIL", "AUTH_DMARC_FAIL", "BODY_URGENCY_PRESSURE", "BODY_CREDENTIAL_HARVEST"]},
        "url_mismatch.eml": {"overall_score": 85, "rating": RiskRatingEnum.HIGH, "rules": ["HDR_DISPLAY_NAME_SPOOF", "URL_TEXT_HREF_MISMATCH", "URL_DECEPTIVE_SUBDOMAIN"]}
    }

    for f_name, snap in expected_snapshots.items():
        with open(FIXTURES_DIR / f_name, "rb") as f:
            raw_bytes = f.read()

        state = {
            "raw_bytes": raw_bytes,
            "input_type": "eml",
            "file_name": f_name,
            "simulate_both_fail": True,
            "trace": []
        }
        result_state = await investigation_graph.ainvoke(state)
        result = result_state["final_result"]

        assert result.risk.overall_score == snap["overall_score"], f"{f_name} score diverged: expected {snap['overall_score']}, got {result.risk.overall_score}"
        assert result.risk.overall_rating == snap["rating"], f"{f_name} rating diverged"
        actual_rules = [e.rule_id for e in result.evidence]
        assert set(actual_rules) == set(snap["rules"]), f"{f_name} rules diverged: expected {snap['rules']}, got {actual_rules}"

