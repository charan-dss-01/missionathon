"""Tests for static QR code detection and analysis in PhishGuard AI."""

import io
import pytest
from PIL import Image
import qrcode
from unittest.mock import patch

from app.analyzers.qr_analyzer import analyze_qr, detect_image_type_by_magic, QRAnalysisResult
from app.workflow.graph import build_investigation_graph, InvestigationState
from app.engine.rule_definitions import RULE_DEFINITIONS
from app.engine.rule_metadata import RULE_METADATA


def _generate_qr_png_bytes(content: str) -> bytes:
    """Generates a harmless PNG QR code image in memory at runtime."""
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(content)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _generate_blank_png_bytes(width: int = 200, height: int = 200) -> bytes:
    """Generates a blank PNG image without any barcodes."""
    im = Image.new("RGB", (width, height), color="white")
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    return buf.getvalue()


def test_qr_rules_and_metadata_registered():
    """Verify ATT_QR_PRESENT and ATT_QR_URL_FLAGGED are properly defined and mapped."""
    assert "ATT_QR_PRESENT" in RULE_DEFINITIONS
    assert "ATT_QR_URL_FLAGGED" in RULE_DEFINITIONS
    assert RULE_DEFINITIONS["ATT_QR_PRESENT"]["severity"].value == "LOW"
    assert RULE_DEFINITIONS["ATT_QR_URL_FLAGGED"]["severity"].value == "HIGH"

    assert "ATT_QR_PRESENT" in RULE_METADATA
    assert "ATT_QR_URL_FLAGGED" in RULE_METADATA
    assert RULE_METADATA["ATT_QR_PRESENT"]["stage"] == "delivery"
    assert RULE_METADATA["ATT_QR_PRESENT"]["mitre_id"] == "T1566.002"
    assert RULE_METADATA["ATT_QR_URL_FLAGGED"]["stage"] == "delivery"
    assert RULE_METADATA["ATT_QR_URL_FLAGGED"]["mitre_id"] == "T1566.002"


def test_qr_found_and_url_flagged():
    """Test runtime QR code encoding a deceptive typosquat URL triggers both rules."""
    target_url = "https://paypa1-example.test/login"
    png_data = _generate_qr_png_bytes(target_url)

    res, evidence = analyze_qr("invoice_qr.png", png_data)

    assert res.qr_detected is True
    assert res.coverage_status == "SCANNED"
    assert target_url in res.payloads
    
    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_QR_PRESENT" in rule_ids
    assert "ATT_QR_URL_FLAGGED" in rule_ids

    # Verify URLs are defanged in supporting observations
    for ev in evidence:
        assert "https://" not in ev.supporting_observation
        assert "hxxps://" in ev.supporting_observation
        assert "[.]test" in ev.supporting_observation


def test_qr_found_benign_url_not_flagged():
    """Test runtime QR code with benign URL emits ATT_QR_PRESENT but NOT ATT_QR_URL_FLAGGED."""
    benign_url = "https://en.wikipedia.org/wiki/Main_Page"
    png_data = _generate_qr_png_bytes(benign_url)

    res, evidence = analyze_qr("event_flyer.png", png_data)

    assert res.qr_detected is True
    assert res.coverage_status == "SCANNED"
    assert benign_url in res.payloads

    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_QR_PRESENT" in rule_ids
    assert "ATT_QR_URL_FLAGGED" not in rule_ids


def test_no_qr_detected():
    """Test image with no QR code returns qr_detected=False and no QR evidence."""
    png_data = _generate_blank_png_bytes(250, 250)

    res, evidence = analyze_qr("photo.png", png_data)

    assert res.qr_detected is False
    assert res.coverage_status == "SCANNED"
    assert len(res.payloads) == 0
    assert len(evidence) == 0


def test_oversized_image_becomes_unscanned():
    """Test image exceeding 4000x4000 pixel dimensions is marked UNSCANNED before decoding."""
    oversized_data = _generate_blank_png_bytes(4200, 100)

    res, evidence = analyze_qr("huge_banner.png", oversized_data)

    assert res.qr_detected is False
    assert res.coverage_status == "UNSCANNED"
    assert "exceed safety limit" in res.limitations.lower()
    assert len(evidence) == 0


def test_library_missing_is_handled():
    """Test that when QR_AVAILABLE is False, analyze_qr skips silently with status note."""
    png_data = _generate_qr_png_bytes("https://example.com")

    with patch("app.analyzers.qr_analyzer.QR_AVAILABLE", False):
        res, evidence = analyze_qr("sample.png", png_data)

        assert res.qr_detected is False
        assert res.coverage_status == "UNKNOWN"
        assert "unavailable" in res.limitations.lower()
        assert len(evidence) == 0


@pytest.mark.asyncio
async def test_graph_end_to_end_with_qr_attachment():
    """Test that an attachment with a QR code processes through LangGraph pipeline."""
    from app.workflow.graph import investigation_graph

    target_url = "https://paypa1-example.test/login"
    qr_bytes = _generate_qr_png_bytes(target_url)

    state = {
        "investigation_id": "inv-test-qr-001",
        "input_type": "attachment",
        "raw_bytes": qr_bytes,
        "file_name": "paypa1_login_qr.png",
        "raw_content": "",
        "force_fallback": False,
        "simulate_both_fail": True,
        "trace": []
    }

    final_output = await investigation_graph.ainvoke(state)

    result = final_output.get("final_result")
    assert result is not None
    assert result.status == "COMPLETED"
    
    # Evidence contains QR rules
    rule_ids = [e.rule_id for e in result.evidence]
    assert "ATT_QR_PRESENT" in rule_ids
    assert "ATT_QR_URL_FLAGGED" in rule_ids

    # Overall score incorporates high severity QR finding
    assert result.risk.overall_score >= 30
    assert result.risk.attachment_score >= 30
