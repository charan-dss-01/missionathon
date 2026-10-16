"""Ensures zero network access or outbound socket communication during static analysis."""

import socket
import pytest
from pathlib import Path
from unittest.mock import patch
import io
import qrcode

from app.workflow.graph import investigation_graph
from app.models.schemas import RiskRatingEnum

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _blocked_connect(self, address):
    raise RuntimeError(f"Forbidden outbound network connection attempted to {address} during static analysis!")


def _blocked_dns(*args, **kwargs):
    raise RuntimeError(f"Forbidden DNS resolution attempted for {args} during static analysis!")


@pytest.mark.asyncio
async def test_zero_network_during_all_corpus_analysis():
    """
    Patches socket.socket.connect and socket.getaddrinfo to assert that the entire
    investigation pipeline executes strictly offline with zero remote DNS lookups
    or network connections.
    """
    fixture_files = ["benign.eml", "reply_to_mismatch.eml", "auth_failure.eml", "url_mismatch.eml"]

    with patch.object(socket.socket, "connect", _blocked_connect), \
         patch("socket.getaddrinfo", _blocked_dns):

        # 1. Analyze every corpus email fixture
        for f_name in fixture_files:
            file_path = FIXTURES_DIR / f_name
            with open(file_path, "rb") as f:
                raw_bytes = f.read()

            state = {
                "raw_bytes": raw_bytes,
                "input_type": "eml",
                "file_name": f_name,
                "simulate_both_fail": True,
                "trace": []
            }
            res = await investigation_graph.ainvoke(state)
            assert res["final_result"].status == "COMPLETED"

        # 2. Analyze raw text with embedded URLs and credentials
        text_state = {
            "raw_content": (
                "From: security@paypal-verify.com\n"
                "Subject: Immediate action required\n\n"
                "Please verify your account at https://paypa1-example.test/login or direct IP http://192.168.1.100/auth"
            ),
            "input_type": "raw_text",
            "simulate_both_fail": True,
            "trace": []
        }
        res_text = await investigation_graph.ainvoke(text_state)
        assert res_text["final_result"].status == "COMPLETED"
        assert res_text["final_result"].risk.overall_score >= 30

        # 3. Analyze QR code attachment (with suspicious typosquat URL)
        qr = qrcode.QRCode(box_size=10, border=4)
        qr.add_data("https://paypa1-example.test/login")
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_bytes = buf.getvalue()

        qr_state = {
            "raw_bytes": qr_bytes,
            "input_type": "attachment",
            "file_name": "qr_code.png",
            "simulate_both_fail": True,
            "trace": []
        }
        res_qr = await investigation_graph.ainvoke(qr_state)
        assert res_qr["final_result"].status == "COMPLETED"
        qr_rules = [e.rule_id for e in res_qr["final_result"].evidence]
        assert "ATT_QR_PRESENT" in qr_rules
        assert "ATT_QR_URL_FLAGGED" in qr_rules

        # 4. Standalone direct URL analysis
        url_state = {
            "raw_content": "https://paypa1-example.test/login",
            "input_type": "url",
            "simulate_both_fail": True,
            "trace": []
        }
        res_url = await investigation_graph.ainvoke(url_state)
        assert res_url["final_result"].status == "COMPLETED"
