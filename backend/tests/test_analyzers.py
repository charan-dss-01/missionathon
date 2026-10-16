import io
import zipfile
import pytest
from app.analyzers.email_parser import EmailParser
from app.analyzers.header_analyzer import HeaderAnalyzer
from app.analyzers.body_analyzer import BodyAnalyzer
from app.analyzers.url_analyzer import URLAnalyzer
from app.analyzers.attachment_analyzer import AttachmentAnalyzer
from app.models.schemas import EmailMetadata, RecordedAuthResults, RiskRatingEnum, AttachmentFinding
from app.engine.risk_engine import RiskEngine

def test_benign_email_parsing():
    raw_email = """From: "HR Team" <hr@company.com>
To: employee@company.com
Subject: Open Enrollment Notice
Date: Mon, 16 Oct 2026 09:00:00 +0000
Authentication-Results: spf=pass dkim=pass dmarc=pass

Please remember that annual benefits enrollment begins next Monday.
"""
    meta, plain, html, atts = EmailParser.parse_raw_text(raw_email)
    assert meta.sender == "hr@company.com"
    assert meta.sender_domain == "company.com"
    assert meta.recorded_auth.spf_result == "PASS"

    evidence = HeaderAnalyzer.analyze(meta)
    # Benign email should have no header spoofing evidence
    assert len(evidence) == 0

def test_reply_to_mismatch():
    meta = EmailMetadata(
        sender="billing@trusted-vendor.com",
        sender_domain="trusted-vendor.com",
        reply_to="attacker@malicious-drop.net",
        subject="Updated Banking Information",
        recorded_auth=RecordedAuthResults(spf_result="PASS")
    )
    evidence = HeaderAnalyzer.analyze(meta)
    rule_ids = [e.rule_id for e in evidence]
    assert "HDR_REPLYTO_MISMATCH" in rule_ids

def test_recorded_dmarc_and_spf_failure():
    meta = EmailMetadata(
        sender="admin@paypal.com",
        sender_domain="paypal.com",
        display_name="PayPal Support",
        subject="Account Suspended",
        recorded_auth=RecordedAuthResults(spf_result="FAIL", dmarc_result="FAIL")
    )
    evidence = HeaderAnalyzer.analyze(meta)
    rule_ids = [e.rule_id for e in evidence]
    assert "AUTH_SPF_FAIL" in rule_ids
    assert "AUTH_DMARC_FAIL" in rule_ids

def test_display_name_spoofing():
    meta = EmailMetadata(
        sender="hacker123@free-webmail.org",
        sender_domain="free-webmail.org",
        display_name="Microsoft Security Team",
        subject="Password Expiry"
    )
    evidence = HeaderAnalyzer.analyze(meta)
    rule_ids = [e.rule_id for e in evidence]
    assert "HDR_DISPLAY_NAME_SPOOF" in rule_ids

def test_body_urgency_and_credential_harvesting():
    plain = "Immediate action required: Your account will be suspended within 24 hours. Confirm your password now."
    evidence, urls = BodyAnalyzer.analyze(plain, "")
    rule_ids = [e.rule_id for e in evidence]
    assert "BODY_URGENCY_PRESSURE" in rule_ids
    assert "BODY_CREDENTIAL_HARVEST" in rule_ids

def test_html_anchor_text_href_mismatch():
    html = """<html><body>
    <p>Please log in to verify your account: <a href="http://evil-attacker-site.com/steal">https://paypal.com/signin</a></p>
    </body></html>"""
    evidence, urls = BodyAnalyzer.analyze("", html)
    rule_ids = [e.rule_id for e in evidence]
    assert "URL_TEXT_HREF_MISMATCH" in rule_ids

def test_url_analyzer_ip_and_punycode():
    url_items = [
        {"url": "http://192.168.1.100/login", "display_text": ""},
        {"url": "https://xn--pple-43d.com/store", "display_text": ""},
        {"url": "https://user:pass@legit.com/portal", "display_text": ""},
        {"url": "https://paypal.com.account-verification-service.net/login", "display_text": ""}
    ]
    findings, evidence = URLAnalyzer.analyze_urls(url_items)
    assert len(findings) == 4
    rule_ids = [e.rule_id for e in evidence]
    assert "URL_IP_LITERAL" in rule_ids
    assert "URL_PUNYCODE_CONFUSABLE" in rule_ids
    assert "URL_USERINFO_EMBEDDED" in rule_ids
    assert "URL_DECEPTIVE_SUBDOMAIN" in rule_ids

def test_attachment_dangerous_and_double_extension():
    # Double extension: Invoice.pdf.exe
    sample_exe = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 50
    findings, evidence = AttachmentAnalyzer.analyze_attachments([
        {"filename": "Invoice.pdf.exe", "bytes": sample_exe, "content_type": "application/x-msdownload"}
    ])
    assert len(findings) == 1
    assert findings[0].dangerous_extension is True
    assert findings[0].double_extension is True
    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_DANGEROUS_EXT" in rule_ids
    assert "ATT_DOUBLE_EXT" in rule_ids

def test_attachment_rtlo():
    # Right to left override character in filename
    rtlo_filename = "Quarterly_Report\u202egdp.exe"
    findings, evidence = AttachmentAnalyzer.analyze_attachments([
        {"filename": rtlo_filename, "bytes": b"clean text data", "content_type": "text/plain"}
    ])
    assert findings[0].rtlo_detected is True
    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_RTLO_DETECTED" in rule_ids

def test_attachment_mime_magic_mismatch():
    # File claims to be .pdf, but contains Windows PE "MZ" magic bytes
    fake_pdf = b"MZ\x90\x00\x03\x00" + b"\x00" * 100
    findings, evidence = AttachmentAnalyzer.analyze_attachments([
        {"filename": "Scanned_Contract.pdf", "bytes": fake_pdf, "content_type": "application/pdf"}
    ])
    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_MIME_MISMATCH" in rule_ids

def test_attachment_pdf_active_content():
    # PDF containing /JavaScript and /OpenAction
    pdf_payload = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1);) >> >>\nendobj\n%%EOF"
    findings, evidence = AttachmentAnalyzer.analyze_attachments([
        {"filename": "Brochure.pdf", "bytes": pdf_payload, "content_type": "application/pdf"}
    ])
    assert findings[0].active_content_detected is True
    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_PDF_ACTIVE_CONTENT" in rule_ids

def test_unsupported_file_coverage():
    # Random unidentifiable binary bytes
    unsupported_data = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe" * 20
    findings, evidence = AttachmentAnalyzer.analyze_attachments([
        {"filename": "proprietary_firmware.bin", "bytes": unsupported_data, "content_type": "application/octet-stream"}
    ])
    assert findings[0].coverage_status == "UNSUPPORTED"
    assert findings[0].detected_type == "UNKNOWN"

def test_header_auth_none():
    raw_email = """From: "Marketing Newsletter" <news@unauthenticated-domain.org>
To: recipient@company.com
Subject: Weekly Digest
Date: Mon, 16 Oct 2026 10:00:00 +0000
Authentication-Results: spf=none dkim=none dmarc=none

Here is your weekly news update.
"""
    meta, plain, html, atts = EmailParser.parse_raw_text(raw_email)
    evidence = HeaderAnalyzer.analyze(meta)
    rule_ids = [e.rule_id for e in evidence]
    assert "AUTH_SPF_NONE" in rule_ids
    assert "AUTH_DKIM_NONE" in rule_ids
    assert "AUTH_DMARC_NONE" in rule_ids

def test_declared_mime_mismatch():
    # Declares image/png but sends .exe with MZ magic bytes
    findings, evidence = AttachmentAnalyzer.analyze_attachments([
        {"filename": "vacation_photo.exe", "bytes": b"MZ\x90\x00" + b"\x00" * 50, "content_type": "image/png"}
    ])
    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_MIME_DECLARED_MISMATCH" in rule_ids

def test_pdf_embedded_file():
    pdf_payload = b"%PDF-1.5\n1 0 obj\n<< /Type /Filespec /F (payload.exe) /EF << /F 2 0 R >> /EmbeddedFile >>\nendobj\n%%EOF"
    findings, evidence = AttachmentAnalyzer.analyze_attachments([
        {"filename": "Invoice_Details.pdf", "bytes": pdf_payload, "content_type": "application/pdf"}
    ])
    assert findings[0].active_content_detected is True
    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_PDF_ACTIVE_CONTENT" in rule_ids

def test_office_macro_extension():
    findings, evidence = AttachmentAnalyzer.analyze_attachments([
        {"filename": "Payroll_Calculations.xlsm", "bytes": b"PK\x03\x04" + b"\x00" * 50, "content_type": "application/vnd.ms-excel.sheet.macroEnabled.12"}
    ])
    assert findings[0].macro_detected is True
    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_OFFICE_MACRO_EXT" in rule_ids

def test_html_smuggling_indicators():
    html_payload = b'<!DOCTYPE html><html><body><script>var blob = new Blob(["malicious"], {type: "application/octet-stream"});var url = URL.createObjectURL(blob);var a = document.createElement("a");a.href = url;a.download = "update.exe";a.click();</script></body></html>'
    findings, evidence = AttachmentAnalyzer.analyze_attachments([
        {"filename": "statement.html", "bytes": html_payload, "content_type": "text/html"}
    ])
    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_HTML_SMUGGLING" in rule_ids

def test_archive_encrypted_and_password_in_body():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr("secret.doc", b"encrypted content")
    b = bytearray(buf.getvalue())
    b[6] |= 1
    cd_idx = b.find(b"PK\x01\x02")
    if cd_idx != -1:
        b[cd_idx + 8] |= 1
    zip_bytes = bytes(b)

    findings, evidence = AttachmentAnalyzer.analyze_attachments(
        [{"filename": "confidential_archive.zip", "bytes": zip_bytes, "content_type": "application/zip"}],
        email_body="Hello, please find the attached confidential archive. The password to extract is: Spring2026!"
    )
    assert findings[0].encrypted is True
    assert findings[0].coverage_status == "UNKNOWN"
    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_ARCHIVE_ENCRYPTED" in rule_ids
    assert "ATT_ARCHIVE_PASSWORD_IN_BODY" in rule_ids

def test_archive_nested():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr("inner_payload.zip", b"PK\x03\x04" + b"\x00" * 30)
        zf.writestr("notes.txt", b"simple notes")
    zip_bytes = buf.getvalue()

    findings, evidence = AttachmentAnalyzer.analyze_attachments([
        {"filename": "outer_bundle.zip", "bytes": zip_bytes, "content_type": "application/zip"}
    ])
    assert findings[0].nested_archive_count >= 1
    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_ARCHIVE_NESTED" in rule_ids

def test_archive_corrupt_unknown():
    # Corrupt ZIP header: starts with PK\x03\x04 but followed by garbage
    corrupt_zip = b"PK\x03\x04" + b"\xff\xfe\xfd\xfc" * 20
    findings, evidence = AttachmentAnalyzer.analyze_attachments([
        {"filename": "broken_transfer.zip", "bytes": corrupt_zip, "content_type": "application/zip"}
    ])
    assert findings[0].coverage_status in ["CORRUPT", "UNKNOWN"]
    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_CORRUPT_OR_UNPARSEABLE" in rule_ids

def test_attachment_count_limit():
    attachments = [
        {"filename": f"file_{i}.txt", "bytes": b"sample text", "content_type": "text/plain"}
        for i in range(15)
    ]
    findings, evidence = AttachmentAnalyzer.analyze_attachments(attachments)
    assert len(findings) == 15
    for f in findings[10:]:
        assert f.coverage_status == "UNSCANNED"
    rule_ids = [e.rule_id for e in evidence]
    assert "ATT_LIMIT_EXCEEDED" in rule_ids

def test_risk_engine_unscanned_never_safe():
    unscanned_att = AttachmentFinding(
        filename="huge_file.iso",
        detected_type="OVERSIZED",
        size_bytes=10000000,
        coverage_status="OVERSIZED",
        limitations="Exceeds limit"
    )
    risk = RiskEngine.calculate(evidence=[], attachments=[unscanned_att], has_email_body=True)
    # Must never be LOW or SAFE
    assert risk.overall_rating == RiskRatingEnum.UNSCANNED
    assert "never SAFE" in risk.scoring_explanation
