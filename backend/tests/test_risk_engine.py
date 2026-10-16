import pytest
from app.engine.risk_engine import RiskEngine
from app.models.schemas import EvidenceRecord, SeverityEnum, ConfidenceEnum, RiskRatingEnum, AttachmentFinding

def test_clean_input_zero_score():
    risk = RiskEngine.calculate(
        evidence=[],
        attachments=[],
        has_email_body=True,
        has_headers=True
    )
    assert risk.overall_score == 0
    assert risk.overall_rating == RiskRatingEnum.LOW

def test_high_risk_scoring():
    ev = [
        EvidenceRecord(
            rule_id="URL_TEXT_HREF_MISMATCH",
            category="urls",
            title="Deceptive Anchor Mismatch",
            severity=SeverityEnum.CRITICAL,
            description="Mismatch",
            supporting_observation="Obs"
        ),
        EvidenceRecord(
            rule_id="BODY_CREDENTIAL_HARVEST",
            category="body",
            title="Credential Solicitation",
            severity=SeverityEnum.HIGH,
            description="Harvesting",
            supporting_observation="Obs"
        )
    ]
    risk = RiskEngine.calculate(evidence=ev, attachments=[])
    assert risk.overall_score >= 60
    assert risk.overall_rating == RiskRatingEnum.HIGH

def test_unsupported_attachment_coverage_notice():
    att = AttachmentFinding(
        filename="custom.dat",
        detected_type="UNKNOWN",
        coverage_status="UNSUPPORTED"
    )
    risk = RiskEngine.calculate(evidence=[], attachments=[att])
    assert risk.coverage_status.value == "PARTIAL"


def test_granular_4_way_risk_breakdown():
    """Verify that sender, body, url, and attachment vectors are calculated independently and accurately."""
    ev = [
        # Sender vector: headers (20) + auth (30) = 50
        EvidenceRecord(
            rule_id="HDR_REPLYTO_MISMATCH",
            category="headers",
            title="Reply-To Mismatch",
            severity=SeverityEnum.MEDIUM,
            description="From vs Reply-To divergence",
            supporting_observation="Obs"
        ),
        EvidenceRecord(
            rule_id="AUTH_DMARC_FAIL",
            category="authentication",
            title="DMARC Policy Rejection",
            severity=SeverityEnum.HIGH,
            description="DMARC failed",
            supporting_observation="Obs"
        ),
        # Body vector: urgency (15) = 15
        EvidenceRecord(
            rule_id="BODY_URGENCY_PRESSURE",
            category="body",
            title="Urgency Pressure",
            severity=SeverityEnum.MEDIUM,
            description="Coercive language",
            supporting_observation="Obs"
        ),
        # URL vector: deceptive anchor (35) = 35
        EvidenceRecord(
            rule_id="URL_TEXT_HREF_MISMATCH",
            category="urls",
            title="Anchor vs Destination Mismatch",
            severity=SeverityEnum.CRITICAL,
            description="Deceptive link",
            supporting_observation="Obs"
        ),
        # Attachment vector: MIME mismatch (40) = 40
        EvidenceRecord(
            rule_id="ATT_MIME_MISMATCH",
            category="attachments",
            title="MIME Extension Signature Mismatch",
            severity=SeverityEnum.CRITICAL,
            description="Disguised executable",
            supporting_observation="Obs"
        )
    ]

    att = AttachmentFinding(
        filename="invoice.pdf",
        detected_type="Windows PE Executable (.exe/.dll/.scr)",
        coverage_status="SCANNED"
    )

    risk = RiskEngine.calculate(evidence=ev, attachments=[att])

    assert risk.sender_score == 50
    assert risk.body_score == 15
    assert risk.url_score == 35
    assert risk.attachment_score == 30
    assert risk.email_score == 100  # Combined sender (50) + body (15) + url (35)
    assert risk.overall_score >= 60
    assert risk.overall_rating == RiskRatingEnum.HIGH

