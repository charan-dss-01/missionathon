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
