import pytest
from app.services.evidence_validator import EvidenceValidator
from app.models.schemas import EvidenceRecord, SeverityEnum

def test_evidence_validator_accepts_valid_rules():
    authoritative_evidence = [
        EvidenceRecord(
            rule_id="URL_TEXT_HREF_MISMATCH",
            category="urls",
            title="Mismatch",
            severity=SeverityEnum.CRITICAL,
            description="desc",
            supporting_observation="obs"
        )
    ]
    raw_interpretation = {
        "summary": "Suspicious email with link mismatch.",
        "evidence_ids": ["URL_TEXT_HREF_MISMATCH"]
    }
    validated, rejected = EvidenceValidator.validate_interpretation(raw_interpretation, authoritative_evidence)
    assert "URL_TEXT_HREF_MISMATCH" in validated
    assert len(rejected) == 0

def test_evidence_validator_rejects_hallucinations():
    authoritative_evidence = []
    raw_interpretation = {
        "summary": "This is a malicious ransomware campaign.",
        "evidence_ids": ["FICTIONAL_EXPLOIT_RULE", "ZERO_DAY_RULE_999"]
    }
    validated, rejected = EvidenceValidator.validate_interpretation(raw_interpretation, authoritative_evidence)
    assert len(validated) == 0
    assert len(rejected) >= 2
    assert any("FICTIONAL_EXPLOIT_RULE" in r for r in rejected)
