import pytest
from pathlib import Path
from app.workflow.graph import investigation_graph
from app.models.schemas import (
    EmailMetadata,
    URLFinding,
    AttachmentFinding,
    EvidenceRecord,
    SeverityEnum,
    ConfidenceEnum,
    InvestigationResult,
    ComponentRisk,
    RiskRatingEnum,
    LLMInterpretation,
    Insights
)
from app.services.insights_builder import build_insights
from app.config import settings

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.mark.asyncio
async def test_insights_on_reply_to_mismatch_fixture():
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
    result: InvestigationResult = result_state["final_result"]

    assert result.insights is not None
    deceptions = result.insights.deceptions
    assert any(d.kind == "reply_to_mismatch" for d in deceptions)

    reply_dec = next(d for d in deceptions if d.kind == "reply_to_mismatch")
    assert "HDR_REPLYTO_MISMATCH" in reply_dec.rule_ids
    assert reply_dec.shown != reply_dec.actual

    # Verify timeline contains deception stage
    stages = [step.stage for step in result.insights.timeline]
    assert "deception" in stages
    deception_step = next(s for s in result.insights.timeline if s.stage == "deception")
    assert "HDR_REPLYTO_MISMATCH" in deception_step.rule_ids
    assert "T1036" in deception_step.mitre_ids
    assert len(deception_step.summary) > 0


@pytest.mark.asyncio
async def test_insights_on_url_mismatch_fixture():
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
    result: InvestigationResult = result_state["final_result"]

    assert result.insights is not None
    link_deceptions = [d for d in result.insights.deceptions if d.kind == "link_text_vs_href"]
    assert len(link_deceptions) > 0
    dec = link_deceptions[0]
    # Defanged checks: should use hxxp/hxxps and [.]
    assert "hxxp" in dec.shown or "hxxp" in dec.actual
    assert "[.]" in dec.shown or "[.]" in dec.actual


@pytest.mark.asyncio
async def test_insights_on_benign_fixture_empty_stages():
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
    result: InvestigationResult = result_state["final_result"]

    assert result.insights is not None
    # Benign email should have no deceptions and no timeline steps (empty stages skipped)
    assert len(result.insights.deceptions) == 0
    assert len(result.insights.timeline) == 0
    assert result.risk.overall_score < 30


def test_build_insights_deception_variants_inline():
    """Assert all 5 deception types are correctly extracted and populated."""
    meta = EmailMetadata(
        sender="attacker@evil-domain.com",
        sender_domain="evil-domain.com",
        display_name="Microsoft 365 Security Team",
        reply_to="stealth@external-inbox.com"
    )

    url_findings = [
        URLFinding(
            url="https://evil-credential-harvest.com/login",
            display_text="https://login.microsoftonline.com",
            domain="evil-credential-harvest.com",
            is_text_mismatch=True,
            matched_rules=["URL_TEXT_HREF_MISMATCH"]
        )
    ]

    attachment_findings = [
        AttachmentFinding(
            filename="financial_summary\u202epdf.exe",
            detected_type="Windows PE Executable (.exe/.dll/.scr)",
            rtlo_detected=True,
            matched_rules=["ATT_RTLO_DETECTED", "ATT_MIME_MISMATCH", "ATT_DANGEROUS_EXT"]
        )
    ]

    evidence_records = [
        EvidenceRecord(
            rule_id="HDR_DISPLAY_NAME_SPOOF",
            category="headers",
            title="Display Name Spoof",
            severity=SeverityEnum.HIGH,
            description="Display name spoofing",
            supporting_observation="Spoofed display name",
            source_location="Headers: From"
        ),
        EvidenceRecord(
            rule_id="HDR_REPLYTO_MISMATCH",
            category="headers",
            title="Reply-To Mismatch",
            severity=SeverityEnum.MEDIUM,
            description="Reply-To diversion",
            supporting_observation="Diverted reply-to",
            source_location="Headers: Reply-To"
        ),
        EvidenceRecord(
            rule_id="BODY_URGENCY_PRESSURE",
            category="body",
            title="High Urgency",
            severity=SeverityEnum.MEDIUM,
            description="Urgent coercion",
            supporting_observation="Immediate suspension threat",
            source_location="Body text line 4"
        ),
        EvidenceRecord(
            rule_id="URL_TEXT_HREF_MISMATCH",
            category="urls",
            title="Anchor Mismatch",
            severity=SeverityEnum.CRITICAL,
            description="Mismatch link",
            supporting_observation="Deceptive link",
            source_location="URL: https://evil-credential-harvest.com/login"
        ),
        EvidenceRecord(
            rule_id="ATT_RTLO_DETECTED",
            category="attachments",
            title="RTLO Detected",
            severity=SeverityEnum.CRITICAL,
            description="Right to left override",
            supporting_observation="RTLO found in filename",
            source_location="Attachment: financial_summary\u202epdf.exe"
        ),
        EvidenceRecord(
            rule_id="ATT_MIME_MISMATCH",
            category="attachments",
            title="MIME Mismatch",
            severity=SeverityEnum.HIGH,
            description="MIME mismatch",
            supporting_observation="Executable disguised as pdf",
            source_location="Attachment: financial_summary\u202epdf.exe"
        ),
        EvidenceRecord(
            rule_id="ATT_DANGEROUS_EXT",
            category="attachments",
            title="Dangerous Executable Extension",
            severity=SeverityEnum.CRITICAL,
            description="High risk executable extension",
            supporting_observation="Executable .exe found",
            source_location="Attachment: financial_summary\u202epdf.exe"
        ),
        EvidenceRecord(
            rule_id="BODY_CREDENTIAL_HARVEST",
            category="body",
            title="Credential Harvest",
            severity=SeverityEnum.HIGH,
            description="Password solicitation",
            supporting_observation="Requests password entry",
            source_location="Body line 12"
        )
    ]

    insights: Insights = build_insights(
        metadata=meta,
        plain_body="Urgent action required! Enter credentials immediately.",
        html_body="",
        url_findings=url_findings,
        attachment_findings=attachment_findings,
        evidence_records=evidence_records
    )

    kinds = [d.kind for d in insights.deceptions]
    assert "display_name_spoof" in kinds
    assert "reply_to_mismatch" in kinds
    assert "link_text_vs_href" in kinds
    assert "rtlo_override" in kinds
    assert "extension_vs_detected_type" in kinds

    # Verify RTLO removal in actual
    rtlo_dec = next(d for d in insights.deceptions if d.kind == "rtlo_override")
    assert "\u202e" not in rtlo_dec.actual
    assert rtlo_dec.actual == "financial_summarypdf.exe"

    # Verify link defanging in link_text_vs_href
    link_dec = next(d for d in insights.deceptions if d.kind == "link_text_vs_href")
    assert "hxxps://" in link_dec.shown
    assert "hxxps://" in link_dec.actual
    assert "[.]" in link_dec.actual

    # Verify clues: check regions
    clue_regions = {c.region for c in insights.clues}
    assert "header" in clue_regions
    assert "body" in clue_regions
    assert "link" in clue_regions
    assert "attachment" in clue_regions

    # Verify timeline order: strictly lure -> deception -> delivery -> action
    stage_sequence = [step.stage for step in insights.timeline]
    expected_sequence = ["lure", "deception", "delivery", "action"]
    assert stage_sequence == expected_sequence

    # Verify mitre_ids in timeline steps
    for step in insights.timeline:
        assert isinstance(step.summary, str) and len(step.summary) > 0
        assert len(step.rule_ids) > 0


def test_investigation_result_serialization_when_insights_none():
    """Assert exports and schemas function seamlessly when insights is None."""
    result = InvestigationResult(
        id="inv-test-none",
        input_type="raw_text",
        status="COMPLETED",
        risk=ComponentRisk(overall_score=10, overall_rating=RiskRatingEnum.LOW),
        evidence=[],
        llm_interpretation=LLMInterpretation(
            summary="Clean text",
            attack_vector="None",
            targeted_assets=[],
            actionable_recommendations=[],
            limitations=[]
        ),
        insights=None
    )
    dumped = result.model_dump()
    assert dumped["insights"] is None

    # Re-instantiate from dict without errors
    recreated = InvestigationResult(**dumped)
    assert recreated.insights is None
