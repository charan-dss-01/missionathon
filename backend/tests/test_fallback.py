import pytest
from app.services.llm_router import LLMRouter
from app.models.schemas import EvidenceRecord, ComponentRisk, RiskRatingEnum, SeverityEnum
from app.workflow.graph import investigation_graph

@pytest.mark.asyncio
async def test_llm_router_redaction():
    text = "Secret token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9. Password: MySecretPassword123! Card: 4111 2222 3333 4444"
    redacted = LLMRouter.redact_sensitive_data(text)
    assert "[REDACTED_TOKEN]" in redacted
    assert "[REDACTED_PASSWORD]" in redacted
    assert "[REDACTED_CARD_NUMBER]" in redacted
    assert "MySecretPassword123!" not in redacted

@pytest.mark.asyncio
async def test_deterministic_fallback_when_both_fail():
    ev = [
        EvidenceRecord(
            rule_id="BODY_CREDENTIAL_HARVEST",
            category="body",
            title="Credential Solicitation",
            severity=SeverityEnum.HIGH,
            description="Solicitation",
            supporting_observation="Obs"
        )
    ]
    risk = ComponentRisk(
        email_score=75,
        attachment_score=0,
        overall_score=75,
        overall_rating=RiskRatingEnum.HIGH
    )
    interpretation = await LLMRouter.interpret(
        evidence=ev,
        risk=risk,
        email_metadata=None,
        plain_body="Enter your password here",
        simulate_both_fail=True
    )
    assert interpretation.provider_used == "template"
    assert interpretation.fallback_used is True
    assert "Simulated provider failure" in interpretation.fallback_reason
    assert len(interpretation.actionable_recommendations) > 0
    assert "BODY_CREDENTIAL_HARVEST" in interpretation.validated_evidence_ids

@pytest.mark.asyncio
async def test_end_to_end_graph_execution_with_fallback():
    # Run graph with simulated provider fallback
    state = {
        "raw_content": "Subject: Test\nFrom: user@test.local\n\nPlease confirm your password immediately: https://evil.com",
        "raw_bytes": None,
        "input_type": "raw_text",
        "simulate_both_fail": True,
        "trace": []
    }
    result_state = await investigation_graph.ainvoke(state)
    final_res = result_state.get("final_result")
    assert final_res is not None
    assert final_res.status == "COMPLETED"
    assert final_res.llm_interpretation.fallback_used is True
    assert len(final_res.trace) == 10
    # Every step in trace should be completed or skipped
    for step in final_res.trace:
        assert step.status.value in ["COMPLETED", "SKIPPED"]
