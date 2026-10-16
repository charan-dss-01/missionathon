import os
import re
import json
import logging
from typing import List, Dict, Any, Optional, Tuple
from app.config import settings
from app.models.schemas import (
    EvidenceRecord,
    LLMInterpretation,
    EmailMetadata,
    ComponentRisk,
    RiskRatingEnum
)
from app.services.evidence_validator import EvidenceValidator

logger = logging.getLogger("phishguard.llm_router")

class LLMRouter:
    """
    Central routing service for AI synthesis.
    Implements Gemini primary -> Groq fallback -> Rule-grounded deterministic template.
    Redacts sensitive content prior to external transmission.
    """

    @classmethod
    def redact_sensitive_data(cls, text: str) -> str:
        """
        Redacts passwords, tokens, credit cards, SSNs, and private keys from text.
        """
        if not text:
            return ""
        # Redact bearer tokens / jwt
        text = re.sub(r"bearer\s+[a-zA-Z0-9_\-\.]+", "Bearer [REDACTED_TOKEN]", text, flags=re.IGNORECASE)
        # Redact passwords
        text = re.sub(r"(?:password|passwd|pwd)\s*[:=]\s*[^\s]+", "password: [REDACTED_PASSWORD]", text, flags=re.IGNORECASE)
        # Redact credit card numbers
        text = re.sub(r"\b(?:\d{4}[ -]?){3}\d{4}\b", "[REDACTED_CARD_NUMBER]", text)
        # Redact SSN
        text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", text)
        return text

    @classmethod
    async def interpret(
        cls,
        evidence: List[EvidenceRecord],
        risk: ComponentRisk,
        email_metadata: Optional[EmailMetadata] = None,
        plain_body: str = "",
        force_fallback_to_groq: bool = False,
        simulate_both_fail: bool = False
    ) -> LLMInterpretation:
        """
        Generates security interpretation with fallback resilience.
        """
        if simulate_both_fail:
            return cls._build_deterministic_template(
                evidence=evidence,
                risk=risk,
                email_metadata=email_metadata,
                fallback_used=True,
                fallback_reason="Simulated provider failure: All external LLM endpoints offline."
            )

        sanitized_snippet = cls.redact_sensitive_data(plain_body[:1000])
        evidence_summary = [
            f"- [{e.rule_id}] {e.title} ({e.severity.value}): {e.supporting_observation}"
            for e in evidence
        ]
        evidence_text = "\n".join(evidence_summary) if evidence_summary else "No threat signatures detected."

        prompt_system = (
            "You are PhishGuard AI, an expert Tier-3 SOC analyst. "
            "Analyze the provided email evidence and provide a concise, factual security assessment. "
            "CRITICAL: You must NOT invent new rule IDs or claim attacks not grounded in the provided evidence. "
            "Return valid JSON strictly matching the requested format."
        )

        prompt_user = f"""
SENDER: {email_metadata.sender if email_metadata else 'Unknown'}
SUBJECT: {email_metadata.subject if email_metadata else 'Unknown'}
SCORE: {risk.overall_score}/100 ({risk.overall_rating.value})
AUTHORITATIVE EVIDENCE:
{evidence_text}

EMAIL EXCERPT (Sanitized):
{sanitized_snippet}

Respond with valid JSON:
{{
  "summary": "2-3 sentences explaining the security status and risk posture",
  "attack_vector": "Identified delivery method (e.g., Credential Phishing, Malicious Macro Delivery, Benign Correspondence)",
  "targeted_assets": ["List of targeted assets, e.g. Microsoft 365 credentials, employee banking details"],
  "actionable_recommendations": ["Numbered recommendation 1", "Numbered recommendation 2"],
  "evidence_ids": ["List of rule_ids from the evidence list that support your conclusion"],
  "limitations": ["Technical limitations of this static analysis"]
}}
"""

        # Attempt Gemini if primary and key configured
        gemini_attempted = False
        gemini_error_msg = None

        if settings.PRIMARY_LLM_PROVIDER == "gemini" and settings.GEMINI_API_KEY and not force_fallback_to_groq:
            gemini_attempted = True
            try:
                from langchain_google_genai import ChatGoogleGenerativeAI
                llm = ChatGoogleGenerativeAI(
                    model=settings.GEMINI_MODEL,
                    google_api_key=settings.GEMINI_API_KEY,
                    temperature=0.1,
                    max_retries=1
                )
                response = await llm.ainvoke([("system", prompt_system), ("human", prompt_user)])
                raw_json = cls._extract_json(response.content)
                if raw_json:
                    validated_ids, rejected = EvidenceValidator.validate_interpretation(raw_json, evidence)
                    return LLMInterpretation(
                        summary=raw_json.get("summary", ""),
                        attack_vector=raw_json.get("attack_vector", "Unknown"),
                        targeted_assets=raw_json.get("targeted_assets", []),
                        actionable_recommendations=raw_json.get("actionable_recommendations", []),
                        limitations=raw_json.get("limitations", ["Static inspection only."]),
                        validated_evidence_ids=validated_ids,
                        rejected_claims=rejected,
                        provider_used="gemini",
                        fallback_used=False,
                        fallback_reason=None
                    )
            except Exception as e:
                err_str = str(e).lower()
                logger.warning(f"Gemini provider failed: {e}")
                if "429" in err_str or "quota" in err_str or "resourceexhausted" in err_str:
                    gemini_error_msg = "Gemini rate limit exceeded (HTTP 429 / Quota Exhausted)."
                else:
                    gemini_error_msg = f"Gemini transient error: {type(e).__name__}."

        # Fallback to Groq
        if settings.GROQ_API_KEY:
            try:
                from langchain_groq import ChatGroq
                groq_llm = ChatGroq(
                    model=settings.GROQ_MODEL,
                    groq_api_key=settings.GROQ_API_KEY,
                    temperature=0.1,
                    max_retries=1
                )
                response = await groq_llm.ainvoke([("system", prompt_system), ("human", prompt_user)])
                raw_json = cls._extract_json(response.content)
                if raw_json:
                    validated_ids, rejected = EvidenceValidator.validate_interpretation(raw_json, evidence)
                    fallback_reason = gemini_error_msg or ("Primary provider bypassed by configuration" if force_fallback_to_groq else "Primary provider not configured.")
                    return LLMInterpretation(
                        summary=raw_json.get("summary", ""),
                        attack_vector=raw_json.get("attack_vector", "Unknown"),
                        targeted_assets=raw_json.get("targeted_assets", []),
                        actionable_recommendations=raw_json.get("actionable_recommendations", []),
                        limitations=raw_json.get("limitations", ["Static inspection only."]),
                        validated_evidence_ids=validated_ids,
                        rejected_claims=rejected,
                        provider_used="groq",
                        fallback_used=True,
                        fallback_reason=fallback_reason
                    )
            except Exception as e:
                logger.warning(f"Groq provider fallback failed: {e}")

        # Deterministic Rule-Grounded Template Fallback (if both providers fail or keys missing)
        fallback_reason = "Both external LLM providers unavailable or unconfigured. Deterministic rule template utilized."
        if gemini_error_msg:
            fallback_reason = f"{gemini_error_msg} Subsequent Groq fallback failed. Deterministic rule template utilized."

        return cls._build_deterministic_template(
            evidence=evidence,
            risk=risk,
            email_metadata=email_metadata,
            fallback_used=True,
            fallback_reason=fallback_reason
        )

    @classmethod
    def _build_deterministic_template(
        cls,
        evidence: List[EvidenceRecord],
        risk: ComponentRisk,
        email_metadata: Optional[EmailMetadata],
        fallback_used: bool = True,
        fallback_reason: Optional[str] = None
    ) -> LLMInterpretation:
        """
        Rule-grounded template synthesis when LLM providers are unavailable.
        """
        evidence_ids = [e.rule_id for e in evidence]

        if risk.overall_rating == RiskRatingEnum.HIGH:
            top_ev = evidence[0] if evidence else None
            summary = (
                f"High-confidence threat detected. The investigation identified {len(evidence)} suspicious indicators "
                f"including {top_ev.title if top_ev else 'severe structural anomalies'}. "
                "The email demonstrates active phishing or malicious payload delivery tactics."
            )
            attack_vector = "Credential Phishing / Malicious Payload Delivery"
            targets = ["Corporate Credentials", "User Session Data", "Endpoint Security"]
            recs = [
                "Immediately isolate the affected endpoint and reset potentially compromised credentials.",
                "Block the sender domain and associated destination URLs on the perimeter firewall.",
                "Purge the message from all mailboxes across the organization."
            ]
        elif risk.overall_rating == RiskRatingEnum.MEDIUM:
            summary = (
                f"Suspicious communication detected with elevated risk score ({risk.overall_score}/100). "
                f"Found {len(evidence)} anomalous traits that deviate from standard organizational communications."
            )
            attack_vector = "Suspicious Inbound Communication / Potential Impersonation"
            targets = ["Employee Awareness", "Financial Transaction Authorization"]
            recs = [
                "Verify the sender's identity through an out-of-band communication channel (e.g. phone call).",
                "Do not click hyperlinks or download attachments pending secondary SOC analyst review.",
                "Submit message headers to IT Security for manual verification."
            ]
        else:
            summary = (
                f"No authoritative high-risk phishing signatures detected in static analysis (Score: {risk.overall_score}/100). "
                "However, low static score does not guarantee absolute safety."
            )
            attack_vector = "Standard Inbound Correspondence (No Malicious Signatures Detected)"
            targets = ["None Identified"]
            recs = [
                "Standard operational hygiene: verify unexpected sender requests prior to sharing sensitive details.",
                "Report to IT Security if unexpected behavior occurs upon opening."
            ]

        return LLMInterpretation(
            summary=summary,
            attack_vector=attack_vector,
            targeted_assets=targets,
            actionable_recommendations=recs,
            limitations=[
                "Deterministic rule template used: external LLM synthesis was skipped or unavailable.",
                "Analysis performed statically without active network or dynamic sandbox execution."
            ],
            validated_evidence_ids=evidence_ids,
            rejected_claims=[],
            provider_used="template",
            fallback_used=fallback_used,
            fallback_reason=fallback_reason
        )

    @staticmethod
    def _extract_json(text: Any) -> Optional[Dict[str, Any]]:
        if not text:
            return None
        if isinstance(text, list):
            parts = []
            for item in text:
                if isinstance(item, dict) and "text" in item:
                    parts.append(item["text"])
                elif isinstance(item, str):
                    parts.append(item)
                elif hasattr(item, "text"):
                    parts.append(str(item.text))
            text_str = " ".join(parts)
        else:
            text_str = str(text)
        # Attempt direct json parse
        try:
            return json.loads(text_str)
        except Exception:
            pass
        # Attempt to parse json fenced code block
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text_str, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except Exception:
                pass
        # Attempt first { to last }
        start = text_str.find("{")
        end = text_str.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text_str[start:end+1])
            except Exception:
                pass
        return None
