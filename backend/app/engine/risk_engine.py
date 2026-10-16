from typing import List, Dict, Any, Tuple
from app.models.schemas import (
    EvidenceRecord,
    ComponentRisk,
    RiskRatingEnum,
    CoverageStatusEnum,
    AttachmentFinding
)
from app.engine.rule_definitions import RULE_DEFINITIONS
from app.engine.qr_rules import QR_RULE_DEFINITIONS # FEATURE:qr

class RiskEngine:
    """
    Deterministic risk calculation engine for PhishGuard AI.
    Calculates email score, attachment score, overall combined risk,
    deduplicates correlated signals, and tracks analysis coverage.
    """

    LOW_THRESHOLD = 30
    MEDIUM_THRESHOLD = 60

    @classmethod
    def calculate(
        cls,
        evidence: List[EvidenceRecord],
        attachments: List[AttachmentFinding],
        has_email_body: bool = True,
        has_headers: bool = True
    ) -> ComponentRisk:
        email_score = 0
        attachment_score = 0
        contributing_findings: List[str] = []
        applied_rules = set()

        # Categorize evidence into email vs attachment
        for record in evidence:
            rule_def = RULE_DEFINITIONS.get(record.rule_id, {})
            weight = rule_def.get("weight", 15)
            
            # Correlated signal damping:
            # If multiple authentication headers fail (SPF + DKIM + DMARC), avoid inflating past 45
            if record.category == "authentication":
                if "AUTH_DMARC_FAIL" in applied_rules and record.rule_id in ["AUTH_SPF_FAIL", "AUTH_DKIM_FAIL"]:
                    weight = int(weight * 0.5) # Correlated damping
            
            # If both display name spoof and urgency trigger, apply full weights
            applied_rules.add(record.rule_id)
            contributing_findings.append(f"{record.title} (+{weight} pts)")

            if record.category in ["headers", "body", "urls", "authentication"]:
                email_score += weight
            elif record.category == "attachments":
                attachment_score += weight

        # Bounding scores [0, 100]
        email_score = min(100, max(0, email_score))
        attachment_score = min(100, max(0, attachment_score))

        # Overall score combination:
        # If an attachment has critical malicious traits (e.g. executable, RTLO, macro),
        # the overall score reflects the highest component danger.
        if attachment_score > 0 and email_score > 0:
            # Weighted blend prioritizing the highest risk vector with a compounding bonus
            highest = max(email_score, attachment_score)
            secondary = min(email_score, attachment_score)
            overall_score = min(100, int(highest + (secondary * 0.25)))
        elif attachment_score > 0:
            overall_score = attachment_score
        else:
            overall_score = email_score

        # Determine Rating
        if overall_score < cls.LOW_THRESHOLD:
            overall_rating = RiskRatingEnum.LOW
        elif overall_score < cls.MEDIUM_THRESHOLD:
            overall_rating = RiskRatingEnum.MEDIUM
        else:
            overall_rating = RiskRatingEnum.HIGH

        # Determine Coverage Status
        coverage_status = CoverageStatusEnum.FULL
        unscanned_count = sum(1 for a in attachments if a.coverage_status in ["UNKNOWN", "UNSCANNED", "UNSUPPORTED", "CORRUPT", "OVERSIZED"])
        if unscanned_count > 0:
            coverage_status = CoverageStatusEnum.PARTIAL
        if not has_headers and not has_email_body and not attachments:
            coverage_status = CoverageStatusEnum.INCOMPLETE

        # Explanation formulation
        explanation_parts = []
        if overall_rating == RiskRatingEnum.HIGH:
            explanation_parts.append(
                f"HIGH RISK ({overall_score}/100): Confirmed high-severity threat indicators detected. "
                "Immediate containment and quarantine recommended."
            )
        elif overall_rating == RiskRatingEnum.MEDIUM:
            explanation_parts.append(
                f"SUSPICIOUS / ELEVATED RISK ({overall_score}/100): Multiple anomalies detected requiring cautious human verification."
            )
        else:
            explanation_parts.append(
                f"LOW IDENTIFIED RISK ({overall_score}/100): No authoritative high-severity phishing signatures detected in static analysis. "
                "Notice: Low score does NOT guarantee safety."
            )

        if coverage_status != CoverageStatusEnum.FULL:
            explanation_parts.append(
                f"Coverage Notice ({coverage_status.value}): Some attachments or artifacts were unsupported or incomplete."
            )

        scoring_explanation = " ".join(explanation_parts)

        return ComponentRisk(
            email_score=email_score,
            attachment_score=attachment_score,
            overall_score=overall_score,
            overall_rating=overall_rating,
            contributing_findings=contributing_findings,
            coverage_status=coverage_status,
            scoring_explanation=scoring_explanation
        )
