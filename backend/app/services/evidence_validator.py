from typing import List, Dict, Any, Tuple
from app.models.schemas import EvidenceRecord, LLMInterpretation

class EvidenceValidator:
    """
    Ensures LLM output does not fabricate evidence, hallucinate rule IDs,
    or introduce unsupported attack claims.
    """

    @classmethod
    def validate_interpretation(
        cls,
        raw_interpretation: Dict[str, Any],
        authoritative_evidence: List[EvidenceRecord]
    ) -> Tuple[List[str], List[str]]:
        """
        Cross-checks referenced evidence IDs from LLM against authoritative records.
        Returns: (validated_evidence_ids, rejected_claims)
        """
        valid_rule_ids = {e.rule_id for e in authoritative_evidence}
        
        referenced_ids = raw_interpretation.get("evidence_ids", [])
        if isinstance(referenced_ids, str):
            referenced_ids = [referenced_ids]

        validated_ids: List[str] = []
        rejected_claims: List[str] = []

        for ref in referenced_ids:
            if ref in valid_rule_ids:
                validated_ids.append(ref)
            else:
                rejected_claims.append(f"Referenced unverified rule ID: '{ref}'")

        # Check for hallucinated claims in summary or attack vector if they contradict zero-findings
        if not authoritative_evidence:
            summary = raw_interpretation.get("summary", "").lower()
            if "malicious" in summary or "trojan" in summary or "ransomware" in summary:
                rejected_claims.append("LLM claimed malicious payload but 0 authoritative evidence signals were detected.")

        return validated_ids, rejected_claims
