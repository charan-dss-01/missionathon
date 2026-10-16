from typing import List
from app.models.schemas import EmailMetadata, EvidenceRecord, SeverityEnum, ConfidenceEnum
from app.engine.rule_definitions import RULE_DEFINITIONS

KNOWN_BRANDS = {
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "docusign": ["docusign.net", "docusign.com"],
    "dropbox": ["dropbox.com"],
    "it support": [],
    "helpdesk": [],
    "security team": [],
    "admin": [],
    "payroll": []
}

class HeaderAnalyzer:
    """
    Analyzes email headers for domain spoofing, reply-to diversion,
    display-name deception, and recorded authentication failures.
    """

    @classmethod
    def analyze(cls, metadata: EmailMetadata) -> List[EvidenceRecord]:
        evidence: List[EvidenceRecord] = []

        if not metadata.sender:
            return evidence

        sender_domain = metadata.sender_domain.lower()

        # 1. From vs Reply-To Mismatch
        if metadata.reply_to:
            reply_domain = metadata.reply_to.split("@")[-1].lower() if "@" in metadata.reply_to else ""
            if reply_domain and reply_domain != sender_domain:
                rule = RULE_DEFINITIONS["HDR_REPLYTO_MISMATCH"]
                evidence.append(EvidenceRecord(
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    title=rule["title"],
                    severity=rule["severity"],
                    description=rule["description"],
                    supporting_observation=f"Sender domain is '{sender_domain}', but Reply-To redirects to '{reply_domain}' ({metadata.reply_to}).",
                    source_location="Headers: From vs Reply-To",
                    confidence=ConfidenceEnum.CONFIRMED,
                    limitations=rule["limitations"]
                ))
                metadata.inconsistencies.append(f"Reply-To mismatch: {reply_domain} != {sender_domain}")

        # 2. From vs Return-Path Mismatch
        if metadata.return_path:
            return_domain = metadata.return_path.split("@")[-1].lower() if "@" in metadata.return_path else ""
            if return_domain and return_domain != sender_domain:
                rule = RULE_DEFINITIONS["HDR_RETURNPATH_MISMATCH"]
                evidence.append(EvidenceRecord(
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    title=rule["title"],
                    severity=rule["severity"],
                    description=rule["description"],
                    supporting_observation=f"Sender domain is '{sender_domain}', but envelope Return-Path is '{return_domain}'.",
                    source_location="Headers: From vs Return-Path",
                    confidence=ConfidenceEnum.HIGH,
                    limitations=rule["limitations"]
                ))

        # 3. Display Name Brand Spoofing
        if metadata.display_name:
            d_lower = metadata.display_name.lower()
            for brand, legit_domains in KNOWN_BRANDS.items():
                if brand in d_lower:
                    # Check if actual sender domain is authorized for this brand
                    is_legit = any(sender_domain.endswith(legit_d) for legit_d in legit_domains)
                    if not is_legit:
                        rule = RULE_DEFINITIONS["HDR_DISPLAY_NAME_SPOOF"]
                        evidence.append(EvidenceRecord(
                            rule_id=rule["rule_id"],
                            category=rule["category"],
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            supporting_observation=(
                                f"Display name '{metadata.display_name}' impersonates brand/authority '{brand.title()}', "
                                f"but the actual sending address domain is '{sender_domain}'."
                            ),
                            source_location="Headers: From (Display Name vs Address)",
                            confidence=ConfidenceEnum.HIGH,
                            limitations=rule["limitations"]
                        ))
                        metadata.inconsistencies.append(f"Display name spoofing '{brand}' from {sender_domain}")
                        break

        # 4. Recorded SPF Check (Fail or None)
        spf = (metadata.recorded_auth.spf_result or "").upper()
        if spf in ["FAIL", "SOFTFAIL"]:
            rule = RULE_DEFINITIONS["AUTH_SPF_FAIL"]
            evidence.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=f"Recorded header SPF check returned '{spf}'. Sender server is not an authorized sender for '{sender_domain}'.",
                source_location="Headers: Authentication-Results (SPF)",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations=rule["limitations"]
            ))
        elif spf == "NONE" and metadata.recorded_auth.raw_header:
            rule = RULE_DEFINITIONS["AUTH_SPF_NONE"]
            evidence.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=f"Recorded header SPF check recorded as 'none' or unconfigured for '{sender_domain}'.",
                source_location="Headers: Authentication-Results (SPF)",
                confidence=ConfidenceEnum.HIGH,
                limitations=rule["limitations"]
            ))

        # 5. Recorded DKIM Check (Fail or None)
        dkim = (metadata.recorded_auth.dkim_result or "").upper()
        if dkim == "FAIL":
            rule = RULE_DEFINITIONS["AUTH_DKIM_FAIL"]
            evidence.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation="Recorded header DKIM signature verification failed. The message body or headers may have been modified in transit.",
                source_location="Headers: Authentication-Results (DKIM)",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations=rule["limitations"]
            ))
        elif dkim == "NONE" and metadata.recorded_auth.raw_header:
            rule = RULE_DEFINITIONS["AUTH_DKIM_NONE"]
            evidence.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=f"No passing cryptographic DKIM signature recorded for '{sender_domain}' (recorded status: none).",
                source_location="Headers: Authentication-Results (DKIM)",
                confidence=ConfidenceEnum.HIGH,
                limitations=rule["limitations"]
            ))

        # 6. Recorded DMARC Check (Fail or None)
        dmarc = (metadata.recorded_auth.dmarc_result or "").upper()
        if dmarc == "FAIL":
            rule = RULE_DEFINITIONS["AUTH_DMARC_FAIL"]
            evidence.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=f"Recorded header DMARC policy evaluation failed for domain '{sender_domain}'.",
                source_location="Headers: Authentication-Results (DMARC)",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations=rule["limitations"]
            ))
        elif dmarc == "NONE" and metadata.recorded_auth.raw_header:
            rule = RULE_DEFINITIONS["AUTH_DMARC_NONE"]
            evidence.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=f"Recorded header DMARC policy evaluation recorded as 'none' or not enforced for '{sender_domain}'.",
                source_location="Headers: Authentication-Results (DMARC)",
                confidence=ConfidenceEnum.HIGH,
                limitations=rule["limitations"]
            ))

        return evidence
