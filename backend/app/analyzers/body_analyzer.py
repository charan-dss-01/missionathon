import re
from typing import List, Tuple, Dict, Any
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from app.models.schemas import EvidenceRecord, SeverityEnum, ConfidenceEnum
from app.engine.rule_definitions import RULE_DEFINITIONS

URGENCY_PATTERNS = [
    r"immediate(?:ly)?\s+action\s+required",
    r"within\s+(?:24|12|48)\s+hours",
    r"account\s+(?:has\s+been|will\s+be)\s+(?:suspended|terminated|disabled|locked|closed)",
    r"unauthorized\s+activity\s+detected",
    r"security\s+alert:\s+unusual\s+sign-in",
    r"failure\s+to\s+comply\s+will\s+result",
    r"act\s+now\s+to\s+prevent\s+permanent",
    r"urgent\s+security\s+notice"
]

CREDENTIAL_PATTERNS = [
    r"confirm\s+(?:your\s+)?(?:password|credentials|identity)",
    r"enter\s+(?:your\s+)?(?:password|credentials|mfa|passcode)",
    r"verify\s+(?:your\s+)?(?:account|identity|email|login)",
    r"validate\s+(?:your\s+)?(?:credentials|profile)",
    r"update\s+(?:your\s+)?(?:password|security\s+questions)",
    r"provide\s+(?:your\s+)?(?:one-time|verification)\s+code"
]

FINANCIAL_PATTERNS = [
    r"urgent\s+wire\s+transfer",
    r"updated\s+bank(?:ing)?\s+(?:details|information|account)",
    r"purchase\s+gift\s+cards?",
    r"overdue\s+invoice\s+payment",
    r"cryptocurrency\s+payment",
    r"remit\s+payment\s+immediately"
]

class BodyAnalyzer:
    """
    Analyzes email body (plain text and HTML) for urgency cues, credential theft keywords,
    financial coercion, and visible text vs actual href anchor mismatches.
    """

    @classmethod
    def analyze(cls, plain_body: str, html_body: str) -> Tuple[List[EvidenceRecord], List[Dict[str, str]]]:
        evidence: List[EvidenceRecord] = []
        extracted_urls: List[Dict[str, str]] = [] # list of {"url": ..., "display_text": ...}
        
        combined_text = f"{plain_body} {cls._strip_html_to_text(html_body)}".strip()

        # 1. HTML Link Mismatch Analysis & URL Extraction
        if html_body:
            cls._inspect_html_anchors(html_body, evidence, extracted_urls)

        # Also extract plain URLs from plain_body using regex
        url_matches = re.findall(r"https?://[^\s<>\"']+", plain_body)
        existing_urls = {u["url"] for u in extracted_urls}
        for u in url_matches:
            clean_u = u.rstrip(".,;)>]")
            if clean_u not in existing_urls:
                extracted_urls.append({"url": clean_u, "display_text": ""})
                existing_urls.add(clean_u)

        # 2. Urgency and Coercion Language
        urgency_hits = [p for p in URGENCY_PATTERNS if re.search(p, combined_text, re.IGNORECASE)]
        if urgency_hits:
            rule = RULE_DEFINITIONS["BODY_URGENCY_PRESSURE"]
            sample_match = re.search(urgency_hits[0], combined_text, re.IGNORECASE)
            snippet = sample_match.group(0) if sample_match else urgency_hits[0]
            evidence.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=f"Detected high-urgency/coercive phrasing: '{snippet}'. Total urgency triggers: {len(urgency_hits)}.",
                source_location="Email Body: Textual Analysis",
                confidence=ConfidenceEnum.HIGH,
                limitations=rule["limitations"]
            ))

        # 3. Credential Harvesting / Identity Solicitations
        cred_hits = [p for p in CREDENTIAL_PATTERNS if re.search(p, combined_text, re.IGNORECASE)]
        if cred_hits:
            rule = RULE_DEFINITIONS["BODY_CREDENTIAL_HARVEST"]
            sample_match = re.search(cred_hits[0], combined_text, re.IGNORECASE)
            snippet = sample_match.group(0) if sample_match else cred_hits[0]
            evidence.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=f"Detected credential harvesting solicitation pattern: '{snippet}'.",
                source_location="Email Body: Textual Analysis",
                confidence=ConfidenceEnum.HIGH,
                limitations=rule["limitations"]
            ))

        # 4. Financial Pressure / Payment Coercion
        fin_hits = [p for p in FINANCIAL_PATTERNS if re.search(p, combined_text, re.IGNORECASE)]
        if fin_hits:
            rule = RULE_DEFINITIONS["BODY_FINANCIAL_PRESSURE"]
            sample_match = re.search(fin_hits[0], combined_text, re.IGNORECASE)
            snippet = sample_match.group(0) if sample_match else fin_hits[0]
            evidence.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=f"Detected coercive financial demand: '{snippet}'.",
                source_location="Email Body: Textual Analysis",
                confidence=ConfidenceEnum.HIGH,
                limitations=rule["limitations"]
            ))

        return evidence, extracted_urls

    @classmethod
    def _inspect_html_anchors(
        cls,
        html_body: str,
        evidence: List[EvidenceRecord],
        extracted_urls: List[Dict[str, str]]
    ) -> None:
        try:
            soup = BeautifulSoup(html_body, "html.parser")
            anchors = soup.find_all("a", href=True)

            for a in anchors:
                href = a.get("href", "").strip()
                if not href or href.startswith("mailto:") or href.startswith("#") or href.startswith("tel:"):
                    continue

                display_text = a.get_text(strip=True)
                extracted_urls.append({"url": href, "display_text": display_text})

                # Check if display text mimics a URL
                url_like_match = re.search(r"^(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", display_text)
                if url_like_match:
                    displayed_domain = url_like_match.group(1).lower()
                    
                    parsed_href = urlparse(href)
                    actual_domain = parsed_href.netloc.lower()
                    if ":" in actual_domain:
                        actual_domain = actual_domain.split(":")[0]

                    # If displayed domain is a known domain and actual domain does not match
                    if displayed_domain and actual_domain and (not actual_domain.endswith(displayed_domain)):
                        rule = RULE_DEFINITIONS["URL_TEXT_HREF_MISMATCH"]
                        evidence.append(EvidenceRecord(
                            rule_id=rule["rule_id"],
                            category=rule["category"],
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            supporting_observation=(
                                f"Deceptive anchor text displays '{displayed_domain}', "
                                f"but actual link destination redirects to '{actual_domain}' ({href[:80]})."
                            ),
                            source_location="Email Body: HTML Anchor Tag",
                            confidence=ConfidenceEnum.CONFIRMED,
                            limitations=rule["limitations"]
                        ))
        except Exception:
            # HTML parsing failed gracefully
            pass

    @staticmethod
    def _strip_html_to_text(html: str) -> str:
        if not html:
            return ""
        try:
            soup = BeautifulSoup(html, "html.parser")
            return soup.get_text(separator=" ")
        except Exception:
            return re.sub(r"<[^>]+>", " ", html)
