import re
import ipaddress
from urllib.parse import urlparse, unquote
from typing import List, Tuple, Dict, Any
from app.models.schemas import URLFinding, EvidenceRecord, SeverityEnum, ConfidenceEnum
from app.engine.rule_definitions import RULE_DEFINITIONS

SUSPICIOUS_BRAND_TOKENS = [
    "microsoft", "office365", "outlook", "google", "gmail",
    "paypal", "apple", "icloud", "amazon", "netflix", "bankofamerica",
    "chase", "wellsfargo", "docusign", "dropbox", "login", "secure", "verify"
]

class URLAnalyzer:
    """
    Performs purely static, non-navigational URL syntactic inspection.
    Detects IP literals, punycode/homoglyphs, deceptive subdomains,
    embedded user-info, and obfuscated encodings.
    NEVER accesses the network or resolves remote targets.
    """

    @classmethod
    def analyze_urls(cls, url_items: List[Dict[str, str]]) -> Tuple[List[URLFinding], List[EvidenceRecord]]:
        findings: List[URLFinding] = []
        evidence: List[EvidenceRecord] = []

        seen_urls = set()

        for item in url_items:
            raw_url = item.get("url", "").strip()
            display_text = item.get("display_text", "")

            if not raw_url or raw_url in seen_urls:
                continue
            seen_urls.add(raw_url)

            finding, ev_list = cls._inspect_single_url(raw_url, display_text)
            findings.append(finding)
            evidence.extend(ev_list)

        return findings, evidence

    @classmethod
    def _inspect_single_url(cls, raw_url: str, display_text: str) -> Tuple[URLFinding, List[EvidenceRecord]]:
        ev_list: List[EvidenceRecord] = []
        matched_rules: List[str] = []
        max_severity = SeverityEnum.LOW

        parsed = urlparse(raw_url)
        netloc = parsed.netloc.lower()
        host = netloc
        if ":" in host and not host.startswith("["):
            host = host.split(":")[0]

        is_ip_literal = False
        is_punycode = False
        has_confusable = False
        has_deceptive_subdomain = False
        has_userinfo = False
        has_suspicious_encoding = False

        # 1. Check Embedded Userinfo (@ in netloc)
        if parsed.username or "@" in netloc:
            has_userinfo = True
            matched_rules.append("URL_USERINFO_EMBEDDED")
            rule = RULE_DEFINITIONS["URL_USERINFO_EMBEDDED"]
            ev_list.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=f"URL contains embedded authority userinfo credentials ('@' in '{netloc}').",
                source_location=f"URL: {raw_url[:60]}",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations=rule["limitations"]
            ))
            max_severity = SeverityEnum.MEDIUM

        # 2. Check IP-Literal Host
        try:
            # Strip brackets for IPv6
            clean_ip_str = host.strip("[]")
            ipaddress.ip_address(clean_ip_str)
            is_ip_literal = True
            matched_rules.append("URL_IP_LITERAL")
            rule = RULE_DEFINITIONS["URL_IP_LITERAL"]
            ev_list.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=f"URL targets direct IP-literal '{clean_ip_str}' instead of a registered domain.",
                source_location=f"URL: {raw_url[:60]}",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations=rule["limitations"]
            ))
            max_severity = SeverityEnum.HIGH
        except ValueError:
            is_ip_literal = False

        # 3. Check Punycode & Non-ASCII / Homoglyphs
        if "xn--" in host:
            is_punycode = True
            matched_rules.append("URL_PUNYCODE_CONFUSABLE")
            rule = RULE_DEFINITIONS["URL_PUNYCODE_CONFUSABLE"]
            ev_list.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=f"URL host contains Punycode ('{host}') commonly employed for homograph lookalike spoofing.",
                source_location=f"URL: {raw_url[:60]}",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations=rule["limitations"]
            ))
            max_severity = SeverityEnum.HIGH

        # Check for non-ASCII characters in host
        try:
            host.encode("ascii")
        except UnicodeEncodeError:
            has_confusable = True
            if not is_punycode:
                matched_rules.append("URL_PUNYCODE_CONFUSABLE")
                rule = RULE_DEFINITIONS["URL_PUNYCODE_CONFUSABLE"]
                ev_list.append(EvidenceRecord(
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    title=rule["title"],
                    severity=rule["severity"],
                    description=rule["description"],
                    supporting_observation=f"URL host contains raw non-ASCII unicode characters ('{host}') indicating potential homoglyph attack.",
                    source_location=f"URL: {raw_url[:60]}",
                    confidence=ConfidenceEnum.HIGH,
                    limitations=rule["limitations"]
                ))
                max_severity = SeverityEnum.HIGH

        # 4. Deceptive Subdomains & Lookalikes
        # E.g. paypal.com.attacker.com or login-microsoft.com
        parts = host.split(".")
        if len(parts) >= 3:
            subdomain_part = ".".join(parts[:-2])
            for brand in SUSPICIOUS_BRAND_TOKENS:
                if brand in subdomain_part and not host.endswith(f".{brand}.com"):
                    has_deceptive_subdomain = True
                    matched_rules.append("URL_DECEPTIVE_SUBDOMAIN")
                    rule = RULE_DEFINITIONS["URL_DECEPTIVE_SUBDOMAIN"]
                    ev_list.append(EvidenceRecord(
                        rule_id=rule["rule_id"],
                        category=rule["category"],
                        title=rule["title"],
                        severity=rule["severity"],
                        description=rule["description"],
                        supporting_observation=f"URL utilizes deceptive subdomain pattern '{brand}' inside apex host '{host}'.",
                        source_location=f"URL: {raw_url[:60]}",
                        confidence=ConfidenceEnum.HIGH,
                        limitations=rule["limitations"]
                    ))
                    max_severity = SeverityEnum.HIGH
                    break

        # 5. Suspicious Encoding (%25 double encoding or excessive encoding)
        if "%25" in raw_url or "%00" in raw_url:
            has_suspicious_encoding = True
            matched_rules.append("URL_SUSPICIOUS_ENCODING")
            rule = RULE_DEFINITIONS["URL_SUSPICIOUS_ENCODING"]
            ev_list.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation="URL utilizes double percent encoding (%25) or null-byte characters for filter evasion.",
                source_location=f"URL: {raw_url[:60]}",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations=rule["limitations"]
            ))
            if max_severity != SeverityEnum.HIGH:
                max_severity = SeverityEnum.MEDIUM

        finding = URLFinding(
            url=raw_url,
            display_text=display_text if display_text else None,
            domain=host,
            is_ip_literal=is_ip_literal,
            is_punycode=is_punycode,
            has_confusable_chars=has_confusable,
            has_deceptive_subdomains=has_deceptive_subdomain,
            has_embedded_userinfo=has_userinfo,
            has_suspicious_encoding=has_suspicious_encoding,
            matched_rules=matched_rules,
            severity=max_severity,
            notes="Analyzed purely statically. No network resolution performed."
        )

        return finding, ev_list
