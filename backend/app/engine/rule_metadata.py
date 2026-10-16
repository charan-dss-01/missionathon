"""Presentation metadata and MITRE ATT&CK mapping for PhishGuard AI detection rules."""

from typing import Dict, Any, Optional

VALID_STAGES = {"lure", "deception", "delivery", "action"}

RULE_METADATA: Dict[str, Dict[str, Any]] = {
    "AUTH_SPF_FAIL": {
        "stage": "deception",
        "mitre_id": "T1036",  # TODO: verify at attack.mitre.org
        "mitre_name": "Masquerading",  # TODO: verify at attack.mitre.org
        "plain_text": "The sender's email server is not authorized by the real domain owner to send emails on their behalf.",
        "hint": "Verify with the sender through a separate, trusted channel before trusting the sender's identity.",
    },
    "AUTH_DKIM_FAIL": {
        "stage": "deception",
        "mitre_id": "T1036",  # TODO: verify at attack.mitre.org
        "mitre_name": "Masquerading",  # TODO: verify at attack.mitre.org
        "plain_text": "The email's cryptographic signature failed verification, suggesting the content was modified or the sender was forged.",
        "hint": "Treat the message contents with caution and confirm authenticity with the supposed sender.",
    },
    "AUTH_DMARC_FAIL": {
        "stage": "deception",
        "mitre_id": "T1036",  # TODO: verify at attack.mitre.org
        "mitre_name": "Masquerading",  # TODO: verify at attack.mitre.org
        "plain_text": "The domain owner's strict security policy rejected this message because it failed authentication checks.",
        "hint": "Do not trust the sender name or domain displayed on this message.",
    },
    "HDR_REPLYTO_MISMATCH": {
        "stage": "deception",
        "mitre_id": "T1036",  # TODO: verify at attack.mitre.org
        "mitre_name": "Masquerading",  # TODO: verify at attack.mitre.org
        "plain_text": "Replying to this email will send your response to an address with a different domain than the sender.",
        "hint": "Check the Reply-To address closely to make sure your response will not go to an unknown third party.",
    },
    "HDR_RETURNPATH_MISMATCH": {
        "stage": "deception",
        "mitre_id": "T1036",  # TODO: verify at attack.mitre.org
        "mitre_name": "Masquerading",  # TODO: verify at attack.mitre.org
        "plain_text": "The technical return address of this email does not match the address shown in the From line.",
        "hint": "Inspect the return path header or contact your IT security team to confirm if this sender is legitimate.",
    },
    "HDR_DISPLAY_NAME_SPOOF": {
        "stage": "deception",
        "mitre_id": "T1036",  # TODO: verify at attack.mitre.org
        "mitre_name": "Masquerading",  # TODO: verify at attack.mitre.org
        "plain_text": "The sender's name claims to be a trusted brand or executive, but the actual email address is completely different.",
        "hint": "Look past the friendly display name and check the actual email address between the angle brackets.",
    },
    "BODY_URGENCY_PRESSURE": {
        "stage": "lure",
        "mitre_id": "T1204",  # TODO: verify at attack.mitre.org
        "mitre_name": "User Execution",  # TODO: verify at attack.mitre.org
        "plain_text": "The email uses artificial urgency or threatening deadlines to pressure you into acting without thinking.",
        "hint": "Slow down and do not rush into clicking or replying under perceived deadline pressure.",
    },
    "BODY_CREDENTIAL_HARVEST": {
        "stage": "action",
        "mitre_id": "T1566.002",  # TODO: verify at attack.mitre.org
        "mitre_name": "Spearphishing Link",  # TODO: verify at attack.mitre.org
        "plain_text": "The message attempts to persuade you to reveal your login credentials, passwords, or authentication codes.",
        "hint": "Never enter your password or one-time codes on a page linked from an unsolicited email.",
    },
    "BODY_FINANCIAL_PRESSURE": {
        "stage": "action",
        "mitre_id": "T1204",  # TODO: verify at attack.mitre.org
        "mitre_name": "User Execution",  # TODO: verify at attack.mitre.org
        "plain_text": "The email urgently demands money, wire transfers, gift cards, or cryptocurrency payments.",
        "hint": "Confirm payment requests by calling the requester on a known internal phone number before proceeding.",
    },
    "URL_TEXT_HREF_MISMATCH": {
        "stage": "deception",
        "mitre_id": "T1566.002",  # TODO: verify at attack.mitre.org
        "mitre_name": "Spearphishing Link",  # TODO: verify at attack.mitre.org
        "plain_text": "The visible link text shows one website, but clicking it takes you to an entirely different address.",
        "hint": "Hover over the link without clicking to inspect the real destination URL in your status bar.",
    },
    "URL_IP_LITERAL": {
        "stage": "delivery",
        "mitre_id": "T1566.002",  # TODO: verify at attack.mitre.org
        "mitre_name": "Spearphishing Link",  # TODO: verify at attack.mitre.org
        "plain_text": "The link points directly to a raw numerical IP address instead of a standard recognizable domain name.",
        "hint": "Avoid clicking raw IP links as legitimate business services use registered domain names.",
    },
    "URL_PUNYCODE_CONFUSABLE": {
        "stage": "deception",
        "mitre_id": "T1036",  # TODO: verify at attack.mitre.org
        "mitre_name": "Masquerading",  # TODO: verify at attack.mitre.org
        "plain_text": "The link uses look-alike foreign alphabet characters to disguise a fake domain as a genuine brand name.",
        "hint": "Examine the spelling carefully and navigate directly to the official website instead of clicking.",
    },
    "URL_DECEPTIVE_SUBDOMAIN": {
        "stage": "deception",
        "mitre_id": "T1036",  # TODO: verify at attack.mitre.org
        "mitre_name": "Masquerading",  # TODO: verify at attack.mitre.org
        "plain_text": "The link includes a trusted brand name inside a subdomain to disguise an unrelated destination website.",
        "hint": "Look at the primary domain right before the first slash to identify who truly hosts the website.",
    },
    "URL_USERINFO_EMBEDDED": {
        "stage": "deception",
        "mitre_id": "T1566.002",  # TODO: verify at attack.mitre.org
        "mitre_name": "Spearphishing Link",  # TODO: verify at attack.mitre.org
        "plain_text": "The link includes an '@' symbol or embedded credentials designed to trick you about where it actually leads.",
        "hint": "Do not click links containing '@' symbols in the web address.",
    },
    "URL_SUSPICIOUS_ENCODING": {
        "stage": "delivery",
        "mitre_id": "T1027",  # TODO: verify at attack.mitre.org
        "mitre_name": "Obfuscated Files or Information",  # TODO: verify at attack.mitre.org
        "plain_text": "The web address uses obfuscated or double-encoded characters to hide its true destination from security filters.",
        "hint": "Do not open URLs that contain unusual percent signs or encoded character strings.",
    },
    "ATT_DANGEROUS_EXT": {
        "stage": "delivery",
        "mitre_id": "T1566.001",  # TODO: verify at attack.mitre.org
        "mitre_name": "Spearphishing Attachment",  # TODO: verify at attack.mitre.org
        "plain_text": "The attached file has an executable or script extension that could run software or commands on your computer.",
        "hint": "Do not download, open, or execute attachments with executable or script extensions.",
    },
    "ATT_DOUBLE_EXT": {
        "stage": "deception",
        "mitre_id": "T1036",  # TODO: verify at attack.mitre.org
        "mitre_name": "Masquerading",  # TODO: verify at attack.mitre.org
        "plain_text": "The attachment hides a dangerous executable type behind a fake harmless extension like .pdf or .doc.",
        "hint": "Check file extensions with your file manager configured to show full filename extensions.",
    },
    "ATT_RTLO_DETECTED": {
        "stage": "deception",
        "mitre_id": "T1036",  # TODO: verify at attack.mitre.org
        "mitre_name": "Masquerading",  # TODO: verify at attack.mitre.org
        "plain_text": "The attachment uses a hidden Unicode character that visually reverses the filename to deceive you about its real type.",
        "hint": "Do not open files with unusual character reversing or right-to-left layout tricks.",
    },
    "ATT_MIME_MISMATCH": {
        "stage": "deception",
        "mitre_id": "T1036",  # TODO: verify at attack.mitre.org
        "mitre_name": "Masquerading",  # TODO: verify at attack.mitre.org
        "plain_text": "The file's internal binary signature does not match its claimed file extension.",
        "hint": "Treat this file as potentially deceptive and report it to your IT security administrator.",
    },
    "ATT_OFFICE_MACRO": {
        "stage": "delivery",
        "mitre_id": "T1566.001",  # TODO: verify at attack.mitre.org
        "mitre_name": "Spearphishing Attachment",  # TODO: verify at attack.mitre.org
        "plain_text": "This Office document contains embedded macro scripts that could automatically run unauthorized code.",
        "hint": "Never click 'Enable Content' or enable macros on documents received from external or unexpected senders.",
    },
    "ATT_PDF_ACTIVE_CONTENT": {
        "stage": "delivery",
        "mitre_id": "T1566.001",  # TODO: verify at attack.mitre.org
        "mitre_name": "Spearphishing Attachment",  # TODO: verify at attack.mitre.org
        "plain_text": "The PDF attachment contains embedded scripts or launch commands capable of triggering system actions.",
        "hint": "Open the PDF only in a restricted sandbox or secure viewer with JavaScript disabled.",
    },
    "ATT_HTML_FORM_SCRIPT": {
        "stage": "action",
        "mitre_id": "T1566.001",  # TODO: verify at attack.mitre.org
        "mitre_name": "Spearphishing Attachment",  # TODO: verify at attack.mitre.org
        "plain_text": "The attachment is a web page designed to harvest your credentials or redirect you to a malicious site.",
        "hint": "Do not open HTML attachments that ask for your password or company credentials.",
    },
    "ATT_ARCHIVE_SUSPICIOUS": {
        "stage": "delivery",
        "mitre_id": "T1566.001",  # TODO: verify at attack.mitre.org
        "mitre_name": "Spearphishing Attachment",  # TODO: verify at attack.mitre.org
        "plain_text": "The compressed archive contains hidden files with dangerous extensions or suspicious compression ratios.",
        "hint": "Do not extract or run compressed archives from unverified sources.",
    },
    "ATT_UNSUPPORTED_TYPE": {
        "stage": "delivery",
        "mitre_id": "T1027",  # TODO: verify at attack.mitre.org
        "mitre_name": "Obfuscated Files or Information",  # TODO: verify at attack.mitre.org
        "plain_text": "The attachment format or encryption prevented automatic security inspection.",
        "hint": "Request assistance from security personnel before attempting to open unsupported or encrypted attachments.",
    },
    "AUTH_SPF_NONE": {
        "stage": "deception",
        "mitre_id": "T1036",
        "mitre_name": "Masquerading",
        "plain_text": "The sending domain has not published an SPF policy or the message lacks SPF authorization records.",
        "hint": "Verify the sender's identity through an independent channel since SPF protection is not active.",
    },
    "AUTH_DKIM_NONE": {
        "stage": "deception",
        "mitre_id": "T1036",
        "mitre_name": "Masquerading",
        "plain_text": "The email has no cryptographic DKIM signature verifying that it originated from the declared sending domain.",
        "hint": "Treat this message cautiously as sender authentication cannot be cryptographically verified.",
    },
    "AUTH_DMARC_NONE": {
        "stage": "deception",
        "mitre_id": "T1036",
        "mitre_name": "Masquerading",
        "plain_text": "The sender domain has no enforced DMARC policy governing email delivery and spoof protection.",
        "hint": "Inspect the message origin carefully because domain spoofing protections are unconfigured.",
    },
    "ATT_MIME_DECLARED_MISMATCH": {
        "stage": "delivery",
        "mitre_id": "T1036",
        "mitre_name": "Masquerading",
        "plain_text": "The declared MIME type contradicts the file extension or binary magic bytes of the attachment.",
        "hint": "Do not open the file; the mismatched type indicates potential cloaking of dangerous executable content.",
    },
    "ATT_OFFICE_MACRO_EXT": {
        "stage": "delivery",
        "mitre_id": "T1566.001",
        "mitre_name": "Spearphishing Attachment",
        "plain_text": "The attachment has a macro-enabled extension (.docm, .xlsm, etc.) commonly used to run malicious scripts upon opening.",
        "hint": "Never enable macros for unsolicited or unexpected Office documents.",
    },
    "ATT_HTML_SMUGGLING": {
        "stage": "delivery",
        "mitre_id": "T1027",
        "mitre_name": "Obfuscated Files or Information",
        "plain_text": "The HTML attachment employs JavaScript smuggling (Blob/Data URI generation) to construct payloads directly in the browser.",
        "hint": "Do not download or open files generated dynamically by suspicious HTML attachments.",
    },
    "ATT_ARCHIVE_ENCRYPTED": {
        "stage": "delivery",
        "mitre_id": "T1027",
        "mitre_name": "Obfuscated Files or Information",
        "plain_text": "The archive is password-protected or encrypted to evade automatic gateway and antimalware inspection.",
        "hint": "Avoid entering passwords to unlock unverified archives sent via email.",
    },
    "ATT_ARCHIVE_PASSWORD_IN_BODY": {
        "stage": "lure",
        "mitre_id": "T1566.001",
        "mitre_name": "Spearphishing Attachment",
        "plain_text": "The email body explicitly supplies a password to unlock an encrypted attachment, a classic evasion technique.",
        "hint": "Attackers provide archive passwords in text to bypass automated security scanning while prompting user execution.",
    },
    "ATT_ARCHIVE_NESTED": {
        "stage": "delivery",
        "mitre_id": "T1027",
        "mitre_name": "Obfuscated Files or Information",
        "plain_text": "The attachment embeds archives inside other archives, a common technique to evade single-tier scanning.",
        "hint": "Do not decompress multi-layered archives from untrusted or unexpected sources.",
    },
    "ATT_ARCHIVE_DEPTH_EXCEEDED": {
        "stage": "delivery",
        "mitre_id": "T1027",
        "mitre_name": "Obfuscated Files or Information",
        "plain_text": "The archive structure exceeds the maximum nesting depth limit, preventing complete safety verification.",
        "hint": "Treat deeply nested or recursive archives with extreme caution as they may conceal malicious payloads or decompression bombs.",
    },
    "ATT_CORRUPT_OR_UNPARSEABLE": {
        "stage": "delivery",
        "mitre_id": "T1027",
        "mitre_name": "Obfuscated Files or Information",
        "plain_text": "The attachment header or container structure is damaged, malformed, or unparseable.",
        "hint": "Never assume an uninspected or unparseable attachment is harmless. Escalate to your security team for sandbox analysis.",
    },
    "ATT_LIMIT_EXCEEDED": {
        "stage": "delivery",
        "mitre_id": "T1027",
        "mitre_name": "Obfuscated Files or Information",
        "plain_text": "The attachment exceeds file size or processing limits and could not be fully analyzed statically.",
        "hint": "Submit oversized or unscanned files to an isolated malware analysis environment before opening.",
    },
}
from app.engine.qr_rules import QR_RULE_METADATA; RULE_METADATA.update(QR_RULE_METADATA) # FEATURE:qr


def get_metadata(rule_id: Optional[str]) -> Dict[str, Any]:
    """
    Returns presentation metadata for a given rule_id.
    Returns safe defaults for unknown or None IDs (stage 'deception', no mitre).
    """
    if rule_id and rule_id in RULE_METADATA:
        return dict(RULE_METADATA[rule_id])
    return {
        "stage": "deception",
        "mitre_id": None,
        "mitre_name": None,
        "plain_text": "Security rule triggered during automated inspection.",
        "hint": "Inspect the email headers, links, and attachments carefully before taking action.",
    }


def validate_metadata_covers_rules() -> bool:
    """
    Validates that every rule in RULE_DEFINITIONS has valid presentation metadata
    and that all stages conform to the allowed set ('lure', 'deception', 'delivery', 'action').
    """
    from app.engine.rule_definitions import RULE_DEFINITIONS

    missing = set(RULE_DEFINITIONS.keys()) - set(RULE_METADATA.keys())
    if missing:
        raise ValueError(f"Missing presentation metadata for rules: {missing}")

    for r_id, meta in RULE_METADATA.items():
        if "stage" not in meta or meta["stage"] not in VALID_STAGES:
            raise ValueError(f"Invalid or missing stage for rule {r_id}: {meta.get('stage')}")
        if "plain_text" not in meta or not meta["plain_text"]:
            raise ValueError(f"Missing plain_text for rule {r_id}")
        if "hint" not in meta or not meta["hint"]:
            raise ValueError(f"Missing hint for rule {r_id}")
        if "mitre_id" not in meta:
            raise ValueError(f"Missing mitre_id for rule {r_id}")
        if "mitre_name" not in meta:
            raise ValueError(f"Missing mitre_name for rule {r_id}")

    return True
