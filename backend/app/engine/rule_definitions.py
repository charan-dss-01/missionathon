from typing import Dict, Any
from app.models.schemas import SeverityEnum

RULE_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "AUTH_SPF_FAIL": {
        "rule_id": "AUTH_SPF_FAIL",
        "category": "authentication",
        "title": "Recorded SPF Verification Failure",
        "severity": SeverityEnum.HIGH,
        "weight": 25,
        "description": "Email headers record a softfail or hardfail for Sender Policy Framework (SPF).",
        "limitations": "Analysis based on recorded headers in email only; live DNS SPF lookup was not performed."
    },
    "AUTH_DKIM_FAIL": {
        "rule_id": "AUTH_DKIM_FAIL",
        "category": "authentication",
        "title": "Recorded DKIM Signature Failure",
        "severity": SeverityEnum.HIGH,
        "weight": 25,
        "description": "Email headers indicate DKIM cryptographic verification failed or signature was corrupted.",
        "limitations": "Analysis relies on existing Authentication-Results headers; cryptographic re-verification was not performed."
    },
    "AUTH_DMARC_FAIL": {
        "rule_id": "AUTH_DMARC_FAIL",
        "category": "authentication",
        "title": "Recorded DMARC Policy Rejection",
        "severity": SeverityEnum.HIGH,
        "weight": 30,
        "description": "Recorded headers show DMARC policy check failed for the sender domain.",
        "limitations": "Header inspection only. Live DMARC policy query was not conducted."
    },
    "HDR_REPLYTO_MISMATCH": {
        "rule_id": "HDR_REPLYTO_MISMATCH",
        "category": "headers",
        "title": "From / Reply-To Domain Divergence",
        "severity": SeverityEnum.MEDIUM,
        "weight": 20,
        "description": "The Reply-To address domain does not match the From address domain, a classic tactic to divert replies to an external inbox.",
        "limitations": "Legitimate mailing lists and support ticketing systems can occasionally have different Reply-To addresses."
    },
    "HDR_RETURNPATH_MISMATCH": {
        "rule_id": "HDR_RETURNPATH_MISMATCH",
        "category": "headers",
        "title": "From / Return-Path Domain Divergence",
        "severity": SeverityEnum.MEDIUM,
        "weight": 15,
        "description": "The Return-Path (envelope sender) domain does not match the From address domain.",
        "limitations": "Certain transactional email relays (e.g. SendGrid, Mailchimp) use relay envelope addresses."
    },
    "HDR_DISPLAY_NAME_SPOOF": {
        "rule_id": "HDR_DISPLAY_NAME_SPOOF",
        "category": "headers",
        "title": "Display Name Brand / Executive Spoofing",
        "severity": SeverityEnum.HIGH,
        "weight": 25,
        "description": "The sender's display name references a trusted corporate entity, executive title, or security team, but the actual sending address is from a generic or unrelated domain.",
        "limitations": "Rule evaluated against known corporate brands and executive patterns."
    },
    "BODY_URGENCY_PRESSURE": {
        "rule_id": "BODY_URGENCY_PRESSURE",
        "category": "body",
        "title": "High Urgency / Coercive Language",
        "severity": SeverityEnum.MEDIUM,
        "weight": 15,
        "description": "Message creates artificial urgency, threatening immediate account suspension, legal action, or loss of access if the user does not act immediately.",
        "limitations": "Legitimate security notifications may also communicate time sensitivity."
    },
    "BODY_CREDENTIAL_HARVEST": {
        "rule_id": "BODY_CREDENTIAL_HARVEST",
        "category": "body",
        "title": "Credential or Identity Solicitation",
        "severity": SeverityEnum.HIGH,
        "weight": 25,
        "description": "Message prompts the recipient to verify passwords, enter login credentials, or provide one-time multi-factor authentication (MFA) codes.",
        "limitations": "Contextual detection based on heuristic keyword clusters; legitimate password resets also reference passwords."
    },
    "BODY_FINANCIAL_PRESSURE": {
        "rule_id": "BODY_FINANCIAL_PRESSURE",
        "category": "body",
        "title": "Financial Transaction / Payment Coercion",
        "severity": SeverityEnum.HIGH,
        "weight": 20,
        "description": "Message solicits urgent wire transfers, gift card purchases, unexpected invoice updates, or cryptocurrency transactions.",
        "limitations": "Requires correlation with sender legitimacy to distinguish from legitimate billing notices."
    },
    "URL_TEXT_HREF_MISMATCH": {
        "rule_id": "URL_TEXT_HREF_MISMATCH",
        "category": "urls",
        "title": "Deceptive Anchor vs. Destination Mismatch",
        "severity": SeverityEnum.CRITICAL,
        "weight": 35,
        "description": "The visible text presented to the user displays a trusted domain or URL, but the underlying hyperlink destination leads to an entirely different host.",
        "limitations": "Detected from HTML anchor inspection. Does not evaluate destination redirect chains."
    },
    "URL_IP_LITERAL": {
        "rule_id": "URL_IP_LITERAL",
        "category": "urls",
        "title": "Direct IP-Literal Host in URL",
        "severity": SeverityEnum.HIGH,
        "weight": 25,
        "description": "The URL uses a raw IP address (IPv4 or IPv6) instead of a registered domain name, often used to bypass domain reputation blocklists.",
        "limitations": "Static syntax check. No network connection made."
    },
    "URL_PUNYCODE_CONFUSABLE": {
        "rule_id": "URL_PUNYCODE_CONFUSABLE",
        "category": "urls",
        "title": "Punycode or Homograph Impersonation",
        "severity": SeverityEnum.HIGH,
        "weight": 30,
        "description": "The URL domain utilizes Punycode ('xn--') or Cyrillic/Greek homoglyphs that visually mimic a well-known brand.",
        "limitations": "Static Unicode analysis; non-Latin regional domains may register as punycode legitimately."
    },
    "URL_DECEPTIVE_SUBDOMAIN": {
        "rule_id": "URL_DECEPTIVE_SUBDOMAIN",
        "category": "urls",
        "title": "Deceptive Brand Subdomain Pattern",
        "severity": SeverityEnum.HIGH,
        "weight": 25,
        "description": "A well-known brand is nested as a subdomain or hyphenated prefix within an unrelated apex domain (e.g., login.microsoft.com.security-verify.net).",
        "limitations": "Evaluated against common brand token patterns."
    },
    "URL_USERINFO_EMBEDDED": {
        "rule_id": "URL_USERINFO_EMBEDDED",
        "category": "urls",
        "title": "Embedded User-Info Obfuscation in URL",
        "severity": SeverityEnum.MEDIUM,
        "weight": 20,
        "description": "The URL contains embedded user-info or an '@' symbol intended to confuse users about the actual destination authority.",
        "limitations": "Standard URI syntax parsing."
    },
    "URL_SUSPICIOUS_ENCODING": {
        "rule_id": "URL_SUSPICIOUS_ENCODING",
        "category": "urls",
        "title": "Obfuscated / Multi-Encoded URL Characters",
        "severity": SeverityEnum.MEDIUM,
        "weight": 15,
        "description": "URL includes anomalous double-encoding (%25xx), raw hex escapes, or non-standard port specifications.",
        "limitations": "Syntax parsing only."
    },
    "ATT_DANGEROUS_EXT": {
        "rule_id": "ATT_DANGEROUS_EXT",
        "category": "attachments",
        "title": "High-Risk Executable / Script Extension",
        "severity": SeverityEnum.CRITICAL,
        "weight": 45,
        "description": "Attachment filename carries an executable, script, or disk image extension (.exe, .scr, .vbs, .js, .hta, .bat, .cmd, .ps1, .iso, .vhd).",
        "limitations": "Static filename and magic byte check. No execution permitted."
    },
    "ATT_DOUBLE_EXT": {
        "rule_id": "ATT_DOUBLE_EXT",
        "category": "attachments",
        "title": "Double Extension Obfuscation Technique",
        "severity": SeverityEnum.CRITICAL,
        "weight": 40,
        "description": "Attachment uses a deceptive double extension (e.g., 'document.pdf.exe') to mislead users about the actual file type.",
        "limitations": "Static filename pattern detection."
    },
    "ATT_RTLO_DETECTED": {
        "rule_id": "ATT_RTLO_DETECTED",
        "category": "attachments",
        "title": "Right-to-Left Override (RTLO) Unicode Injection",
        "severity": SeverityEnum.CRITICAL,
        "weight": 45,
        "description": "Attachment filename contains the Unicode Right-to-Left Override character (U+202E), which reverses visible file extension characters.",
        "limitations": "Unicode codepoint scan."
    },
    "ATT_MIME_MISMATCH": {
        "rule_id": "ATT_MIME_MISMATCH",
        "category": "attachments",
        "title": "MIME Type / File Signature Inconsistency",
        "severity": SeverityEnum.HIGH,
        "weight": 30,
        "description": "The declared MIME type or file extension does not match the binary file magic signature detected.",
        "limitations": "Analyzed against authoritative binary signature headers."
    },
    "ATT_OFFICE_MACRO": {
        "rule_id": "ATT_OFFICE_MACRO",
        "category": "attachments",
        "title": "Active Office Macro Code Detected",
        "severity": SeverityEnum.HIGH,
        "weight": 35,
        "description": "Office document contains embedded VBA macros or macro project streams (vbaProject.bin) capable of executing code.",
        "limitations": "Static stream and ZIP structure inspection. Macros were not executed."
    },
    "ATT_PDF_ACTIVE_CONTENT": {
        "rule_id": "ATT_PDF_ACTIVE_CONTENT",
        "category": "attachments",
        "title": "Active PDF Scripting / Launch Action",
        "severity": SeverityEnum.HIGH,
        "weight": 30,
        "description": "PDF structure contains active content tokens such as /JavaScript, /OpenAction, or /Launch.",
        "limitations": "Bounded byte stream scanning. JavaScript code was not interpreted."
    },
    "ATT_HTML_FORM_SCRIPT": {
        "rule_id": "ATT_HTML_FORM_SCRIPT",
        "category": "attachments",
        "title": "HTML Attachment with Credential Form or Script",
        "severity": SeverityEnum.HIGH,
        "weight": 35,
        "description": "HTML or SVG attachment embeds input credential fields, password forms, or obfuscated redirect scripts.",
        "limitations": "DOM syntax inspection. No external resources fetched."
    },
    "ATT_ARCHIVE_SUSPICIOUS": {
        "rule_id": "ATT_ARCHIVE_SUSPICIOUS",
        "category": "attachments",
        "title": "Suspicious Archive Member Identified",
        "severity": SeverityEnum.HIGH,
        "weight": 35,
        "description": "Archive directory table contains members with dangerous extensions, double extensions, or anomalous compression ratios.",
        "limitations": "Central directory metadata inspection only; archive was not extracted to disk."
    },
    "ATT_UNSUPPORTED_TYPE": {
        "rule_id": "ATT_UNSUPPORTED_TYPE",
        "category": "attachments",
        "title": "Unsupported or Incomplete Attachment Inspection",
        "severity": SeverityEnum.LOW,
        "weight": 5,
        "description": "The file type or encryption prevents deep static inspection. Status reported as UNKNOWN / UNSCANNED.",
        "limitations": "Never assume an uninspected file is benign. Additional specialized sandbox analysis advised."
    },
    "AUTH_SPF_NONE": {
        "rule_id": "AUTH_SPF_NONE",
        "category": "authentication",
        "title": "Recorded SPF Policy Missing or None",
        "severity": SeverityEnum.LOW,
        "weight": 5,
        "description": "Recorded headers indicate spf=none or missing SPF policy for the sender domain.",
        "limitations": "Extracted strictly from recorded headers; no live DNS queries performed. Not definitive proof of phishing."
    },
    "AUTH_DKIM_NONE": {
        "rule_id": "AUTH_DKIM_NONE",
        "category": "authentication",
        "title": "Recorded DKIM Signature Missing or None",
        "severity": SeverityEnum.LOW,
        "weight": 5,
        "description": "Email headers record dkim=none or lack a verified cryptographic DKIM signature pass.",
        "limitations": "Extracted strictly from recorded headers; no live DNS queries performed."
    },
    "AUTH_DMARC_NONE": {
        "rule_id": "AUTH_DMARC_NONE",
        "category": "authentication",
        "title": "Recorded DMARC Policy Missing or None",
        "severity": SeverityEnum.LOW,
        "weight": 5,
        "description": "Recorded headers show dmarc=none or no enforced DMARC policy for the sender domain.",
        "limitations": "Extracted strictly from recorded headers; no live DNS queries performed."
    },
    "ATT_MIME_DECLARED_MISMATCH": {
        "rule_id": "ATT_MIME_DECLARED_MISMATCH",
        "category": "attachments",
        "title": "Declared Content-Type / Signature Discrepancy",
        "severity": SeverityEnum.HIGH,
        "weight": 25,
        "description": "The declared MIME Content-Type contradicts the filename extension or detected binary magic bytes.",
        "limitations": "Evaluated against standard MIME mappings and magic byte tables."
    },
    "ATT_OFFICE_MACRO_EXT": {
        "rule_id": "ATT_OFFICE_MACRO_EXT",
        "category": "attachments",
        "title": "Explicit Macro-Enabled Office Extension",
        "severity": SeverityEnum.HIGH,
        "weight": 30,
        "description": "Attachment carries an explicit macro-enabled Office extension (.docm, .xlsm, .dotm, .xltm).",
        "limitations": "Static extension check. Macros were not executed."
    },
    "ATT_HTML_SMUGGLING": {
        "rule_id": "ATT_HTML_SMUGGLING",
        "category": "attachments",
        "title": "HTML Smuggling Technique Detected",
        "severity": SeverityEnum.HIGH,
        "weight": 35,
        "description": "HTML attachment embeds client-side JavaScript download patterns (Blob, URL.createObjectURL, FileReader, or base64 data) intended to deliver payloads past perimeter firewalls.",
        "limitations": "Static DOM syntax inspection. JavaScript code was not executed."
    },
    "ATT_ARCHIVE_ENCRYPTED": {
        "rule_id": "ATT_ARCHIVE_ENCRYPTED",
        "category": "attachments",
        "title": "Password-Protected / Encrypted Archive",
        "severity": SeverityEnum.HIGH,
        "weight": 30,
        "description": "Archive metadata flags that members are password-encrypted, preventing deep static payload inspection.",
        "limitations": "Static archive header inspection. Password was not cracked or brute-forced."
    },
    "ATT_ARCHIVE_PASSWORD_IN_BODY": {
        "rule_id": "ATT_ARCHIVE_PASSWORD_IN_BODY",
        "category": "attachments",
        "title": "Archive Password Instructed in Message Body",
        "severity": SeverityEnum.HIGH,
        "weight": 35,
        "description": "Email body contains likely password instructions correlating with an encrypted archive attachment, a common evasion pattern.",
        "limitations": "Heuristic correlation. Passwords are never stored or logged."
    },
    "ATT_ARCHIVE_NESTED": {
        "rule_id": "ATT_ARCHIVE_NESTED",
        "category": "attachments",
        "title": "Nested Archive Structure Identified",
        "severity": SeverityEnum.MEDIUM,
        "weight": 20,
        "description": "Archive directory contains nested archive files (.zip, .tar, .7z, .iso), commonly used to evade single-tier security scanners.",
        "limitations": "Bounded in-memory directory scan. Contents not extracted to disk."
    },
    "ATT_ARCHIVE_DEPTH_EXCEEDED": {
        "rule_id": "ATT_ARCHIVE_DEPTH_EXCEEDED",
        "category": "attachments",
        "title": "Archive Nesting Depth Limit Exceeded",
        "severity": SeverityEnum.HIGH,
        "weight": 25,
        "description": "Archive structure exceeds maximum allowed nesting depth (depth > 2). Inner contents marked UNSCANNED.",
        "limitations": "Enforced bounds to prevent decompression bomb or recursion denial of service."
    },
    "ATT_CORRUPT_OR_UNPARSEABLE": {
        "rule_id": "ATT_CORRUPT_OR_UNPARSEABLE",
        "category": "attachments",
        "title": "Corrupt or Unparseable Attachment Structure",
        "severity": SeverityEnum.MEDIUM,
        "weight": 15,
        "description": "Attachment file headers or compression table are corrupt or unparseable. Reported as UNKNOWN with reason.",
        "limitations": "Parsing blocked by truncated or corrupt data. Never assumed safe."
    },
    "ATT_LIMIT_EXCEEDED": {
        "rule_id": "ATT_LIMIT_EXCEEDED",
        "category": "attachments",
        "title": "Attachment Processing Limits Exceeded",
        "severity": SeverityEnum.MEDIUM,
        "weight": 15,
        "description": "Attachment exceeds file size threshold or email exceeds maximum attachment count. Marked UNSCANNED.",
        "limitations": "Inputs beyond limits are marked UNSCANNED, never SAFE."
    }
}
