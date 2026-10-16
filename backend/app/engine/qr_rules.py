"""QR Code Detection & Analysis Rules for PhishGuard AI."""

from typing import Dict, Any
from app.models.schemas import SeverityEnum
from app.engine.rule_definitions import RULE_DEFINITIONS

QR_RULE_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "ATT_QR_PRESENT": {
        "rule_id": "ATT_QR_PRESENT",
        "category": "attachments",
        "title": "QR Code Detected in Image Attachment",
        "severity": SeverityEnum.LOW,
        "weight": 10,
        "description": "An image attachment contains an embedded QR code barcode (quishing vector) capable of leading to external resources.",
        "limitations": "Detection is purely static barcode recognition. Legitimate flyers, event invitations, and documents regularly include QR codes."
    },
    "ATT_QR_URL_FLAGGED": {
        "rule_id": "ATT_QR_URL_FLAGGED",
        "category": "attachments",
        "title": "Malicious or Suspicious URL Decoded from QR Code",
        "severity": SeverityEnum.HIGH,
        "weight": 30,
        "description": "A QR code inside an image attachment decodes to a URL exhibiting phishing, homograph, or deceptive characteristics.",
        "limitations": "URL inspection is purely static and syntactic; no remote connection or redirect resolution was performed."
    }
}

QR_RULE_METADATA: Dict[str, Dict[str, Any]] = {
    "ATT_QR_PRESENT": {
        "stage": "delivery",
        "mitre_id": "T1566.002",
        "mitre_name": "Spearphishing Link",
        "plain_text": "An image attachment contains an embedded QR code, which may be used to divert you away from enterprise email security controls.",
        "hint": "Exercise caution before scanning QR codes received from unexpected sources.",
    },
    "ATT_QR_URL_FLAGGED": {
        "stage": "delivery",
        "mitre_id": "T1566.002",
        "mitre_name": "Spearphishing Link",
        "plain_text": "The QR code in the image attachment points to a suspicious or deceptive link.",
        "hint": "Do not navigate to the destination link encoded within this QR code.",
    },
}

# Additive merge into global definitions and presentation metadata
for r_id, r_def in QR_RULE_DEFINITIONS.items():
    if r_id not in RULE_DEFINITIONS:
        RULE_DEFINITIONS[r_id] = r_def

