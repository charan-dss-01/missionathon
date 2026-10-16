"""Static QR code detection and syntactic analysis for email image attachments.

Decodes barcodes in-memory without disk execution or remote network fetching.
Enforces strict size, dimension, and per-email count limits to prevent image bombs.
"""

import io
import struct
import logging
from typing import List, Tuple, Dict, Any, Optional
from urllib.parse import urlparse

from app.models.schemas import (
    AttachmentFinding,
    EvidenceRecord,
    URLFinding,
    SeverityEnum,
    ConfidenceEnum
)
from app.analyzers.url_analyzer import URLAnalyzer
from app.engine.qr_rules import QR_RULE_DEFINITIONS
from app.services.defang import defang_url

logger = logging.getLogger(__name__)

# 1. Optional dependency check: OpenCV / pyzbar
QR_AVAILABLE = False
try:
    import cv2
    import numpy as np
    QR_AVAILABLE = True
except Exception as e:
    try:
        from pyzbar import pyzbar
        QR_AVAILABLE = True
    except Exception:
        QR_AVAILABLE = False
        logger.info(f"QR detection library unavailable ({e}). Skipping QR analysis silently.")


# Limits
MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_DIMENSION = 4000               # 4000 x 4000 px
MAX_IMAGES_PER_EMAIL = 3


class QRAnalysisResult(list):
    """
    Dual list/dict container representing the QR analysis results for an attachment.
    Can be iterated over as a list of findings, or queried as a dict/object.
    """
    def __init__(self, items=None, **kwargs):
        super().__init__(items or [])
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __getitem__(self, key):
        if isinstance(key, str):
            if key in self.__dict__:
                return self.__dict__[key]
            raise KeyError(key)
        return super().__getitem__(key)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)


def detect_image_type_by_magic(data: bytes) -> Optional[str]:
    """Detects PNG, JPEG, or GIF based strictly on magic header bytes, not file extension."""
    if len(data) < 8:
        return None
    if data.startswith(b"\x89PNG\r\n\x1a\n") or data.startswith(b"\x89PNG"):
        return "PNG"
    if data.startswith(b"\xff\xd8"):
        return "JPEG"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "GIF"
    return None


def get_image_dimensions_from_header(data: bytes) -> Optional[Tuple[int, int]]:
    """
    Extracts image (width, height) directly from the binary header
    WITHOUT decoding full pixel bitmaps into memory.
    """
    if len(data) < 16:
        return None

    # PNG: IHDR chunk has width and height at offset 16..24
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        try:
            w, h = struct.unpack(">II", data[16:24])
            return (w, h)
        except Exception:
            return None

    # GIF: Logical Screen Width & Height at offset 6..10
    if (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")) and len(data) >= 10:
        try:
            w, h = struct.unpack("<HH", data[6:10])
            return (w, h)
        except Exception:
            return None

    # JPEG: Scan marker stream for Start Of Frame (SOF) markers
    if data.startswith(b"\xff\xd8"):
        idx = 2
        data_len = len(data)
        while idx < data_len - 9:
            if data[idx] != 0xFF:
                idx += 1
                continue
            marker = data[idx + 1]
            # Standard SOF markers (SOF0..SOF15 except DHT, JPG, DAC)
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                try:
                    h, w = struct.unpack(">HH", data[idx + 5:idx + 9])
                    return (w, h)
                except Exception:
                    break
            elif marker == 0xD9:  # End of Image
                break
            else:
                try:
                    length = struct.unpack(">H", data[idx + 2:idx + 4])[0]
                    idx += 2 + length
                except Exception:
                    break

    # Header parsing fallback using PIL if available without loading pixels
    try:
        from PIL import Image
        with Image.open(io.BytesIO(data)) as im:
            return im.size
    except Exception:
        return None


def is_suspicious_decoded_url(raw_url: str, url_evidence: List[EvidenceRecord], url_findings: List[URLFinding]) -> bool:
    """
    Evaluates whether a decoded URL exhibits phishing, brand typosquatting,
    or evasive characteristics.
    """
    # 1. Any evidence emitted by URLAnalyzer
    if url_evidence:
        return True

    # 2. Any URLFinding with elevated severity or matched rules
    for f in url_findings:
        if f.severity in (SeverityEnum.MEDIUM, SeverityEnum.HIGH, SeverityEnum.CRITICAL):
            return True
        if f.matched_rules:
            return True

    # 3. Static brand typosquatting / leetspeak heuristics
    parsed = urlparse(raw_url.lower())
    netloc = parsed.netloc.split(":")[0]
    path = parsed.path

    typo_brands = [
        "paypa1", "paypai", "micros0ft", "m1crosoft", "goog1e", "g00gle",
        "app1e", "amaz0n", "docus1gn", "wellsfarg0", "netf1ix", "bofa"
    ]
    for brand in typo_brands:
        if brand in netloc:
            return True

    # 4. Credential / login path on non-standard domains or TLDs
    if any(k in path for k in ["/login", "/signin", "/verify", "/account", "/auth", "/password", "/update"]):
        suspicious_tlds = [".test", ".xyz", ".top", ".tk", ".ml", ".work", ".click", ".buzz", ".live"]
        if any(netloc.endswith(tld) for tld in suspicious_tlds):
            return True
        if "-" in netloc or any(k in netloc for k in ["secure", "verify", "update", "portal"]):
            return True

    return False


def analyze_qr(filename: str, data: bytes) -> Tuple[QRAnalysisResult, List[EvidenceRecord]]:
    """
    Inspects an image attachment statically for QR codes and analyzes decoded URLs.
    
    Safety constraints:
    - Only for PNG/JPEG/GIF verified by magic bytes.
    - Max 5 MB file size.
    - Max 4000x4000 pixels checked BEFORE decoding.
    - In-memory decoding only.
    - Never fetches remote targets.
    - Returns (qr_findings, evidence_records).
    """
    evidence_records: List[EvidenceRecord] = []

    # 1. Library availability check
    if not QR_AVAILABLE:
        return (
            QRAnalysisResult(
                [],
                filename=filename,
                qr_detected=False,
                payloads=[],
                coverage_status="UNKNOWN",
                limitations="QR detection library (opencv-python-headless/pyzbar) is unavailable. Status reported as UNKNOWN."
            ),
            []
        )

    # 2. Magic byte inspection (PNG / JPEG / GIF only)
    img_type = detect_image_type_by_magic(data)
    if not img_type:
        return (
            QRAnalysisResult(
                [],
                filename=filename,
                qr_detected=False,
                payloads=[],
                coverage_status="SKIPPED",
                limitations="File magic bytes do not match supported image formats (PNG/JPEG/GIF)."
            ),
            []
        )

    # 3. File size limit
    if len(data) > MAX_IMAGE_BYTES:
        return (
            QRAnalysisResult(
                [],
                filename=filename,
                qr_detected=False,
                payloads=[],
                coverage_status="UNSCANNED",
                limitations=f"Image size ({len(data)} bytes) exceeds 5MB limit. Reported as UNSCANNED."
            ),
            []
        )

    # 4. Pixel dimensions limit checked from header BEFORE decoding
    dims = get_image_dimensions_from_header(data)
    if dims is None:
        return (
            QRAnalysisResult(
                [],
                filename=filename,
                qr_detected=False,
                payloads=[],
                coverage_status="UNKNOWN",
                limitations="Failed to safely read image header dimensions. Reported as UNKNOWN."
            ),
            []
        )

    w, h = dims
    if w > MAX_DIMENSION or h > MAX_DIMENSION:
        return (
            QRAnalysisResult(
                [],
                filename=filename,
                qr_detected=False,
                payloads=[],
                coverage_status="UNSCANNED",
                limitations=f"Image dimensions ({w}x{h}) exceed safety limit ({MAX_DIMENSION}x{MAX_DIMENSION}). Reported as UNSCANNED."
            ),
            []
        )

    # 5. Decode image in-memory only
    try:
        nparr = np.frombuffer(data, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return (
                QRAnalysisResult(
                    [],
                    filename=filename,
                    qr_detected=False,
                    payloads=[],
                    coverage_status="UNKNOWN",
                    limitations="In-memory image decoding failed. Reported as UNKNOWN."
                ),
                []
            )

        detector = cv2.QRCodeDetector()
        raw_payloads: List[str] = []

        # Attempt multi-code detection
        try:
            retval, decoded_info, _, _ = detector.detectAndDecodeMulti(img)
            if retval and decoded_info:
                for text in decoded_info:
                    if text and text.strip():
                        raw_payloads.append(text.strip())
        except Exception:
            pass

        # Fallback to single detector if multi returned nothing
        if not raw_payloads:
            try:
                single_text, _, _ = detector.detectAndDecode(img)
                if single_text and single_text.strip():
                    raw_payloads.append(single_text.strip())
            except Exception:
                pass

    except Exception as e:
        logger.warning(f"Error scanning QR code in {filename}: {e}")
        return (
            QRAnalysisResult(
                [],
                filename=filename,
                qr_detected=False,
                payloads=[],
                coverage_status="UNKNOWN",
                limitations=f"Error encountered during QR code detection: {str(e)}. Reported as UNKNOWN."
            ),
            []
        )

    # 6. No QR detected in image
    if not raw_payloads:
        return (
            QRAnalysisResult(
                [],
                filename=filename,
                qr_detected=False,
                payloads=[],
                coverage_status="SCANNED",
                limitations="No QR codes detected in image."
            ),
            []
        )

    # 7. QR detected: process each decoded payload
    payload_findings: List[Dict[str, Any]] = []
    all_url_findings: List[URLFinding] = []
    matched_rules: List[str] = []

    # Rule 1: ATT_QR_PRESENT (Severity LOW)
    rule_present = QR_RULE_DEFINITIONS["ATT_QR_PRESENT"]
    matched_rules.append(rule_present["rule_id"])
    evidence_records.append(EvidenceRecord(
        rule_id=rule_present["rule_id"],
        category=rule_present["category"],
        title=rule_present["title"],
        severity=rule_present["severity"],
        description=rule_present["description"],
        supporting_observation=(
            f"Image attachment '{filename}' contains an embedded QR code barcode. "
            f"Decoded payload(s): {', '.join(defang_url(p) for p in raw_payloads[:3])}"
        ),
        source_location=f"Attachment: {filename} (QR Code)",
        confidence=ConfidenceEnum.CONFIRMED,
        limitations=rule_present["limitations"]
    ))

    # Evaluate each payload
    has_flagged_url = False
    for payload in raw_payloads:
        parsed = urlparse(payload.strip())
        is_url = parsed.scheme.lower() in ("http", "https") and bool(parsed.netloc)

        item_findings: List[URLFinding] = []
        item_evidence: List[EvidenceRecord] = []

        if is_url:
            # Static syntactic inspection through URLAnalyzer (NEVER fetches remote resources)
            item_findings, item_evidence = URLAnalyzer.analyze_urls([
                {"url": payload, "display_text": f"Decoded QR from {filename}"}
            ])
            all_url_findings.extend(item_findings)
            evidence_records.extend(item_evidence)

            # Check if this URL should trigger ATT_QR_URL_FLAGGED
            if is_suspicious_decoded_url(payload, item_evidence, item_findings):
                has_flagged_url = True

        payload_findings.append({
            "payload": payload,
            "is_url": is_url,
            "defanged": defang_url(payload) if is_url else payload,
            "url_findings": item_findings,
            "url_evidence": item_evidence
        })

    # Rule 2: ATT_QR_URL_FLAGGED (Severity HIGH)
    if has_flagged_url:
        rule_flagged = QR_RULE_DEFINITIONS["ATT_QR_URL_FLAGGED"]
        matched_rules.append(rule_flagged["rule_id"])
        evidence_records.append(EvidenceRecord(
            rule_id=rule_flagged["rule_id"],
            category=rule_flagged["category"],
            title=rule_flagged["title"],
            severity=rule_flagged["severity"],
            description=rule_flagged["description"],
            supporting_observation=(
                f"QR code inside '{filename}' decodes to a flagged or suspicious URL: "
                f"{', '.join(defang_url(p) for p in raw_payloads if urlparse(p).scheme.lower() in ('http', 'https'))}"
            ),
            source_location=f"Attachment: {filename} (QR Code)",
            confidence=ConfidenceEnum.CONFIRMED,
            limitations=rule_flagged["limitations"]
        ))

    result = QRAnalysisResult(
        payload_findings,
        filename=filename,
        qr_detected=True,
        payloads=raw_payloads,
        urls=[p for p in raw_payloads if urlparse(p).scheme.lower() in ("http", "https")],
        url_findings=all_url_findings,
        coverage_status="SCANNED",
        matched_rules=matched_rules,
        limitations="Decoded strictly in-memory. URLs analyzed purely syntactically without network access."
    )

    return result, evidence_records


def process_attachments_qr(
    raw_attachments: List[Dict[str, Any]],
    findings: List[AttachmentFinding],
    evidence: List[EvidenceRecord],
    state: Optional[Dict[str, Any]] = None
) -> Tuple[List[AttachmentFinding], List[EvidenceRecord]]:
    """
    Hook called from graph.py to scan image attachments for QR codes.
    Limits scanning to max 3 images per email. On any error reports the image
    as UNKNOWN with a reason, never SAFE.
    """
    image_count = 0

    for raw in raw_attachments:
        filename = raw.get("filename", "unknown_file")
        data = raw.get("bytes", b"")

        # Find matching finding in findings
        match_finding = next((f for f in findings if f.filename == filename), None)

        # Check magic bytes for image
        img_type = detect_image_type_by_magic(data)
        if not img_type:
            continue

        image_count += 1
        if image_count > MAX_IMAGES_PER_EMAIL:
            if match_finding:
                match_finding.coverage_status = "UNSCANNED"
                match_finding.limitations = (
                    f"Exceeded maximum scan limit of {MAX_IMAGES_PER_EMAIL} images per email. "
                    "Reported as UNSCANNED."
                )
            continue

        try:
            qr_result, qr_evidence = analyze_qr(filename, data)

            if match_finding:
                # Update coverage status based on QR result if it was unscanned or unknown
                if qr_result.coverage_status in ("UNSCANNED", "UNKNOWN"):
                    match_finding.coverage_status = qr_result.coverage_status
                    match_finding.limitations = qr_result.limitations
                    if qr_result.coverage_status == "UNKNOWN":
                        match_finding.detected_type = "UNKNOWN"

                # If QR code was detected, update finding
                if qr_result.get("qr_detected"):
                    match_finding.matched_rules.extend(qr_result.get("matched_rules", []))
                    match_finding.detected_type = f"{img_type} (QR Code)"

            # Append new evidence records
            evidence.extend(qr_evidence)

            # Attach any decoded URL findings to state if provided
            if state is not None and qr_result.get("url_findings"):
                current_urls = state.get("url_findings", [])
                state["url_findings"] = current_urls + qr_result.get("url_findings", [])

        except Exception as err:
            logger.error(f"Unexpected error in QR scanning for {filename}: {err}")
            if match_finding:
                match_finding.coverage_status = "UNKNOWN"
                match_finding.detected_type = "UNKNOWN"
                match_finding.limitations = f"QR inspection failed: {str(err)}. Status reported as UNKNOWN."

    return findings, evidence
