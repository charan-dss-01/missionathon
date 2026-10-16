import hashlib
import zipfile
import io
import re
from typing import List, Tuple, Dict, Any, Optional
from bs4 import BeautifulSoup

from app.models.schemas import (
    AttachmentFinding,
    EvidenceRecord,
    SeverityEnum,
    ConfidenceEnum,
    RiskRatingEnum
)
from app.engine.rule_definitions import RULE_DEFINITIONS

# High-risk executable/script extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".bat", ".cmd", ".ps1", ".psm1", ".hta", ".cpl", ".iso", ".img",
    ".vhd", ".vhdx", ".lnk", ".pif", ".jar", ".msi", ".reg", ".dll"
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".dotm", ".xltm", ".pptm", ".potm"}

DOUBLE_EXT_ALLOWED_INNER = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".jpg", ".png", ".txt"}

ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".iso"}

# Known file signatures (magic bytes)
MAGIC_SIGNATURES = [
    (b"MZ", "Windows PE Executable (.exe/.dll/.scr)", [".exe", ".dll", ".scr", ".cpl"]),
    (b"%PDF-", "PDF Document", [".pdf"]),
    (b"PK\x03\x04", "ZIP / OOXML Archive", [".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".jar", ".apk"]),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE Compound Document (Legacy Office)", [".doc", ".xls", ".ppt", ".msg"]),
    (b"\x89PNG\r\n\x1a\n", "PNG Image", [".png"]),
    (b"\xff\xd8\xff", "JPEG Image", [".jpg", ".jpeg"]),
    (b"GIF87a", "GIF Image", [".gif"]),
    (b"GIF89a", "GIF Image", [".gif"]),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", [".7z"]),
    (b"Rar!\x1a\x07", "RAR Archive", [".rar"]),
    (b"\x1f\x8b", "GZIP Compressed", [".gz", ".tar.gz"])
]

# Mapping of common declared MIME types to permissible extensions
MIME_TO_EXTENSIONS = {
    "application/pdf": [".pdf"],
    "image/jpeg": [".jpg", ".jpeg"],
    "image/png": [".png"],
    "image/gif": [".gif"],
    "text/plain": [".txt", ".log", ".csv"],
    "text/html": [".html", ".htm"],
    "application/zip": [".zip"],
    "application/x-zip-compressed": [".zip"],
    "application/vnd.ms-excel": [".xls", ".csv", ".xlsm"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [".xlsx"],
    "application/msword": [".doc", ".dot"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [".docx"],
    "application/vnd.ms-word.document.macroenabled.12": [".docm"],
    "application/vnd.ms-excel.sheet.macroenabled.12": [".xlsm"]
}

class AttachmentAnalyzer:
    """
    Safely inspects file attachments statically without execution or extraction to disk.
    Enforces strict memory, entry-count, attachment-count, and nested structure limits.
    """

    MAX_INSPECT_BYTES = 5 * 1024 * 1024 # 5 MB
    MAX_ARCHIVE_ENTRIES = 50
    MAX_ATTACHMENTS_PER_EMAIL = 10
    MAX_NESTING_DEPTH = 2

    @classmethod
    def analyze_attachments(
        cls,
        attachments: List[Dict[str, Any]],
        email_body: str = ""
    ) -> Tuple[List[AttachmentFinding], List[EvidenceRecord]]:
        findings: List[AttachmentFinding] = []
        evidence: List[EvidenceRecord] = []

        for idx, att in enumerate(attachments):
            filename = att.get("filename", "unknown_file")
            data = att.get("bytes", b"")
            declared_mime = att.get("content_type", "")

            # Enforce maximum attachments per email limit
            if idx >= cls.MAX_ATTACHMENTS_PER_EMAIL:
                sha256 = hashlib.sha256(data).hexdigest() if data else ""
                rule = RULE_DEFINITIONS["ATT_LIMIT_EXCEEDED"]
                limit_ev = EvidenceRecord(
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    title=rule["title"],
                    severity=rule["severity"],
                    description=rule["description"],
                    supporting_observation=(
                        f"Attachment '{filename}' exceeds maximum attachments-per-email limit "
                        f"({cls.MAX_ATTACHMENTS_PER_EMAIL}). Marked UNSCANNED, never SAFE."
                    ),
                    source_location=f"Attachment Index {idx + 1}: {filename}",
                    confidence=ConfidenceEnum.CONFIRMED,
                    limitations="Limits enforced. Inputs beyond limits are marked UNSCANNED, never SAFE."
                )
                evidence.append(limit_ev)
                findings.append(AttachmentFinding(
                    filename=filename,
                    declared_mime=declared_mime,
                    detected_type="UNSCANNED_LIMIT_EXCEEDED",
                    size_bytes=len(data),
                    sha256=sha256,
                    coverage_status="UNSCANNED",
                    matched_rules=["ATT_LIMIT_EXCEEDED"],
                    limitations="Exceeds attachments-per-email limit. Marked UNSCANNED, never SAFE.",
                    risk_score=0,
                    risk_level=RiskRatingEnum.UNSCANNED,
                    recommended_action="Classification inconclusive: attachment exceeds the maximum attachments-per-email limit (10). Marked UNSCANNED (never assume safe). Submit for offline perimeter analysis.",
                    classification_reason="Unscanned: Exceeds attachments-per-email limit.",
                    evidence_records=[limit_ev]
                ))
                continue

            finding, ev_list = cls._inspect_single_attachment(filename, data, declared_mime, email_body)
            findings.append(finding)
            evidence.extend(ev_list)

        return findings, evidence

    @classmethod
    def _inspect_single_attachment(
        cls,
        filename: str,
        data: bytes,
        declared_mime: str,
        email_body: str = ""
    ) -> Tuple[AttachmentFinding, List[EvidenceRecord]]:
        ev_list: List[EvidenceRecord] = []
        matched_rules: List[str] = []

        size_bytes = len(data)
        sha256 = hashlib.sha256(data).hexdigest() if data else ""

        # 1. Check size bounds
        if size_bytes > cls.MAX_INSPECT_BYTES:
            rule = RULE_DEFINITIONS["ATT_LIMIT_EXCEEDED"]
            limit_ev = EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=(
                    f"Attachment '{filename}' ({size_bytes / (1024*1024):.1f}MB) exceeds 5.0MB inspection limit. "
                    "Marked UNSCANNED, never SAFE."
                ),
                source_location=f"Attachment: {filename}",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations="Limits enforced. Inputs beyond limits are marked UNSCANNED, never SAFE."
            )
            ev_list.append(limit_ev)
            finding = AttachmentFinding(
                filename=filename,
                declared_mime=declared_mime,
                detected_type="OVERSIZED",
                size_bytes=size_bytes,
                sha256=sha256,
                coverage_status="OVERSIZED",
                matched_rules=["ATT_LIMIT_EXCEEDED"],
                limitations=f"File exceeds inspection limit ({cls.MAX_INSPECT_BYTES / (1024*1024):.1f}MB). Reported as UNSCANNED, never SAFE.",
                risk_score=0,
                risk_level=RiskRatingEnum.UNSCANNED,
                recommended_action="Classification inconclusive: file exceeds the 5.0MB safe static inspection limit. Marked UNSCANNED (never assume safe). Submit for offline perimeter analysis.",
                classification_reason=f"Unscanned: File exceeds inspection limit ({size_bytes / (1024*1024):.1f}MB > 5.0MB).",
                evidence_records=[limit_ev]
            )
            return finding, ev_list

        # 2. Right-to-Left Override (RTLO) Check in filename
        rtlo_detected = "\u202e" in filename
        if rtlo_detected:
            matched_rules.append("ATT_RTLO_DETECTED")
            rule = RULE_DEFINITIONS["ATT_RTLO_DETECTED"]
            ev_list.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=f"Filename '{filename}' contains Unicode Right-to-Left Override character (\\u202e) used to mask extension.",
                source_location=f"Attachment Filename: {filename}",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations=rule["limitations"]
            ))

        # 3. Filename Extensions Inspection
        clean_name = filename.replace("\u202e", "").strip().lower()
        parts = clean_name.split(".")
        outer_ext = f".{parts[-1]}" if len(parts) > 1 else ""
        
        dangerous_ext = outer_ext in DANGEROUS_EXTENSIONS
        if dangerous_ext:
            matched_rules.append("ATT_DANGEROUS_EXT")
            rule = RULE_DEFINITIONS["ATT_DANGEROUS_EXT"]
            ev_list.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=f"File has high-risk executable/script extension '{outer_ext}'.",
                source_location=f"Attachment: {filename}",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations=rule["limitations"]
            ))

        # Macro-enabled extension check
        macro_ext = outer_ext in MACRO_EXTENSIONS
        if macro_ext:
            matched_rules.append("ATT_OFFICE_MACRO_EXT")
            rule = RULE_DEFINITIONS["ATT_OFFICE_MACRO_EXT"]
            ev_list.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation=f"File carries an explicitly macro-enabled Office extension '{outer_ext}'.",
                source_location=f"Attachment: {filename}",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations=rule["limitations"]
            ))

        # Double Extension Check (e.g. invoice.pdf.exe)
        double_ext = False
        if len(parts) >= 3:
            inner_ext = f".{parts[-2]}"
            if inner_ext in DOUBLE_EXT_ALLOWED_INNER and dangerous_ext:
                double_ext = True
                matched_rules.append("ATT_DOUBLE_EXT")
                rule = RULE_DEFINITIONS["ATT_DOUBLE_EXT"]
                ev_list.append(EvidenceRecord(
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    title=rule["title"],
                    severity=rule["severity"],
                    description=rule["description"],
                    supporting_observation=f"File uses deceptive double extension '{inner_ext}{outer_ext}' to impersonate a document.",
                    source_location=f"Attachment: {filename}",
                    confidence=ConfidenceEnum.CONFIRMED,
                    limitations=rule["limitations"]
                ))

        # 4. Magic Byte & MIME Validation
        detected_type = "UNKNOWN"
        matching_exts = []
        for magic, desc, valid_exts in MAGIC_SIGNATURES:
            if data.startswith(magic):
                detected_type = desc
                matching_exts = valid_exts
                break

        # Check for signature / extension mismatch (e.g. named .pdf but is Windows PE executable)
        if matching_exts and outer_ext:
            if outer_ext not in matching_exts:
                matched_rules.append("ATT_MIME_MISMATCH")
                rule = RULE_DEFINITIONS["ATT_MIME_MISMATCH"]
                ev_list.append(EvidenceRecord(
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    title=rule["title"],
                    severity=rule["severity"],
                    description=rule["description"],
                    supporting_observation=f"Extension '{outer_ext}' contradicts detected binary magic '{detected_type}'.",
                    source_location=f"Attachment Signature: {filename}",
                    confidence=ConfidenceEnum.CONFIRMED,
                    limitations=rule["limitations"]
                ))

        # Check declared MIME mismatch
        norm_mime = declared_mime.strip().lower().split(";")[0] if declared_mime else ""
        if norm_mime and norm_mime not in ["application/octet-stream", "binary/octet-stream", "application/x-download"]:
            expected_exts = MIME_TO_EXTENSIONS.get(norm_mime)
            if expected_exts:
                mismatch_reasons = []
                if outer_ext and outer_ext not in expected_exts:
                    mismatch_reasons.append(f"extension '{outer_ext}' is not standard for declared MIME '{norm_mime}'")
                if matching_exts and not any(e in matching_exts for e in expected_exts):
                    mismatch_reasons.append(f"binary signature '{detected_type}' does not correspond to '{norm_mime}'")

                if mismatch_reasons:
                    matched_rules.append("ATT_MIME_DECLARED_MISMATCH")
                    rule = RULE_DEFINITIONS["ATT_MIME_DECLARED_MISMATCH"]
                    ev_list.append(EvidenceRecord(
                        rule_id=rule["rule_id"],
                        category=rule["category"],
                        title=rule["title"],
                        severity=rule["severity"],
                        description=rule["description"],
                        supporting_observation=f"Declared Content-Type '{norm_mime}' mismatch: {'; '.join(mismatch_reasons)}.",
                        source_location=f"Declared MIME Header: {filename}",
                        confidence=ConfidenceEnum.CONFIRMED,
                        limitations=rule["limitations"]
                    ))

        # 5. Specialized Deep Structural Check: PDF Active Content (/JavaScript, /OpenAction, /Launch, /EmbeddedFile)
        active_content = False
        if outer_ext == ".pdf" or data.startswith(b"%PDF-"):
            pdf_sample = data[:min(len(data), cls.MAX_INSPECT_BYTES)]
            pdf_tokens = re.findall(rb"/(JavaScript|JS|OpenAction|Launch|EmbeddedFile)\b", pdf_sample)
            if pdf_tokens:
                active_content = True
                token_names = ", ".join(sorted(list({t.decode("ascii", errors="ignore") for t in pdf_tokens})))
                matched_rules.append("ATT_PDF_ACTIVE_CONTENT")
                rule = RULE_DEFINITIONS["ATT_PDF_ACTIVE_CONTENT"]
                ev_list.append(EvidenceRecord(
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    title=rule["title"],
                    severity=rule["severity"],
                    description=rule["description"],
                    supporting_observation=f"PDF structure contains active content tokens (/{token_names}).",
                    source_location=f"PDF Structure: {filename}",
                    confidence=ConfidenceEnum.HIGH,
                    limitations=rule["limitations"]
                ))

        # 6. Specialized Deep Structural Check: Office Macros
        macro_detected = macro_ext
        # OOXML check (.docm, .xlsm, or disguised .docx with vbaProject.bin)
        if data.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
                    member_names = zf.namelist()
                    if any("vbaProject.bin" in m or "vbaData.xml" in m for m in member_names):
                        macro_detected = True
            except Exception:
                pass
        # OLE legacy check (D0CF11E0)
        elif data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            if any(k in data for k in [b"VBA", b"Macro", b"_VBA_PROJECT", b"Sub AutoOpen", b"Document_Open"]):
                macro_detected = True

        if macro_detected and not macro_ext:
            matched_rules.append("ATT_OFFICE_MACRO")
            rule = RULE_DEFINITIONS["ATT_OFFICE_MACRO"]
            ev_list.append(EvidenceRecord(
                rule_id=rule["rule_id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                description=rule["description"],
                supporting_observation="Office document contains active VBA macro code or vbaProject.bin stream.",
                source_location=f"Document Streams: {filename}",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations=rule["limitations"]
            ))

        # 7. Specialized Structural Check: HTML / SVG Phishing & Smuggling
        forms_scripts_detected = False
        if outer_ext in [".html", ".htm", ".svg"] or b"<html" in data[:500].lower() or b"<!doctype html" in data[:500].lower():
            html_snippet = data[:200000].lower()
            has_form = b"<form" in html_snippet
            has_pwd = b'type="password"' in html_snippet or b"type='password'" in html_snippet
            has_action = b"action=" in html_snippet
            has_script = b"<script" in html_snippet

            if (has_form and (has_pwd or has_action)) or (has_script and (b"window.location" in html_snippet or b"eval(" in html_snippet or b"document.write" in html_snippet)):
                forms_scripts_detected = True
                matched_rules.append("ATT_HTML_FORM_SCRIPT")
                rule = RULE_DEFINITIONS["ATT_HTML_FORM_SCRIPT"]
                ev_list.append(EvidenceRecord(
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    title=rule["title"],
                    severity=rule["severity"],
                    description=rule["description"],
                    supporting_observation="HTML attachment contains credential harvesting password input form or redirect script.",
                    source_location=f"HTML Attachment: {filename}",
                    confidence=ConfidenceEnum.CONFIRMED,
                    limitations=rule["limitations"]
                ))

            # Check for HTML Smuggling
            smuggling_indicators = []
            if b"createobjecturl" in html_snippet or b"blob(" in html_snippet:
                smuggling_indicators.append("Blob / createObjectURL")
            if b"filereader" in html_snippet:
                smuggling_indicators.append("FileReader")
            if (b'download="' in html_snippet or b"download='" in html_snippet) and (b"data:application/octet-stream" in html_snippet or b"base64," in html_snippet):
                smuggling_indicators.append("Base64 Download Mechanism")

            if smuggling_indicators:
                matched_rules.append("ATT_HTML_SMUGGLING")
                rule = RULE_DEFINITIONS["ATT_HTML_SMUGGLING"]
                ev_list.append(EvidenceRecord(
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    title=rule["title"],
                    severity=rule["severity"],
                    description=rule["description"],
                    supporting_observation=f"HTML attachment exhibits HTML-smuggling indicators: {', '.join(smuggling_indicators)}.",
                    source_location=f"HTML Attachment: {filename}",
                    confidence=ConfidenceEnum.CONFIRMED,
                    limitations=rule["limitations"]
                ))

        # 8. Archive Inspection (Central Directory Header Inspection without disk extraction)
        archive_members: List[str] = []
        is_encrypted = False
        nested_count = 0
        unparseable_reason = None
        is_archive = data.startswith(b"PK\x03\x04") and outer_ext in [".zip", ".7z", ".rar", ".tar", ".gz"]

        if is_archive:
            try:
                with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
                    infolist = zf.infolist()
                    suspicious_members = []
                    for idx, info in enumerate(infolist):
                        if idx >= cls.MAX_ARCHIVE_ENTRIES:
                            break
                        archive_members.append(info.filename)

                        # Check encryption flag bit (bit 0 indicates password encryption)
                        if info.flag_bits & 0x1:
                            is_encrypted = True

                        m_name_lower = info.filename.lower()
                        m_ext = f".{m_name_lower.split('.')[-1]}" if "." in m_name_lower else ""

                        if m_ext in DANGEROUS_EXTENSIONS:
                            suspicious_members.append(info.filename)

                        if m_ext in ARCHIVE_EXTENSIONS and info.filename != filename:
                            nested_count += 1

                    if is_encrypted:
                        matched_rules.append("ATT_ARCHIVE_ENCRYPTED")
                        rule = RULE_DEFINITIONS["ATT_ARCHIVE_ENCRYPTED"]
                        ev_list.append(EvidenceRecord(
                            rule_id=rule["rule_id"],
                            category=rule["category"],
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            supporting_observation="Archive metadata flags that members are password-encrypted, preventing deep static payload inspection.",
                            source_location=f"Archive Headers: {filename}",
                            confidence=ConfidenceEnum.CONFIRMED,
                            limitations=rule["limitations"]
                        ))

                        # Check for password instruction in email body
                        if email_body:
                            pwd_cue = re.search(
                                r"(?:pass(?:word)?|passcode|code|archive\s+pass(?:word)?)\s*[:=]\s*(\S+)",
                                email_body,
                                re.IGNORECASE
                            ) or re.search(
                                r"(?:password|passcode)\s+(?:is|to\s+extract|to\s+open|to\s+unlock)\s*[:]?\s*(\S+)",
                                email_body,
                                re.IGNORECASE
                            )
                            if pwd_cue:
                                matched_rules.append("ATT_ARCHIVE_PASSWORD_IN_BODY")
                                rule = RULE_DEFINITIONS["ATT_ARCHIVE_PASSWORD_IN_BODY"]
                                ev_list.append(EvidenceRecord(
                                    rule_id=rule["rule_id"],
                                    category=rule["category"],
                                    title=rule["title"],
                                    severity=rule["severity"],
                                    description=rule["description"],
                                    supporting_observation="Email body contains explicit password unlock instructions corresponding to this encrypted archive attachment.",
                                    source_location=f"Email Body / Archive: {filename}",
                                    confidence=ConfidenceEnum.HIGH,
                                    limitations="Heuristic pattern correlation. Password values are never stored or logged."
                                ))

                    if suspicious_members:
                        matched_rules.append("ATT_ARCHIVE_SUSPICIOUS")
                        rule = RULE_DEFINITIONS["ATT_ARCHIVE_SUSPICIOUS"]
                        ev_list.append(EvidenceRecord(
                            rule_id=rule["rule_id"],
                            category=rule["category"],
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            supporting_observation=f"Archive contains high-risk executable member(s): {', '.join(suspicious_members[:3])}.",
                            source_location=f"Archive Metadata: {filename}",
                            confidence=ConfidenceEnum.CONFIRMED,
                            limitations=rule["limitations"]
                        ))

                    if nested_count > 0:
                        matched_rules.append("ATT_ARCHIVE_NESTED")
                        rule = RULE_DEFINITIONS["ATT_ARCHIVE_NESTED"]
                        ev_list.append(EvidenceRecord(
                            rule_id=rule["rule_id"],
                            category=rule["category"],
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            supporting_observation=f"Archive contains {nested_count} nested archive member(s), a tactic often used to evade perimeter detection.",
                            source_location=f"Archive Metadata: {filename}",
                            confidence=ConfidenceEnum.CONFIRMED,
                            limitations=rule["limitations"]
                        ))

                        if nested_count >= cls.MAX_NESTING_DEPTH:
                            matched_rules.append("ATT_ARCHIVE_DEPTH_EXCEEDED")
                            rule = RULE_DEFINITIONS["ATT_ARCHIVE_DEPTH_EXCEEDED"]
                            ev_list.append(EvidenceRecord(
                                rule_id=rule["rule_id"],
                                category=rule["category"],
                                title=rule["title"],
                                severity=rule["severity"],
                                description=rule["description"],
                                supporting_observation=f"Archive nesting depth reached limit ({cls.MAX_NESTING_DEPTH}). Nested contents marked UNSCANNED.",
                                source_location=f"Archive Metadata: {filename}",
                                confidence=ConfidenceEnum.CONFIRMED,
                                limitations=rule["limitations"]
                            ))

            except zipfile.BadZipFile as bzf:
                unparseable_reason = f"Corrupt ZIP header or invalid archive directory structure ({bzf})."
                matched_rules.append("ATT_CORRUPT_OR_UNPARSEABLE")
                rule = RULE_DEFINITIONS["ATT_CORRUPT_OR_UNPARSEABLE"]
                ev_list.append(EvidenceRecord(
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    title=rule["title"],
                    severity=rule["severity"],
                    description=rule["description"],
                    supporting_observation=f"Archive '{filename}' is corrupted or truncated: {bzf}.",
                    source_location=f"Archive Header: {filename}",
                    confidence=ConfidenceEnum.CONFIRMED,
                    limitations="Inspection blocked by corruption. Reported as UNKNOWN, never SAFE."
                ))
            except Exception as exc:
                unparseable_reason = f"Failed to parse archive headers: {type(exc).__name__} ({exc})."
                matched_rules.append("ATT_CORRUPT_OR_UNPARSEABLE")
                rule = RULE_DEFINITIONS["ATT_CORRUPT_OR_UNPARSEABLE"]
                ev_list.append(EvidenceRecord(
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    title=rule["title"],
                    severity=rule["severity"],
                    description=rule["description"],
                    supporting_observation=f"Unparseable attachment '{filename}': {exc}.",
                    source_location=f"Archive Header: {filename}",
                    confidence=ConfidenceEnum.CONFIRMED,
                    limitations="Inspection blocked. Reported as UNKNOWN, never SAFE."
                ))

        coverage = "SCANNED"
        if unparseable_reason:
            coverage = "CORRUPT" if "corrupt" in unparseable_reason.lower() else "UNKNOWN"
        elif is_encrypted:
            coverage = "UNKNOWN"
        elif detected_type == "UNKNOWN" and not dangerous_ext:
            coverage = "UNSUPPORTED"

        att_score, att_rating, att_action, att_reason = cls._derive_attachment_assessment(
            filename=filename,
            detected_type=detected_type,
            coverage=coverage,
            matched_rules=matched_rules,
            ev_list=ev_list,
            unparseable_reason=unparseable_reason
        )

        finding = AttachmentFinding(
            filename=filename,
            declared_mime=declared_mime,
            detected_type=detected_type,
            size_bytes=size_bytes,
            sha256=sha256,
            dangerous_extension=dangerous_ext,
            double_extension=double_ext,
            rtlo_detected=rtlo_detected,
            macro_detected=macro_detected,
            active_content_detected=active_content,
            forms_scripts_detected=forms_scripts_detected,
            archive_members=archive_members,
            encrypted=is_encrypted,
            nested_archive_count=nested_count,
            unparseable_reason=unparseable_reason,
            coverage_status=coverage,
            matched_rules=matched_rules,
            risk_score=att_score,
            risk_level=att_rating,
            recommended_action=att_action,
            classification_reason=att_reason,
            evidence_records=list(ev_list)
        )

        return finding, ev_list

    @classmethod
    def _derive_attachment_assessment(
        cls,
        filename: str,
        detected_type: str,
        coverage: str,
        matched_rules: List[str],
        ev_list: List[EvidenceRecord],
        unparseable_reason: Optional[str] = None
    ) -> Tuple[int, RiskRatingEnum, str, str]:
        """
        Derives deterministic individual attachment risk score, rating, actionable recommendation,
        and human-readable classification reason from specific static findings.
        """
        # 1. Calculate raw attachment score from triggered rules
        score = 0
        applied_rules = set()
        for ev in ev_list:
            if ev.rule_id not in applied_rules:
                applied_rules.add(ev.rule_id)
                rule_def = RULE_DEFINITIONS.get(ev.rule_id, {})
                score += rule_def.get("weight", 15)
        score = min(100, max(0, score))

        # 2. Determine Risk Rating Level
        if coverage in ["UNSCANNED", "OVERSIZED"]:
            rating = RiskRatingEnum.UNSCANNED
        elif coverage in ["UNKNOWN", "CORRUPT"] and score == 0:
            rating = RiskRatingEnum.UNKNOWN
        elif score >= 60 or any(r in matched_rules for r in [
            "ATT_MIME_MISMATCH", "ATT_RTLO_DETECTED", "ATT_HTML_SMUGGLING",
            "ATT_ARCHIVE_PASSWORD_IN_BODY", "ATT_DANGEROUS_EXT"
        ]):
            rating = RiskRatingEnum.HIGH
        elif score >= 30 or any(r in matched_rules for r in [
            "ATT_OFFICE_MACRO_EXT", "ATT_OFFICE_MACRO", "ATT_PDF_ACTIVE_CONTENT",
            "ATT_ARCHIVE_ENCRYPTED", "ATT_DOUBLE_EXT"
        ]):
            rating = RiskRatingEnum.MEDIUM
        elif coverage == "UNSUPPORTED" and score == 0:
            rating = RiskRatingEnum.UNKNOWN
        else:
            rating = RiskRatingEnum.LOW

        # 3. Deterministic Actionable Recommendations (precedence-ordered)
        clean_ext = filename.lower()
        if "ATT_MIME_MISMATCH" in matched_rules:
            action = "Do not open or execute. Extension conflicts with binary signature (executable disguised as document). Quarantine immediately and escalate to SOC."
        elif "ATT_ARCHIVE_PASSWORD_IN_BODY" in matched_rules:
            action = "Do not extract. Password-protected archive with email body unlock key is a confirmed malware delivery technique. Quarantine file."
        elif "ATT_RTLO_DETECTED" in matched_rules:
            action = "Do not open. Filename uses Right-to-Left Override spoofing to disguise dangerous extension. Quarantine immediately."
        elif "ATT_HTML_SMUGGLING" in matched_rules:
            action = "Do not open in browser. HTML smuggling scripts detected that dynamically assemble payloads in memory. Block and quarantine."
        elif "ATT_HTML_FORM_SCRIPT" in matched_rules:
            action = "Do not open. HTML attachment contains credential harvesting password forms or redirect scripts. Block immediately."
        elif "ATT_DANGEROUS_EXT" in matched_rules:
            action = "Do not launch. Direct script or executable attachment detected. Block and isolate according to organizational policy."
        elif "ATT_OFFICE_MACRO_EXT" in matched_rules or "ATT_OFFICE_MACRO" in matched_rules:
            action = "Verify sender and business necessity out-of-band. Do not enable macros. Analyze in an isolated sandbox environment if required."
        elif "ATT_PDF_ACTIVE_CONTENT" in matched_rules:
            action = "Do not open in standard PDF reader. Active executable /Launch or /JavaScript actions detected. Inspect in an isolated sandbox."
        elif "ATT_ARCHIVE_ENCRYPTED" in matched_rules:
            action = "Do not extract on standard workstation. Password encryption prevents static inspection. Verify sender through verified corporate channels."
        elif coverage == "OVERSIZED" or "ATT_LIMIT_EXCEEDED" in matched_rules:
            action = "Classification inconclusive: file exceeds safe static inspection bounds. Treat as UNSCANNED (never assume safe). Submit for offline perimeter analysis."
        elif coverage in ["UNKNOWN", "CORRUPT"]:
            action = "Classification inconclusive: attachment is corrupted, encrypted, or unparseable. Treat as UNKNOWN (never assume safe)."
        elif coverage == "UNSUPPORTED":
            action = "Classification inconclusive: file type is not supported for deep structural parsing. Treat as UNKNOWN (never assume safe)."
        elif score == 0:
            if clean_ext.endswith(".pdf"):
                action = "Clean static signature. Standard document hygiene applies. Verify sender through official channel if unexpected; open with approved PDF reader."
            elif clean_ext.endswith((".docx", ".xlsx")):
                action = "Clean OpenXML structure. No executable macros or hidden binary streams detected. Normal workflow permitted per security policy."
            elif clean_ext.endswith(".zip"):
                action = "Clean archive structure. Contains non-executable files with zero encryption or nested archives. Normal workflow permitted."
            else:
                action = "Static inspection found no malicious indicators. Standard operational hygiene applies; verify unexpected sender requests."
        else:
            action = "Elevated risk detected. Proceed with caution and request secondary analyst review."

        # 4. Human-readable Classification Reason
        if rating == RiskRatingEnum.HIGH:
            reason = f"High Risk ({score}/100): Confirmed high-severity threat signatures detected ({', '.join(matched_rules)})."
        elif rating == RiskRatingEnum.MEDIUM:
            reason = f"Medium Risk ({score}/100): Suspicious active content or structural anomalies detected ({', '.join(matched_rules)})."
        elif rating == RiskRatingEnum.UNSCANNED:
            reason = f"Unscanned ({score}/100): Attachment exceeds inspection limits ({coverage})."
        elif rating == RiskRatingEnum.UNKNOWN:
            reason = f"Unknown Status ({score}/100): Attachment is {unparseable_reason or 'unparseable/encrypted'}; cannot be verified safe."
        else:
            reason = f"Low Risk ({score}/100): Valid {detected_type} with 0 detected malicious indicators."

        return score, rating, action, reason

