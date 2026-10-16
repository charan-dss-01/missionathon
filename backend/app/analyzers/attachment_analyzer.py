import hashlib
import zipfile
import io
import re
from typing import List, Tuple, Dict, Any, Optional
from app.models.schemas import AttachmentFinding, EvidenceRecord, SeverityEnum, ConfidenceEnum
from app.engine.rule_definitions import RULE_DEFINITIONS

# High-risk executable/script extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".bat", ".cmd", ".ps1", ".psm1", ".hta", ".cpl", ".iso", ".img",
    ".vhd", ".vhdx", ".lnk", ".pif", ".jar", ".msi", ".reg", ".dll"
}

DOUBLE_EXT_ALLOWED_INNER = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".jpg", ".png", ".txt"}

# Known file signatures (magic bytes)
MAGIC_SIGNATURES = [
    (b"MZ", "Windows PE Executable (.exe/.dll/.scr)", [".exe", ".dll", ".scr", ".cpl"]),
    (b"%PDF-", "PDF Document", [".pdf"]),
    (b"PK\x03\x04", "ZIP / OOXML Archive", [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"]),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE Compound Document (Legacy Office)", [".doc", ".xls", ".ppt", ".msg"]),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", [".7z"]),
    (b"Rar!\x1a\x07", "RAR Archive", [".rar"]),
    (b"\x1f\x8b", "GZIP Compressed", [".gz", ".tar.gz"])
]

class AttachmentAnalyzer:
    """
    Safely inspects file attachments statically without execution or extraction to disk.
    Enforces strict memory, entry-count, and nested structure limits.
    """

    MAX_INSPECT_BYTES = 5 * 1024 * 1024 # 5 MB
    MAX_ARCHIVE_ENTRIES = 50

    @classmethod
    def analyze_attachments(cls, attachments: List[Dict[str, Any]]) -> Tuple[List[AttachmentFinding], List[EvidenceRecord]]:
        findings: List[AttachmentFinding] = []
        evidence: List[EvidenceRecord] = []

        for att in attachments:
            filename = att.get("filename", "unknown_file")
            data = att.get("bytes", b"")
            declared_mime = att.get("content_type", "")

            finding, ev_list = cls._inspect_single_attachment(filename, data, declared_mime)
            findings.append(finding)
            evidence.extend(ev_list)

        return findings, evidence

    @classmethod
    def _inspect_single_attachment(
        cls,
        filename: str,
        data: bytes,
        declared_mime: str
    ) -> Tuple[AttachmentFinding, List[EvidenceRecord]]:
        ev_list: List[EvidenceRecord] = []
        matched_rules: List[str] = []

        size_bytes = len(data)
        sha256 = hashlib.sha256(data).hexdigest() if data else ""

        # Check bounds
        if size_bytes > cls.MAX_INSPECT_BYTES:
            finding = AttachmentFinding(
                filename=filename,
                declared_mime=declared_mime,
                detected_type="OVERSIZED",
                size_bytes=size_bytes,
                sha256=sha256,
                coverage_status="OVERSIZED",
                limitations=f"File exceeds inspection limit ({cls.MAX_INSPECT_BYTES / (1024*1024):.1f}MB). Reported as UNSCANNED."
            )
            return finding, ev_list

        # 1. Right-to-Left Override (RTLO) Check in filename
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

        # 2. Filename Extensions Inspection
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

        # 3. Double Extension Check (e.g. invoice.pdf.exe)
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
                # Flag mismatch
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

        # 5. Specialized Deep Structural Check: PDF Active Content
        active_content = False
        if outer_ext == ".pdf" or data.startswith(b"%PDF-"):
            pdf_sample = data[:min(len(data), 1024 * 1024)]
            # Check for /JavaScript, /JS, /OpenAction, /Launch
            if re.search(rb"/(?:JavaScript|JS|OpenAction|Launch)\b", pdf_sample):
                active_content = True
                matched_rules.append("ATT_PDF_ACTIVE_CONTENT")
                rule = RULE_DEFINITIONS["ATT_PDF_ACTIVE_CONTENT"]
                ev_list.append(EvidenceRecord(
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    title=rule["title"],
                    severity=rule["severity"],
                    description=rule["description"],
                    supporting_observation="PDF structure contains active content tokens (/JavaScript, /OpenAction, or /Launch).",
                    source_location=f"PDF Structure: {filename}",
                    confidence=ConfidenceEnum.HIGH,
                    limitations=rule["limitations"]
                ))

        # 6. Specialized Deep Structural Check: Office Macros
        macro_detected = False
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
            if b"VBA" in data or b"Macro" in data or b"Sub AutoOpen" in data or b"Document_Open" in data:
                macro_detected = True

        if macro_detected:
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

        # 7. Specialized Structural Check: HTML / SVG Phishing Attachments
        forms_scripts_detected = False
        if outer_ext in [".html", ".htm", ".svg"] or b"<html" in data[:500].lower():
            html_snippet = data[:200000].lower()
            if b"<form" in html_snippet and (b'type="password"' in html_snippet or b"type='password'" in html_snippet or b"action=" in html_snippet):
                forms_scripts_detected = True
            elif b"<script" in html_snippet and (b"window.location" in html_snippet or b"document.write" in html_snippet or b"eval(" in html_snippet):
                forms_scripts_detected = True

            if forms_scripts_detected:
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

        # 8. Archive Inspection (Central Directory Header Inspection without disk extraction)
        archive_members: List[str] = []
        if data.startswith(b"PK\x03\x04") and outer_ext in [".zip", ".7z", ".rar", ".tar", ".gz"]:
            try:
                with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
                    infolist = zf.infolist()
                    suspicious_members = []
                    for idx, info in enumerate(infolist):
                        if idx >= cls.MAX_ARCHIVE_ENTRIES:
                            break
                        archive_members.append(info.filename)
                        m_ext = f".{info.filename.split('.')[-1].lower()}" if "." in info.filename else ""
                        if m_ext in DANGEROUS_EXTENSIONS:
                            suspicious_members.append(info.filename)

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
            except zipfile.BadZipFile:
                pass
            except Exception:
                pass

        coverage = "SCANNED"
        if detected_type == "UNKNOWN" and not dangerous_ext:
            coverage = "UNSUPPORTED"

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
            coverage_status=coverage,
            matched_rules=matched_rules
        )

        return finding, ev_list
