import email
from email import policy
from email.parser import BytesParser, Parser
from typing import Tuple, List, Dict, Any, Optional
import re
from app.models.schemas import EmailMetadata, RecordedAuthResults

class EmailParser:
    """
    Robust RFC 5322 email parser for raw strings and .eml byte streams.
    Extracts headers, bodies, and attachment payloads safely within size limits.
    """

    MAX_BODY_CHARS = 200000

    @classmethod
    def parse_eml_bytes(cls, raw_bytes: bytes) -> Tuple[EmailMetadata, str, str, List[Dict[str, Any]]]:
        """
        Parses raw bytes from an uploaded .eml file.
        Returns: (metadata, plain_body, html_body, attachments)
        """
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        return cls._extract_from_message(msg)

    @classmethod
    def parse_raw_text(cls, raw_text: str) -> Tuple[EmailMetadata, str, str, List[Dict[str, Any]]]:
        """
        Parses raw text (which may be a full RFC 5322 string or just a pasted email body/headers).
        """
        # If it looks like standard RFC 5322 headers (contains From: and Subject:)
        if re.search(r"^From:\s*.+", raw_text, re.MULTILINE | re.IGNORECASE):
            msg = Parser(policy=policy.default).parsestr(raw_text)
            return cls._extract_from_message(msg)
        else:
            # Fallback for plain pasted text without headers
            meta = EmailMetadata(
                sender="unknown@unspecified.local",
                sender_domain="unspecified.local",
                display_name="Unspecified Sender",
                subject="(Pasted Plaintext Snippet)",
                date=None,
                recipients=[]
            )
            return meta, raw_text[:cls.MAX_BODY_CHARS], "", []

    @classmethod
    def _extract_from_message(cls, msg: email.message.EmailMessage) -> Tuple[EmailMetadata, str, str, List[Dict[str, Any]]]:
        from_header = str(msg.get("From", "") or "")
        reply_to_header = str(msg.get("Reply-To", "") or "")
        return_path_header = str(msg.get("Return-Path", "") or "")
        subject_header = str(msg.get("Subject", "") or "")
        date_header = str(msg.get("Date", "") or "")
        to_header = str(msg.get("To", "") or "")
        message_id = str(msg.get("Message-ID", "") or "")

        # Extract sender address and display name
        display_name, sender_address = cls._parse_address(from_header)
        sender_domain = sender_address.split("@")[-1].lower() if "@" in sender_address else ""

        # Extract reply-to
        _, reply_to_addr = cls._parse_address(reply_to_header) if reply_to_header else ("", "")
        # Extract return-path
        _, return_path_addr = cls._parse_address(return_path_header) if return_path_header else ("", "")

        # Extract recipients
        recipients = [addr.strip() for addr in to_header.split(",") if addr.strip()]

        # Recorded Authentication headers
        auth_results = cls._extract_recorded_auth(msg)

        metadata = EmailMetadata(
            sender=sender_address,
            sender_domain=sender_domain,
            display_name=display_name,
            reply_to=reply_to_addr if reply_to_addr else None,
            return_path=return_path_addr if return_path_addr else None,
            subject=subject_header,
            date=date_header if date_header else None,
            recipients=recipients,
            message_id=message_id if message_id else None,
            recorded_auth=auth_results
        )

        # Extract plain and html bodies
        plain_parts = []
        html_parts = []
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                content_type = part.get_content_type()
                filename = part.get_filename()

                if filename or "attachment" in content_disposition.lower():
                    # Attachment
                    payload = part.get_payload(decode=True)
                    if payload is not None:
                        attachments.append({
                            "filename": filename or "unnamed_attachment",
                            "content_type": content_type,
                            "bytes": payload,
                            "size_bytes": len(payload)
                        })
                elif content_type == "text/plain":
                    try:
                        text = part.get_content()
                        if isinstance(text, str):
                            plain_parts.append(text)
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            plain_parts.append(payload.decode("utf-8", errors="ignore"))
                elif content_type == "text/html":
                    try:
                        html = part.get_content()
                        if isinstance(html, str):
                            html_parts.append(html)
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            html_parts.append(payload.decode("utf-8", errors="ignore"))
        else:
            content_type = msg.get_content_type()
            try:
                content = msg.get_content()
                if content_type == "text/html":
                    html_parts.append(str(content))
                else:
                    plain_parts.append(str(content))
            except Exception:
                payload = msg.get_payload(decode=True)
                if payload:
                    decoded = payload.decode("utf-8", errors="ignore")
                    if content_type == "text/html":
                        html_parts.append(decoded)
                    else:
                        plain_parts.append(decoded)

        plain_body = "\n".join(plain_parts)[:cls.MAX_BODY_CHARS]
        html_body = "\n".join(html_parts)[:cls.MAX_BODY_CHARS]

        return metadata, plain_body, html_body, attachments

    @staticmethod
    def _parse_address(raw_header: str) -> Tuple[str, str]:
        if not raw_header:
            return "", ""
        # Match "Display Name <user@domain.com>" or "user@domain.com"
        match = re.search(r"^(.*?)(?:<([^>]+)>)?$", raw_header.strip())
        if match:
            display, addr = match.groups()
            display = display.strip().strip('"').strip("'")
            if addr:
                return display, addr.strip().lower()
            elif "@" in display:
                return "", display.strip().lower()
            return display, ""
        return "", raw_header.strip().lower()

    @staticmethod
    def _extract_recorded_auth(msg: email.message.EmailMessage) -> RecordedAuthResults:
        auth_header = str(msg.get("Authentication-Results", "") or "")
        received_spf = str(msg.get("Received-SPF", "") or "")
        arc_results = str(msg.get("ARC-Authentication-Results", "") or "")
        full_auth_text = f"{auth_header} {received_spf} {arc_results}".lower()

        spf = "NONE"
        dkim = "NONE"
        dmarc = "NONE"

        # Check SPF
        if "spf=pass" in full_auth_text or "pass (" in received_spf.lower():
            spf = "PASS"
        elif "spf=fail" in full_auth_text or "fail (" in received_spf.lower():
            spf = "FAIL"
        elif "spf=softfail" in full_auth_text:
            spf = "SOFTFAIL"
        elif "spf=neutral" in full_auth_text:
            spf = "NEUTRAL"

        # Check DKIM
        if "dkim=pass" in full_auth_text:
            dkim = "PASS"
        elif "dkim=fail" in full_auth_text:
            dkim = "FAIL"

        # Check DMARC
        if "dmarc=pass" in full_auth_text:
            dmarc = "PASS"
        elif "dmarc=fail" in full_auth_text:
            dmarc = "FAIL"

        return RecordedAuthResults(
            spf_result=spf,
            dkim_result=dkim,
            dmarc_result=dmarc,
            raw_header=auth_header[:300] if auth_header else None,
            notes="Extracted strictly from recorded email headers; no external DNS resolution performed."
        )
