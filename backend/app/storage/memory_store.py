import threading
from typing import Dict, List, Optional
from datetime import datetime, timezone, timedelta
from app.models.schemas import (
    InvestigationResult,
    ComponentRisk,
    RiskRatingEnum,
    CoverageStatusEnum,
    EvidenceRecord,
    EmailMetadata,
    RecordedAuthResults,
    URLFinding,
    AttachmentFinding,
    LLMInterpretation,
    TraceStep,
    TraceStatusEnum,
    SeverityEnum,
    ConfidenceEnum,
    FeedbackRecord
)
from app.engine.rule_definitions import RULE_DEFINITIONS

class MemoryStore:
    """
    Thread-safe session-only in-memory store for investigations.
    Explicitly labeled as ephemeral session-only storage.
    Includes realistic synthetic seed investigations for demo walkthroughs.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._investigations: Dict[str, InvestigationResult] = {}
        self._users_by_email: Dict[str, dict] = {}
        self._users_by_id: Dict[str, dict] = {}
        self._audit_events: List[dict] = []
        self._feedback: List[FeedbackRecord] = []
        self._seed_demo_data()

    def add_user(self, user_dict: dict) -> None:
        with self._lock:
            email = user_dict["email"].lower()
            self._users_by_email[email] = user_dict
            self._users_by_id[user_dict["id"]] = user_dict

    def get_user_by_email(self, email: str) -> Optional[dict]:
        with self._lock:
            return self._users_by_email.get(email.lower())

    def get_user_by_id(self, user_id: str) -> Optional[dict]:
        with self._lock:
            return self._users_by_id.get(user_id)

    def update_user(self, user_id: str, updates: dict) -> Optional[dict]:
        with self._lock:
            user = self._users_by_id.get(user_id)
            if user:
                user.update(updates)
                return user
            return None

    def add_audit(self, audit_dict: dict) -> None:
        with self._lock:
            self._audit_events.append(audit_dict)

    def get_audits(self, user_id: Optional[str] = None) -> List[dict]:
        with self._lock:
            if user_id:
                return [a for a in self._audit_events if a.get("user_id") == user_id]
            return list(self._audit_events)

    def add(self, result: InvestigationResult) -> None:
        with self._lock:
            self._investigations[result.id] = result

    def get(self, inv_id: str) -> Optional[InvestigationResult]:
        with self._lock:
            return self._investigations.get(inv_id)

    def list_all(self) -> List[InvestigationResult]:
        with self._lock:
            # Sort newest first
            return sorted(
                list(self._investigations.values()),
                key=lambda x: x.created_at,
                reverse=True
            )

    def update_review(self, inv_id: str, review_status: str, notes: Optional[str] = None) -> Optional[InvestigationResult]:
        with self._lock:
            if inv_id in self._investigations:
                inv = self._investigations[inv_id]
                inv.review_status = review_status
                if notes is not None:
                    inv.review_notes = notes
                return inv
            return None

    def add_feedback(self, feedback: FeedbackRecord) -> None:
        with self._lock:
            self._feedback.append(feedback)

    def get_feedback_for_investigation(self, inv_id: str) -> List[FeedbackRecord]:
        with self._lock:
            return [f for f in self._feedback if f.investigation_id == inv_id]

    def list_all_feedback(self) -> List[FeedbackRecord]:
        with self._lock:
            return list(self._feedback)

    def _seed_demo_data(self):
        now = datetime.now(timezone.utc)

        # Seed 1: High-Risk Urgent Microsoft 365 Credential Phishing
        rule_mismatch = RULE_DEFINITIONS["URL_TEXT_HREF_MISMATCH"]
        rule_urgency = RULE_DEFINITIONS["BODY_URGENCY_PRESSURE"]
        rule_cred = RULE_DEFINITIONS["BODY_CREDENTIAL_HARVEST"]
        rule_replyto = RULE_DEFINITIONS["HDR_REPLYTO_MISMATCH"]
        rule_dmarc = RULE_DEFINITIONS["AUTH_DMARC_FAIL"]

        inv1_ev = [
            EvidenceRecord(
                rule_id=rule_mismatch["rule_id"],
                category=rule_mismatch["category"],
                title=rule_mismatch["title"],
                severity=rule_mismatch["severity"],
                description=rule_mismatch["description"],
                supporting_observation="Deceptive anchor displays 'https://account.microsoft.com/security' but hyperlink redirects to 'https://login-m365-verify.attacker-portal.net/auth'.",
                source_location="Email Body: HTML Anchor Tag",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations=rule_mismatch["limitations"]
            ),
            EvidenceRecord(
                rule_id=rule_urgency["rule_id"],
                category=rule_urgency["category"],
                title=rule_urgency["title"],
                severity=rule_urgency["severity"],
                description=rule_urgency["description"],
                supporting_observation="Detected high-urgency phrase: 'account will be suspended within 24 hours unless verified'.",
                source_location="Email Body: Textual Analysis",
                confidence=ConfidenceEnum.HIGH,
                limitations=rule_urgency["limitations"]
            ),
            EvidenceRecord(
                rule_id=rule_cred["rule_id"],
                category=rule_cred["category"],
                title=rule_cred["title"],
                severity=rule_cred["severity"],
                description=rule_cred["description"],
                supporting_observation="Detected credential solicitation: 'confirm your password and one-time verification code immediately'.",
                source_location="Email Body: Textual Analysis",
                confidence=ConfidenceEnum.HIGH,
                limitations=rule_cred["limitations"]
            ),
            EvidenceRecord(
                rule_id=rule_replyto["rule_id"],
                category=rule_replyto["category"],
                title=rule_replyto["title"],
                severity=rule_replyto["severity"],
                description=rule_replyto["description"],
                supporting_observation="Sender address is 'admin@company-notice.com', but Reply-To redirects to 'exfiltrate@drop-box-mail.ru'.",
                source_location="Headers: From vs Reply-To",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations=rule_replyto["limitations"]
            ),
            EvidenceRecord(
                rule_id=rule_dmarc["rule_id"],
                category=rule_dmarc["category"],
                title=rule_dmarc["title"],
                severity=rule_dmarc["severity"],
                description=rule_dmarc["description"],
                supporting_observation="Recorded header Authentication-Results indicates DMARC check failed.",
                source_location="Headers: Authentication-Results (DMARC)",
                confidence=ConfidenceEnum.CONFIRMED,
                limitations=rule_dmarc["limitations"]
            )
        ]

        inv1_trace = [
            TraceStep(
                node="parse_input", name="Parse Raw Inbound Payload", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(minutes=45), end_time=now - timedelta(minutes=45) + timedelta(milliseconds=12),
                duration_ms=12.4, message="Parsed RFC 5322 MIME email payload.", data_summary={"subject": "CRITICAL: Urgent M365 Password Expiration Alert"}
            ),
            TraceStep(
                node="analyze_headers", name="Inspect Authentication & Sender Headers", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(minutes=45), end_time=now - timedelta(minutes=45) + timedelta(milliseconds=18),
                duration_ms=18.1, message="Detected From/Reply-To mismatch and DMARC failure.", data_summary={"indicators": 2}
            ),
            TraceStep(
                node="analyze_body", name="Inspect Body Language & HTML Hyperlinks", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(minutes=45), end_time=now - timedelta(minutes=45) + timedelta(milliseconds=25),
                duration_ms=25.2, message="Identified deceptive anchor text and credential solicitation.", data_summary={"indicators": 3}
            ),
            TraceStep(
                node="analyze_urls", name="Static Syntactic URL Inspection", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(minutes=45), end_time=now - timedelta(minutes=45) + timedelta(milliseconds=15),
                duration_ms=15.0, message="URL static inspection detected deceptive subdomain pattern.", data_summary={"url_count": 1}
            ),
            TraceStep(
                node="analyze_attachments", name="Static Attachment & File Signature Analysis", status=TraceStatusEnum.SKIPPED,
                start_time=now - timedelta(minutes=45), end_time=now - timedelta(minutes=45),
                duration_ms=0.5, message="No attachments present.", data_summary={"reason": "no_attachments"}
            ),
            TraceStep(
                node="aggregate_evidence", name="Aggregate Security Findings & Deduplicate", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(minutes=45), end_time=now - timedelta(minutes=45) + timedelta(milliseconds=8),
                duration_ms=8.0, message="Aggregated 5 authoritative security findings.", data_summary={"total_findings": 5}
            ),
            TraceStep(
                node="calculate_risk", name="Deterministic Risk Engine Evaluation", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(minutes=45), end_time=now - timedelta(minutes=45) + timedelta(milliseconds=6),
                duration_ms=6.2, message="Calculated overall score 95/100 (HIGH).", data_summary={"overall_score": 95}
            ),
            TraceStep(
                node="interpret_with_llm", name="Tier-3 AI Synthesis (Gemini / Groq / Fallback)", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(minutes=45), end_time=now - timedelta(minutes=45) + timedelta(milliseconds=850),
                duration_ms=850.0, message="Synthesis completed using Gemini primary provider.", data_summary={"provider": "gemini"}
            ),
            TraceStep(
                node="validate_evidence", name="Validate LLM Claims Against Authoritative Evidence", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(minutes=45), end_time=now - timedelta(minutes=45) + timedelta(milliseconds=5),
                duration_ms=5.0, message="Validated 5 claimed evidence IDs. 0 hallucinations.", data_summary={"validated": 5, "rejected": 0}
            ),
            TraceStep(
                node="generate_report", name="Assemble Final SOC Investigation Dossier", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(minutes=45), end_time=now - timedelta(minutes=45) + timedelta(milliseconds=4),
                duration_ms=4.1, message="Dossier compiled successfully.", data_summary={"id": "inv-demo-m365-phish"}
            )
        ]

        inv1 = InvestigationResult(
            id="inv-demo-m365-phish",
            created_at=now - timedelta(minutes=45),
            input_type="eml",
            status="COMPLETED",
            risk=ComponentRisk(
                sender_score=55,
                body_score=40,
                url_score=35,
                attachment_score=0,
                email_score=95,
                overall_score=95,
                overall_rating=RiskRatingEnum.HIGH,
                contributing_findings=[
                    "Deceptive Anchor vs. Destination Mismatch (+35 pts)",
                    "Display Name Brand / Executive Spoofing (+25 pts)",
                    "Credential or Identity Solicitation (+25 pts)",
                    "High Urgency / Coercive Language (+15 pts)",
                    "Recorded DMARC Policy Rejection (+30 pts)"
                ],
                coverage_status=CoverageStatusEnum.FULL,
                scoring_explanation="HIGH RISK (95/100): Confirmed high-severity threat indicators detected. Immediate containment and quarantine recommended."
            ),
            evidence=inv1_ev,
            email_metadata=EmailMetadata(
                sender="security-alert@company-notice.com",
                sender_domain="company-notice.com",
                display_name="Microsoft 365 Security Team",
                reply_to="exfiltrate@drop-box-mail.ru",
                return_path="bounce@company-notice.com",
                subject="CRITICAL: Urgent M365 Password Expiration Alert - Action Required",
                date=(now - timedelta(minutes=46)).strftime("%a, %d %b %Y %H:%M:%S +0000"),
                recipients=["finance-team@acme-corp.com"],
                message_id="<20261016.993821@company-notice.com>",
                recorded_auth=RecordedAuthResults(
                    spf_result="FAIL",
                    dkim_result="NONE",
                    dmarc_result="FAIL",
                    raw_header="dmarc=fail (p=reject dis=none) header.from=company-notice.com",
                    notes="Extracted from recorded email headers only; no live DNS validation performed."
                ),
                inconsistencies=["Reply-To mismatch: drop-box-mail.ru != company-notice.com", "Display name spoofing 'Microsoft' from company-notice.com"]
            ),
            urls=[
                URLFinding(
                    url="https://login-m365-verify.attacker-portal.net/auth",
                    display_text="https://account.microsoft.com/security",
                    domain="login-m365-verify.attacker-portal.net",
                    has_deceptive_subdomains=True,
                    is_text_mismatch=True,
                    matched_rules=["URL_TEXT_HREF_MISMATCH", "URL_DECEPTIVE_SUBDOMAIN"],
                    severity=SeverityEnum.CRITICAL,
                    notes="Deceptive anchor mismatch leading to credential collection portal."
                )
            ],
            attachments=[],
            llm_interpretation=LLMInterpretation(
                summary="High-confidence Microsoft 365 credential harvesting campaign. The sender address attempts brand impersonation with failed DMARC policy, diverted Reply-To headers, and deceptive anchor links leading to an attacker-controlled infrastructure.",
                attack_vector="Brand Impersonation & Hyperlink Credential Harvesting",
                targeted_assets=["Corporate M365 User Credentials", "Active Directory SSO Tokens"],
                actionable_recommendations=[
                    "Purge this email and associated message IDs from all enterprise mailboxes.",
                    "Block the destination domain 'attacker-portal.net' and sender 'company-notice.com' on proxy/firewalls.",
                    "Audit Azure AD / Okta sign-in logs for any successful authentications originating from suspicious IP addresses in the past 2 hours."
                ],
                limitations=[
                    "Static heuristic analysis only; destination server hosting status was not queried over network.",
                    "Recorded authentication headers were evaluated as stamped by upstream MTA."
                ],
                validated_evidence_ids=["URL_TEXT_HREF_MISMATCH", "BODY_URGENCY_PRESSURE", "BODY_CREDENTIAL_HARVEST", "HDR_REPLYTO_MISMATCH", "AUTH_DMARC_FAIL"],
                rejected_claims=[],
                provider_used="gemini",
                fallback_used=False
            ),
            trace=inv1_trace,
            review_status="IN_REVIEW",
            review_notes="Flagged for Tier-2 SOC escalation due to executive mailbox recipient."
        )

        # Seed 2: Benign Regular Vendor Invoice Receipt
        inv2_trace = [
            TraceStep(
                node="parse_input", name="Parse Raw Inbound Payload", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(hours=2), end_time=now - timedelta(hours=2) + timedelta(milliseconds=10),
                duration_ms=10.0, message="Parsed RFC 5322 MIME email payload.", data_summary={"subject": "Monthly Cloud Invoice - October 2026"}
            ),
            TraceStep(
                node="analyze_headers", name="Inspect Authentication & Sender Headers", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(hours=2), end_time=now - timedelta(hours=2) + timedelta(milliseconds=12),
                duration_ms=12.0, message="Authentication passed. SPF and DKIM confirmed.", data_summary={"indicators": 0}
            ),
            TraceStep(
                node="analyze_body", name="Inspect Body Language & HTML Hyperlinks", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(hours=2), end_time=now - timedelta(hours=2) + timedelta(milliseconds=18),
                duration_ms=18.0, message="No coercive language or anchor mismatches found.", data_summary={"indicators": 0}
            ),
            TraceStep(
                node="analyze_urls", name="Static Syntactic URL Inspection", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(hours=2), end_time=now - timedelta(hours=2) + timedelta(milliseconds=9),
                duration_ms=9.0, message="URLs correspond to legitimate vendor portals.", data_summary={"indicators": 0}
            ),
            TraceStep(
                node="analyze_attachments", name="Static Attachment & File Signature Analysis", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(hours=2), end_time=now - timedelta(hours=2) + timedelta(milliseconds=14),
                duration_ms=14.0, message="Inspected PDF attachment. Valid %PDF- magic bytes; no active scripts.", data_summary={"indicators": 0}
            ),
            TraceStep(
                node="aggregate_evidence", name="Aggregate Security Findings & Deduplicate", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(hours=2), end_time=now - timedelta(hours=2) + timedelta(milliseconds=4),
                duration_ms=4.0, message="0 risk indicators identified.", data_summary={"total_findings": 0}
            ),
            TraceStep(
                node="calculate_risk", name="Deterministic Risk Engine Evaluation", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(hours=2), end_time=now - timedelta(hours=2) + timedelta(milliseconds=5),
                duration_ms=5.0, message="Calculated overall score 0/100 (LOW).", data_summary={"overall_score": 0}
            ),
            TraceStep(
                node="interpret_with_llm", name="Tier-3 AI Synthesis (Gemini / Groq / Fallback)", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(hours=2), end_time=now - timedelta(hours=2) + timedelta(milliseconds=620),
                duration_ms=620.0, message="Synthesis completed using Gemini primary provider.", data_summary={"provider": "gemini"}
            ),
            TraceStep(
                node="validate_evidence", name="Validate LLM Claims Against Authoritative Evidence", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(hours=2), end_time=now - timedelta(hours=2) + timedelta(milliseconds=3),
                duration_ms=3.0, message="Validated 0 claimed evidence IDs.", data_summary={"validated": 0, "rejected": 0}
            ),
            TraceStep(
                node="generate_report", name="Assemble Final SOC Investigation Dossier", status=TraceStatusEnum.COMPLETED,
                start_time=now - timedelta(hours=2), end_time=now - timedelta(hours=2) + timedelta(milliseconds=3),
                duration_ms=3.0, message="Dossier compiled successfully.", data_summary={"id": "inv-demo-benign-invoice"}
            )
        ]

        inv2 = InvestigationResult(
            id="inv-demo-benign-invoice",
            created_at=now - timedelta(hours=2),
            input_type="eml",
            status="COMPLETED",
            risk=ComponentRisk(
                sender_score=0,
                body_score=0,
                url_score=0,
                attachment_score=0,
                email_score=0,
                overall_score=0,
                overall_rating=RiskRatingEnum.LOW,
                contributing_findings=[],
                coverage_status=CoverageStatusEnum.FULL,
                scoring_explanation="LOW IDENTIFIED RISK (0/100): No authoritative high-severity phishing signatures detected in static analysis. Notice: Low score does NOT guarantee safety."
            ),
            evidence=[],
            email_metadata=EmailMetadata(
                sender="billing@cloudprovider.com",
                sender_domain="cloudprovider.com",
                display_name="CloudProvider Billing",
                reply_to=None,
                return_path="billing@cloudprovider.com",
                subject="Monthly Cloud Invoice - October 2026",
                date=(now - timedelta(hours=2, minutes=1)).strftime("%a, %d %b %Y %H:%M:%S +0000"),
                recipients=["accounts@acme-corp.com"],
                message_id="<billing.20261016.12938@cloudprovider.com>",
                recorded_auth=RecordedAuthResults(
                    spf_result="PASS",
                    dkim_result="PASS",
                    dmarc_result="PASS",
                    raw_header="spf=pass dkim=pass dmarc=pass header.from=cloudprovider.com",
                    notes="Extracted from recorded email headers only; no live DNS validation performed."
                )
            ),
            urls=[
                URLFinding(
                    url="https://cloudprovider.com/invoices/2026-10",
                    display_text="View Invoice Online",
                    domain="cloudprovider.com",
                    severity=SeverityEnum.LOW,
                    notes="Official domain matching authenticated sender."
                )
            ],
            attachments=[
                AttachmentFinding(
                    filename="Invoice-Oct2026.pdf",
                    declared_mime="application/pdf",
                    detected_type="PDF Document",
                    size_bytes=142850,
                    sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    coverage_status="SCANNED",
                    limitations="Static signature and structure inspection only. Does not guarantee harmlessness."
                )
            ],
            llm_interpretation=LLMInterpretation(
                summary="Authentic billing receipt correspondence. Recorded SPF, DKIM, and DMARC alignments are all intact, hyperlinks lead to verified official domain endpoints, and attached PDF exhibits standard static document structure without executable streams.",
                attack_vector="Standard Inbound Correspondence (No Malicious Signatures Detected)",
                targeted_assets=["None Identified"],
                actionable_recommendations=[
                    "Routine operational processing: file invoice with Accounts Payable according to corporate procedure."
                ],
                limitations=[
                    "Static signature and header analysis only; no external reputation server queried.",
                    "Low risk score does not guarantee safety against previously unseen zero-day exploits."
                ],
                validated_evidence_ids=[],
                rejected_claims=[],
                provider_used="gemini",
                fallback_used=False
            ),
            trace=inv2_trace,
            review_status="RESOLVED_BENIGN",
            review_notes="Verified against expected monthly billing recurring schedule."
        )

        # FEATURE:insights
        try:
            from app.services.insights_builder import build_insights
            inv1.insights = build_insights(inv1.email_metadata, "", "", inv1.urls, inv1.attachments, inv1.evidence)
            inv2.insights = build_insights(inv2.email_metadata, "", "", inv2.urls, inv2.attachments, inv2.evidence)
        except Exception:
            pass

        self._investigations[inv1.id] = inv1
        self._investigations[inv2.id] = inv2

# Global in-memory store singleton
store = MemoryStore()
