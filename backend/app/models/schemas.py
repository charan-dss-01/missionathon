from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class SeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ConfidenceEnum(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class RiskRatingEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class CoverageStatusEnum(str, Enum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    INCOMPLETE = "INCOMPLETE"
    UNKNOWN = "UNKNOWN"
    UNSCANNED = "UNSCANNED"

class TraceStatusEnum(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"

class EvidenceRecord(BaseModel):
    rule_id: str
    category: str # headers, body, urls, attachments, authentication
    title: str
    severity: SeverityEnum
    description: str
    supporting_observation: str
    source_location: Optional[str] = None
    confidence: ConfidenceEnum = ConfidenceEnum.HIGH
    limitations: Optional[str] = None

class RecordedAuthResults(BaseModel):
    spf_result: Optional[str] = "NONE" # PASS, FAIL, SOFTFAIL, NEUTRAL, NONE
    dkim_result: Optional[str] = "NONE"
    dmarc_result: Optional[str] = "NONE"
    raw_header: Optional[str] = None
    notes: str = "Extracted from recorded email headers only; no live DNS validation performed."

class EmailMetadata(BaseModel):
    sender: str = ""
    sender_domain: str = ""
    display_name: str = ""
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    subject: str = ""
    date: Optional[str] = None
    recipients: List[str] = []
    message_id: Optional[str] = None
    recorded_auth: RecordedAuthResults = Field(default_factory=RecordedAuthResults)
    inconsistencies: List[str] = []

class URLFinding(BaseModel):
    url: str
    display_text: Optional[str] = None
    domain: str = ""
    is_ip_literal: bool = False
    is_punycode: bool = False
    has_confusable_chars: bool = False
    has_deceptive_subdomains: bool = False
    has_embedded_userinfo: bool = False
    has_suspicious_encoding: bool = False
    is_text_mismatch: bool = False
    matched_rules: List[str] = []
    severity: SeverityEnum = SeverityEnum.LOW
    notes: Optional[str] = None

class AttachmentFinding(BaseModel):
    filename: str
    declared_mime: Optional[str] = None
    detected_type: str = "UNKNOWN"
    size_bytes: int = 0
    sha256: str = ""
    dangerous_extension: bool = False
    double_extension: bool = False
    rtlo_detected: bool = False
    macro_detected: bool = False
    active_content_detected: bool = False
    forms_scripts_detected: bool = False
    archive_members: List[str] = []
    coverage_status: str = "SCANNED" # SCANNED, UNKNOWN, UNSCANNED, UNSUPPORTED, CORRUPT, OVERSIZED
    matched_rules: List[str] = []
    limitations: str = "Static signature and structure inspection only. Does not guarantee harmlessness."

class ComponentRisk(BaseModel):
    email_score: int = 0
    attachment_score: int = 0
    overall_score: int = 0
    overall_rating: RiskRatingEnum = RiskRatingEnum.LOW
    contributing_findings: List[str] = []
    coverage_status: CoverageStatusEnum = CoverageStatusEnum.FULL
    scoring_explanation: str = ""

class TraceStep(BaseModel):
    node: str
    name: str
    status: TraceStatusEnum = TraceStatusEnum.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    message: Optional[str] = None
    data_summary: Optional[Dict[str, Any]] = None

class LLMInterpretation(BaseModel):
    summary: str
    attack_vector: str
    targeted_assets: List[str] = []
    actionable_recommendations: List[str] = []
    limitations: List[str] = []
    validated_evidence_ids: List[str] = []
    rejected_claims: List[str] = []
    provider_used: str = "template" # gemini, groq, template
    fallback_used: bool = False
    fallback_reason: Optional[str] = None

class InvestigationResult(BaseModel):
    id: str
    owner_id: Optional[str] = None # User ID of the owner in MongoDB
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    input_type: str # eml, raw_text, url, attachment
    status: str = "COMPLETED" # COMPLETED, FAILED, IN_REVIEW
    risk: ComponentRisk
    evidence: List[EvidenceRecord] = []
    email_metadata: Optional[EmailMetadata] = None
    urls: List[URLFinding] = []
    attachments: List[AttachmentFinding] = []
    llm_interpretation: LLMInterpretation
    trace: List[TraceStep] = []
    review_status: str = "NEW" # NEW, IN_REVIEW, RESOLVED_MALICIOUS, RESOLVED_BENIGN
    review_notes: Optional[str] = None

class AnalyzeRequest(BaseModel):
    raw_content: Optional[str] = None
    file_name: Optional[str] = None
    input_type: Optional[str] = "raw_text" # raw_text, eml, url

class ProviderStatus(BaseModel):
    primary_provider: str
    gemini_configured: bool
    gemini_model: str
    groq_configured: bool
    groq_model: str
    fallback_ready: bool
    deterministic_fallback_ready: bool = True
