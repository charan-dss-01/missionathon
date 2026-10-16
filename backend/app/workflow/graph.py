import time
import uuid
from datetime import datetime, timezone
from typing import TypedDict, List, Dict, Any, Optional
from langgraph.graph import StateGraph, START, END

from app.models.schemas import (
    EvidenceRecord,
    EmailMetadata,
    URLFinding,
    AttachmentFinding,
    ComponentRisk,
    LLMInterpretation,
    TraceStep,
    TraceStatusEnum,
    InvestigationResult,
    RiskRatingEnum
)
from app.analyzers.email_parser import EmailParser
from app.analyzers.header_analyzer import HeaderAnalyzer
from app.analyzers.body_analyzer import BodyAnalyzer
from app.analyzers.url_analyzer import URLAnalyzer
from app.analyzers.attachment_analyzer import AttachmentAnalyzer
from app.engine.risk_engine import RiskEngine
from app.services.llm_router import LLMRouter
from app.services.evidence_validator import EvidenceValidator

class InvestigationState(TypedDict, total=False):
    investigation_id: str
    raw_content: str
    raw_bytes: Optional[bytes]
    file_name: Optional[str]
    input_type: str # eml, raw_text, url, attachment
    force_fallback: bool
    simulate_both_fail: bool

    # Pipeline data
    email_metadata: Optional[EmailMetadata]
    plain_body: str
    html_body: str
    raw_attachments: List[Dict[str, Any]]
    extracted_urls: List[Dict[str, str]]

    # Findings & Evidence
    header_evidence: List[EvidenceRecord]
    body_evidence: List[EvidenceRecord]
    url_evidence: List[EvidenceRecord]
    attachment_evidence: List[EvidenceRecord]
    url_findings: List[URLFinding]
    attachment_findings: List[AttachmentFinding]
    aggregated_evidence: List[EvidenceRecord]

    # Risk & Synthesis
    risk: Optional[ComponentRisk]
    llm_interpretation: Optional[LLMInterpretation]
    trace: List[TraceStep]
    error: Optional[str]
    final_result: Optional[InvestigationResult]


def _record_trace(
    state: InvestigationState,
    node: str,
    name: str,
    status: TraceStatusEnum,
    start_time: float,
    message: str,
    data_summary: Optional[Dict[str, Any]] = None
) -> None:
    end_time = time.time()
    duration_ms = round((end_time - start_time) * 1000, 2)
    step = TraceStep(
        node=node,
        name=name,
        status=status,
        start_time=datetime.fromtimestamp(start_time, tz=timezone.utc),
        end_time=datetime.fromtimestamp(end_time, tz=timezone.utc),
        duration_ms=duration_ms,
        message=message,
        data_summary=data_summary or {}
    )
    if "trace" not in state or state["trace"] is None:
        state["trace"] = []
    state["trace"].append(step)


# Node 1: parse_input
def parse_input_node(state: InvestigationState) -> Dict[str, Any]:
    t0 = time.time()
    node = "parse_input"
    name = "Parse Raw Inbound Payload"
    input_type = state.get("input_type", "raw_text")
    raw_bytes = state.get("raw_bytes")
    raw_content = state.get("raw_content", "")
    file_name = state.get("file_name", "")

    metadata = None
    plain_body = ""
    html_body = ""
    raw_attachments: List[Dict[str, Any]] = []

    try:
        if input_type == "eml" and raw_bytes:
            metadata, plain_body, html_body, raw_attachments = EmailParser.parse_eml_bytes(raw_bytes)
        elif input_type == "attachment" and raw_bytes:
            raw_attachments.append({
                "filename": file_name or "uploaded_attachment",
                "content_type": "application/octet-stream",
                "bytes": raw_bytes,
                "size_bytes": len(raw_bytes)
            })
            metadata = EmailMetadata(
                sender="",
                sender_domain="",
                display_name="Standalone Attachment Analysis",
                subject=f"Direct Attachment Upload: {file_name}"
            )
        elif input_type == "url":
            plain_body = f"Target URL: {raw_content}"
            metadata = EmailMetadata(
                sender="",
                sender_domain="",
                display_name="Standalone URL Scan",
                subject=f"Direct URL Investigation: {raw_content[:40]}"
            )
        else:
            # raw text or fallback
            metadata, plain_body, html_body, raw_attachments = EmailParser.parse_raw_text(raw_content)

        _record_trace(
            state, node, name, TraceStatusEnum.COMPLETED, t0,
            f"Successfully parsed {input_type} payload. Extracted {len(raw_attachments)} attachment(s).",
            {"subject": metadata.subject if metadata else "", "attachments_count": len(raw_attachments)}
        )
        return {
            "email_metadata": metadata,
            "plain_body": plain_body,
            "html_body": html_body,
            "raw_attachments": raw_attachments,
            "trace": state["trace"]
        }
    except Exception as e:
        _record_trace(
            state, node, name, TraceStatusEnum.FAILED, t0,
            f"Parser error: {str(e)}", {"error": str(e)}
        )
        return {
            "error": str(e),
            "trace": state["trace"]
        }


# Node 2: analyze_headers
def analyze_headers_node(state: InvestigationState) -> Dict[str, Any]:
    t0 = time.time()
    node = "analyze_headers"
    name = "Inspect Authentication & Sender Headers"
    metadata = state.get("email_metadata")

    if not metadata or not metadata.sender:
        _record_trace(
            state, node, name, TraceStatusEnum.SKIPPED, t0,
            "No email headers available for analysis.", {"reason": "missing_headers"}
        )
        return {"header_evidence": [], "trace": state["trace"]}

    evidence = HeaderAnalyzer.analyze(metadata)
    _record_trace(
        state, node, name, TraceStatusEnum.COMPLETED, t0,
        f"Analyzed headers for domain '{metadata.sender_domain}'. Identified {len(evidence)} risk indicator(s).",
        {"sender_domain": metadata.sender_domain, "indicators": len(evidence)}
    )
    return {"header_evidence": evidence, "trace": state["trace"]}


# Node 3: analyze_body
def analyze_body_node(state: InvestigationState) -> Dict[str, Any]:
    t0 = time.time()
    node = "analyze_body"
    name = "Inspect Body Language & HTML Hyperlinks"
    plain_body = state.get("plain_body", "")
    html_body = state.get("html_body", "")

    if not plain_body and not html_body:
        _record_trace(
            state, node, name, TraceStatusEnum.SKIPPED, t0,
            "No message body present.", {"reason": "empty_body"}
        )
        return {"body_evidence": [], "extracted_urls": [], "trace": state["trace"]}

    evidence, extracted_urls = BodyAnalyzer.analyze(plain_body, html_body)
    _record_trace(
        state, node, name, TraceStatusEnum.COMPLETED, t0,
        f"Scanned body content. Found {len(evidence)} linguistic/anchor indicator(s) and {len(extracted_urls)} URL(s).",
        {"indicators": len(evidence), "extracted_urls": len(extracted_urls)}
    )
    return {
        "body_evidence": evidence,
        "extracted_urls": extracted_urls,
        "trace": state["trace"]
    }


# Node 4: analyze_urls
def analyze_urls_node(state: InvestigationState) -> Dict[str, Any]:
    t0 = time.time()
    node = "analyze_urls"
    name = "Static Syntactic URL Inspection"
    extracted_urls = state.get("extracted_urls", [])
    raw_content = state.get("raw_content", "")
    input_type = state.get("input_type", "")

    if input_type == "url" and raw_content:
        extracted_urls.append({"url": raw_content.strip(), "display_text": ""})

    if not extracted_urls:
        _record_trace(
            state, node, name, TraceStatusEnum.SKIPPED, t0,
            "No URLs identified in input to analyze.", {"reason": "no_urls"}
        )
        return {"url_findings": [], "url_evidence": [], "trace": state["trace"]}

    findings, evidence = URLAnalyzer.analyze_urls(extracted_urls)
    _record_trace(
        state, node, name, TraceStatusEnum.COMPLETED, t0,
        f"Completed static syntactic inspection of {len(findings)} URL(s). Discovered {len(evidence)} indicator(s).",
        {"url_count": len(findings), "indicators": len(evidence)}
    )
    return {
        "url_findings": findings,
        "url_evidence": evidence,
        "trace": state["trace"]
    }


# Node 5: analyze_attachments
def analyze_attachments_node(state: InvestigationState) -> Dict[str, Any]:
    t0 = time.time()
    node = "analyze_attachments"
    name = "Static Attachment & File Signature Analysis"
    raw_attachments = state.get("raw_attachments", [])

    if not raw_attachments:
        _record_trace(
            state, node, name, TraceStatusEnum.SKIPPED, t0,
            "No attachments present for static inspection.", {"reason": "no_attachments"}
        )
        return {"attachment_findings": [], "attachment_evidence": [], "trace": state["trace"]}

    findings, evidence = AttachmentAnalyzer.analyze_attachments(raw_attachments)
    _record_trace(
        state, node, name, TraceStatusEnum.COMPLETED, t0,
        f"Inspected {len(findings)} attachment(s) statically. Discovered {len(evidence)} risk indicator(s).",
        {"attachment_count": len(findings), "indicators": len(evidence)}
    )
    return {
        "attachment_findings": findings,
        "attachment_evidence": evidence,
        "trace": state["trace"]
    }


# Node 6: aggregate_evidence
def aggregate_evidence_node(state: InvestigationState) -> Dict[str, Any]:
    t0 = time.time()
    node = "aggregate_evidence"
    name = "Aggregate Security Findings & Deduplicate"
    
    header_ev = state.get("header_evidence", []) or []
    body_ev = state.get("body_evidence", []) or []
    url_ev = state.get("url_evidence", []) or []
    att_ev = state.get("attachment_evidence", []) or []

    combined = header_ev + body_ev + url_ev + att_ev

    # Deduplicate by rule_id + source_location
    seen = set()
    deduped: List[EvidenceRecord] = []
    for ev in combined:
        key = (ev.rule_id, ev.supporting_observation)
        if key not in seen:
            seen.add(key)
            deduped.append(ev)

    _record_trace(
        state, node, name, TraceStatusEnum.COMPLETED, t0,
        f"Aggregated {len(deduped)} unique authoritative evidence findings across all modules.",
        {"total_findings": len(deduped)}
    )
    return {"aggregated_evidence": deduped, "trace": state["trace"]}


# Node 7: calculate_risk
def calculate_risk_node(state: InvestigationState) -> Dict[str, Any]:
    t0 = time.time()
    node = "calculate_risk"
    name = "Deterministic Risk Engine Evaluation"
    
    evidence = state.get("aggregated_evidence", []) or []
    attachments = state.get("attachment_findings", []) or []
    metadata = state.get("email_metadata")
    has_body = bool(state.get("plain_body") or state.get("html_body"))
    has_headers = bool(metadata and metadata.sender)

    risk = RiskEngine.calculate(
        evidence=evidence,
        attachments=attachments,
        has_email_body=has_body,
        has_headers=has_headers
    )

    _record_trace(
        state, node, name, TraceStatusEnum.COMPLETED, t0,
        f"Calculated overall risk score {risk.overall_score}/100 ({risk.overall_rating.value}). Email: {risk.email_score}, Attachment: {risk.attachment_score}.",
        {"overall_score": risk.overall_score, "rating": risk.overall_rating.value}
    )
    return {"risk": risk, "trace": state["trace"]}


# Node 8: interpret_with_llm
async def interpret_with_llm_node(state: InvestigationState) -> Dict[str, Any]:
    t0 = time.time()
    node = "interpret_with_llm"
    name = "Tier-3 AI Synthesis (Gemini / Groq / Fallback)"
    
    evidence = state.get("aggregated_evidence", []) or []
    risk = state.get("risk")
    metadata = state.get("email_metadata")
    plain_body = state.get("plain_body", "")
    force_fallback = state.get("force_fallback", False)
    simulate_both_fail = state.get("simulate_both_fail", False)

    interpretation = await LLMRouter.interpret(
        evidence=evidence,
        risk=risk,
        email_metadata=metadata,
        plain_body=plain_body,
        force_fallback_to_groq=force_fallback,
        simulate_both_fail=simulate_both_fail
    )

    status_desc = f"Synthesis generated using provider '{interpretation.provider_used}'"
    if interpretation.fallback_used:
        status_desc += f" (Fallback active: {interpretation.fallback_reason})"

    _record_trace(
        state, node, name, TraceStatusEnum.COMPLETED, t0,
        status_desc,
        {
            "provider": interpretation.provider_used,
            "fallback_used": interpretation.fallback_used,
            "attack_vector": interpretation.attack_vector
        }
    )
    return {"llm_interpretation": interpretation, "trace": state["trace"]}


# Node 9: validate_evidence
def validate_evidence_node(state: InvestigationState) -> Dict[str, Any]:
    t0 = time.time()
    node = "validate_evidence"
    name = "Validate LLM Claims Against Authoritative Evidence"
    
    interpretation = state.get("llm_interpretation")
    evidence = state.get("aggregated_evidence", []) or []

    if interpretation:
        valid_ids, rejected = EvidenceValidator.validate_interpretation(
            interpretation.model_dump(),
            evidence
        )
        interpretation.validated_evidence_ids = valid_ids
        interpretation.rejected_claims = rejected

        msg = f"Validated {len(valid_ids)} claimed evidence IDs."
        if rejected:
            msg += f" Rejected {len(rejected)} unsupported claim(s)."
        _record_trace(
            state, node, name, TraceStatusEnum.COMPLETED, t0,
            msg, {"validated": len(valid_ids), "rejected": len(rejected)}
        )
    else:
        _record_trace(
            state, node, name, TraceStatusEnum.SKIPPED, t0,
            "No LLM interpretation to validate.", {}
        )

    return {"llm_interpretation": interpretation, "trace": state["trace"]}


# Node 10: generate_report
def generate_report_node(state: InvestigationState) -> Dict[str, Any]:
    t0 = time.time()
    node = "generate_report"
    name = "Assemble Final SOC Investigation Dossier"
    
    inv_id = state.get("investigation_id") or f"inv-{uuid.uuid4().hex[:8]}"
    input_type = state.get("input_type", "raw_text")
    risk = state.get("risk")
    evidence = state.get("aggregated_evidence", []) or []
    metadata = state.get("email_metadata")
    url_findings = state.get("url_findings", []) or []
    attachment_findings = state.get("attachment_findings", []) or []
    interpretation = state.get("llm_interpretation")
    trace = state.get("trace", []) or []

    result = InvestigationResult(
        id=inv_id,
        created_at=datetime.now(timezone.utc),
        input_type=input_type,
        status="COMPLETED",
        risk=risk,
        evidence=evidence,
        email_metadata=metadata,
        urls=url_findings,
        attachments=attachment_findings,
        llm_interpretation=interpretation,
        trace=trace,
        review_status="NEW"
    )

    _record_trace(
        state, node, name, TraceStatusEnum.COMPLETED, t0,
        f"Investigation dossier {inv_id} compiled successfully with {len(evidence)} finding(s).",
        {"id": inv_id, "findings_count": len(evidence)}
    )

    # Update trace inside result
    result.trace = state["trace"]

    return {"final_result": result, "trace": state["trace"]}


def build_investigation_graph():
    """
    Builds and compiles the 10-node LangGraph investigation pipeline.
    """
    builder = StateGraph(InvestigationState)

    # Add all 10 nodes
    builder.add_node("parse_input", parse_input_node)
    builder.add_node("analyze_headers", analyze_headers_node)
    builder.add_node("analyze_body", analyze_body_node)
    builder.add_node("analyze_urls", analyze_urls_node)
    builder.add_node("analyze_attachments", analyze_attachments_node)
    builder.add_node("aggregate_evidence", aggregate_evidence_node)
    builder.add_node("calculate_risk", calculate_risk_node)
    builder.add_node("interpret_with_llm", interpret_with_llm_node)
    builder.add_node("validate_evidence", validate_evidence_node)
    builder.add_node("generate_report", generate_report_node)

    # Linear and conditional edges
    builder.add_edge(START, "parse_input")
    builder.add_edge("parse_input", "analyze_headers")
    builder.add_edge("analyze_headers", "analyze_body")
    builder.add_edge("analyze_body", "analyze_urls")
    builder.add_edge("analyze_urls", "analyze_attachments")
    builder.add_edge("analyze_attachments", "aggregate_evidence")
    builder.add_edge("aggregate_evidence", "calculate_risk")
    builder.add_edge("calculate_risk", "interpret_with_llm")
    builder.add_edge("interpret_with_llm", "validate_evidence")
    builder.add_edge("validate_evidence", "generate_report")
    builder.add_edge("generate_report", END)

    return builder.compile()

# Global compiled graph singleton
investigation_graph = build_investigation_graph()
