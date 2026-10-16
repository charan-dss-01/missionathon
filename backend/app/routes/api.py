import io
import csv
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Any, Dict
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Query, Response, Depends, status
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from app.config import settings
from app.models.schemas import (
    InvestigationResult,
    ProviderStatus,
    AnalyzeRequest,
    FeedbackCreateRequest,
    FeedbackRecord,
    FeedbackCategoryEnum
)
from app.models.user import UserProfileResponse
from app.storage.memory_store import store
from app.workflow.graph import investigation_graph
from app.db.mongodb import db_manager
from app.services.auth_service import get_current_user, get_optional_current_user

router = APIRouter(prefix="/api")

@router.get("/health")
async def get_health():
    """
    Health check endpoint reporting API health, uptime, and real-time MongoDB Atlas status.
    """
    db_health = await db_manager.check_health()
    return {
        "status": "healthy" if db_health.get("status") == "connected" else "degraded",
        "service": "PhishGuard AI Backend",
        "version": "1.0.0-hackathon-mvp",
        "database": db_health,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@router.get("/providers/status", response_model=ProviderStatus)
def get_provider_status():
    """
    Returns sanitized provider availability and fallback readiness.
    Never exposes provider API keys.
    """
    gemini_ready = bool(settings.GEMINI_API_KEY and len(settings.GEMINI_API_KEY.strip()) > 5)
    groq_ready = bool(settings.GROQ_API_KEY and len(settings.GROQ_API_KEY.strip()) > 5)

    return ProviderStatus(
        primary_provider=settings.PRIMARY_LLM_PROVIDER,
        gemini_configured=gemini_ready,
        gemini_model=settings.GEMINI_MODEL,
        groq_configured=groq_ready,
        groq_model=settings.GROQ_MODEL,
        fallback_ready=groq_ready,
        deterministic_fallback_ready=True
    )

@router.post("/analyze", response_model=InvestigationResult)
async def analyze_input(
    raw_content: Optional[str] = Form(None),
    input_type: Optional[str] = Form("raw_text"),
    force_fallback: Optional[bool] = Form(False),
    simulate_both_fail: Optional[bool] = Form(False),
    file: Optional[UploadFile] = File(None),
    current_user: Optional[UserProfileResponse] = Depends(get_optional_current_user)
):
    """
    Main investigation analysis endpoint supporting raw text, URLs, .eml, and attachments.
    Executes the 10-node LangGraph pipeline deterministically.
    Persists the final dossier in MongoDB under the authenticated user's ID.
    """
    raw_bytes = None
    file_name = None
    actual_content = raw_content or ""
    actual_input_type = input_type or "raw_text"

    if file:
        file_name = file.filename
        raw_bytes = await file.read()
        
        # Enforce upload bounds
        if len(raw_bytes) > settings.MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Uploaded file exceeds {settings.MAX_UPLOAD_BYTES / (1024*1024):.0f}MB bounded limit."
            )

        if file_name and file_name.lower().endswith(".eml"):
            actual_input_type = "eml"
        else:
            actual_input_type = "attachment"

    initial_state = {
        "raw_content": actual_content,
        "raw_bytes": raw_bytes,
        "file_name": file_name,
        "input_type": actual_input_type,
        "force_fallback": bool(force_fallback),
        "simulate_both_fail": bool(simulate_both_fail),
        "trace": []
    }

    try:
        # Run LangGraph pipeline
        final_state = await investigation_graph.ainvoke(initial_state)
        result: Optional[InvestigationResult] = final_state.get("final_result")

        if not result:
            raise HTTPException(status_code=500, detail="Investigation pipeline failed to yield a final dossier.")

        # Assign ownership
        owner_id = current_user.id if current_user else "anonymous"
        result.owner_id = owner_id

        # Persist to MongoDB
        if db_manager.is_connected:
            col = db_manager.get_investigations_col()
            doc = result.model_dump()
            # Ensure _id is unique or omit to let mongo generate
            doc["_id"] = result.id
            await col.replace_one({"_id": result.id}, doc, upsert=True)

        # Also maintain in-memory store for session continuity
        store.add(result)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Investigation workflow error: {str(e)}"
        )

@router.post("/analyze/json", response_model=InvestigationResult)
async def analyze_input_json(
    req: AnalyzeRequest,
    current_user: Optional[UserProfileResponse] = Depends(get_optional_current_user)
):
    """
    JSON-based analyze endpoint for pasted plaintext or URLs.
    """
    initial_state = {
        "raw_content": req.raw_content or "",
        "raw_bytes": None,
        "file_name": req.file_name,
        "input_type": req.input_type or "raw_text",
        "force_fallback": False,
        "simulate_both_fail": False,
        "trace": []
    }
    try:
        final_state = await investigation_graph.ainvoke(initial_state)
        result = final_state.get("final_result")
        if not result:
            raise HTTPException(status_code=500, detail="Pipeline error.")
        
        result.owner_id = current_user.id if current_user else "anonymous"
        
        if db_manager.is_connected:
            col = db_manager.get_investigations_col()
            doc = result.model_dump()
            doc["_id"] = result.id
            await col.replace_one({"_id": result.id}, doc, upsert=True)

        store.add(result)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

ORDERED_PIPELINE_STAGES = [
    ("parse_input", "Parse Raw Inbound Payload"),
    ("analyze_headers", "Inspect Authentication & Sender Headers"),
    ("analyze_body", "Inspect Body Language & HTML Hyperlinks"),
    ("analyze_urls", "Static Syntactic URL Inspection"),
    ("analyze_attachments", "Static Attachment & File Signature Analysis"),
    ("aggregate_evidence", "Aggregate Security Findings & Deduplicate"),
    ("calculate_risk", "Deterministic Risk Engine Evaluation"),
    ("interpret_with_llm", "Tier-3 AI Synthesis (Gemini / Groq / Fallback)"),
    ("validate_evidence", "Validate LLM Claims Against Authoritative Evidence"),
    ("generate_report", "Assemble Final SOC Investigation Dossier"),
]

@router.post("/analyze/stream")
async def analyze_input_stream(
    raw_content: Optional[str] = Form(None),
    input_type: Optional[str] = Form("raw_text"),
    force_fallback: Optional[bool] = Form(False),
    simulate_both_fail: Optional[bool] = Form(False),
    file: Optional[UploadFile] = File(None),
    current_user: Optional[UserProfileResponse] = Depends(get_optional_current_user)
):
    """
    Real-time Server-Sent Events (SSE) investigation analysis endpoint.
    Streams LangGraph node execution events (node_started, node_completed, complete)
    as they occur deterministically in real time.
    """
    raw_bytes = None
    file_name = None
    actual_content = raw_content or ""
    actual_input_type = input_type or "raw_text"

    if file:
        file_name = file.filename
        raw_bytes = await file.read()
        if len(raw_bytes) > settings.MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Uploaded file exceeds {settings.MAX_UPLOAD_BYTES / (1024*1024):.0f}MB bounded limit."
            )
        if file_name and file_name.lower().endswith(".eml"):
            actual_input_type = "eml"
        else:
            actual_input_type = "attachment"

    inv_id = f"inv-{uuid.uuid4().hex[:8]}"
    initial_state = {
        "investigation_id": inv_id,
        "raw_content": actual_content,
        "raw_bytes": raw_bytes,
        "file_name": file_name,
        "input_type": actual_input_type,
        "force_fallback": bool(force_fallback),
        "simulate_both_fail": bool(simulate_both_fail),
        "trace": []
    }
    owner_id = current_user.id if current_user else "anonymous"

    async def event_generator():
        # 1. Pipeline started
        yield f"event: pipeline_started\ndata: {json.dumps({'event': 'pipeline_started', 'investigation_id': inv_id, 'timestamp': datetime.now(timezone.utc).isoformat(), 'input_type': actual_input_type})}\n\n"

        # 2. First node start
        first_node, first_name = ORDERED_PIPELINE_STAGES[0]
        yield f"event: node_started\ndata: {json.dumps({'event': 'node_started', 'investigation_id': inv_id, 'node': first_node, 'name': first_name, 'status': 'RUNNING', 'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"

        accumulated_state = dict(initial_state)
        stage_keys = [s[0] for s in ORDERED_PIPELINE_STAGES]

        try:
            async for chunk in investigation_graph.astream(initial_state):
                for node_name, state_update in chunk.items():
                    accumulated_state.update(state_update)
                    trace_steps = state_update.get("trace", []) or accumulated_state.get("trace", [])
                    matching_step = next((s for s in reversed(trace_steps) if s.node == node_name), None)

                    status_str = matching_step.status.value if (matching_step and hasattr(matching_step.status, 'value')) else (str(matching_step.status) if matching_step else "COMPLETED")
                    duration_ms = matching_step.duration_ms if matching_step else 0.0
                    summary = matching_step.message if matching_step else f"{node_name} completed."
                    data_summary = matching_step.data_summary if matching_step else {}

                    finding_count = 0
                    if "indicators" in data_summary:
                        finding_count = data_summary["indicators"]
                    elif "total_findings" in data_summary:
                        finding_count = data_summary["total_findings"]
                    elif "findings_count" in data_summary:
                        finding_count = data_summary["findings_count"]
                    elif "url_count" in data_summary:
                        finding_count = data_summary.get("indicators", 0)
                    elif "attachments_count" in data_summary:
                        finding_count = data_summary["attachments_count"]

                    node_completed_event = {
                        "event": "node_completed",
                        "investigation_id": inv_id,
                        "node": node_name,
                        "name": matching_step.name if matching_step else node_name,
                        "status": status_str,
                        "duration_ms": duration_ms,
                        "finding_count": finding_count,
                        "summary": summary,
                        "data_summary": data_summary,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    yield f"event: node_completed\ndata: {json.dumps(node_completed_event)}\n\n"

                    # Emit node_started for next stage
                    if node_name in stage_keys:
                        idx = stage_keys.index(node_name)
                        if idx + 1 < len(ORDERED_PIPELINE_STAGES):
                            next_node, next_name = ORDERED_PIPELINE_STAGES[idx + 1]
                            next_started = {
                                "event": "node_started",
                                "investigation_id": inv_id,
                                "node": next_node,
                                "name": next_name,
                                "status": "RUNNING",
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            }
                            yield f"event: node_started\ndata: {json.dumps(next_started)}\n\n"

            # 3. Final Result Dossier Assembly
            result: Optional[InvestigationResult] = accumulated_state.get("final_result")
            if not result:
                yield f"event: error\ndata: {json.dumps({'event': 'error', 'investigation_id': inv_id, 'error': 'Pipeline did not yield a final dossier.'})}\n\n"
                return

            result.owner_id = owner_id

            if db_manager.is_connected:
                col = db_manager.get_investigations_col()
                doc = result.model_dump()
                doc["_id"] = result.id
                await col.replace_one({"_id": result.id}, doc, upsert=True)

            store.add(result)

            # 4. Final events
            result_dict = result.model_dump(mode="json")
            yield f"event: complete\ndata: {json.dumps({'event': 'complete', 'investigation_id': inv_id, 'result': result_dict})}\n\n"
            yield f"event: pipeline_completed\ndata: {json.dumps({'event': 'pipeline_completed', 'investigation_id': inv_id, 'status': 'COMPLETED', 'overall_score': result.risk.overall_score if result.risk else 0, 'overall_rating': result.risk.overall_rating.value if result.risk else 'UNKNOWN', 'total_evidence': len(result.evidence)})}\n\n"

        except Exception as exc:
            yield f"event: error\ndata: {json.dumps({'event': 'error', 'investigation_id': inv_id, 'error': str(exc)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@router.get("/investigations/{id}/events")
async def get_investigation_events(id: str):
    """
    Returns recorded SSE events for an existing investigation for replay or visual sync.
    """
    inv = store.get(id)
    if not inv and db_manager.is_connected:
        col = db_manager.get_investigations_col()
        doc = await col.find_one({"_id": id})
        if doc:
            inv = InvestigationResult(**doc)

    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{id}' not found.")

    async def event_generator():
        yield f"event: pipeline_started\ndata: {json.dumps({'event': 'pipeline_started', 'investigation_id': id, 'timestamp': inv.created_at.isoformat(), 'input_type': inv.input_type})}\n\n"
        for step in inv.trace:
            finding_count = (step.data_summary or {}).get("indicators") or (step.data_summary or {}).get("total_findings") or (step.data_summary or {}).get("findings_count") or 0
            ev = {
                "event": "node_completed",
                "investigation_id": id,
                "node": step.node,
                "name": step.name,
                "status": step.status.value if hasattr(step.status, 'value') else str(step.status),
                "duration_ms": step.duration_ms,
                "finding_count": finding_count,
                "summary": step.message,
                "data_summary": step.data_summary or {},
                "timestamp": step.end_time.isoformat() if step.end_time else datetime.now(timezone.utc).isoformat()
            }
            yield f"event: node_completed\ndata: {json.dumps(ev)}\n\n"

        result_dict = inv.model_dump(mode="json")
        yield f"event: complete\ndata: {json.dumps({'event': 'complete', 'investigation_id': id, 'result': result_dict})}\n\n"
        yield f"event: pipeline_completed\ndata: {json.dumps({'event': 'pipeline_completed', 'investigation_id': id, 'status': inv.status, 'overall_score': inv.risk.overall_score if inv.risk else 0, 'overall_rating': inv.risk.overall_rating.value if inv.risk else 'UNKNOWN', 'total_evidence': len(inv.evidence)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"}
    )

@router.get("/investigations", response_model=List[InvestigationResult])
async def list_investigations(
    rating: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    current_user: Optional[UserProfileResponse] = Depends(get_optional_current_user)
):
    """
    Retrieves investigations isolated by owner.
    Authenticated users only see their own investigations (or all if admin).
    """
    results: List[InvestigationResult] = []

    # If MongoDB is connected, query by owner
    if db_manager.is_connected:
        col = db_manager.get_investigations_col()
        query = {}
        
        # Enforce multi-tenant isolation
        if current_user:
            if current_user.role != "admin":
                query["$or"] = [{"owner_id": current_user.id}, {"owner_id": "anonymous"}, {"owner_id": None}]
        else:
            # Unauthenticated: show public/demo items
            query["$or"] = [{"owner_id": "anonymous"}, {"owner_id": None}]

        if rating:
            query["risk.overall_rating"] = rating.upper()
        if status:
            query["review_status"] = status.upper()

        cursor = col.find(query).sort("created_at", -1)
        async for doc in cursor:
            # Remove mongo internal _id if needed
            doc.pop("_id", None)
            try:
                results.append(InvestigationResult(**doc))
            except Exception:
                pass

    # If database returned nothing, fall back to in-memory store
    if not results:
        results = store.list_all()
        if current_user and current_user.role != "admin":
            results = [r for r in results if not r.owner_id or r.owner_id in [current_user.id, "anonymous"]]
        if rating:
            results = [r for r in results if r.risk.overall_rating.value == rating.upper()]
        if status:
            results = [r for r in results if r.review_status == status.upper()]

    # FEATURE:insights
    for r in results:
        if r.insights is None and getattr(settings, "FEATURE_INSIGHTS", True):
            try:
                from app.services.insights_builder import build_insights
                r.insights = build_insights(r.email_metadata, "", "", r.urls or [], r.attachments or [], r.evidence or [])
            except Exception:
                pass

    return results

async def _get_investigation_with_ownership_check(
    inv_id: str,
    current_user: Optional[UserProfileResponse]
) -> InvestigationResult:
    """
    Internal helper to fetch investigation from MongoDB and verify ownership.
    """
    res: Optional[InvestigationResult] = None

    if db_manager.is_connected:
        col = db_manager.get_investigations_col()
        doc = await col.find_one({"id": inv_id})
        if doc:
            doc.pop("_id", None)
            res = InvestigationResult(**doc)

    if not res:
        res = store.get(inv_id)

    if not res:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    # FEATURE:insights
    if res.insights is None and getattr(settings, "FEATURE_INSIGHTS", True):
        try:
            from app.services.insights_builder import build_insights
            res.insights = build_insights(
                metadata=res.email_metadata,
                plain_body="",
                html_body="",
                url_findings=res.urls or [],
                attachment_findings=res.attachments or [],
                evidence_records=res.evidence or []
            )
        except Exception:
            pass

    # Strict multi-tenant authorization
    if res.owner_id and res.owner_id not in ["anonymous", None]:
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required to access this investigation."
            )
        if current_user.id != res.owner_id and current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not have permission to view this investigation."
            )

    return res

@router.get("/investigations/{inv_id}", response_model=InvestigationResult)
async def get_investigation(
    inv_id: str,
    current_user: Optional[UserProfileResponse] = Depends(get_optional_current_user)
):
    """
    Retrieves a single investigation dossier by ID. Enforces ownership authorization.
    """
    return await _get_investigation_with_ownership_check(inv_id, current_user)

@router.get("/investigations/{inv_id}/trace")
async def get_investigation_trace(
    inv_id: str,
    current_user: Optional[UserProfileResponse] = Depends(get_optional_current_user)
):
    """
    Retrieves the execution trace steps for an investigation after verifying ownership.
    """
    res = await _get_investigation_with_ownership_check(inv_id, current_user)
    return {
        "investigation_id": res.id,
        "trace": res.trace
    }

@router.patch("/investigations/{inv_id}/review", response_model=InvestigationResult)
async def update_review_status(
    inv_id: str,
    status_val: str = Query(..., alias="status", description="NEW, IN_REVIEW, RESOLVED_MALICIOUS, RESOLVED_BENIGN"),
    notes: Optional[str] = Query(None),
    current_user: Optional[UserProfileResponse] = Depends(get_optional_current_user)
):
    """
    Updates the human review queue triage status and analyst notes.
    Persists updates to MongoDB.
    """
    res = await _get_investigation_with_ownership_check(inv_id, current_user)
    res.review_status = status_val.upper()
    if notes is not None:
        res.review_notes = notes

    if db_manager.is_connected:
        col = db_manager.get_investigations_col()
        await col.update_one(
            {"id": inv_id},
            {"$set": {"review_status": res.review_status, "review_notes": res.review_notes}}
        )

    store.update_review(inv_id, res.review_status, res.review_notes)
    return res

@router.post("/investigations/{inv_id}/feedback", response_model=FeedbackRecord, status_code=status.HTTP_201_CREATED)
async def submit_investigation_feedback(
    inv_id: str,
    req: FeedbackCreateRequest,
    current_user: Optional[UserProfileResponse] = Depends(get_optional_current_user)
):
    """
    Submits user feedback regarding an incorrect classification, false positive,
    false negative, or wrong file type detection.
    Persists feedback with original prediction snapshot to MongoDB and memory store.
    """
    res = await _get_investigation_with_ownership_check(inv_id, current_user)

    # Validate attachment reference if provided
    if req.attachment_filename:
        filename_clean = req.attachment_filename.strip().lower()
        attachment_matches = [
            a for a in (res.attachments or [])
            if a.filename.strip().lower() == filename_clean
        ]
        if not attachment_matches:
            raise HTTPException(
                status_code=400,
                detail=f"Attachment '{req.attachment_filename}' was not found in investigation '{inv_id}'."
            )

    # Build snapshot of original prediction at submission time
    snapshot: Dict[str, Any] = {
        "overall_score": res.risk.overall_score if res.risk else 0,
        "overall_rating": res.risk.overall_rating.value if res.risk else "UNKNOWN",
        "sender_score": getattr(res.risk, "sender_score", 0) if res.risk else 0,
        "body_score": getattr(res.risk, "body_score", 0) if res.risk else 0,
        "url_score": getattr(res.risk, "url_score", 0) if res.risk else 0,
        "attachment_score": res.risk.attachment_score if res.risk else 0,
        "email_score": res.risk.email_score if res.risk else 0,
        "total_evidence_count": len(res.evidence or []),
        "evidence_rule_ids": [e.rule_id for e in (res.evidence or [])],
        "review_status": res.review_status or "NEW",
    }
    if req.attachment_filename:
        target_att = next(
            (a for a in (res.attachments or []) if a.filename.strip().lower() == req.attachment_filename.strip().lower()),
            None
        )
        if target_att:
            snapshot["attachment_finding"] = {
                "filename": target_att.filename,
                "detected_type": target_att.detected_type,
                "declared_mime": target_att.declared_mime,
                "risk_score": getattr(target_att, "risk_score", 0),
                "risk_level": target_att.risk_level.value if hasattr(target_att.risk_level, "value") else str(target_att.risk_level),
                "matched_rules": target_att.matched_rules,
                "coverage_status": target_att.coverage_status
            }

    # Anti-duplicate policy: check if identical submission occurred in last 60 seconds
    now = datetime.now(timezone.utc)
    existing_records = store.get_feedback_for_investigation(inv_id)
    clean_explanation = req.explanation.strip() if req.explanation else None
    for prev in existing_records:
        if (
            prev.category == req.category
            and prev.attachment_filename == req.attachment_filename
            and prev.explanation == clean_explanation
        ):
            time_diff = (now - prev.created_at).total_seconds()
            if time_diff < 60:
                return prev

    fb_id = f"fb-{uuid.uuid4().hex[:8]}"
    feedback_record = FeedbackRecord(
        id=fb_id,
        investigation_id=inv_id,
        user_id=current_user.id if current_user else "anonymous",
        category=req.category,
        attachment_filename=req.attachment_filename,
        explanation=clean_explanation,
        created_at=now,
        status="SUBMITTED",
        original_prediction_snapshot=snapshot
    )

    if db_manager.is_connected:
        col = db_manager.get_feedback_col()
        doc = feedback_record.model_dump()
        doc["_id"] = fb_id
        await col.replace_one({"_id": fb_id}, doc, upsert=True)

    store.add_feedback(feedback_record)
    return feedback_record

@router.get("/investigations/{inv_id}/feedback", response_model=List[FeedbackRecord])
async def list_investigation_feedback(
    inv_id: str,
    current_user: Optional[UserProfileResponse] = Depends(get_optional_current_user)
):
    """
    Retrieves all submitted feedback records for a specific investigation.
    """
    await _get_investigation_with_ownership_check(inv_id, current_user)

    if db_manager.is_connected:
        col = db_manager.get_feedback_col()
        cursor = col.find({"investigation_id": inv_id}).sort("created_at", -1)
        db_records = []
        async for doc in cursor:
            doc.pop("_id", None)
            db_records.append(FeedbackRecord(**doc))
        if db_records:
            return db_records

    return store.get_feedback_for_investigation(inv_id)


@router.get("/investigations/{inv_id}/export")
async def export_investigation(
    inv_id: str,
    format: str = Query("json", description="json, csv, or markdown"),
    current_user: Optional[UserProfileResponse] = Depends(get_optional_current_user)
):
    """
    Exports the investigation dossier in JSON, CSV, or Markdown format after verifying ownership.
    """
    res = await _get_investigation_with_ownership_check(inv_id, current_user)
    fmt = format.lower()

    def _sanitize_csv(cell: Any) -> Any:
        if cell is None:
            return ""
        s = str(cell)
        if s and s[0] in ["=", "+", "-", "@", "\t", "\r"]:
            return f"'{s}"
        return s

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Investigation ID", "Created At", "Risk Rating", "Risk Score",
            "Sender Score", "Body Score", "URL Score", "Attachment Score",
            "Email Score", "Rule ID", "Finding Title", "Severity", "Observation"
        ])
        
        if res.evidence:
            for ev in res.evidence:
                writer.writerow([
                    _sanitize_csv(res.id),
                    _sanitize_csv(res.created_at.isoformat()),
                    _sanitize_csv(res.risk.overall_rating.value),
                    _sanitize_csv(res.risk.overall_score),
                    _sanitize_csv(getattr(res.risk, "sender_score", 0)),
                    _sanitize_csv(getattr(res.risk, "body_score", 0)),
                    _sanitize_csv(getattr(res.risk, "url_score", 0)),
                    _sanitize_csv(res.risk.attachment_score),
                    _sanitize_csv(res.risk.email_score),
                    _sanitize_csv(ev.rule_id),
                    _sanitize_csv(ev.title),
                    _sanitize_csv(ev.severity.value),
                    _sanitize_csv(ev.supporting_observation)
                ])
        else:
            writer.writerow([
                _sanitize_csv(res.id),
                _sanitize_csv(res.created_at.isoformat()),
                _sanitize_csv(res.risk.overall_rating.value),
                _sanitize_csv(res.risk.overall_score),
                _sanitize_csv(getattr(res.risk, "sender_score", 0)),
                _sanitize_csv(getattr(res.risk, "body_score", 0)),
                _sanitize_csv(getattr(res.risk, "url_score", 0)),
                _sanitize_csv(res.risk.attachment_score),
                _sanitize_csv(res.risk.email_score),
                "NONE", "No High Risk Indicators", "LOW", "Clean static analysis"
            ])

        response = Response(content=output.getvalue(), media_type="text/csv")
        response.headers["Content-Disposition"] = f"attachment; filename=phishguard_{res.id}.csv"
        return response

    elif fmt == "markdown":
        sender_sc = getattr(res.risk, "sender_score", 0)
        body_sc = getattr(res.risk, "body_score", 0)
        url_sc = getattr(res.risk, "url_score", 0)
        md_lines = [
            f"# PhishGuard AI — Investigation Dossier `{res.id}`",
            f"**Generated:** {res.created_at.isoformat()}Z  ",
            f"**Risk Score:** {res.risk.overall_score}/100 ({res.risk.overall_rating.value})  ",
            f"**4-Way Risk Breakdown:** Sender: {sender_sc}/100 | Body: {body_sc}/100 | URLs: {url_sc}/100 | Attachments: {res.risk.attachment_score}/100  ",
            f"**Combined Email Vector:** {res.risk.email_score}/100  ",
            f"**Coverage Status:** {res.risk.coverage_status.value}  ",
            f"**Scoring Explanation:** {res.risk.scoring_explanation}  ",
            "",
            "## Mandatory Safe Verification Guidance",
            "1. **Verify Official Channel:** Verify the message through an independently obtained official channel (out-of-band portal or verified phone).",
            "2. **Protect Credentials:** Never enter passwords, credentials, or MFA codes via links received in unexpected messages.",
            "3. **Report Immediately:** Report suspicious messages to the internal IT or Information Security team for quarantine.",
            "",
            "## Executive AI Synthesis",
            f"**Provider Used:** {res.llm_interpretation.provider_used.upper()} " +
            (f"(Fallback: {res.llm_interpretation.fallback_reason})" if res.llm_interpretation.fallback_used else ""),
            "",
            f"**Attack Vector:** {res.llm_interpretation.attack_vector}  ",
            f"**Summary:** {res.llm_interpretation.summary}  ",
            "",
            "### Targeted Assets",
            *[f"- {asset}" for asset in res.llm_interpretation.targeted_assets],
            "",
            "### Actionable SOC Recommendations",
            *[f"1. {rec}" for rec in res.llm_interpretation.actionable_recommendations],
            "",
            "## Authoritative Evidence Records",
            "| Rule ID | Category | Title | Severity | Observation |",
            "| :--- | :--- | :--- | :--- | :--- |"
        ]
        for ev in res.evidence:
            md_lines.append(f"| `{ev.rule_id}` | {ev.category} | {ev.title} | **{ev.severity.value}** | {ev.supporting_observation} |")

        if not res.evidence:
            md_lines.append("| `NONE` | baseline | Clean Static Analysis | LOW | No threat signatures detected |")

        if res.attachments:
            md_lines.extend([
                "",
                "## Attachment Inventory",
                "| Filename | Declared MIME | Detected Type | Size (Bytes) | SHA-256 | Status | Limitations |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
            ])
            for att in res.attachments:
                md_lines.append(f"| `{att.filename}` | {att.declared_mime or 'None'} | {att.detected_type} | {att.size_bytes} | `{att.sha256[:16]}...` | **{att.coverage_status}** | {att.limitations} |")

        if res.urls:
            md_lines.extend([
                "",
                "## URL Inspection Results",
                "| URL | Domain | IP Literal | Punycode | Deceptive Subdomain | Severity |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |"
            ])
            for u in res.urls:
                md_lines.append(f"| `{u.url[:60]}` | {u.domain} | {u.is_ip_literal} | {u.is_punycode} | {u.has_deceptive_subdomains} | {u.severity.value} |")

        md_lines.extend([
            "",
            "## Technical Limitations & Disclaimers",
            *[f"- {lim}" for lim in res.llm_interpretation.limitations],
            "- **Disclaimer:** Static inspection cannot guarantee 100% absence of novel zero-day exploits. Never label uninspected files as safe."
        ])

        response = Response(content="\n".join(md_lines), media_type="text/markdown")
        response.headers["Content-Disposition"] = f"attachment; filename=phishguard_{res.id}.md"
        return response

    # Default JSON
    return res
