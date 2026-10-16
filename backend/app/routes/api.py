import io
import csv
import json
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Query, Response, Depends, status
from fastapi.responses import JSONResponse, PlainTextResponse

from app.config import settings
from app.models.schemas import (
    InvestigationResult,
    ProviderStatus,
    AnalyzeRequest
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

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Investigation ID", "Created At", "Risk Rating", "Risk Score", "Email Score", "Attachment Score", "Rule ID", "Finding Title", "Severity", "Observation"])
        
        if res.evidence:
            for ev in res.evidence:
                writer.writerow([
                    res.id,
                    res.created_at.isoformat(),
                    res.risk.overall_rating.value,
                    res.risk.overall_score,
                    res.risk.email_score,
                    res.risk.attachment_score,
                    ev.rule_id,
                    ev.title,
                    ev.severity.value,
                    ev.supporting_observation
                ])
        else:
            writer.writerow([
                res.id,
                res.created_at.isoformat(),
                res.risk.overall_rating.value,
                res.risk.overall_score,
                res.risk.email_score,
                res.risk.attachment_score,
                "NONE", "No High Risk Indicators", "LOW", "Clean static analysis"
            ])

        response = Response(content=output.getvalue(), media_type="text/csv")
        response.headers["Content-Disposition"] = f"attachment; filename=phishguard_{res.id}.csv"
        return response

    elif fmt == "markdown":
        md_lines = [
            f"# PhishGuard AI — Investigation Dossier `{res.id}`",
            f"**Generated:** {res.created_at.isoformat()}Z  ",
            f"**Risk Score:** {res.risk.overall_score}/100 ({res.risk.overall_rating.value})  ",
            f"**Email Vector Score:** {res.risk.email_score}/100 | **Attachment Score:** {res.risk.attachment_score}/100  ",
            f"**Coverage Status:** {res.risk.coverage_status.value}  ",
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
