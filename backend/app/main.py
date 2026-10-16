from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uuid
import logging
from contextlib import asynccontextmanager

from app.config import settings
from app.db.mongodb import db_manager
from app.routes.api import router
from app.routes.auth import auth_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize MongoDB connection and verify indexes on startup
    await db_manager.connect()
    yield
    # Gracefully close MongoDB connections on shutdown
    await db_manager.close()

app = FastAPI(
    title="PhishGuard AI — Agentic Cyber Investigation API",
    description="Explainable, rule-grounded email and attachment security analysis with Gemini/Groq LangGraph orchestration and MongoDB Atlas multi-tenant persistence.",
    version="1.0.0",
    lifespan=lifespan
)

# Global safe error handling
@app.middleware("http")
async def add_request_id_and_error_handling(request: Request, call_next):
    request_id = str(uuid.uuid4())[:8]
    request.state.request_id = request_id
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
    except Exception as exc:
        logging.error(f"Unhandled request exception [{request_id}]: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "InternalServerError",
                "message": "An error occurred during investigation processing. Sensitive details suppressed.",
                "request_id": request_id
            },
            headers={"X-Request-ID": request_id}
        )

# Configure CORS as OUTERMOST middleware
cors_origins = [o.strip() for o in settings.CORS_ORIGINS if o.strip() and o.strip() != "*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=r"^(https:\/\/.*\.vercel\.app|http:\/\/(localhost|127\.0\.0\.1)(:\d+)?)$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Request-ID"],
)

# Register routes
app.include_router(auth_router)
app.include_router(router)

@app.get("/")
def read_root():
    return {
        "product": "PhishGuard AI",
        "description": "Agentic SOC Email & Attachment Analysis Platform with MongoDB Atlas persistence",
        "documentation": "/docs",
        "health": "/api/health"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.BACKEND_HOST, port=settings.BACKEND_PORT, reload=True)
