# PhishGuard AI — Agentic Cyber Investigation Platform

[![Next.js](https://img.shields.io/badge/Frontend-Next.js%2014-black?logo=next.js)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/Workflow-LangGraph-FF6F00)](https://langchain-ai.github.io/langgraph/)
[![TailwindCSS](https://img.shields.io/badge/Design-TailwindCSS-38B2AC?logo=tailwind-css)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/Security-Air--Gapped%20Static-blue)](#security-and-privacy)
[![Tests](https://img.shields.io/badge/Tests-60%20Passed-brightgreen)](backend/tests)

**PhishGuard AI** is a production-grade 24-hour hackathon MVP built for Tier-2 and Tier-3 Security Operations Center (SOC) analysts. It performs deep, multi-vector static analysis of suspicious email text, `.eml` files, hyperlinks, attachments, and embedded QR codes. Every finding is backed by transparent, deterministic Python security rules, explainable risk scoring, and multi-tier AI orchestration (Gemini primary, Groq automatic fallback, and deterministic rule-grounded offline templates).

---

## 1. Core Architecture & Product Principles

1. **Every finding must have supporting evidence:** Authoritative detections are generated solely by validated Python security rules.
2. **Deterministic Risk Scoring:** Configurable weights, correlated indicator damping, and discrete component scoring (Email vs. Attachment).
3. **Multi-Tier AI Orchestration:**
   - **Primary:** Google Gemini (1.5 / 2.0 Flash)
   - **Automatic Fallback:** Groq (Llama-3.3-70b-versatile) on HTTP 429 rate limits or transient network errors.
   - **Offline Deterministic Fallback:** Pure Python rule templates if both external providers fail or API keys are omitted.
4. **Authoritative Evidence Validation:** An automated validator cross-checks all LLM claims against known rule IDs; hallucinated or unsupported claims are rejected.
5. **Air-Gapped Static Analysis:** **Zero network navigation.** Links are never clicked, remote resources are never fetched, and attachments are never executed or rendered.
6. **Honest Coverage Status:** Incomplete, unsupported, or encrypted inputs are explicitly marked as `UNKNOWN`, `UNSCANNED`, or `UNSUPPORTED`. Low scores never claim absolute safety.

---

## 2. Advanced Security Capabilities

### Victim View vs. Forensic Truth Mode (`VictimTruthView`)
- Side-by-side interactive comparison between the recipient's deceptive inbox perspective and verified forensic reality.
- Identifies display name spoofing, reply-to redirection, lookalike homograph URLs, RTLO Unicode masking, and binary MIME inconsistencies.

### Visual Attack Story Timeline (`AttackTimeline`)
- Maps observed evidence chronologically across the 4 canonical ATT&CK progression stages: **Lure** $\rightarrow$ **Deception** $\rightarrow$ **Delivery** $\rightarrow$ **Action**.
- Correlates findings to MITRE ATT&CK techniques (`T1036`, `T1204`, `T1566`, `T1566.001`, `T1566.002`, `T1027`).
- Interactive rule chips smoothly scroll and highlight matching records directly in the Authoritative Evidence Table.

### In-Memory QR Code & Quishing Detection (`qr_analyzer`)
- Detects 2D barcodes in image attachments (`PNG`, `JPEG`, `GIF` verified strictly by magic bytes).
- Strict in-memory safety limits: Max 5 MB per image, max $4000\times 4000\text{ px}$ parsed from headers **before** decoding, and a cap of 3 images per email.
- Decoded URLs are routed through `URLAnalyzer` without making remote network calls; user-facing URLs are strictly defanged (`hxxps://`, `[.]`).
- New authoritative rules: `ATT_QR_PRESENT` (Low, 10 pts) and `ATT_QR_URL_FLAGGED` (High, 30 pts).

---

## 3. The 10-Node LangGraph Pipeline

The investigation lifecycle executes across 10 explicit LangGraph nodes:

```
[START]
   │
   ▼
1. parse_input           ──► Extracts RFC 5322 headers, plain/HTML body, attachments
   │
   ▼
2. analyze_headers       ──► Checks SPF/DKIM/DMARC headers, Reply-To & Return-Path, Display Name
   │
   ▼
3. analyze_body          ──► Identifies urgency cues, credential harvesting, anchor text/href mismatches
   │
   ▼
4. analyze_urls          ──► Static syntactic analysis: IP literals, punycode, homoglyphs, deceptive subdomains
   │
   ▼
5. analyze_attachments   ──► Safe byte inspection: magic signatures, RTLO, double exts, macros, QR codes
   │
   ▼
6. aggregate_evidence    ──► Deduplicates correlated findings and compiles authoritative records
   │
   ▼
7. calculate_risk        ──► Deterministic math engine (email_score, attachment_score, overall rating)
   │
   ▼
8. interpret_with_llm    ──► Tier-3 SOC synthesis (Gemini primary ➔ Groq fallback ➔ template fallback)
   │
   ▼
9. validate_evidence     ──► Rejects hallucinated claims; retains only grounded rule evidence
   │
   ▼
10. generate_report      ──► Compiles final SOC dossier with execution trace and metadata
   │
   ▼
 [END]
```

---

## 4. Product Pages & Control Tower Views

| Page | Route | Description |
| :--- | :--- | :--- |
| **1. Overview Dashboard** | `/` | Real-time session telemetry, threat counters, MongoDB Atlas connection status, provider status pills, and recent investigation feed. |
| **2. New Investigation** | `/investigate` | Multi-vector intake supporting plain text, `.eml` uploads, URL static scan, attachment upload, and 1-click synthetic test fixtures. |
| **3. Investigation Results** | `/investigations/[id]` | Full dossier: risk gauges, email vs attachment breakdown, Victim vs Truth view, Attack Story Timeline, AI synthesis, and export tools. |
| **4. Agent Orchestration** | `/trace` | Connected LangGraph DAG timeline with node execution states, duration in milliseconds, logs, and payload inspectors. |
| **5. Investigation History** | `/history` | Full searchable and filterable session audit log with instant export downloads, filtered strictly to the authenticated tenant. |
| **6. Human Review Queue** | `/queue` | Master-detail SOC triage board with status transitions (`NEW`, `IN_REVIEW`, `RESOLVED_MALICIOUS`, `RESOLVED_BENIGN`) and analyst notes. |
| **7. Reports & Export** | `/reports` | Export hub for generating Markdown dossiers, structured CSV data, and JSON exports with privacy disclaimers. |
| **8. SOC Analyst Login** | `/login` | Secure JWT/HTTP-only cookie authentication with rate limiting and audit logging. |
| **9. Analyst Registration** | `/register` | Tenant onboarding with real-time password strength validation and bcrypt salting. |
| **10. Account Security** | `/settings/security` | Analyst profile details, password rotation, audit event metadata, and MongoDB tenant isolation specs. |

---

## 5. API Endpoints Reference

### Authentication (`/api/auth`)
- `POST /api/auth/register` — Register a new analyst account (`email`, `password`, `full_name`).
- `POST /api/auth/login` — Authenticate and receive signed HS256 JWT in secure HTTP-only cookie.
- `POST /api/auth/logout` — Terminate session and invalidate auth cookie.
- `GET /api/auth/me` — Retrieve authenticated user profile and roles.
- `POST /api/auth/change-password` — Securely update analyst credentials.

### Investigations (`/api`)
- `POST /api/analyze` — Intake raw text, `.eml`, URL, or attachment for full pipeline processing.
- `GET /api/investigations` — Retrieve paginated investigations scoped to the authenticated tenant.
- `GET /api/investigations/{id}` — Fetch complete investigation dossier and findings.
- `PATCH /api/investigations/{id}/review` — Commit human triage status and review notes.
- `GET /api/investigations/{id}/export/{format}` — Download investigation in Markdown, CSV, or JSON format.
- `GET /api/health` — Service readiness, MongoDB latency, and version check.
- `GET /api/providers/status` — Live health check for Gemini, Groq, and fallback pipelines.

---

## 6. Environment Variables Reference

### Backend (`backend/.env`)
```ini
# LLM Orchestration
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-flash-latest
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b
PRIMARY_LLM_PROVIDER=gemini

# Feature Flags
FEATURE_INSIGHTS=true    # Enables Victim vs Truth view, Clues, and Attack Story Timeline
FEATURE_QR=true          # Enables in-memory QR barcode analysis on image attachments

# MongoDB Database (Atlas or Local)
MONGODB_URI=mongodb+srv://<username>:<password>@cluster0.mongodb.net/?retryWrites=true&w=majority
MONGODB_DATABASE=phishguard_ai

# JWT Authentication & Cookie Security
JWT_SECRET=phishguard-ai-soc-platform-super-secure-jwt-key-32-chars-min
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=1440
COOKIE_NAME=phishguard_session
COOKIE_SECURE=false      # Set to true in production with HTTPS
COOKIE_SAMESITE=lax

# Server Configuration
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001
MAX_UPLOAD_BYTES=10485760
MAX_ATTACHMENT_SIZE_BYTES=5242880
REQUEST_TIMEOUT_SECONDS=30
```

### Frontend (`frontend/.env.local`)
```ini
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## 7. Running Tests & Verifying Fixtures

The backend includes **60 automated test cases** (100% passing) verifying all analyzers, risk scoring, failover, evidence validation, and network isolation:

```bash
cd backend
venv\Scripts\pytest -v
```

### Test Suite Structure
- `test_no_network.py` (1 test): Patches socket connections and DNS resolution to confirm zero network access across all corpus fixtures.
- `test_fixtures.py` (8 tests): Validates baseline snapshot scoring invariants and realistic email/attachment fixtures.
- `test_qr.py` (7 tests): Validates QR detection, flagged typosquat URLs, benign URLs, oversized images, missing library fallbacks, and graph integration.
- `test_insights.py` (5 tests): Validates Victim vs Truth deceptions, clue locator spans, and attack timeline assembly.
- `test_defang.py` (7 tests): Tests URL defanging idempotence across IP literals, userinfo, subdomains, and protocols.
- `test_rule_metadata.py` (6 tests): Validates presentation descriptions, hints, stages, and MITRE ATT&CK coverage.
- `test_analyzers.py` (12 tests): Unit tests for header, body, URL, and attachment rules.
- `test_auth.py` (3 tests): Tests registration, login, JWT validation, and multi-tenant data isolation.
- `test_risk_engine.py` (3 tests): Validates deterministic weights, component score bounds, and coverage flags.
- `test_fallback.py` (3 tests): Tests sensitive data redaction, Groq failover, and offline rule-grounded fallback.
- `test_validator.py` (2 tests): Verifies rejection of hallucinated LLM claims.
- `test_api.py` (4 tests): Tests REST API endpoints, review triage updates, and health endpoints.

---

## 8. Limitations & Scope of Analysis

- **Static Inspection Only:** PhishGuard AI does not detonate files or run sandboxed dynamic execution. Executable files are evaluated purely via magic bytes, RTLO markers, double extensions, and structure.
- **Air-Gapped URL Evaluation:** URLs are inspected syntactically and defanged. PhishGuard does not execute HTTP requests, follow redirects, or render JavaScript on remote landing pages.
- **Encrypted & Protected Archives:** Password-protected archives (`.zip`, `.rar`, `.7z`) and encrypted PDFs cannot be inspected without keys and are marked as `UNSUPPORTED` / `UNSCANNED`.
- **QR Code Boundaries:** QR detection processes images up to $4000\times 4000\text{ px}$ in memory. Heavily degraded, obstructed, or proprietary 3D codes may require manual SOC review.
- **Analyst-in-the-Loop:** Risk scores and AI syntheses provide decision support; final quarantine and disposition actions remain in human analyst control via `/queue`.

---

## 9. Quickstart Guide

### 1. Start the Backend
```bash
cd backend
python -m venv venv
venv\Scripts\activate       # On Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Start the Frontend
```bash
cd frontend
npm install
npm run dev -- -p 3001
```

Visit **`http://localhost:3001`** in your browser. Default demo cases and test fixtures are pre-seeded and ready for immediate evaluation.
