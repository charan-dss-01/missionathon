# PhishGuard AI — Agentic Cyber Investigation Platform

[![Next.js](https://img.shields.io/badge/Frontend-Next.js%2014-black?logo=next.js)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/Workflow-LangGraph-FF6F00)](https://langchain-ai.github.io/langgraph/)
[![TailwindCSS](https://img.shields.io/badge/Design-TailwindCSS-38B2AC?logo=tailwind-css)](https://tailwindcss.com/)
[![Security](https://img.shields.io/badge/Security-Air--Gapped%20Static-blue)](#8-limitations--scope-of-analysis)
[![Tests](https://img.shields.io/badge/Tests-84%20Passed-brightgreen)](EVALUATION.md)
[![Evaluation](https://img.shields.io/badge/Evaluation-Report%20Available-teal)](EVALUATION.md)

**PhishGuard AI** is an enterprise-grade agentic cybersecurity investigation platform built for Tier-2 and Tier-3 Security Operations Center (SOC) analysts. It performs deep, multi-vector static inspection of suspicious email messages, `.eml` files, raw RFC 5322 text, hyperlinks, attachments, and embedded QR codes. 

Every detection is backed by transparent, deterministic Python security rules, explainable risk scoring, and multi-tier AI orchestration (Google Gemini primary, Groq automatic fallback, and deterministic rule-grounded offline templates).

---

## Table of Contents
1. [Core Architecture & Product Principles](#1-core-architecture--product-principles)
2. [Advanced Security & Mission Capabilities](#2-advanced-security--mission-capabilities)
3. [The 10-Node LangGraph Pipeline](#3-the-10-node-langgraph-pipeline)
4. [Product Pages & Control Tower Views](#4-product-pages--control-tower-views)
5. [API Endpoints Reference](#5-api-endpoints-reference)
6. [Configuration & Environment Variables](#6-configuration--environment-variables)
7. [Installation & Setup Instructions](#7-installation--setup-instructions)
8. [Cloud Deployment Guide (Render + Vercel)](#8-cloud-deployment-guide-render--vercel)
9. [Automated Test Suite & Evaluation Results](#9-automated-test-suite--evaluation-results)
10. [Limitations & Scope of Analysis](#10-limitations--scope-of-analysis)

---

## 1. Core Architecture & Product Principles

1. **Every finding must have supporting evidence:** Detections are generated solely by validated Python security rules. LLMs synthesize context but never invent facts.
2. **Deterministic Risk Scoring:** Configurable weights, correlated indicator damping, discrete component scoring (Email vs. Attachment), and granular 4-way sub-score breakdown.
3. **Multi-Tier AI Orchestration:**
   - **Primary:** Google Gemini (1.5 Flash / Flash Latest)
   - **Automatic Fallback:** Groq (Llama-3.3-70b-versatile / GPT-OSS) on HTTP 429 rate limits or network issues.
   - **Offline Deterministic Fallback:** Pure Python rule templates if both providers fail or API keys are omitted.
4. **Authoritative Evidence Validation:** An automated validator cross-checks all LLM claims against known rule IDs; hallucinated or unsupported claims are rejected.
5. **Air-Gapped Static Analysis:** **Zero network navigation.** Links are never clicked, remote resources are never fetched, and attachments are never executed or rendered.
6. **Honest Coverage Status:** Incomplete, unsupported, or encrypted inputs are explicitly marked as `UNKNOWN`, `UNSCANNED`, or `UNSUPPORTED`. Low scores never claim absolute safety.

---

## 2. Advanced Security & Mission Capabilities

### Victim View vs. Forensic Truth Mode (`VictimTruthView`)
- Side-by-side interactive comparison between the recipient's deceptive inbox perspective and verified forensic reality.
- Identifies display name spoofing, reply-to redirection, lookalike homograph URLs, RTLO Unicode masking, and binary MIME inconsistencies.

### Visual Attack Story Timeline (`AttackTimeline`)
- Maps observed evidence chronologically across the 4 canonical ATT&CK progression stages: **Lure** $\rightarrow$ **Deception** $\rightarrow$ **Delivery** $\rightarrow$ **Action**.
- Correlates findings to MITRE ATT&CK techniques (`T1036`, `T1204`, `T1566`, `T1566.001`, `T1566.002`, `T1027`).
- Interactive rule chips smoothly scroll and highlight matching records directly in the Authoritative Evidence Table.

### Granular 4-Way Risk Breakdown (Mission #03)
Provides discrete, transparent forensic scores across all 4 key attack vectors:
- **Header & Sender Auth Risk (0–100):** SPF/DKIM/DMARC verdicts, Return-Path, and Reply-To consistency.
- **Body & Urgency Language Risk (0–100):** Coercive deadlines, fear appeals, and credential harvesting patterns.
- **Link & Domain Risk (0–100):** Deceptive subdomains, punycode homoglyphs, and IP literals.
- **Attachment & Payload Risk (0–100):** Executable magic bytes, RTLO masking, double extensions, and macros.

### Independent Attachment Report Cards (Mission #03)
- Dedicated forensic cards for every uploaded or embedded attachment.
- Computes SHA-256 hashes, file sizes, verified magic byte MIME types vs. declared types, RTLO presence, and actionable security recommendations (e.g., immediate quarantine for disguised executables).

### Analyst Classification Feedback System (Mission #03)
- Human-in-the-loop review feedback submission (`agree`, `disagree`, `suggested_rating`, notes, confidence level).
- Built-in duplicate protection and tenant scoping stored persistently in MongoDB Atlas.

### In-Memory QR Code & Quishing Detection (`qr_analyzer`)
- Detects 2D barcodes in image attachments (`PNG`, `JPEG`, `GIF` verified strictly by magic bytes).
- Strict in-memory safety limits: Max 5 MB per image, max $4000\times 4000\text{ px}$ parsed from headers **before** decoding, and a cap of 3 images per email.
- Decoded URLs are routed through `URLAnalyzer` without making remote network calls; user-facing URLs are strictly defanged (`hxxps://`, `[.]`).

### Executive Forensic PDF Dossier Export
- Client-side high-fidelity PDF generation with styled threat gauges, forensic metadata, attack progression, and evidence breakdown for executive presentations.

---

## 3. The 10-Node LangGraph Pipeline

The investigation lifecycle executes across 10 explicit LangGraph nodes with full execution tracing and SSE streaming:

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
7. calculate_risk        ──► Deterministic math engine (email_score, attachment_score, 4-way breakdown)
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
| **1. Overview Dashboard** | `/` or `/overview` | Real-time session telemetry, threat counters, MongoDB Atlas connection status, provider status pills, and recent investigation feed. |
| **2. New Investigation** | `/investigate` | Multi-vector intake supporting plain text, `.eml` uploads, URL static scan, attachment upload, and 1-click synthetic test fixtures. |
| **3. Investigation Results** | `/investigations/[id]` | Full dossier: risk gauges, 4-way breakdown, attachment report cards, Victim vs Truth view, Attack Timeline, AI synthesis, and PDF export. |
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

### Investigations & Analysis (`/api`)
- `POST /api/analyze` — Intake raw text, `.eml`, URL, or attachment for full pipeline processing.
- `POST /api/analyze/stream` — Real-time Server-Sent Events (SSE) stream broadcasting node-by-node execution events.
- `POST /api/analyze/json` — JSON payload analysis endpoint.
- `GET /api/investigations` — Retrieve paginated investigations scoped to the authenticated tenant.
- `GET /api/investigations/{id}` — Fetch complete investigation dossier and findings.
- `PATCH /api/investigations/{id}/review` — Commit human triage status and review notes.
- `POST /api/investigations/{id}/feedback` — Submit analyst classification feedback (Mission #03).
- `GET /api/investigations/{id}/feedback` — Retrieve feedback history for an investigation.
- `GET /api/investigations/{id}/export/{format}` — Download investigation in Markdown, CSV, or JSON format.
- `GET /api/health` — Service readiness, MongoDB Atlas connection latency, and version check.
- `GET /api/providers/status` — Live health check for Gemini, Groq, and fallback pipelines.

---

## 6. Configuration & Environment Variables

Templates are provided in [`backend/.env.example`](backend/.env.example) and [`frontend/.env.example`](frontend/.env.example).

### Backend (`backend/.env`)
```ini
# LLM Provider Configuration
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-flash-latest
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b
PRIMARY_LLM_PROVIDER=gemini

# MongoDB Database (Atlas Cloud or Local)
MONGODB_URI=mongodb+srv://<username>:<password>@cluster0.mongodb.net/?retryWrites=true&w=majority
MONGODB_DATABASE=phishguard_ai

# JWT Authentication & Session Security
JWT_SECRET=replace-with-a-very-strong-random-secret-key-at-least-32-chars
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=1440
COOKIE_NAME=phishguard_session
COOKIE_SECURE=false      # Set to true in production with HTTPS
COOKIE_SAMESITE=lax

# Server Configuration & CORS
ENV=development          # Set to production on Render
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001
MAX_UPLOAD_BYTES=10485760
MAX_ATTACHMENT_SIZE_BYTES=5242880
REQUEST_TIMEOUT_SECONDS=30
FEATURE_INSIGHTS=true
FEATURE_QR=true
```

### Frontend (`frontend/.env.local`)
```ini
# Local Development:
NEXT_PUBLIC_API_URL=http://127.0.0.1:8000
BACKEND_URL=http://127.0.0.1:8000

# Production Deployment (e.g. Vercel pointing to Render):
# NEXT_PUBLIC_API_URL=https://<your-render-service>.onrender.com
# BACKEND_URL=https://<your-render-service>.onrender.com
```

---

## 7. Installation & Setup Instructions

### Prerequisites
- **Python:** 3.11+ (Python 3.11.9 recommended)
- **Node.js:** 18.x or 20.x LTS
- **MongoDB:** MongoDB Atlas cloud cluster (recommended) or local MongoDB instance

### Step 1: Clone the Repository
```bash
git clone https://github.com/charan-dss-01/missionathon.git
cd missionathon
```

### Step 2: Set Up Backend
```bash
cd backend
python -m venv venv

# Windows:
venv\Scripts\activate
# macOS / Linux:
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env   # Configure your MONGODB_URI and API keys
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
*The backend API will be available at `http://127.0.0.1:8000` (Interactive docs: `http://127.0.0.1:8000/docs`).*

### Step 3: Set Up Frontend
```bash
cd ../frontend
npm install
npm run dev
```
*The frontend will be available at `http://localhost:3000` (or `http://localhost:3001`).*

---

## 8. Cloud Deployment Guide (Render + Vercel)

### Backend Deployment on Render (FastAPI)
1. In the [Render Dashboard](https://dashboard.render.com/), create a new **Web Service**.
2. Connect your GitHub repository.
3. Set the following build and runtime settings:
   - **Root Directory:** `backend`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Add the required Environment Variables (`MONGODB_URI`, `JWT_SECRET`, `ENV=production`, `PYTHON_VERSION=3.11.9`, `GEMINI_API_KEY`, `GROQ_API_KEY`).
5. Deploy and note your live URL (e.g., `https://your-backend.onrender.com`).

### Frontend Deployment on Vercel (Next.js)
1. In the [Vercel Dashboard](https://vercel.com/dashboard), import your GitHub repository.
2. Set **Root Directory** to `frontend`.
3. Add Environment Variables:
   - `NEXT_PUBLIC_API_URL` = `https://your-backend.onrender.com`
   - `BACKEND_URL` = `https://your-backend.onrender.com`
4. Click **Deploy**. Vercel will build all routes and connect to your Render backend.

---

## 9. Automated Test Suite & Evaluation Results

The backend contains **84 automated test cases with a 100% pass rate**:

```bash
cd backend
venv\Scripts\pytest tests/ -v
```

```
============================= 84 passed in 10.47s =============================
```

### Test Suite Summary
- `test_analyzers.py` (22 tests) — Header, body, URL, and attachment rule unit testing.
- `test_mission_03_features.py` (9 tests) — 4-way risk breakdown, attachment report cards, and classification feedback.
- `test_fixtures.py` (8 tests) — Baseline snapshot scoring invariants and realistic email/attachment fixtures.
- `test_qr.py` (7 tests) — Quishing barcode detection, flagged URLs, benign QR codes, and memory guards.
- `test_defang.py` (7 tests) — URL defanging idempotence across IP literals, schemes, and subdomains.
- `test_api.py` (7 tests) — REST endpoints, live SSE streaming, stream replay, and triage review updates.
- `test_rule_metadata.py` (6 tests) — Presentation descriptions, stages, and MITRE ATT&CK coverage.
- `test_insights.py` (5 tests) — Victim vs Truth deceptions, clue locators, and attack timeline assembly.
- `test_risk_engine.py` (4 tests) — Deterministic scoring bounds, component weights, and coverage flags.
- `test_auth.py` (3 tests) — Registration, login, JWT validation, and multi-tenant data isolation.
- `test_fallback.py` (3 tests) — Sensitive data redaction, Groq failover, and offline rule-grounded fallback.
- `test_validator.py` (2 tests) — Suppression of hallucinated LLM claims.
- `test_no_network.py` (1 test) — Strict unit test sandbox enforcing zero external socket or DNS egress.

*For detailed test data fixtures, evaluation methodology, and performance benchmarks, refer to [`EVALUATION.md`](EVALUATION.md).*

---

## 10. Limitations & Scope of Analysis

- **Air-Gapped Static Analysis Only:** PhishGuard AI does not detonate files or execute binaries in dynamic sandboxes. Executable files are detected via magic bytes, RTLO markers, double extensions, and PE headers.
- **Syntactic URL Inspection:** Links are inspected syntactically and defanged. The platform does not perform HTTP navigation to external landing pages.
- **Encrypted Archives:** Password-protected archives (`.zip`, `.rar`, `.7z`) and encrypted PDFs cannot be opened without credentials and are explicitly marked as `UNSUPPORTED` / `UNSCANNED`.
- **Analyst-in-the-Loop:** Risk scores and AI syntheses provide decision support; final quarantine and disposition actions remain in human analyst control via `/queue`.

---

## License & Attribution

Built for the **Missionathon Cyber Defense Hackathon 2026**.
Developed with FastAPI, LangGraph, Next.js, and MongoDB Atlas.
