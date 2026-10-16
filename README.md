# PhishGuard AI — Agentic Cyber Investigation Platform

[![Next.js](https://img.shields.io/badge/Frontend-Next.js%2014-black?logo=next.js)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/Workflow-LangGraph-FF6F00)](https://langchain-ai.github.io/langgraph/)
[![TailwindCSS](https://img.shields.io/badge/Design-TailwindCSS-38B2AC?logo=tailwind-css)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/Security-Air--Gapped%20Static-blue)](#security-and-privacy)

**PhishGuard AI** is a production-grade 24-hour hackathon MVP built for Tier-2 and Tier-3 Security Operations Center (SOC) analysts. It performs deep, multi-vector static analysis of suspicious email text, `.eml` files, hyperlinks, and attachments. Every finding is backed by transparent, deterministic Python security rules, explainable risk scoring, and multi-tier AI orchestration (Gemini primary, Groq automatic fallback, and deterministic rule-grounded offline templates).

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

## 2. The 10-Node LangGraph Pipeline

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
5. analyze_attachments   ──► Safe byte inspection: magic signatures, RTLO (\u202e), double exts, macros, active scripts
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

---

## 3. Product Pages & Control Tower Views

| Page | Route | Description |
| :--- | :--- | :--- |
| **1. Overview Dashboard** | `/` | Real-time session telemetry, threat counters, MongoDB Atlas connection status, provider status pills, and recent investigation feed. |
| **2. New Investigation** | `/investigate` | Multi-vector intake supporting pasted plain text, `.eml` uploads, URL static scan, attachment upload, and 1-click synthetic test fixtures. Includes fallback simulation toggles. |
| **3. Investigation Results** | `/investigations/[id]` | Full investigation dossier: risk gauges, email vs attachment breakdown, AI synthesis, evidence table, header telemetry, and export buttons. |
| **4. Agent Orchestration** | `/trace` | Connected LangGraph DAG timeline with node execution states, duration in milliseconds, logs, and payload inspectors. |
| **5. Investigation History** | `/history` | Full searchable and filterable session audit log with instant export downloads, filtered strictly to the authenticated tenant. |
| **6. Human Review Queue** | `/queue` | Master-detail SOC triage board with status transitions (`NEW`, `IN_REVIEW`, `RESOLVED_MALICIOUS`, `RESOLVED_BENIGN`) and analyst notes. |
| **7. Reports & Export** | `/reports` | Export hub for generating Markdown dossiers, structured CSV data, and JSON exports with privacy disclaimers. |
| **8. SOC Analyst Login** | `/login` | Secure JWT/HTTP-only cookie authentication with rate limiting and audit logging. |
| **9. Analyst Registration** | `/register` | Tenant onboarding with real-time password strength validation and bcrypt salting. |
| **10. Account Security** | `/settings/security` | Analyst profile details, password rotation, audit event metadata, and MongoDB tenant isolation specs. |

---

## 4. MongoDB Database & User Authentication Architecture

PhishGuard AI features an enterprise multi-tenant MongoDB layer with strict tenant isolation:

1. **Async Motor Driver:** Native non-blocking async I/O fully integrated into FastAPI's lifespan lifecycle.
2. **Atlas & Local Support:** Seamlessly connects to MongoDB Atlas clusters via `mongodb+srv://` or local MongoDB instances.
3. **Database Collections & Indexes:**
   - `users`: Unique index on normalized `email`. Stores user ID, name, bcrypt password hash (cost factor 12), role (`user`/`admin`), and login timestamps.
   - `investigations`: Unique index on `id`, compound index on `(owner_id, created_at)`.
   - `audit_events`: Indexed by `created_at` and `user_id`. Tracks `REGISTER_SUCCESS`, `LOGIN_SUCCESS`, `LOGIN_FAILED`, `PASSWORD_CHANGE`, and `LOGOUT`.
4. **Multi-Tenant Isolation:** Every investigation is tagged with `owner_id`. Backend endpoints (`GET /api/investigations/{id}`, `/trace`, `/review`, `/export`) enforce ownership and strictly return `403 Forbidden` if an unauthorized user attempts access.
5. **Session Security:** Issues signed HS256 JWT tokens transmitted via secure HTTP-only cookies (`phishguard_session`) with `SameSite=Lax` and optional `Authorization: Bearer` fallback. Passwords are never stored in plaintext and never returned in API payloads.

---

## 5. Visual Design Direction

Inspired by high-performance cyber command centers (Obsidian `#080B10`, Layered Panels `#101720`, Cyan Highlights `#4DEBFF`, Acid-Lime Accents `#C7FF5E`, and Alert Crimson `#FF5364`). Features subtle borders, restrained glass effects, and accessible responsive layouts.

---

## 6. Quickstart & Installation

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- MongoDB Atlas cluster URI OR local MongoDB instance running on `127.0.0.1:27017`

### 1. Backend Setup
```bash
cd backend

# Create and activate virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template and fill in keys
cp .env.example .env

# Run automated test suite (33 tests)
pytest -v

# Start FastAPI backend (port 8000)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Frontend Setup
```bash
cd frontend

# Install dependencies
npm install

# Run production build or development server
npm run build
npm run dev -- -p 3001
```

Visit `http://localhost:3001` (or `http://localhost:3000`) in your browser.

---

## 7. Environment Variables Reference

### Backend (`backend/.env`)
```ini
# LLM Orchestration
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-flash-latest
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b
PRIMARY_LLM_PROVIDER=gemini

# MongoDB Atlas / Local Database
MONGODB_URI=mongodb://127.0.0.1:27017
MONGODB_DATABASE=phishguard_ai

# JWT Authentication & Cookie Security
JWT_SECRET=replace-with-a-very-strong-random-secret-key-at-least-32-chars
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
COOKIE_NAME=phishguard_session
COOKIE_SECURE=false
COOKIE_SAMESITE=lax

# Server Configuration
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001
MAX_UPLOAD_BYTES=10485760
REQUEST_TIMEOUT_SECONDS=30
```

*Note: If no LLM keys are configured, PhishGuard automatically falls back to deterministic rule scoring and template synthesis without downtime.*


*Note: If no API keys are provided, PhishGuard automatically executes the deterministic rule engine and rule-grounded template synthesis without failing!*

### Frontend (`frontend/.env.local`)
```ini
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## 7. Running Tests & Verifying Fixtures

The backend includes 30 automated test cases covering analyzers, risk math, failover logic, evidence validation, and realistic synthetic fixtures:

```bash
cd backend
venv\Scripts\pytest -v
```

Test categories:
- `test_analyzers.py`: Validates header, body, URL, and attachment rules (RTLO, double extension, magic bytes, macro detection).
- `test_risk_engine.py`: Tests deterministic weights, component score calculation, and coverage flags.
- `test_fallback.py`: Tests sensitive data redaction, Groq failover, and offline rule fallback.
- `test_validator.py`: Verifies rejection of hallucinated claims.
- `test_fixtures.py`: Validates synthetic `.eml` and attachment fixtures end-to-end.
- `test_api.py`: Validates REST API endpoints (`/api/health`, `/api/providers/status`, `/api/analyze`, exports).

---

## 8. Demo Walkthrough for Evaluators

1. **Dashboard (`/`):** View live metrics, active provider telemetry, and seeded demo investigations.
2. **Run New Scan (`/investigate`):**
   - Click one of the **Synthetic Test Fixtures** (e.g. *Phishing: M365 Credential Theft*).
   - Check the **"Simulate Gemini 429 / Failover to Groq"** checkbox to observe automatic failover.
   - Click **Run Investigation**.
3. **Inspect Dossier (`/investigations/[id]`):**
   - Review overall risk score (e.g. 95/100 HIGH).
   - Review component attack vectors (Email vs. Attachment).
   - Read the AI synthesis with validated evidence IDs and actionable SOC recommendations.
   - Explore the **Authoritative Evidence Table** detailing rule IDs and exact text observations.
   - Switch to the **LangGraph Execution Trace** tab to view actual execution durations for each node.
4. **Human Review Queue (`/queue`):**
   - Triage cases between `NEW`, `IN_REVIEW`, `RESOLVED_MALICIOUS`, and `RESOLVED_BENIGN`.
   - Add analyst case notes and click **Commit Triage Decision**.
5. **Export (`/reports`):**
   - Download the investigation dossier in **Markdown**, **CSV**, or **JSON** format.

---

## 9. Security & Privacy Guarantees

- **No Remote Navigation:** URLs are analyzed syntactically without DNS resolution or HTTP requests.
- **Zero Execution:** File attachments are analyzed purely through bounded magic bytes and central directory tables.
- **PII Redaction:** Credit card numbers, bearer tokens, passwords, and SSNs are stripped before external LLM transmission.
- **No Persistence of Secrets:** API keys are server-side only and never transmitted to the browser.
- **Bounded Resource Limits:** Uploads are strictly capped at 10 MB (5 MB per attachment) to protect against memory exhaustion attacks.
