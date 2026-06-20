# 🛡️ PII Shield — Automated PII Detection & Sanitization System

> Built for **HACKaMINeD Track Hackathon** | FastAPI · Streamlit · spaCy · SQLite · JWT

A full-stack application that automatically **detects and sanitizes Personally Identifiable Information (PII)** from multiple file formats — including SQL dumps, PDFs, DOCX, CSV, JSON, and plain text. Designed with enterprise-grade security practices: role-based access control, file encryption at rest, tamper-resistant audit logs, and a hybrid NLP + regex detection engine.

---


## 🚀 Quick Start (One Click)

Double-click to launch the entire system automatically:

```
start_backend.bat    ← Starts FastAPI backend on http://localhost:8000
start_frontend.bat   ← Starts Streamlit frontend on http://localhost:8501
```

**Default admin credentials:**
- Username: `admin`
- Password: `admin123`

---

## ✨ Features

### 🔍 Hybrid PII Detection Engine
- **Regex-based detection** for structured patterns (Aadhaar, PAN, email, credit card, IP, phone, DOB)
- **NLP/NER-based detection** using spaCy for unstructured person names and contextual entities
- **India-specific patterns** — Aadhaar (12-digit), PAN (ABCDE1234F), Indian mobile numbers
- **Confidence scoring** per entity with detection method tracking

### 🧹 Three Sanitization Modes
| Mode | Example Input | Example Output |
|---|---|---|
| **Mask** | `john@gmail.com` | `j***@gmail.com` |
| **Redact** | `9876543210` | `[REDACTED_PHONE]` |
| **Tokenize** | `ABCDE1234F` | `[TOK_A3F9C2]` (stable HMAC token) |

### 📁 Supported File Formats
- SQL dumps (`.sql`) — parses INSERT statements and string literals
- PDFs (`.pdf`) — text extraction via PyMuPDF
- Word Documents (`.docx`) — paragraph and table scanning via python-docx
- Plain Text (`.txt`), CSV (`.csv`), JSON (`.json`)

### 🔐 Security Architecture
- **JWT Authentication** — HS256 tokens with 1-hour expiry
- **bcrypt Password Hashing** — 12 rounds with salt
- **Fernet Symmetric Encryption** — all uploaded files encrypted at rest
- **RBAC** — Admin and Standard User roles with strict endpoint guards
- **Tamper-Resistant Audit Logs** — append-only, no raw PII stored, includes file hash + IP + user agent

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     Streamlit Frontend                       │
│               (http://localhost:8501)                        │
│    Login → Upload → View Results → Download Sanitized File   │
└──────────────────────┬───────────────────────────────────────┘
                       │ REST API (JWT Bearer Token)
┌──────────────────────▼───────────────────────────────────────┐
│                   FastAPI Backend                            │
│               (http://localhost:8000)                        │
│                                                              │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│   │  /auth   │  │  /files  │  │  /admin  │  │/analysis │   │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│        │              │              │              │         │
│   ┌────▼──────────────▼──────────────▼──────────────▼────┐   │
│   │              Services Layer                          │   │
│   │  ┌─────────────────┐   ┌─────────────────────────┐  │   │
│   │  │  PII Detector   │   │   Sanitizer (Base ABC)  │  │   │
│   │  │  - RegexEngine  │   │   - TextSanitizer       │  │   │
│   │  │  - spaCy NER    │   │   - PDFSanitizer        │  │   │
│   │  └─────────────────┘   │   - DOCXSanitizer       │  │   │
│   │                        │   - SQLSanitizer        │  │   │
│   │  ┌─────────────────┐   └─────────────────────────┘  │   │
│   │  │  Audit Service  │                                  │   │
│   │  │  (append-only)  │   ┌─────────────────────────┐  │   │
│   │  └─────────────────┘   │   File Storage + Fernet  │  │   │
│   │                        │   Encryption at Rest     │  │   │
│   │                        └─────────────────────────┘  │   │
│   └──────────────────────────────────────────────────────┘   │
│                                                              │
│   ┌──────────────────────────────────────────────────────┐   │
│   │         SQLAlchemy ORM → SQLite Database             │   │
│   │   Users · FileRecords · AuditLogs                    │   │
│   └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Structure

```
PII-Detection-System/
│
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app entry point, startup hooks, CORS
│   │   ├── config.py            # Pydantic settings, env vars, directory setup
│   │   ├── database.py          # SQLAlchemy engine, session factory, Base
│   │   │
│   │   ├── models/              # ORM Models (SQLAlchemy)
│   │   │   ├── user.py          # User model with role enum (ADMIN/STANDARD)
│   │   │   ├── file.py          # FileRecord model (original + sanitized paths)
│   │   │   └── audit_log.py     # AuditLog model (event type, user, file, PII counts)
│   │   │
│   │   ├── routers/             # API Route Handlers
│   │   │   ├── auth.py          # /auth/login, /auth/register, /auth/me
│   │   │   ├── files.py         # /files/upload, /files/{id}/download, /files/{id}/preview
│   │   │   ├── admin.py         # /admin/users, /admin/audit-logs, /admin/stats
│   │   │   └── analysis.py      # /analysis — PII analysis without saving files
│   │   │
│   │   ├── services/            # Core Business Logic
│   │   │   ├── pii_detector.py  # Hybrid detection engine (regex + spaCy NER)
│   │   │   ├── audit_service.py # Audit log creation and querying
│   │   │   └── sanitizers/      # Format-specific sanitization implementations
│   │   │       ├── base.py          # Abstract base class (mask/redact/tokenize logic)
│   │   │       ├── text_sanitizer.py
│   │   │       ├── pdf_sanitizer.py    # PyMuPDF-based PDF sanitization
│   │   │       ├── docx_sanitizer.py   # python-docx paragraph + table scanning
│   │   │       └── sql_sanitizer.py    # sqlparse-based SQL sanitization
│   │   │
│   │   └── utils/
│   │       ├── security.py      # JWT, bcrypt, Fernet encryption helpers
│   │       └── file_storage.py  # Encrypted file I/O, path resolution
│   │
│   ├── tests/
│   │   ├── test_detectors.py    # Unit tests for all regex + NER patterns
│   │   ├── test_sanitizers.py   # Sanitization mode tests
│   │   ├── test_rbac.py         # Role-based access control tests
│   │   └── test_audit.py        # Audit log integrity tests
│   │
│   ├── requirements.txt
│   └── pytest.ini
│
├── frontend/
│   ├── app.py                   # Full Streamlit UI (login, upload, dashboard, admin panel)
│   └── requirements.txt
│
├── samples/                     # Test files with embedded PII
│   ├── sample_data.sql          # SQL dump with employee/customer data
│   ├── sample_document.pdf      # PDF with personal information
│   ├── sample_document.txt      # Plain text with customer records
│   ├── generate_samples.py      # Script to regenerate sample files
│   └── create_binary_samples.py # Script to create binary test samples
│
├── start_backend.bat            # One-click Windows launcher (backend)
├── start_frontend.bat           # One-click Windows launcher (frontend)
└── README.md
```

---

## 🔬 What Each File Does

### Backend Core

| File | Purpose |
|---|---|
| `main.py` | FastAPI app setup, CORS config, router registration, startup hook to seed default admin |
| `config.py` | Reads env vars via Pydantic Settings — SECRET_KEY, DATABASE_URL, UPLOAD_DIR, etc. |
| `database.py` | Creates SQLAlchemy engine and `SessionLocal`, imports `Base` for ORM migrations |

### Models

| Model | Key Fields |
|---|---|
| `user.py` | `username`, `email`, `hashed_password`, `role` (ADMIN/STANDARD), `is_active` |
| `file.py` | `original_path`, `sanitized_path`, `file_type`, `pii_count`, `sanitization_mode` |
| `audit_log.py` | `event_type`, `username`, `user_role`, `entity_counts` (JSON), `file_hash`, `ip_address` |

### Routers (API Layer)

| Router | Endpoints |
|---|---|
| `auth.py` | POST `/auth/login`, POST `/auth/register` (admin only), GET `/auth/me` |
| `files.py` | POST `/files/upload`, GET `/files/`, GET `/files/{id}/download`, GET `/files/{id}/preview` |
| `admin.py` | CRUD `/admin/users`, GET `/admin/audit-logs`, GET `/admin/stats` |
| `analysis.py` | POST `/analysis` — analyze PII without storing file (preview mode) |

### Services (Business Logic)

**`pii_detector.py`** — The heart of the system:
- `RegexDetectors` class holds compiled regex patterns for Email, Phone, Aadhaar, PAN, IP, Credit Card, DOB, Passport, Bank Account
- `NERDetector` class wraps spaCy's `en_core_web_sm` model for PERSON/ORG/GPE entities
- `PIIDetectionEngine` merges both, deduplicates overlapping spans, returns a list of `PIIDetection` dataclasses with `entity_type`, `confidence`, `detection_method`

**`sanitizers/base.py`** — Abstract `BaseSanitizer`:
- `mask()` — entity-aware partial masking (e.g. email: `j***@domain.com`, phone: `******3210`)
- `redact()` — full replacement with label (e.g. `[REDACTED_EMAIL]`)
- `tokenize()` — stable HMAC-SHA256 token (same input always gives same token within a session)

**`audit_service.py`** — Logs every action (upload, download, login, user creation) to DB without storing any raw PII. Entity counts stored as JSON (`{"EMAIL": 3, "PHONE": 2}`).

### Utils

| File | Purpose |
|---|---|
| `security.py` | `create_access_token()`, `verify_token()`, `get_password_hash()`, `verify_password()`, Fernet key derivation |
| `file_storage.py` | `save_encrypted_file()`, `read_encrypted_file()`, `get_secure_path()` — wraps all file I/O with Fernet encryption |

---

## 🧰 Tech Stack

| Layer | Technology | Why |
|---|---|---|
| **Backend API** | FastAPI 0.109 | Async support, automatic OpenAPI docs, Pydantic validation |
| **Frontend** | Streamlit | Rapid UI prototyping, Python-native, ideal for hackathons |
| **Database** | SQLite + SQLAlchemy ORM | Zero-config setup, easy to swap to PostgreSQL |
| **PII Detection** | Custom Regex + spaCy `en_core_web_sm` | Regex for structured patterns, NER for unstructured names |
| **PDF Processing** | PyMuPDF (fitz) | Fast, reliable text extraction from PDFs |
| **DOCX Processing** | python-docx | Paragraph + table traversal |
| **SQL Parsing** | sqlparse | Tokenizes SQL to safely identify and replace string literals |
| **Authentication** | JWT (python-jose) + bcrypt (passlib) | Industry-standard stateless auth + secure password hashing |
| **Encryption** | Fernet (cryptography lib) | Symmetric AES-128-CBC + HMAC — simple, secure at-rest encryption |
| **Testing** | pytest + httpx | Fast async-compatible test suite |

---

## 🔐 PII Entities Detected

| Entity | Method | Example |
|---|---|---|
| Email | Regex | `john@example.com` |
| Indian Mobile | Regex | `+91-9876543210` |
| Aadhaar Number | Regex | `1234 5678 9012` |
| PAN Number | Regex | `ABCDE1234F` |
| Credit Card | Regex | `4111 1111 1111 1111` |
| IPv4 Address | Regex | `192.168.1.1` |
| Date of Birth | Regex | `14/03/1992`, `1992-03-14` |
| Passport Number | Regex | `A1234567` |
| Bank Account | Regex | `123456789012` |
| Person Name | spaCy NER | `Rahul Sharma` |

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.8+
- pip

### 1. Clone the repository

```bash
git clone https://github.com/Krishhh2410/PII-Detection-System.git
cd PII-Detection-System
```

### 2. Backend setup

```bash
cd backend
pip install -r requirements.txt

# Download spaCy NER model (required for person name detection)
python -m spacy download en_core_web_sm
```

### 3. Configure environment (optional)

Create a `.env` file in the `backend/` directory:

```env
SECRET_KEY=your-secret-key-min-32-chars
JWT_SECRET_KEY=your-jwt-secret-key-min-32-chars
DATABASE_URL=sqlite:///./pii_system.db
UPLOAD_DIR=./uploads
SANITIZED_DIR=./sanitized
ENCRYPTION_KEY=your-encryption-key-32-bytes
ACCESS_TOKEN_EXPIRE_MINUTES=60
MAX_FILE_SIZE=52428800
```

> If no `.env` is provided, the system uses secure auto-generated defaults for local development.

### 4. Frontend setup

```bash
cd ../frontend
pip install -r requirements.txt
```

### 5. Run the application

**Terminal 1 — Backend:**
```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 — Frontend:**
```bash
cd frontend
streamlit run app.py
```

- Backend API: http://localhost:8000
- Swagger Docs: http://localhost:8000/docs
- Frontend UI: http://localhost:8501

### Default Credentials
| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `admin123` |

---

## 🧪 Running Tests

```bash
cd backend
pytest
```

| Test File | What It Covers |
|---|---|
| `test_detectors.py` | All regex patterns + NER detection accuracy |
| `test_sanitizers.py` | Mask / Redact / Tokenize across all modes |
| `test_rbac.py` | Admin vs Standard user endpoint access |
| `test_audit.py` | Audit log creation, integrity, no-PII-in-logs |

---

## 📖 API Reference

### Auth
```
POST /auth/login           → Returns JWT token
POST /auth/register        → Create user (Admin only)
GET  /auth/me              → Get current user profile
```

### Files
```
POST /files/upload         → Upload + process file (Admin only)
GET  /files/               → List accessible files
GET  /files/{id}/download  → Download sanitized file
GET  /files/{id}/original  → Download original (Admin only)
GET  /files/{id}/preview   → Preview sanitized content
```

### Admin
```
GET    /admin/users        → List all users
POST   /admin/users        → Create user
PUT    /admin/users/{id}   → Update user
DELETE /admin/users/{id}   → Deactivate user
GET    /admin/audit-logs   → View full audit trail
GET    /admin/stats        → System statistics (file count, PII totals)
```

---

## 🚧 Known Limitations & Future Improvements

- [ ] **Image OCR**: Scanned PDFs and image files not yet supported (Tesseract integration planned)
- [ ] **Larger NLP Models**: spaCy `en_core_web_sm` used for speed; `en_core_web_trf` (transformer-based) would improve name detection accuracy
- [ ] **PostgreSQL Support**: SQLite used for simplicity; production deployment should use PostgreSQL
- [ ] **Async Task Queue**: Large file processing should be offloaded to Celery/Redis
- [ ] **Docker Compose**: Containerized deployment not yet included
- [ ] **Hindi/Regional PII**: Aadhaar/PAN patterns exist; regional language name NER not yet supported

---

## 👥 Team

Built at **HACKaMINeD Track Hackathon**

- [Krish](https://github.com/Krishhh2410)




## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🌟 If you found this useful, please star the repo!
