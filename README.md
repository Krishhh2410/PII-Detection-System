# PII Detection & Sanitization System

A full-stack application for automatically detecting and sanitizing Personally Identifiable Information (PII) from multiple file formats including SQL dumps, PDFs, and DOCX files. Built for the HACKaMINeD Track hackathon.

## 🚀 QUICK START - ONE CLICK LAUNCH

**Double-click either of these files to start the entire system automatically:**

1. `start_backend.bat` - Main launcher (recommended)
2. `start_frontend.bat` - Alternative launcher

**What happens automatically:**
- ✅ Backend server starts on http://localhost:8000
- ✅ Frontend starts on http://localhost:8501
- ✅ Browser opens automatically
- ✅ Admin account created: admin / admin123

**No command line needed!**

## Features

### Core Features
- **Multi-format Support**: Process SQL dumps, PDFs, DOCX, CSV, JSON, and TXT files
- **Hybrid PII Detection**: Combines regex-based and NLP/NER-based detection
- **Multiple Sanitization Modes**: Mask, Redact, or Tokenize detected PII
- **Role-Based Access Control (RBAC)**: Admin and Standard user roles
- **Audit Logging**: Comprehensive, tamper-resistant audit trails
- **Encryption at Rest**: All files encrypted using Fernet symmetric encryption

### PII Entities Detected
- Email addresses
- Phone numbers (India-focused + international)
- Aadhaar numbers (12-digit Indian ID)
- PAN numbers (Indian tax ID)
- IP addresses (IPv4)
- Credit card numbers
- Person names (via NLP)
- Dates of birth

### Sanitization Modes
1. **Mask**: Partial replacement (e.g., `j***@email.com`, `******3210`)
2. **Redact**: Full replacement with entity type (e.g., `[REDACTED_EMAIL]`)
3. **Tokenize**: Stable HMAC-based tokens (e.g., `[TOK_ABC123]`)

## Tech Stack

- **Backend**: FastAPI, SQLAlchemy, SQLite
- **Frontend**: Streamlit
- **Security**: JWT authentication, bcrypt password hashing, Fernet encryption
- **PII Detection**: Custom regex patterns + spaCy NER
- **Document Processing**: PyMuPDF (PDF), python-docx (DOCX), sqlparse (SQL)

## Project Structure

```
.
├── backend/
│   ├── app/
│   │   ├── models/          # Database models (User, FileRecord, AuditLog)
│   │   ├── routers/         # API endpoints (auth, files, admin)
│   │   ├── services/        # Business logic (PII detection, sanitization)
│   │   ├── utils/           # Security and file storage utilities
│   │   ├── config.py        # Configuration settings
│   │   ├── database.py      # SQLAlchemy setup
│   │   └── main.py          # FastAPI application entry point
│   ├── tests/               # pytest test suite
│   ├── requirements.txt     # Python dependencies
│   └── pytest.ini          # pytest configuration
├── frontend/
│   ├── app.py              # Streamlit application
│   └── requirements.txt    # Frontend dependencies
├── samples/                # Sample files for testing
│   ├── sample_data.sql
│   ├── sample_document.pdf
│   └── sample_document.txt
└── README.md
```

## Quick Start

### Prerequisites
- Python 3.8+
- pip

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd pii-detection-system
```

2. Install backend dependencies:
```bash
cd backend
pip install -r requirements.txt
```

3. (Optional) Download spaCy model for NER:
```bash
python -m spacy download en_core_web_sm
```

4. Install frontend dependencies:
```bash
cd ../frontend
pip install -r requirements.txt
```

### Running the Application

1. Start the backend server:
```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`
API documentation: `http://localhost:8000/docs`

2. Start the frontend (in a new terminal):
```bash
cd frontend
streamlit run app.py
```

The UI will open in your browser at `http://localhost:8501`

### Default Credentials

On first startup, a default admin user is created:
- **Username**: `admin`
- **Password**: `admin123`

## Usage Guide

### Admin Workflow

1. **Login**: Use admin credentials to log in
2. **Upload Files**: 
   - Navigate to "Upload (Admin)" page
   - Select a file (SQL, PDF, DOCX, etc.)
   - Choose sanitization mode (Mask/Redact/Tokenize)
   - Upload and process
3. **View Results**: See detected PII counts and download sanitized files
4. **Manage Users**: Create standard users for restricted access
5. **View Audit Logs**: Monitor all system activities

### Standard User Workflow

1. **Login**: Use provided credentials
2. **View Files**: See list of sanitized files only
3. **Download**: Download sanitized files
4. **Preview**: View sanitized content preview

### Demo Script

```bash
# 1. Start the backend
cd backend
uvicorn app.main:app --reload

# 2. In another terminal, start the frontend
cd frontend
streamlit run app.py

# 3. Login with default admin credentials
#    Username: admin
#    Password: admin123

# 4. Create a standard user (Admin > Users > Create User)

# 5. Upload sample files from the samples/ directory
#    - Upload sample_data.sql
#    - Upload sample_document.pdf
#    - Try different sanitization modes

# 6. View the sanitized outputs and compare with originals

# 7. Check audit logs to see all activities logged

# 8. Login as standard user and verify:
#    - Can view sanitized files
#    - Cannot access original files
#    - Cannot upload files
```

## API Endpoints

### Authentication
- `POST /auth/login` - Login and get JWT token
- `POST /auth/register` - Create new user (admin only)
- `GET /auth/me` - Get current user info

### Files
- `POST /files/upload` - Upload and process file (admin only)
- `GET /files/` - List files
- `GET /files/{id}/download` - Download sanitized file
- `GET /files/{id}/original` - Download original file (admin only)
- `GET /files/{id}/preview` - Preview file content

### Admin
- `GET /admin/users` - List all users
- `POST /admin/users` - Create user
- `PUT /admin/users/{id}` - Update user
- `DELETE /admin/users/{id}` - Deactivate user
- `GET /admin/files` - List all files with details
- `GET /admin/audit-logs` - View audit logs
- `GET /admin/stats` - System statistics

## Testing

Run the test suite:

```bash
cd backend
pytest
```

### Test Coverage

- **test_detectors.py**: PII detection regex patterns and engine
- **test_sanitizers.py**: Sanitization modes (mask, redact, tokenize)
- **test_rbac.py**: Role-based access control
- **test_audit.py**: Audit logging functionality

## Security Features

1. **Authentication**: JWT tokens with 1-hour expiration
2. **Password Hashing**: bcrypt with salt
3. **File Encryption**: Fernet symmetric encryption at rest
4. **Access Control**: Role-based permissions
5. **Audit Logging**: Append-only logs with no raw PII
6. **Input Validation**: File type and size restrictions

## Sample Files

The `samples/` directory contains test files with embedded PII:

- **sample_data.sql**: SQL dump with employee and customer data
- **sample_document.pdf**: PDF with employee information
- **sample_document.txt**: Plain text with customer data

## Configuration

Environment variables (create `.env` file in backend directory):

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

## Limitations & Future Improvements

1. **NLP Model**: Currently uses spaCy small model; larger models may improve name detection
2. **Image OCR**: Tesseract OCR not yet implemented for image files
3. **PDF Processing**: Complex PDFs with images may not process perfectly
4. **Scalability**: SQLite is used for simplicity; PostgreSQL recommended for production
5. **Distributed Processing**: Large files could benefit from async task queues

## License

MIT License - See LICENSE file for details

## Contributors

Built for HACKaMINeD Track hackathon.
