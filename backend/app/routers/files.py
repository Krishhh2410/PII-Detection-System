import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import io

from app.database import get_db
from app.models.user import User
from app.models.file import FileRecord, ProcessingStatus
from app.routers.auth import get_current_active_user, get_current_admin
from app.utils.file_storage import (
    save_encrypted_file, 
    read_encrypted_file, 
    is_allowed_file, 
    get_file_type,
    get_file_size
)
from app.utils.security import generate_encryption_key_id, compute_file_hash
from app.services.pii_detector import detect_pii, detection_engine
from app.services.sanitizers.sql_sanitizer import SQLSanitizer
from app.services.sanitizers.pdf_sanitizer import PDFSanitizer
from app.services.sanitizers.docx_sanitizer import DOCXSanitizer
from app.services.sanitizers.text_sanitizer import TextSanitizer
from app.services.audit_service import AuditService
from app.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/files", tags=["files"])


# ==================== Pydantic Models ====================

from pydantic import BaseModel

class FileResponse(BaseModel):
    id: int
    filename: str
    original_filename: str
    file_type: str
    file_size: int
    status: str
    anonymization_mode: Optional[str]
    entity_counts: Optional[dict]
    created_at: str
    
    class Config:
        from_attributes = True


class ProcessingResult(BaseModel):
    file_id: int
    status: str
    entity_counts: dict
    total_entities: int
    message: str


# ==================== Helper Functions ====================

def extract_text_from_file(content: bytes, file_type: str) -> str:
    """Extract text from file based on type for PII detection."""
    if file_type == 'pdf':
        sanitizer = PDFSanitizer()
        return sanitizer.extract_text(content)
    elif file_type == 'docx':
        sanitizer = DOCXSanitizer()
        return sanitizer.extract_text(content)
    elif file_type in ['sql', 'txt', 'csv', 'json']:
        return content.decode('utf-8', errors='ignore')
    else:
        # Try to decode as text
        try:
            return content.decode('utf-8')
        except:
            return ""


def sanitize_file(content: bytes, file_type: str, detections: list, mode: str) -> bytes:
    """Sanitize file based on type."""
    if file_type == 'sql':
        sanitizer = SQLSanitizer(mode=mode)
        return sanitizer.sanitize(content, detections)
    elif file_type == 'pdf':
        sanitizer = PDFSanitizer(mode=mode)
        return sanitizer.sanitize(content, detections)
    elif file_type == 'docx':
        sanitizer = DOCXSanitizer(mode=mode)
        return sanitizer.sanitize(content, detections)
    else:
        # For text-based files, use TextSanitizer
        sanitizer = TextSanitizer(mode=mode)
        return sanitizer.sanitize(content, detections)


def get_client_ip(request: Request) -> Optional[str]:
    """Get client IP from request."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    if request.headers.get("X-Real-IP"):
        return request.headers.get("X-Real-IP")
    return request.client.host if request.client else None


# ==================== Endpoints ====================

@router.post("/upload", response_model=ProcessingResult)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    mode: str = Form("mask"),  # mask, redact, tokenize
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)  # Only admins can upload
):
    """
    Upload a file for PII detection and sanitization.
    Only admin users can upload files.
    """
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    if not is_allowed_file(file.filename):
        raise HTTPException(
            status_code=400, 
            detail=f"File type not allowed. Allowed types: .sql, .pdf, .docx, .csv, .json, .txt"
        )
    
    # Validate mode
    if mode not in ["mask", "redact", "tokenize"]:
        raise HTTPException(status_code=400, detail="Invalid mode. Use: mask, redact, tokenize")
    
    # Read file content
    content = await file.read()
    
    if len(content) > settings.MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail=f"File too large. Max size: {settings.MAX_FILE_SIZE} bytes")
    
    # Save encrypted original
    file_type = get_file_type(file.filename)
    original_path, original_hash = save_encrypted_file(
        content, file.filename, settings.UPLOAD_DIR
    )
    
    # Create file record
    file_record = FileRecord(
        filename=file.filename,
        original_filename=file.filename,
        file_type=file_type,
        file_size=len(content),
        original_path=original_path,
        encryption_key_id=generate_encryption_key_id(),
        status=ProcessingStatus.PROCESSING,
        anonymization_mode=mode,
        original_hash=original_hash,
        uploaded_by=current_user.id
    )
    
    db.add(file_record)
    db.commit()
    db.refresh(file_record)
    
    # Log upload
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")
    AuditService.log_file_upload(db, current_user, file_record, client_ip, user_agent)
    
    try:
        # Extract text for PII detection
        text = extract_text_from_file(content, file_type)
        
        # Detect PII
        detections, entity_counts = detect_pii(text)
        
        # Store detection results
        file_record.pii_detected = detection_engine.detections_to_json(detections)
        file_record.entity_counts = json.dumps(entity_counts)
        
        # Log PII detection
        AuditService.log_pii_detection(
            db, current_user, file_record, entity_counts, 
            sum(entity_counts.values()), client_ip, user_agent
        )
        
        # Sanitize file
        sanitized_content = sanitize_file(content, file_type, detections, mode)
        
        # Save sanitized file
        sanitized_path, sanitized_hash = save_encrypted_file(
            sanitized_content, f"sanitized_{file.filename}", settings.SANITIZED_DIR
        )
        
        file_record.sanitized_path = sanitized_path
        file_record.sanitized_hash = sanitized_hash
        file_record.status = ProcessingStatus.COMPLETED
        
        db.commit()
        
        # Log sanitization
        AuditService.log_sanitization(
            db, current_user, file_record, mode, entity_counts, 
            success=True, ip_address=client_ip, user_agent=user_agent
        )
        
        return ProcessingResult(
            file_id=file_record.id,
            status="completed",
            entity_counts=entity_counts,
            total_entities=sum(entity_counts.values()),
            message="File processed successfully"
        )
        
    except Exception as e:
        file_record.status = ProcessingStatus.FAILED
        db.commit()
        
        # Log failure
        AuditService.log_sanitization(
            db, current_user, file_record, mode, {}, 
            success=False, error_message=str(e),
            ip_address=client_ip, user_agent=user_agent
        )
        
        raise HTTPException(status_code=500, detail=f"Processing failed: {str(e)}")


@router.get("/", response_model=List[FileResponse])
def list_files(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    List files accessible to the user.
    - Admins see all files
    - Standard users see only sanitized files
    """
    if current_user.is_admin():
        files = db.query(FileRecord).all()
    else:
        files = db.query(FileRecord).filter(
            FileRecord.status == ProcessingStatus.COMPLETED
        ).all()
    
    result = []
    for file in files:
        file_dict = {
            "id": file.id,
            "filename": file.filename,
            "original_filename": file.original_filename,
            "file_type": file.file_type,
            "file_size": file.file_size,
            "status": file.status.value,
            "anonymization_mode": file.anonymization_mode,
            "entity_counts": json.loads(file.entity_counts) if file.entity_counts else None,
            "created_at": file.created_at.isoformat() if file.created_at else None
        }
        result.append(file_dict)
    
    return result


@router.get("/{file_id}/download")
def download_file(
    request: Request,
    file_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Download sanitized file.
    All users can download sanitized files.
    """
    file_record = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    
    if file_record.status != ProcessingStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="File processing not completed")
    
    # Read sanitized file
    content = read_encrypted_file(file_record.sanitized_path)
    
    # Log download
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")
    AuditService.log_file_download(
        db, current_user, file_record, is_sanitized=True,
        ip_address=client_ip, user_agent=user_agent
    )
    
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename=sanitized_{file_record.original_filename}"
        }
    )


@router.get("/{file_id}/original")
def download_original(
    request: Request,
    file_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """
    Download original file.
    Only admin users can access original files.
    """
    file_record = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Read original file
    content = read_encrypted_file(file_record.original_path)
    
    # Log access to original
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")
    AuditService.log_view_original(
        db, current_user, file_record,
        ip_address=client_ip, user_agent=user_agent
    )
    
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename={file_record.original_filename}"
        }
    )


@router.get("/{file_id}/preview")
def preview_file(
    file_id: int,
    view_original: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Preview file content (text only).
    - Standard users can only preview sanitized content
    - Admins can preview original content with view_original=true
    """
    file_record = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Check permissions
    if view_original and not current_user.is_admin():
        raise HTTPException(status_code=403, detail="Admin access required to view original")
    
    if view_original:
        content = read_encrypted_file(file_record.original_path)
    else:
        if file_record.status != ProcessingStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="File processing not completed")
        content = read_encrypted_file(file_record.sanitized_path)
    
    # Try to decode as text
    try:
        text = content.decode('utf-8')
        return {"content": text[:10000], "truncated": len(text) > 10000}  # Limit preview size
    except:
        return {"content": "[Binary file - preview not available]", "truncated": False}
