from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database import get_db
from app.models.user import User, UserRole
from app.models.file import FileRecord
from app.models.audit_log import AuditLog
from app.routers.auth import get_current_admin
from app.services.audit_service import AuditService

router = APIRouter(prefix="/admin", tags=["admin"])


# ==================== Pydantic Models ====================

class UserCreateRequest(BaseModel):
    username: str
    email: str
    password: str
    role: UserRole = UserRole.STANDARD


class UserUpdateRequest(BaseModel):
    email: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: int
    created_at: Optional[str]
    
    class Config:
        from_attributes = True


class AuditLogResponse(BaseModel):
    id: int
    event_type: str
    username: str
    user_role: str
    filename: Optional[str]
    entity_counts: Optional[dict]
    total_entities: Optional[int]
    anonymization_mode: Optional[str]
    success: int
    error_message: Optional[str]
    timestamp: str
    
    class Config:
        from_attributes = True


# ==================== Helper Functions ====================

def get_client_ip(request: Request) -> Optional[str]:
    """Get client IP from request."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    if request.headers.get("X-Real-IP"):
        return request.headers.get("X-Real-IP")
    return request.client.host if request.client else None


# ==================== User Management Endpoints ====================

@router.get("/users", response_model=List[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """List all users."""
    users = db.query(User).all()
    
    result = []
    for user in users:
        user_dict = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None
        }
        result.append(user_dict)
    
    return result


@router.post("/users", response_model=UserResponse)
def create_user(
    request: Request,
    user_data: UserCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Create a new user."""
    # Check if username exists
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Check if email exists
    existing = db.query(User).filter(User.email == user_data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    
    from app.utils.security import get_password_hash
    
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        role=user_data.role,
        is_active=1
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Log user creation
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")
    AuditService.log_user_created(
        db, current_user, new_user,
        ip_address=client_ip, user_agent=user_agent
    )
    
    return {
        "id": new_user.id,
        "username": new_user.username,
        "email": new_user.email,
        "role": new_user.role.value,
        "is_active": new_user.is_active,
        "created_at": new_user.created_at.isoformat() if new_user.created_at else None
    }


@router.put("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user_data: UserUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Update a user."""
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user_data.email is not None:
        user.email = user_data.email
    
    if user_data.role is not None:
        user.role = user_data.role
    
    if user_data.is_active is not None:
        user.is_active = 1 if user_data.is_active else 0
    
    db.commit()
    db.refresh(user)
    
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None
    }


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Delete (deactivate) a user."""
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    # Soft delete - deactivate
    user.is_active = 0
    db.commit()
    
    return {"message": "User deactivated successfully"}


# ==================== File Management Endpoints ====================

@router.get("/files")
def list_all_files(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """List all files with full details."""
    files = db.query(FileRecord).all()
    
    result = []
    for file in files:
        import json
        file_dict = {
            "id": file.id,
            "filename": file.filename,
            "original_filename": file.original_filename,
            "file_type": file.file_type,
            "file_size": file.file_size,
            "status": file.status.value,
            "anonymization_mode": file.anonymization_mode,
            "entity_counts": json.loads(file.entity_counts) if file.entity_counts else None,
            "uploaded_by": file.uploaded_by,
            "created_at": file.created_at.isoformat() if file.created_at else None,
            "processed_at": file.processed_at.isoformat() if file.processed_at else None
        }
        result.append(file_dict)
    
    return result


@router.delete("/files/{file_id}")
def delete_file(
    file_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Delete a file and its records."""
    file_record = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Delete physical files
    from app.utils.file_storage import delete_file
    delete_file(file_record.original_path)
    if file_record.sanitized_path:
        delete_file(file_record.sanitized_path)
    
    # Delete from database
    db.delete(file_record)
    db.commit()
    
    return {"message": "File deleted successfully"}


# ==================== Audit Log Endpoints ====================

@router.get("/audit-logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    event_type: Optional[str] = None,
    username: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get audit logs with optional filtering."""
    query = db.query(AuditLog)
    
    if event_type:
        query = query.filter(AuditLog.event_type == event_type)
    
    if username:
        query = query.filter(AuditLog.username == username)
    
    logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
    
    result = []
    import json
    for log in logs:
        log_dict = {
            "id": log.id,
            "event_type": log.event_type,
            "username": log.username,
            "user_role": log.user_role,
            "filename": log.filename,
            "entity_counts": json.loads(log.entity_counts) if log.entity_counts else None,
            "total_entities": log.total_entities,
            "anonymization_mode": log.anonymization_mode,
            "success": log.success,
            "error_message": log.error_message,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None
        }
        result.append(log_dict)
    
    return result


@router.get("/stats")
def get_system_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get comprehensive system statistics."""
    import json
    from datetime import datetime, timedelta
    from app.models.file import ProcessingStatus
    from app.models.audit_log import AuditLog
    from sqlalchemy import func
    
    total_users = db.query(User).count()
    total_files = db.query(FileRecord).count()
    completed_files = db.query(FileRecord).filter(
        FileRecord.status == ProcessingStatus.COMPLETED
    ).count()
    pending_files = db.query(FileRecord).filter(
        FileRecord.status == ProcessingStatus.PENDING
    ).count()
    failed_files = db.query(FileRecord).filter(
        FileRecord.status == ProcessingStatus.FAILED
    ).count()
    processing_files = db.query(FileRecord).filter(
        FileRecord.status == ProcessingStatus.PROCESSING
    ).count()
    
    # Calculate total PII entities detected and breakdown by type
    total_pii = 0
    entity_type_totals = {}
    files = db.query(FileRecord).all()
    for file in files:
        if file.entity_counts:
            counts = json.loads(file.entity_counts)
            for entity_type, count in counts.items():
                total_pii += count
                entity_type_totals[entity_type] = entity_type_totals.get(entity_type, 0) + count
    
    # Get recent activity (last 7 days)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    recent_uploads = db.query(FileRecord).filter(
        FileRecord.created_at >= seven_days_ago
    ).count()
    
    recent_logins = db.query(AuditLog).filter(
        AuditLog.timestamp >= seven_days_ago,
        AuditLog.event_type == "USER_LOGIN"
    ).count()
    
    # Get top PII entity types
    top_entities = sorted(
        entity_type_totals.items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:10]
    
    # Get file type distribution
    file_types = {}
    for file in files:
        file_types[file.file_type] = file_types.get(file.file_type, 0) + 1
    
    # Get sanitization mode usage
    mode_usage = {}
    for file in files:
        if file.anonymization_mode:
            mode_usage[file.anonymization_mode] = mode_usage.get(file.anonymization_mode, 0) + 1
    
    return {
        "users": {
            "total": total_users,
            "admins": db.query(User).filter(User.role == UserRole.ADMIN).count(),
            "standard": db.query(User).filter(User.role == UserRole.STANDARD).count(),
            "active": db.query(User).filter(User.is_active == 1).count()
        },
        "files": {
            "total": total_files,
            "completed": completed_files,
            "pending": pending_files,
            "processing": processing_files,
            "failed": failed_files
        },
        "pii_stats": {
            "total_entities_detected": total_pii,
            "entity_type_breakdown": entity_type_totals,
            "top_entity_types": top_entities
        },
        "file_types": file_types,
        "sanitization_modes": mode_usage,
        "recent_activity": {
            "uploads_last_7_days": recent_uploads,
            "logins_last_7_days": recent_logins
        }
    }


@router.get("/pii-trends")
def get_pii_trends(
    days: int = 30,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get PII detection trends over time."""
    import json
    from datetime import datetime, timedelta
    
    start_date = datetime.utcnow() - timedelta(days=days)
    files = db.query(FileRecord).filter(
        FileRecord.created_at >= start_date,
        FileRecord.status == ProcessingStatus.COMPLETED
    ).all()
    
    # Group by date
    daily_stats = {}
    for file in files:
        date_key = file.created_at.strftime("%Y-%m-%d")
        if date_key not in daily_stats:
            daily_stats[date_key] = {"files": 0, "entities": 0, "types": {}}
        
        daily_stats[date_key]["files"] += 1
        
        if file.entity_counts:
            counts = json.loads(file.entity_counts)
            daily_stats[date_key]["entities"] += sum(counts.values())
            for entity_type, count in counts.items():
                daily_stats[date_key]["types"][entity_type] = \
                    daily_stats[date_key]["types"].get(entity_type, 0) + count
    
    # Sort by date
    sorted_dates = sorted(daily_stats.keys())
    
    return {
        "period_days": days,
        "daily_data": [
            {
                "date": date,
                "files_processed": daily_stats[date]["files"],
                "entities_detected": daily_stats[date]["entities"],
                "entity_breakdown": daily_stats[date]["types"]
            }
            for date in sorted_dates
        ]
    }


@router.get("/user-activity")
def get_user_activity(
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get recent user activity summary."""
    import json
    from app.models.audit_log import AuditLog
    
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    
    activity_list = []
    for log in logs:
        activity_list.append({
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "username": log.username,
            "event_type": log.event_type,
            "filename": log.filename,
            "success": log.success,
            "ip_address": log.ip_address
        })
    
    return {"activities": activity_list}
