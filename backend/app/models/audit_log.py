from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Event details
    event_type = Column(String, nullable=False, index=True)
    # Types: FILE_UPLOAD, FILE_DOWNLOAD, FILE_VIEW_ORIGINAL, PII_DETECTED, 
    #        USER_LOGIN, USER_LOGOUT, USER_CREATED, SANITIZATION_COMPLETED
    
    # User who performed the action
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", backref="audit_logs")
    username = Column(String, nullable=False)  # Denormalized for audit integrity
    user_role = Column(String, nullable=False)
    
    # File reference (if applicable)
    file_id = Column(Integer, ForeignKey("file_records.id"), nullable=True)
    file_record = relationship("FileRecord", backref="audit_logs")
    filename = Column(String, nullable=True)  # Denormalized
    
    # PII Detection summary (no actual PII stored)
    entity_counts = Column(Text, nullable=True)  # JSON: {"email": 5, "phone": 3}
    total_entities = Column(Integer, nullable=True)
    
    # Sanitization details
    anonymization_mode = Column(String, nullable=True)
    
    # Status and integrity
    success = Column(Integer, default=1)  # 1 = success, 0 = failure
    error_message = Column(Text, nullable=True)
    file_hash = Column(String, nullable=True)  # Hash of output file (if applicable)
    
    # IP address and user agent (for security tracking)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    
    # Timestamp
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, event_type={self.event_type}, user={self.username})>"
