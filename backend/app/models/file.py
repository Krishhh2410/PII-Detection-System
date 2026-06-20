import enum
from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database import Base


class ProcessingStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class FileRecord(Base):
    __tablename__ = "file_records"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    original_filename = Column(String, nullable=False)
    file_type = Column(String, nullable=False)  # sql, pdf, docx, etc.
    file_size = Column(Integer, nullable=False)
    
    # Storage paths (encrypted files)
    original_path = Column(String, nullable=False)
    sanitized_path = Column(String, nullable=True)
    
    # Encryption
    encryption_key_id = Column(String, nullable=False)
    
    # Processing
    status = Column(Enum(ProcessingStatus), default=ProcessingStatus.PENDING)
    anonymization_mode = Column(String, nullable=True)  # mask, redact, tokenize
    
    # PII Detection Results (JSON string)
    pii_detected = Column(Text, nullable=True)
    entity_counts = Column(Text, nullable=True)  # JSON: {"email": 5, "phone": 3}
    
    # File hash for integrity
    original_hash = Column(String, nullable=False)
    sanitized_hash = Column(String, nullable=True)
    
    # User relationship
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", backref="files")
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    processed_at = Column(DateTime(timezone=True), nullable=True)
    
    def __repr__(self):
        return f"<FileRecord(id={self.id}, filename={self.filename}, status={self.status})>"
