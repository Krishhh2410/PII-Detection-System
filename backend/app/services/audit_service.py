import json
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.user import User
from app.models.file import FileRecord

# PII Detector Module Content
import re
from typing import List, Tuple
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class PIIDetection:
    """Represents a detected PII entity."""
    entity_type: str
    start: int
    end: int
    text: str
    confidence: float = 1.0


class RegexDetectors:
    """Regex-based PII detection utilities."""
    
    # Email pattern
    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        re.IGNORECASE
    )
    
    # Indian phone patterns
    PHONE_PATTERN = re.compile(
        r'(?:\+91[-\s]?|0)?[6-9]\d{9}|(?:\+91[-\s]?|0)?[6-9]\d{4}\s?\d{5}',
        re.IGNORECASE
    )
    
    # Aadhaar pattern (12 digits, optionally spaced)
    AADHAAR_PATTERN = re.compile(
        r'\b\d{4}\s?\d{4}\s?\d{4}\b|\b\d{12}\b'
    )
    
    # PAN pattern (5 letters + 4 digits + 1 letter)
    PAN_PATTERN = re.compile(
        r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
        re.IGNORECASE
    )
    
    # IP Address pattern
    IP_PATTERN = re.compile(
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    )
    
    # Credit Card pattern
    CREDIT_CARD_PATTERN = re.compile(
        r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
    )
    
    @classmethod
    def detect_emails(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect email addresses in text."""
        return [(m.start(), m.end(), m.group()) for m in cls.EMAIL_PATTERN.finditer(text)]
    
    @classmethod
    def detect_phones(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect phone numbers in text."""
        return [(m.start(), m.end(), m.group()) for m in cls.PHONE_PATTERN.finditer(text)]
    
    @classmethod
    def detect_aadhaar(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect Aadhaar numbers in text."""
        return [(m.start(), m.end(), m.group()) for m in cls.AADHAAR_PATTERN.finditer(text)]
    
    @classmethod
    def detect_pan(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect PAN numbers in text."""
        return [(m.start(), m.end(), m.group()) for m in cls.PAN_PATTERN.finditer(text)]
    
    @classmethod
    def detect_ips(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect IP addresses in text."""
        return [(m.start(), m.end(), m.group()) for m in cls.IP_PATTERN.finditer(text)]
    
    @classmethod
    def detect_credit_cards(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect credit card numbers in text."""
        return [(m.start(), m.end(), m.group()) for m in cls.CREDIT_CARD_PATTERN.finditer(text)]


class PIIDetectionEngine:
    """Main PII detection engine."""
    
    def __init__(self):
        self.detectors = {
            'email': RegexDetectors.detect_emails,
            'phone': RegexDetectors.detect_phones,
            'aadhaar': RegexDetectors.detect_aadhaar,
            'pan': RegexDetectors.detect_pan,
            'ip': RegexDetectors.detect_ips,
            'credit_card': RegexDetectors.detect_credit_cards,
        }
    
    def detect_all(self, text: str) -> List[PIIDetection]:
        """Detect all types of PII in text."""
        detections = []
        
        for entity_type, detector in self.detectors.items():
            matches = detector(text)
            for start, end, matched_text in matches:
                detection = PIIDetection(
                    entity_type=entity_type,
                    start=start,
                    end=end,
                    text=matched_text,
                    confidence=1.0
                )
                detections.append(detection)
        
        # Sort by start position
        detections.sort(key=lambda x: x.start)
        return detections
    
    def get_entity_counts(self, detections: List[PIIDetection]) -> Dict[str, int]:
        """Get counts of each entity type."""
        counts = defaultdict(int)
        for detection in detections:
            counts[detection.entity_type] += 1
        return dict(counts)


# Global engine instance
_engine = PIIDetectionEngine()


def detect_pii(text: str):
    """Convenience function to detect PII in text.
    
    Args:
        text: Text to analyze
        
    Returns:
        Tuple of (detections, entity_counts)
    """
    detections = _engine.detect_all(text)
    counts = _engine.get_entity_counts(detections)
    return detections, counts


# Additional utility functions
def mask_pii(text: str, mask_char: str = '*') -> str:
    """Mask detected PII in text."""
    detections, _ = detect_pii(text)
    
    # Process in reverse order to maintain indices
    for detection in reversed(detections):
        masked = mask_char * len(detection.text)
        text = text[:detection.start] + masked + text[detection.end:]
    
    return text


def redact_pii(text: str) -> str:
    """Redact detected PII with entity type labels."""
    detections, _ = detect_pii(text)
    
    # Process in reverse order to maintain indices
    for detection in reversed(detections):
        replacement = f"[REDACTED_{detection.entity_type.upper()}]"
        text = text[:detection.start] + replacement + text[detection.end:]
    
    return text

# End PII Detector Module Content


class AuditService:
    """Service for creating and managing audit logs."""
    
    @staticmethod
    def log_event(
        db: Session,
        event_type: str,
        user: User,
        file_record: Optional[FileRecord] = None,
        entity_counts: Optional[Dict[str, int]] = None,
        total_entities: Optional[int] = None,
        anonymization_mode: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        file_hash: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """
        Create an audit log entry.
        
        Note: No raw PII is stored in audit logs - only counts and metadata.
        """
        audit_log = AuditLog(
            event_type=event_type,
            user_id=user.id,
            username=user.username,
            user_role=user.role.value,
            file_id=file_record.id if file_record else None,
            filename=file_record.original_filename if file_record else None,
            entity_counts=json.dumps(entity_counts) if entity_counts else None,
            total_entities=total_entities,
            anonymization_mode=anonymization_mode,
            success=1 if success else 0,
            error_message=error_message,
            file_hash=file_hash,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        db.add(audit_log)
        db.commit()
        db.refresh(audit_log)
        
        return audit_log
    
    @staticmethod
    def log_file_upload(
        db: Session,
        user: User,
        file_record: FileRecord,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """Log a file upload event."""
        return AuditService.log_event(
            db=db,
            event_type="FILE_UPLOAD",
            user=user,
            file_record=file_record,
            file_hash=file_record.original_hash,
            ip_address=ip_address,
            user_agent=user_agent
        )
    
    @staticmethod
    def log_file_download(
        db: Session,
        user: User,
        file_record: FileRecord,
        is_sanitized: bool = True,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """Log a file download event."""
        event_type = "FILE_DOWNLOAD_SANITIZED" if is_sanitized else "FILE_DOWNLOAD_ORIGINAL"
        return AuditService.log_event(
            db=db,
            event_type=event_type,
            user=user,
            file_record=file_record,
            file_hash=file_record.sanitized_hash if is_sanitized else file_record.original_hash,
            ip_address=ip_address,
            user_agent=user_agent
        )
    
    @staticmethod
    def log_view_original(
        db: Session,
        user: User,
        file_record: FileRecord,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """Log viewing of original file (admin only)."""
        return AuditService.log_event(
            db=db,
            event_type="FILE_VIEW_ORIGINAL",
            user=user,
            file_record=file_record,
            file_hash=file_record.original_hash,
            ip_address=ip_address,
            user_agent=user_agent
        )
    
    @staticmethod
    def log_pii_detection(
        db: Session,
        user: User,
        file_record: FileRecord,
        entity_counts: Dict[str, int],
        total_entities: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """Log PII detection results."""
        return AuditService.log_event(
            db=db,
            event_type="PII_DETECTED",
            user=user,
            file_record=file_record,
            entity_counts=entity_counts,
            total_entities=total_entities,
            ip_address=ip_address,
            user_agent=user_agent
        )
    
    @staticmethod
    def log_sanitization(
        db: Session,
        user: User,
        file_record: FileRecord,
        anonymization_mode: str,
        entity_counts: Dict[str, int],
        success: bool = True,
        error_message: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """Log sanitization completion."""
        return AuditService.log_event(
            db=db,
            event_type="SANITIZATION_COMPLETED",
            user=user,
            file_record=file_record,
            entity_counts=entity_counts,
            total_entities=sum(entity_counts.values()),
            anonymization_mode=anonymization_mode,
            success=success,
            error_message=error_message,
            file_hash=file_record.sanitized_hash,
            ip_address=ip_address,
            user_agent=user_agent
        )
    
    @staticmethod
    def log_user_login(
        db: Session,
        user: User,
        success: bool = True,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """Log user login."""
        return AuditService.log_event(
            db=db,
            event_type="USER_LOGIN",
            user=user,
            success=success,
            ip_address=ip_address,
            user_agent=user_agent
        )
    
    @staticmethod
    def log_user_created(
        db: Session,
        admin_user: User,
        new_user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """Log user creation."""
        return AuditService.log_event(
            db=db,
            event_type="USER_CREATED",
            user=admin_user,
            success=True,
            ip_address=ip_address,
            user_agent=user_agent
        )
