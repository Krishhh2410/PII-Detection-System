import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models.user import User, UserRole
from app.models.file import FileRecord, ProcessingStatus
from app.models.audit_log import AuditLog
from app.services.audit_service import AuditService
from app.utils.security import get_password_hash


# Setup test database
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db():
    """Create a fresh database session for each test."""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    # Create test user
    user = User(
        username="testuser",
        email="test@test.com",
        hashed_password=get_password_hash("testpass"),
        role=UserRole.ADMIN,
        is_active=1
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    yield db
    
    db.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def file_record(db):
    """Create a test file record."""
    file_rec = FileRecord(
        filename="test.txt",
        original_filename="test.txt",
        file_type="txt",
        file_size=100,
        original_path="/tmp/test.txt",
        encryption_key_id="key123",
        status=ProcessingStatus.COMPLETED,
        original_hash="abc123",
        sanitized_hash="def456",
        uploaded_by=1
    )
    db.add(file_rec)
    db.commit()
    db.refresh(file_rec)
    return file_rec


class TestAuditLogCreation:
    """Test audit log creation."""
    
    def test_log_file_upload(self, db, file_record):
        """Test logging file upload."""
        user = db.query(User).first()
        
        log = AuditService.log_file_upload(
            db=db,
            user=user,
            file_record=file_record,
            ip_address="192.168.1.1",
            user_agent="TestAgent"
        )
        
        assert log is not None
        assert log.event_type == "FILE_UPLOAD"
        assert log.user_id == user.id
        assert log.file_id == file_record.id
        assert log.username == user.username
        assert log.ip_address == "192.168.1.1"
        assert log.success == 1
    
    def test_log_file_download(self, db, file_record):
        """Test logging file download."""
        user = db.query(User).first()
        
        log = AuditService.log_file_download(
            db=db,
            user=user,
            file_record=file_record,
            is_sanitized=True,
            ip_address="192.168.1.1"
        )
        
        assert log is not None
        assert log.event_type == "FILE_DOWNLOAD_SANITIZED"
        assert log.file_hash == file_record.sanitized_hash
    
    def test_log_view_original(self, db, file_record):
        """Test logging original file view."""
        user = db.query(User).first()
        
        log = AuditService.log_view_original(
            db=db,
            user=user,
            file_record=file_record,
            ip_address="192.168.1.1"
        )
        
        assert log is not None
        assert log.event_type == "FILE_VIEW_ORIGINAL"
        assert log.file_hash == file_record.original_hash
    
    def test_log_pii_detection(self, db, file_record):
        """Test logging PII detection."""
        user = db.query(User).first()
        entity_counts = {"EMAIL": 5, "PHONE": 3, "AADHAAR": 2}
        
        log = AuditService.log_pii_detection(
            db=db,
            user=user,
            file_record=file_record,
            entity_counts=entity_counts,
            total_entities=10,
            ip_address="192.168.1.1"
        )
        
        assert log is not None
        assert log.event_type == "PII_DETECTED"
        assert log.total_entities == 10
        assert "EMAIL" in log.entity_counts
    
    def test_log_sanitization(self, db, file_record):
        """Test logging sanitization."""
        user = db.query(User).first()
        entity_counts = {"EMAIL": 5}
        
        log = AuditService.log_sanitization(
            db=db,
            user=user,
            file_record=file_record,
            anonymization_mode="mask",
            entity_counts=entity_counts,
            success=True,
            ip_address="192.168.1.1"
        )
        
        assert log is not None
        assert log.event_type == "SANITIZATION_COMPLETED"
        assert log.anonymization_mode == "mask"
        assert log.success == 1
    
    def test_log_user_login(self, db):
        """Test logging user login."""
        user = db.query(User).first()
        
        log = AuditService.log_user_login(
            db=db,
            user=user,
            success=True,
            ip_address="192.168.1.1"
        )
        
        assert log is not None
        assert log.event_type == "USER_LOGIN"
        assert log.success == 1
    
    def test_log_user_created(self, db):
        """Test logging user creation."""
        admin_user = db.query(User).first()
        
        new_user = User(
            username="newuser",
            email="new@test.com",
            hashed_password="hash",
            role=UserRole.STANDARD,
            is_active=1
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        log = AuditService.log_user_created(
            db=db,
            admin_user=admin_user,
            new_user=new_user,
            ip_address="192.168.1.1"
        )
        
        assert log is not None
        assert log.event_type == "USER_CREATED"


class TestAuditLogIntegrity:
    """Test audit log integrity and security."""
    
    def test_no_pii_in_logs(self, db, file_record):
        """Test that no raw PII is stored in audit logs."""
        user = db.query(User).first()
        
        log = AuditService.log_pii_detection(
            db=db,
            user=user,
            file_record=file_record,
            entity_counts={"EMAIL": 5},
            total_entities=5,
            ip_address="192.168.1.1"
        )
        
        # Verify no raw PII in log
        assert log.entity_counts is not None
        # Entity counts should be JSON string, not contain actual emails
        assert "rajesh.kumar" not in log.entity_counts
        assert "test@example.com" not in log.entity_counts
    
    def test_denormalized_fields_for_integrity(self, db, file_record):
        """Test that denormalized fields are stored for audit integrity."""
        user = db.query(User).first()
        
        log = AuditService.log_file_upload(
            db=db,
            user=user,
            file_record=file_record,
            ip_address="192.168.1.1"
        )
        
        # Should have denormalized username
        assert log.username == user.username
        assert log.user_role == user.role.value
        assert log.filename == file_record.original_filename
    
    def test_failed_operation_logging(self, db, file_record):
        """Test logging of failed operations."""
        user = db.query(User).first()
        
        log = AuditService.log_sanitization(
            db=db,
            user=user,
            file_record=file_record,
            anonymization_mode="mask",
            entity_counts={},
            success=False,
            error_message="Processing failed due to invalid file format",
            ip_address="192.168.1.1"
        )
        
        assert log is not None
        assert log.success == 0
        assert log.error_message == "Processing failed due to invalid file format"


class TestAuditLogQueries:
    """Test querying audit logs."""
    
    def test_get_logs_by_event_type(self, db, file_record):
        """Test filtering logs by event type."""
        user = db.query(User).first()
        
        # Create multiple logs
        AuditService.log_file_upload(db, user, file_record)
        AuditService.log_user_login(db, user)
        AuditService.log_pii_detection(db, user, file_record, {"EMAIL": 5}, 5)
        
        # Query logs
        logs = db.query(AuditLog).filter(AuditLog.event_type == "FILE_UPLOAD").all()
        assert len(logs) == 1
        
        logs = db.query(AuditLog).filter(AuditLog.event_type == "USER_LOGIN").all()
        assert len(logs) == 1
    
    def test_get_logs_by_user(self, db, file_record):
        """Test filtering logs by user."""
        user = db.query(User).first()
        
        # Create logs
        AuditService.log_file_upload(db, user, file_record)
        AuditService.log_user_login(db, user)
        
        # Query logs
        logs = db.query(AuditLog).filter(AuditLog.username == "testuser").all()
        assert len(logs) == 2
    
    def test_logs_ordered_by_timestamp(self, db, file_record):
        """Test that logs are ordered by timestamp."""
        user = db.query(User).first()
        
        # Create logs
        log1 = AuditService.log_file_upload(db, user, file_record)
        log2 = AuditService.log_user_login(db, user)
        
        # Query ordered logs
        logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).all()
        
        # Most recent should be first
        assert logs[0].event_type == "USER_LOGIN"
        assert logs[1].event_type == "FILE_UPLOAD"


class TestAuditLogCounts:
    """Test audit log counting and statistics."""
    
    def test_total_entities_counted_correctly(self, db, file_record):
        """Test that total entities are counted correctly."""
        user = db.query(User).first()
        
        entity_counts = {"EMAIL": 5, "PHONE": 3, "AADHAAR": 2}
        
        log = AuditService.log_pii_detection(
            db=db,
            user=user,
            file_record=file_record,
            entity_counts=entity_counts,
            total_entities=10,
            ip_address="192.168.1.1"
        )
        
        assert log.total_entities == 10
        import json
        counts = json.loads(log.entity_counts)
        assert counts["EMAIL"] == 5
        assert counts["PHONE"] == 3
        assert counts["AADHAAR"] == 2
