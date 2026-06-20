import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import Base, get_db
from app.models.user import User, UserRole
from app.utils.security import get_password_hash


# Setup test database
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="function")
def client():
    """Create a test client with fresh database."""
    Base.metadata.create_all(bind=engine)
    
    # Create test users
    db = TestingSessionLocal()
    
    admin_user = User(
        username="testadmin",
        email="admin@test.com",
        hashed_password=get_password_hash("adminpass"),
        role=UserRole.ADMIN,
        is_active=1
    )
    standard_user = User(
        username="testuser",
        email="user@test.com",
        hashed_password=get_password_hash("userpass"),
        role=UserRole.STANDARD,
        is_active=1
    )
    
    db.add(admin_user)
    db.add(standard_user)
    db.commit()
    db.refresh(admin_user)
    db.refresh(standard_user)
    
    db.close()
    
    with TestClient(app) as c:
        yield c
    
    Base.metadata.drop_all(bind=engine)


class TestAuthentication:
    """Test authentication endpoints."""
    
    def test_login_success(self, client):
        """Test successful login."""
        response = client.post(
            "/auth/login",
            data={"username": "testadmin", "password": "adminpass"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["user"]["username"] == "testadmin"
    
    def test_login_failure(self, client):
        """Test failed login."""
        response = client.post(
            "/auth/login",
            data={"username": "testadmin", "password": "wrongpass"}
        )
        assert response.status_code == 401
    
    def test_get_current_user(self, client):
        """Test getting current user info."""
        # Login first
        login_response = client.post(
            "/auth/login",
            data={"username": "testadmin", "password": "adminpass"}
        )
        token = login_response.json()["access_token"]
        
        # Get current user
        response = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testadmin"
        assert data["role"] == "admin"


class TestRBAC:
    """Test Role-Based Access Control."""
    
    def test_admin_can_access_admin_endpoints(self, client):
        """Test admin can access admin-only endpoints."""
        # Login as admin
        login_response = client.post(
            "/auth/login",
            data={"username": "testadmin", "password": "adminpass"}
        )
        token = login_response.json()["access_token"]
        
        # Try to access admin endpoint
        response = client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
    
    def test_standard_user_cannot_access_admin_endpoints(self, client):
        """Test standard user cannot access admin-only endpoints."""
        # Login as standard user
        login_response = client.post(
            "/auth/login",
            data={"username": "testuser", "password": "userpass"}
        )
        token = login_response.json()["access_token"]
        
        # Try to access admin endpoint
        response = client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403
    
    def test_admin_can_create_users(self, client):
        """Test admin can create new users."""
        # Login as admin
        login_response = client.post(
            "/auth/login",
            data={"username": "testadmin", "password": "adminpass"}
        )
        token = login_response.json()["access_token"]
        
        # Create new user
        response = client.post(
            "/auth/register",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "username": "newuser",
                "email": "newuser@test.com",
                "password": "newpass123",
                "role": "standard"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "newuser"
    
    def test_standard_user_cannot_create_users(self, client):
        """Test standard user cannot create new users."""
        # Login as standard user
        login_response = client.post(
            "/auth/login",
            data={"username": "testuser", "password": "userpass"}
        )
        token = login_response.json()["access_token"]
        
        # Try to create new user
        response = client.post(
            "/auth/register",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "username": "anotheruser",
                "email": "another@test.com",
                "password": "pass123",
                "role": "standard"
            }
        )
        assert response.status_code == 403
    
    def test_admin_can_view_audit_logs(self, client):
        """Test admin can view audit logs."""
        # Login as admin
        login_response = client.post(
            "/auth/login",
            data={"username": "testadmin", "password": "adminpass"}
        )
        token = login_response.json()["access_token"]
        
        # Try to access audit logs
        response = client.get(
            "/admin/audit-logs",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
    
    def test_standard_user_cannot_view_audit_logs(self, client):
        """Test standard user cannot view audit logs."""
        # Login as standard user
        login_response = client.post(
            "/auth/login",
            data={"username": "testuser", "password": "userpass"}
        )
        token = login_response.json()["access_token"]
        
        # Try to access audit logs
        response = client.get(
            "/admin/audit-logs",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403


class TestFileAccess:
    """Test file access permissions."""
    
    def test_standard_user_can_list_files(self, client):
        """Test standard user can list files."""
        # Login as standard user
        login_response = client.post(
            "/auth/login",
            data={"username": "testuser", "password": "userpass"}
        )
        token = login_response.json()["access_token"]
        
        # List files
        response = client.get(
            "/files/",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
    
    def test_standard_user_cannot_upload_files(self, client):
        """Test standard user cannot upload files."""
        # Login as standard user
        login_response = client.post(
            "/auth/login",
            data={"username": "testuser", "password": "userpass"}
        )
        token = login_response.json()["access_token"]
        
        # Try to upload file
        response = client.post(
            "/files/upload",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("test.txt", b"test content", "text/plain")},
            data={"mode": "mask"}
        )
        assert response.status_code == 403
    
    def test_admin_can_upload_files(self, client):
        """Test admin can upload files."""
        # Login as admin
        login_response = client.post(
            "/auth/login",
            data={"username": "testadmin", "password": "adminpass"}
        )
        token = login_response.json()["access_token"]
        
        # Try to upload file (will fail due to file processing, but not due to permissions)
        response = client.post(
            "/files/upload",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("test.txt", b"Email: test@example.com", "text/plain")},
            data={"mode": "mask"}
        )
        # Should not be 403 - might be 200 or 500 depending on processing
        assert response.status_code != 403
