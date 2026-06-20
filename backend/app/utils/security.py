import hashlib
import hmac
import base64
import secrets
from datetime import datetime, timedelta
from typing import Optional, Union
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.config import get_settings

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


# ==================== Password Hashing ====================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    try:
        # Try bcrypt first
        return pwd_context.verify(plain_password, hashed_password)
    except:
        # Fallback to SHA-256 verification
        import hashlib
        return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt."""
    try:
        # Try bcrypt first
        # Truncate password to 72 bytes if longer (bcrypt limitation)
        if len(password.encode('utf-8')) > 72:
            password = password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
        return pwd_context.hash(password)
    except:
        # Fallback to SHA-256 if bcrypt fails
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()


# ==================== JWT Token Handling ====================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


# ==================== File Encryption ====================

def get_encryption_key() -> bytes:
    """Derive an encryption key from the settings."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=settings.SECRET_KEY[:16].encode(),
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(settings.ENCRYPTION_KEY.encode()))
    return key


def get_fernet() -> Fernet:
    """Get a Fernet instance for encryption/decryption."""
    return Fernet(get_encryption_key())


def encrypt_data(data: bytes) -> bytes:
    """Encrypt data using Fernet symmetric encryption."""
    f = get_fernet()
    return f.encrypt(data)


def decrypt_data(encrypted_data: bytes) -> bytes:
    """Decrypt data using Fernet symmetric encryption."""
    f = get_fernet()
    return f.decrypt(encrypted_data)


# ==================== Hashing for Integrity ====================

def compute_file_hash(file_data: bytes) -> str:
    """Compute SHA-256 hash of file data for integrity verification."""
    return hashlib.sha256(file_data).hexdigest()


def verify_file_hash(file_data: bytes, expected_hash: str) -> bool:
    """Verify file integrity by comparing hashes."""
    return compute_file_hash(file_data) == expected_hash


# ==================== Tokenization ====================

def generate_token(value: str, secret_key: Optional[str] = None) -> str:
    """
    Generate a stable token for a given value using HMAC.
    Same value will always produce the same token (within the same secret).
    """
    if secret_key is None:
        secret_key = settings.SECRET_KEY
    
    # Create HMAC
    h = hmac.new(
        secret_key.encode(),
        value.encode(),
        hashlib.sha256
    )
    # Get first 10 bytes and encode as base32 for readability
    token_hash = h.digest()[:10]
    token = base64.b32encode(token_hash).decode().rstrip('=')
    return f"TOK_{token}"


def generate_encryption_key_id() -> str:
    """Generate a unique key ID for tracking encryption keys."""
    return secrets.token_urlsafe(16)


# ==================== Secure Random Generation ====================

def generate_secure_random(length: int = 32) -> str:
    """Generate a cryptographically secure random string."""
    return secrets.token_urlsafe(length)
