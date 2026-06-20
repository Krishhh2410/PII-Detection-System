import os
import uuid
from pathlib import Path
from typing import Tuple, Optional
from datetime import datetime

from app.config import get_settings
from app.utils.security import encrypt_data, decrypt_data, compute_file_hash

settings = get_settings()


def generate_unique_filename(original_filename: str) -> str:
    """Generate a unique filename while preserving extension."""
    ext = Path(original_filename).suffix
    unique_id = uuid.uuid4().hex
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{timestamp}_{unique_id}{ext}"


def save_encrypted_file(file_data: bytes, filename: str, directory: str) -> Tuple[str, str]:
    """
    Save file with encryption at rest.
    Returns: (file_path, file_hash)
    """
    # Ensure directory exists
    os.makedirs(directory, exist_ok=True)
    
    # Generate unique filename
    unique_filename = generate_unique_filename(filename)
    file_path = os.path.join(directory, unique_filename)
    
    # Compute hash of original data
    file_hash = compute_file_hash(file_data)
    
    # Encrypt and save
    encrypted_data = encrypt_data(file_data)
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)
    
    return file_path, file_hash


def read_encrypted_file(file_path: str) -> bytes:
    """Read and decrypt an encrypted file."""
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    return decrypt_data(encrypted_data)


def delete_file(file_path: str) -> bool:
    """Securely delete a file."""
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
    except Exception:
        pass
    return False


def get_file_size(file_path: str) -> int:
    """Get file size in bytes."""
    return os.path.getsize(file_path)


def is_allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    allowed_extensions = {'.sql', '.pdf', '.docx', '.csv', '.json', '.txt', '.png', '.jpg', '.jpeg'}
    ext = Path(filename).suffix.lower()
    return ext in allowed_extensions


def get_file_type(filename: str) -> str:
    """Get file type from extension."""
    ext = Path(filename).suffix.lower()
    type_mapping = {
        '.sql': 'sql',
        '.pdf': 'pdf',
        '.docx': 'docx',
        '.csv': 'csv',
        '.json': 'json',
        '.txt': 'txt',
        '.png': 'image',
        '.jpg': 'image',
        '.jpeg': 'image',
    }
    return type_mapping.get(ext, 'unknown')
