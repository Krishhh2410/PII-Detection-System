from pydantic_settings import BaseSettings
from functools import lru_cache
import os


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "PII Detection & Sanitization System"
    DEBUG: bool = False
    
    # Database
    DATABASE_URL: str = "sqlite:///./pii_system.db"
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production-min-32-chars-long"
    JWT_SECRET_KEY: str = "your-jwt-secret-key-change-in-production-32-chars"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # File Storage
    UPLOAD_DIR: str = "./uploads"
    SANITIZED_DIR: str = "./sanitized"
    MAX_FILE_SIZE: int = 50 * 1024 * 1024  # 50MB
    
    # Encryption
    ENCRYPTION_KEY: str = "your-encryption-key-32-bytes-long!!"
    
    # PII Detection
    SPACY_MODEL: str = "en_core_web_sm"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()


# Ensure upload directories exist
def ensure_directories():
    settings = get_settings()
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    os.makedirs(settings.SANITIZED_DIR, exist_ok=True)
