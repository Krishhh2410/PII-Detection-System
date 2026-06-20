import enum
from sqlalchemy import Column, Integer, String, DateTime, Enum
from sqlalchemy.sql import func
from app.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    STANDARD = "standard"


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.STANDARD, nullable=False)
    is_active = Column(Integer, default=1)  # 1 = active, 0 = inactive
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN
    
    def __repr__(self):
        return f"<User(id={self.id}, username={self.username}, role={self.role})>"
