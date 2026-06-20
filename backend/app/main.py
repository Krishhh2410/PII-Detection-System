from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base
from app.config import ensure_directories
from app.routers import auth, files, admin, analysis

# Create database tables
Base.metadata.create_all(bind=engine)

# Ensure upload directories exist
ensure_directories()

app = FastAPI(
    title="PII Detection & Sanitization System",
    description="Automated PII detection and sanitization for SQL, PDF, and DOCX files",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(files.router)
app.include_router(admin.router)
app.include_router(analysis.router)


@app.get("/")
def root():
    """Root endpoint."""
    return {
        "message": "PII Detection & Sanitization System API",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


# Create default admin user on startup
@app.on_event("startup")
def create_default_admin():
    """Create default admin user if no users exist."""
    from sqlalchemy.orm import Session
    from app.database import SessionLocal
    from app.models.user import User, UserRole
    from app.utils.security import get_password_hash
    
    db = SessionLocal()
    try:
        # Check if any users exist
        user_count = db.query(User).count()
        if user_count == 0:
            # Create default admin
            admin = User(
                username="admin",
                email="admin@example.com",
                hashed_password=get_password_hash("admin123"),
                role=UserRole.ADMIN,
                is_active=1
            )
            db.add(admin)
            db.commit()
            print("Default admin user created: username='admin', password='admin123'")
    finally:
        db.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
