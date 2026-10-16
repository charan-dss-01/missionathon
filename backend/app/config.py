import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from backend directory or project root
env_path = Path(__file__).resolve().parent.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

class Settings:
    # MongoDB Settings (MongoDB Atlas preferred, local fallback)
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://127.0.0.1:27017")
    MONGODB_DATABASE: str = os.getenv("MONGODB_DATABASE", "phishguard_ai")

    # JWT & Authentication Settings
    JWT_SECRET: str = os.getenv("JWT_SECRET", "phishguard-ai-soc-platform-super-secure-jwt-key-32-chars-min")
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "1440")) # 24 hours
    COOKIE_NAME: str = "phishguard_session"
    COOKIE_SECURE: bool = os.getenv("ENV", "development").lower() == "production"
    COOKIE_SAMESITE: str = "lax"

    # LLM Settings
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-flash-latest")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    PRIMARY_LLM_PROVIDER: str = os.getenv("PRIMARY_LLM_PROVIDER", "gemini").lower()

    # Server Settings
    BACKEND_HOST: str = os.getenv("BACKEND_HOST", "0.0.0.0")
    BACKEND_PORT: int = int(os.getenv("BACKEND_PORT", "8000"))
    CORS_ORIGINS: list[str] = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001").split(",")
        if origin.strip()
    ]
    
    # Limits & Bounds
    MAX_UPLOAD_BYTES: int = int(os.getenv("MAX_UPLOAD_BYTES", "10485760")) # 10MB
    MAX_ATTACHMENT_SIZE_BYTES: int = 5 * 1024 * 1024 # 5MB per attachment
    MAX_ARCHIVE_ENTRIES: int = 50
    REQUEST_TIMEOUT_SECONDS: int = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30"))
    FEATURE_INSIGHTS: bool = os.getenv("FEATURE_INSIGHTS", "true").lower() in ("true", "1", "yes") # FEATURE:insights

settings = Settings()
