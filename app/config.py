import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    PROJECT_NAME = "Vulnexus AI Scanner"
    VERSION = "2.0.0"
    
    # Security
    SECRET_KEY = os.getenv("SCANNER_API_KEY", "dev-secret-key")
    ENCRYPTION_KEY = os.getenv("SCANNER_ENCRYPTION_KEY", "dev-encryption-key")
    
    # Supabase
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
    SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
    
    # Redis & Celery
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", REDIS_URL)
    CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)
    
    # Scanner
    ALLOW_PRIVATE = os.getenv("ALLOW_PRIVATE", "false").lower() == "true"
    DEFAULT_CONCURRENCY = int(os.getenv("MAX_CONCURRENCY", "10"))
    SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "600"))

settings = Config()
