import os
import jwt
from supabase import create_client, Client
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET")

# Fast fail on missing critical SaaS credentials
if not all([SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_JWT_SECRET]):
    print("WARNING: Supabase SaaS environment variables are missing.")

def get_supabase() -> Client:
    """Returns the Supabase Service Role client to bypass RLS for internal server logic."""
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


security = HTTPBearer()

def verify_supabase_jwt(credentials: HTTPAuthorizationCredentials = Security(security)):
    """
    Middleware to verify Supabase Auth tokens passed in requests.
    Decodes the JWT using the project's secret and returns the user payload.
    """
    token = credentials.credentials
    try:
        # Supabase JWTs are typically encoded with HS256
        payload = jwt.decode(
            token,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            options={"verify_aud": False}  # Adjust audience verification as needed
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid auth token")

