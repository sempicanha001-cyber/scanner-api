import jwt
from supabase import create_client, Client
from app.config import settings
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

supabase: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_ANON_KEY)
supabase_admin: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)

security = HTTPBearer()

def verify_supabase_jwt(auth: HTTPAuthorizationCredentials = Security(security)):
    """Verifies the Supabase JWT and returns the user payload."""
    try:
        payload = jwt.decode(
            auth.credentials,
            settings.SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            audience="authenticated"
        )
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid authentication token: {str(e)}")

class SupabaseService:
    @staticmethod
    async def create_scan(user_id: str, target: str, scan_type: str):
        data = {
            "user_id": user_id,
            "target": target,
            "status": "pending",
            "scan_type": scan_type
        }
        res = supabase_admin.table("scans").insert(data).execute()
        return res.data[0] if res.data else None

    @staticmethod
    async def save_vulnerability(scan_id: str, vuln_data: dict):
        res = supabase_admin.table("vulnerabilities").insert({
            "scan_id": scan_id,
            **vuln_data
        }).execute()
        return res.data

    @staticmethod
    async def get_user_scans(user_id: str):
        res = supabase_admin.table("scans").select("*").eq("user_id", user_id).execute()
        return res.data

service = SupabaseService()
