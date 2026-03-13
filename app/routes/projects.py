from fastapi import APIRouter, Depends
from app.core.supabase import verify_supabase_jwt

router = APIRouter(prefix="/projects", tags=["projects"])

@router.get("/")
async def list_projects(user: dict = Depends(verify_supabase_jwt)):
    # In a real scenario, this would call Supabase to list user projects
    return {"projects": []}

@router.post("/")
async def create_project(name: str, user: dict = Depends(verify_supabase_jwt)):
    return {"message": f"Project {name} created", "id": "proj-uuid"}
