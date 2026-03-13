from fastapi import APIRouter, Depends, HTTPException
from typing import List
from app.core.supabase import verify_supabase_jwt, service
from app.workers.celery_worker import run_scan_task

router = APIRouter(prefix="/scans", tags=["scans"])

@router.post("/")
async def start_scan(target: str, scan_type: str = "full", user: dict = Depends(verify_supabase_jwt)):
    # Create scan record in Supabase
    scan = await service.create_scan(user["sub"], target, scan_type)
    if not scan:
        raise HTTPException(status_code=500, detail="Failed to create scan record")
    
    # Trigger Celery task
    run_scan_task.delay(scan["id"], target, scan_type, user["sub"])
    
    return {"message": "Scan started", "scan_id": scan["id"]}

@router.get("/")
async def list_scans(user: dict = Depends(verify_supabase_jwt)):
    scans = await service.get_user_scans(user["sub"])
    return scans
