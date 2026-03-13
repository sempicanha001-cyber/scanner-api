import asyncio
from celery import Celery
from app.config import settings
from app.core.supabase import supabase_admin
from app.services.scanner_engine import AsyncEngine
from app.models.scan import ScanResult
import json
from datetime import datetime

celery_app = Celery("scanner_worker", broker=settings.CELERY_BROKER_URL)
celery_app.conf.update(result_backend=settings.CELERY_RESULT_BACKEND)

@celery_app.task(name="run_scan_task")
def run_scan_task(scan_id: str, target: str, scan_type: str, user_id: str):
    """Orchestrates the asynchronous scan via the AsyncEngine and persists results."""
    
    async def _execute():
        # Update status to 'running'
        supabase_admin.table("scans").update({"status": "running"}).eq("id", scan_id).execute()
        
        async with AsyncEngine(concurrency=settings.DEFAULT_CONCURRENCY) as engine:
            from app.services.vulnerability_analyzer.sqli import SQLIPlugin # Example
            # In a real scenario, discovery and other plugins would be instantiated here.
            # For simplicity in this step, we simulate the orchestration layer from the reference scanner.
            
            # Simulated result for now - will be replaced by the full orchestrator logic.
            result = ScanResult(target=target, scan_type=scan_type)
            # ... (Logic to run all plugins) ...
            
            # Persist findings
            for finding in result.findings:
                supabase_admin.table("vulnerabilities").insert({
                    "scan_id": scan_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "description": finding.description,
                    "user_id": user_id
                }).execute()
        
        # Update status to 'completed'
        supabase_admin.table("scans").update({
            "status": "completed",
            "completed_at": datetime.utcnow().isoformat()
        }).eq("id", scan_id).execute()

    # Create new event loop for synchronous Celery worker to run async code
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_execute())
    finally:
        loop.close()
