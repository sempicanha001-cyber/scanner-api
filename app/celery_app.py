"""
celery_app.py — Celery configuration and scan task definitions.

This module is the bridge between the FastAPI web layer and the
scanner engine. The API enqueues tasks; Celery workers execute them
in separate processes, storing progress/results in Redis.
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from typing import Any, Dict, Optional

import redis as redis_sync
from celery import Celery
from celery.schedules import crontab
from celery.utils.log import get_task_logger

# ── Celery configuration ──────────────────────────────────────────────────────

BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")

app = Celery(
    "scanner",
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
)

app.conf.update(
    # Serialization
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    # Routing — all scan tasks go to the "scans" queue
    task_routes={"celery_app.run_scan": {"queue": "scans"}},
    task_default_queue="scans",

    # Reliability
    task_acks_late=True,           # Ack only after task succeeds (prevents loss on crash)
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,  # One task at a time per worker slot (scans are heavy)

    # Results
    result_expires=3600,           # Keep results for 1 hour
    result_extended=True,          # Store task name, args, kwargs in result

    # Time limits — scans can be long
    task_soft_time_limit=600,      # 10 min soft limit → raises SoftTimeLimitExceeded
    task_time_limit=660,           # 11 min hard kill

    # Beat schedule (periodic tasks)
    beat_schedule={
        "cleanup-stale-scans": {
            "task": "celery_app.cleanup_stale_scans",
            "schedule": crontab(minute="*/30"),  # Every 30 min
        },
    },
    timezone="UTC",
)

logger = get_task_logger(__name__)

# ── Redis client (for publishing progress events) ────────────────────────────

def get_redis() -> redis_sync.Redis:
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    return redis_sync.from_url(redis_url, decode_responses=True)


def _publish(r: redis_sync.Redis, scan_id: str, event: dict) -> None:
    """Publish a scan event to Redis pub/sub channel."""
    channel = f"scan:{scan_id}"
    r.publish(channel, json.dumps(event))


def _set_scan_state(r: redis_sync.Redis, scan_id: str, data: dict) -> None:
    """Persist current scan state to Redis hash (for REST polling)."""
    key = f"scan_state:{scan_id}"
    # Store each field as a hash entry — JSON-encode complex values
    flat = {
        k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        for k, v in data.items()
    }
    r.hset(key, mapping=flat)
    r.expire(key, 3600)  # TTL 1 hour


# ── Main scan task ────────────────────────────────────────────────────────────

@app.task(bind=True, name="celery_app.run_scan", max_retries=2)
def run_scan(
    self,
    scan_id: str,
    target: str,
    scan_type: str = "full",
    threads: int = 20,
    auth: Optional[str] = None,
    auth_attacker: Optional[str] = None,
    encrypt_result: bool = False,
) -> Dict[str, Any]:
    """
    Execute a full security scan.

    This task:
    1. Runs the async scanner inside asyncio.run()
    2. Publishes findings in real-time to Redis pub/sub
    3. Persists state to Redis so the API can answer polling requests
    4. Returns the final result dict (stored by Celery backend)
    """
    r = get_redis()
    findings_buffer: list = []

    # ── Initial state ──────────────────────────────────────────────────────
    _set_scan_state(r, scan_id, {
        "id": scan_id,
        "status": "running",
        "target": target,
        "scan_type": scan_type,
        "started_at": datetime.utcnow().isoformat() + "Z",
        "findings": [],
        "result": None,
        "error": None,
        "celery_task_id": self.request.id,
    })
    _publish(r, scan_id, {"type": "status", "data": "running"})
    logger.info(f"[{scan_id}] Scan started: {target} ({scan_type})")

    # ── Update Celery task state (visible in Flower) ───────────────────────
    self.update_state(state="PROGRESS", meta={"scan_id": scan_id, "status": "running", "target": target})

    # ── Run async scanner in sync context ─────────────────────────────────
    async def _async_scan() -> Dict[str, Any]:
        from core.engine import AsyncEngine
        from scanner import Scanner
        from scanner_config import ScannerConfig
        from core.crypto import shield

        headers: dict = {}
        if auth:
            headers["Authorization"] = auth if " " in auth else f"Bearer {auth}"

        engine = AsyncEngine(
            concurrency=min(threads, 50),
            timeout=int(os.getenv("SCAN_TIMEOUT", "10")),
            delay=0.0,
            headers=headers,
            allow_internal=os.getenv("ALLOW_PRIVATE", "false").lower() == "true",
        )

        async def on_finding(finding):
            data = finding.to_dict() if hasattr(finding, "to_dict") else {}
            if encrypt_result:
                data = {"encrypted": True, "payload": shield.encrypt(json.dumps(data))}
            findings_buffer.append(data)
            # Update Redis state with latest findings
            _set_scan_state(r, scan_id, {"findings": findings_buffer})
            # Publish real-time event
            _publish(r, scan_id, {"type": "finding", "data": data})

        scanner = Scanner(
            target=target,
            engine=engine,
            scan_type=scan_type,
            config=ScannerConfig(),
            on_finding=on_finding,
        )

        async with engine:
            result = await scanner.run()

        res_dict = result.to_dict() if hasattr(result, "to_dict") else {}
        if encrypt_result:
            res_dict = {"encrypted": True, "payload": shield.encrypt(json.dumps(res_dict))}
        return res_dict

    try:
        result_dict = asyncio.run(_async_scan())

        # ── Success ────────────────────────────────────────────────────────
        _set_scan_state(r, scan_id, {
            "status": "completed",
            "result": result_dict,
            "findings": findings_buffer,
            "completed_at": datetime.utcnow().isoformat() + "Z",
        })
        _publish(r, scan_id, {
            "type": "status",
            "data": "completed",
            "result": result_dict,
        })
        logger.info(f"[{scan_id}] Scan completed. Findings: {len(findings_buffer)}")

        # ── Dispatch async AI analysis (non-blocking) ──────────────────────
        # Fires-and-forgets: scanner result is returned immediately.
        # AI enrichment is stored separately under ai_analysis:{scan_id}.
        try:
            summary_for_ai = result_dict.get("summary", {}) if isinstance(result_dict, dict) else {}
            run_ai_analysis.apply_async(
                kwargs={
                    "scan_id":  scan_id,
                    "findings": findings_buffer,
                    "target":   target,
                    "summary":  summary_for_ai,
                },
                queue="ai",
            )
            logger.info(f"[{scan_id}] AI analysis task dispatched.")
        except Exception as ai_exc:
            # Non-fatal: AI task failure must never break scan delivery
            logger.warning(f"[{scan_id}] Could not dispatch AI task: {ai_exc}")

        return {"scan_id": scan_id, "status": "completed", "result": result_dict}


    except Exception as exc:
        error_msg = str(exc)
        logger.error(f"[{scan_id}] Scan failed: {error_msg}")

        _set_scan_state(r, scan_id, {
            "status": "failed",
            "error": error_msg,
            "completed_at": datetime.utcnow().isoformat() + "Z",
        })
        _publish(r, scan_id, {"type": "status", "data": "failed", "error": error_msg})

        # Retry up to 2 times with 30s delay (not for intentional errors)
        if "timeout" in error_msg.lower() or "connection" in error_msg.lower():
            raise self.retry(exc=exc, countdown=30)

        return {"scan_id": scan_id, "status": "failed", "error": error_msg}


# ── Periodic cleanup task ─────────────────────────────────────────────────────

@app.task(name="celery_app.cleanup_stale_scans")
def cleanup_stale_scans() -> Dict[str, int]:
    """
    Ensure all scan_state keys have a TTL — safety net for Redis memory.
    Runs every 30 minutes via Beat.
    Uses SCAN cursor (non-blocking) instead of KEYS (O(N) blocking).
    """
    r = get_redis()
    cleaned = 0
    total = 0
    cursor = 0
    while True:
        cursor, keys = r.scan(cursor, match="scan_state:*", count=100)
        total += len(keys)
        for key in keys:
            ttl = r.ttl(key)
            if ttl == -1:   # Key has no TTL — set one
                r.expire(key, 3600)
                cleaned += 1
        if cursor == 0:
            break
    logger.info(f"Cleanup: fixed TTL on {cleaned}/{total} stale keys")
    return {"cleaned": cleaned, "total_keys": total}


# ── AI Analysis task ──────────────────────────────────────────────────────────

@app.task(
    bind=True,
    name="celery_app.run_ai_analysis",
    max_retries=1,
    queue="ai",               # separate queue — won't block scan workers
    soft_time_limit=300,      # 5 min per analysis batch
    time_limit=360,
)
def run_ai_analysis(
    self,
    scan_id: str,
    findings: list,
    target: str,
    summary: dict,
) -> Dict[str, Any]:
    """
    Async Celery task: run AI analysis on completed scan findings.

    This task runs independently so it never blocks the scanner or API.
    Results are stored back in Redis under ai_analysis:{scan_id}.

    If Ollama is unavailable the task completes immediately with
    ai_available=False — the scanner result is unaffected.
    """
    r = get_redis()
    ai_key = f"ai_analysis:{scan_id}"

    # FIX 2: guard against None — Celery may deserialize missing args as None
    findings = findings or []

    # Mark as in-progress
    r.set(ai_key, json.dumps({"status": "running", "scan_id": scan_id}), ex=3600)
    logger.info(f"[AI] Starting analysis for scan {scan_id} ({len(findings)} findings)")

    try:
        from ai.ai_analyzer import get_analyzer

        analyzer = get_analyzer()

        if not analyzer.available:
            result = {
                "status": "skipped",
                "scan_id": scan_id,
                "ai_available": False,
                "message": (
                    "Ollama not available. Install Ollama and run: ollama pull llama3. "
                    "See OLLAMA_SETUP.md for details."
                ),
                "findings_analysis": {},
                "executive_summary": None,
            }
            r.set(ai_key, json.dumps(result), ex=3600)
            logger.info(f"[AI] Ollama unavailable — skipping analysis for {scan_id}")
            return result

        # Analyze findings (prioritised, capped at 10 to keep runtime manageable)
        findings_analysis_raw = analyzer.analyze_findings_batch(findings, max_findings=10)
        findings_analysis = {
            fid: analysis.to_dict()
            for fid, analysis in findings_analysis_raw.items()
        }

        # Generate executive summary
        by_sev = summary.get("by_severity", {})
        top_vuln_types = list({
            f.get("vuln_type", "") for f in findings if f.get("vuln_type")
        })[:10]

        exec_summary = analyzer.generate_executive_summary(
            target=target,
            total_findings=summary.get("total", 0),
            critical=by_sev.get("CRITICAL", 0),
            high=by_sev.get("HIGH", 0),
            medium=by_sev.get("MEDIUM", 0),
            low=by_sev.get("LOW", 0),
            security_score=summary.get("security_score", 0),
            top_vuln_types=top_vuln_types,
        )

        result = {
            "status": "completed",
            "scan_id": scan_id,
            "ai_available": True,
            "model_used": analyzer.model_name,   # FIX 8: use public property
            "findings_analysis": findings_analysis,
            "executive_summary": exec_summary.to_dict(),
        }

        r.set(ai_key, json.dumps(result, default=str), ex=3600)
        logger.info(
            f"[AI] Analysis complete for {scan_id}. "
            f"Analyzed {len(findings_analysis)}/{len(findings)} findings."
        )
        return result

    except Exception as exc:
        error_msg = str(exc)
        logger.error(f"[AI] Analysis failed for {scan_id}: {error_msg}")

        error_result = {
            "status": "failed",
            "scan_id": scan_id,
            "ai_available": True,
            "error": error_msg,
            "findings_analysis": {},
            "executive_summary": None,
        }
        r.set(ai_key, json.dumps(error_result), ex=3600)
        return error_result
