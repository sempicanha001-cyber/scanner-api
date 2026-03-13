"""
api.py — FastAPI web layer with Celery + Redis integration.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv

# Optional: starlette rate limiting for lightweight production usage
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request

load_dotenv()

# Setup Rate Limiter
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

app = FastAPI(title="Vulnexus API Scanner", version="2.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
API_KEY   = os.getenv("SCANNER_API_KEY") or secrets.token_hex(16)
ALLOW_PRIVATE = os.getenv("ALLOW_PRIVATE", "false").lower() == "true"

# FIX #7: Regex for valid scan_id — exactly 8 uppercase hex chars (format enforced at creation)
_SCAN_ID_RE = re.compile(r'^[A-F0-9]{8}$')

# FIX: Do not print API key to logs — log a masked version only
_masked = API_KEY[:4] + "****" + API_KEY[-2:]
print(f"[*] API key loaded: {_masked}")

# ── Private/internal IP ranges blocked for SSRF ──────────────────────────────
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254.",
    "::1", "fc", "fd",
)
_PRIVATE_HOSTS = {"localhost", "redis", "prometheus", "grafana", "flower",
                  "redis-exporter", "nginx", "worker", "beat"}


def _validate_target_url(target: str) -> str:
    """Validate target URL — reject SSRF targets unless ALLOW_PRIVATE=true."""
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Target must use http:// or https:// scheme")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("Target must include a hostname")
    if not ALLOW_PRIVATE:
        if host.lower() in _PRIVATE_HOSTS:
            raise ValueError(f"Target '{host}' is a private/internal host")
        if any(host.startswith(p) for p in _PRIVATE_PREFIXES):
            raise ValueError(f"Target '{host}' resolves to a private IP range")
        try:
            ip = ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise ValueError(f"Target IP {host} is private/reserved")
        except ValueError as e:
            if "is private" in str(e) or "is loopback" in str(e):
                raise
            pass  # hostname, not IP — engine handles DNS SSRF
    return target.rstrip("/")


# ── Lifespan (replaces deprecated on_event) ──────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    r = await get_redis()
    await r.ping()
    print("[*] Redis connected")
    yield
    # Shutdown
    global _redis_pool
    if _redis_pool:
        await _redis_pool.aclose()
        _redis_pool = None


app = FastAPI(title="API Security Scanner Pro", version="2.0.0", lifespan=lifespan)

# FIX: CORS from env — restrict in production via CORS_ORIGINS env var
_cors_origins_raw = os.getenv("CORS_ORIGINS", "*")
_cors_origins = [o.strip() for o in _cors_origins_raw.split(",")] if _cors_origins_raw != "*" else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["x-api-key", "content-type"],
)

_redis_pool: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = aioredis.from_url(
            REDIS_URL, encoding="utf-8", decode_responses=True, max_connections=20
        )
    return _redis_pool


from core.supabase import verify_supabase_jwt

async def verify_token(payload: dict = Depends(verify_supabase_jwt)):
    # The payload is authenticated using Supabase's JWT secret
    # Extract the user_id (tenant) to isolate scans
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=403, detail="Invalid User Context")
    return user_id


class ScanRequest(BaseModel):
    target: str = Field(..., max_length=2048)  # FIX 10: prevent unbounded input
    scan_type: str = "full"
    auth: Optional[str] = None
    auth_attacker: Optional[str] = None
    threads: int = 20
    encrypt_result: bool = False

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_target_url(v)

    @field_validator("scan_type")
    @classmethod
    def valid_scan_type(cls, v: str) -> str:
        valid = {"quick", "auth", "inject", "api", "full", "stealth", "custom"}
        if v not in valid:
            raise ValueError(f"scan_type must be one of {valid}")
        return v

    @field_validator("threads")
    @classmethod
    def clamp_threads(cls, v: int) -> int:
        return max(1, min(v, 50))


async def _get_scan_state(r: aioredis.Redis, scan_id: str) -> Optional[Dict[str, Any]]:
    raw = await r.hgetall(f"scan_state:{scan_id}")
    if not raw:
        return None
    result = {}
    for k, v in raw.items():
        try:
            result[k] = json.loads(v)
        except (json.JSONDecodeError, TypeError):
            result[k] = v
    return result


# FIX: Replace KEYS with SCAN cursor to avoid O(N) blocking
async def _scan_keys(r: aioredis.Redis, pattern: str) -> List[str]:
    """Non-blocking Redis key scan using SCAN cursor."""
    keys = []
    cursor = 0
    while True:
        cursor, batch = await r.scan(cursor, match=pattern, count=100)
        keys.extend(batch)
        if cursor == 0:
            break
    return keys


@app.post("/scans", dependencies=[])
async def start_scan(req: ScanRequest, user_id: str = Depends(verify_token)):
    from celery_app import run_scan
    scan_id = str(uuid.uuid4())[:8].upper()
    r = await get_redis()
    await r.hset(f"scan_state:{scan_id}", mapping={
        "id": scan_id, "status": "queued", "target": req.target,
        "scan_type": req.scan_type, "queued_at": datetime.utcnow().isoformat() + "Z",
        "findings": "[]", "result": "null", "error": "null", "celery_task_id": "pending",
        "user_id": user_id  # Multi-tenant isolation binding
    })
    await r.expire(f"scan_state:{scan_id}", 3600)
    
    # Supabase persistent sync example (Fires asynchronously into the worker)
    # The worker will update the remote DB, but we initialize it in the DB immediately.
    try:
        from core.supabase import get_supabase
        supabase = get_supabase()
        supabase.table("scans").insert({
            "id": scan_id, "user_id": user_id, "target": req.target,
            "status": "queued", "scan_type": req.scan_type
        }).execute()
    except Exception as e:
        print(f"Supabase sync err (queued state): {e}")

    task = run_scan.apply_async(
        kwargs={
            "scan_id": scan_id, "target": req.target, "scan_type": req.scan_type,
            "threads": req.threads, "auth": req.auth, "auth_attacker": req.auth_attacker,
            "encrypt_result": req.encrypt_result, "user_id": user_id
        },
        task_id=f"scan-{scan_id}",
        queue="scans",
    )
    await r.hset(f"scan_state:{scan_id}", "celery_task_id", task.id)
    return {"scan_id": scan_id, "status": "queued", "target": req.target, "celery_task_id": task.id}


@app.get("/scans/{scan_id}", dependencies=[])
async def get_scan(scan_id: str, user_id: str = Depends(verify_token)):
    # FIX #7: Validate scan_id format to prevent Redis key injection
    if not _SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
    r = await get_redis()
    state = await _get_scan_state(r, scan_id)
    if not state or state.get("user_id") != user_id:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return state


@app.delete("/scans/{scan_id}", dependencies=[Depends(verify_token)])
async def cancel_scan(scan_id: str):
    # FIX #7: Validate scan_id format
    if not _SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
    from celery_app import app as celery_app
    r = await get_redis()
    state = await _get_scan_state(r, scan_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    task_id = state.get("celery_task_id")
    if task_id and task_id != "pending":
        celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
    await r.hset(f"scan_state:{scan_id}", mapping={"status": "cancelled"})
    await r.expire(f"scan_state:{scan_id}", 300)  # Expire cancelled scans sooner
    await r.publish(f"scan:{scan_id}", json.dumps({"type": "status", "data": "cancelled"}))
    return {"scan_id": scan_id, "status": "cancelled"}


@app.get("/scans", dependencies=[])
async def list_scans(user_id: str = Depends(verify_token)):
    r = await get_redis()
    # FIX: Use non-blocking SCAN cursor instead of KEYS
    keys = await _scan_keys(r, "scan_state:*")
    scans = []
    for key in keys:
        sid = key.replace("scan_state:", "")
        state = await _get_scan_state(r, sid)
        # Ensure multi-tenant isolation
        if state and state.get("user_id") == user_id:
            scans.append({
                "id": state.get("id", sid),
                "target": state.get("target", ""),
                "status": state.get("status", "unknown"),
                "scan_type": state.get("scan_type", ""),
            })
    scans.sort(key=lambda x: x.get("id", ""), reverse=True)
    return scans


@app.get("/health")
async def health():
    r = await get_redis()
    redis_ok = False
    try:
        await r.ping()
        redis_ok = True
    except Exception:
        pass

    worker_count = 0
    try:
        from celery_app import app as celery_app
        inspect = celery_app.control.inspect(timeout=1)
        active = inspect.active()
        worker_count = len(active) if active else 0
    except Exception:
        pass

    # FIX: Use SCAN cursor instead of KEYS
    active_scans = len(await _scan_keys(r, "scan_state:*")) if redis_ok else -1

    # Check Ollama/AI availability
    ai_available = False
    ai_model = None
    try:
        from ai.llm_client import get_client as get_llm_client
        llm = get_llm_client()
        ai_available = llm.is_available()
        ai_model = llm.model if ai_available else None
    except Exception:
        pass

    return {
        "status": "ok" if redis_ok else "degraded",
        "redis": "connected" if redis_ok else "disconnected",
        "workers": worker_count,
        "active_scans": active_scans,
        "version": "2.0.0",
        "ai": {
            "available": ai_available,
            "model": ai_model,
            "backend": "ollama",
        },
    }


# ── AI analysis endpoint ──────────────────────────────────────────────────────

@app.get("/scans/{scan_id}/ai", dependencies=[Depends(verify_token)])
async def get_ai_analysis(scan_id: str):
    """
    Return AI analysis results for a completed scan.
    AI analysis runs asynchronously after scan completion.
    Status can be: 'running', 'completed', 'skipped', 'failed', or 'not_found'.
    """
    # FIX #7: Validate scan_id format
    if not _SCAN_ID_RE.match(scan_id):
        return JSONResponse(status_code=400, content={"error": "Invalid scan_id format"})
    r = await get_redis()
    raw = await r.get(f"ai_analysis:{scan_id}")
    if not raw:
        # Check if the scan itself exists
        scan_state = await _get_scan_state(r, scan_id)
        if not scan_state:
            return JSONResponse(status_code=404, content={"error": "Scan not found"})
        return {
            "scan_id": scan_id,
            "status": "pending",
            "message": "AI analysis has not started yet. It begins automatically after scan completion.",
        }
    import json as _json
    try:
        return _json.loads(raw)
    except _json.JSONDecodeError:
        # FIX 3: Redis may store truncated data if worker crashed mid-write
        return JSONResponse(
            status_code=500,
            content={"error": "AI analysis result corrupted. Try POST /scans/{id}/ai/retry", "scan_id": scan_id},
        )


@app.post("/scans/{scan_id}/ai/retry", dependencies=[Depends(verify_token)])
async def retry_ai_analysis(scan_id: str):
    """
    Manually trigger AI analysis for a completed scan.
    Useful if Ollama was unavailable during the initial analysis.
    """
    # FIX #7: Validate scan_id format
    if not _SCAN_ID_RE.match(scan_id):
        return JSONResponse(status_code=400, content={"error": "Invalid scan_id format"})
    r = await get_redis()
    scan_state = await _get_scan_state(r, scan_id)
    if not scan_state:
        return JSONResponse(status_code=404, content={"error": "Scan not found"})

    status = scan_state.get("status")
    if status != "completed":
        return JSONResponse(
            status_code=409,
            content={"error": f"Scan is '{status}'. AI analysis only runs on completed scans."},
        )

    import json as _json
    findings_raw = scan_state.get("findings", "[]")
    findings = _json.loads(findings_raw) if isinstance(findings_raw, str) else findings_raw
    result_raw = scan_state.get("result", "{}")
    result = _json.loads(result_raw) if isinstance(result_raw, str) else result_raw
    summary = result.get("summary", {}) if isinstance(result, dict) else {}
    target = scan_state.get("target", "")

    from celery_app import run_ai_analysis
    task = run_ai_analysis.apply_async(
        kwargs={
            "scan_id":  scan_id,
            "findings": findings,
            "target":   target,
            "summary":  summary,
        },
        queue="ai",
    )

    return {"scan_id": scan_id, "task_id": task.id, "status": "queued"}


# ── Prometheus metrics endpoint ───────────────────────────────────────────────
# FIX #6: Added verify_token dependency — previously unprotected, leaked internal state.
# For Prometheus scraping, generate a dedicated read-only token via SCANNER_API_KEY env var
# and configure it in prometheus.yml scrape_configs as a Bearer token.
@app.get("/metrics", dependencies=[Depends(verify_token)])
async def metrics():
    """
    Prometheus-compatible metrics endpoint.
    NOTE: This endpoint is internal — protect it via Nginx or network policy.
    """
    r = await get_redis()
    try:
        # FIX: Use SCAN cursor instead of KEYS
        keys = await _scan_keys(r, "scan_state:*")
        total = len(keys)
        status_counts: Dict[str, int] = {}
        for key in keys:
            status = await r.hget(key, "status") or "unknown"
            status_counts[status] = status_counts.get(status, 0) + 1
    except Exception:
        total = -1
        status_counts = {}

    lines = [
        "# HELP scanner_active_scans Number of scan state keys in Redis",
        "# TYPE scanner_active_scans gauge",
        f"scanner_active_scans {total}",
        "",
        "# HELP scanner_scans_by_status Total scans by status",
        "# TYPE scanner_scans_by_status gauge",
    ]
    for status, count in status_counts.items():
        lines.append(f'scanner_scans_by_status{{status="{status}"}} {count}')

    lines += [
        "",
        "# HELP scanner_redis_up Redis connectivity (1=up, 0=down)",
        "# TYPE scanner_redis_up gauge",
        f"scanner_redis_up {1 if total >= 0 else 0}",
        "",
        "# HELP scanner_api_info API version info",
        "# TYPE scanner_api_info gauge",
        'scanner_api_info{version="2.0.0"} 1',
    ]

    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    scan_id: str,
    token: str = Query(..., description="API key — same as x-api-key header"),
):
    # FIX #5: WebSocket had NO authentication — any client could stream live findings.
    # WS protocol does not support custom headers during the handshake in all browsers,
    # so the API key is passed as a query param (?token=...) and validated before accept().
    if token != API_KEY:
        await websocket.close(code=1008, reason="Invalid API key")
        return

    # FIX #7: Validate scan_id format before using it in Redis keys
    if not _SCAN_ID_RE.match(scan_id):
        await websocket.close(code=1008, reason="Invalid scan_id format")
        return

    await websocket.accept()
    pubsub_redis = aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    pubsub = pubsub_redis.pubsub()
    channel = f"scan:{scan_id}"
    try:
        r = await get_redis()
        state = await _get_scan_state(r, scan_id)
        if state is None:
            await websocket.send_json({"type": "error", "data": f"Scan {scan_id} not found"})
            return

        buffered = state.get("findings", [])
        if isinstance(buffered, list):
            for f in buffered:
                await websocket.send_json({"type": "finding", "data": f})

        await websocket.send_json({"type": "status", "data": state.get("status", "unknown")})

        terminal = {"completed", "failed", "cancelled"}
        if state.get("status") in terminal:
            if state.get("status") == "completed" and state.get("result"):
                await websocket.send_json({
                    "type": "status", "data": "completed", "result": state.get("result")
                })
            return

        await pubsub.subscribe(channel)

        async def read_pubsub():
            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                try:
                    event = json.loads(message["data"])
                except json.JSONDecodeError:
                    continue
                await websocket.send_json(event)
                if event.get("type") == "status" and event.get("data") in terminal:
                    return

        async def read_ws():
            while True:
                try:
                    data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                    msg = json.loads(data)
                    if msg.get("type") == "ping":
                        await websocket.send_json({"type": "pong"})
                except asyncio.TimeoutError:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    return

        done, pending = await asyncio.wait(
            [asyncio.create_task(read_pubsub()), asyncio.create_task(read_ws())],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except Exception:
            pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
        await pubsub_redis.aclose()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
