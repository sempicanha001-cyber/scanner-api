"""
core/engine.py — Async HTTP Engine (httpx-compatible, built on requests + asyncio)
Drop-in replacement when httpx is not available.
"""
from __future__ import annotations

import asyncio
import random
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Coroutine, Dict, List, Optional
from urllib.parse import urlparse
import ipaddress
import requests as _requests

from core.logger import logger
from core.metrics import RATE_LIMITED_REQS_TOTAL

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "PostmanRuntime/7.36.1",
    "curl/8.6.0",
]

_SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key", "token", "session"}
_SENSITIVE_PATTERNS = [
    re.compile(r"Bearer\s+[a-zA-Z0-9\-\._~+/]+=*", re.I),
    re.compile(r"ey[a-zA-Z0-9+_=\-\.]+", re.I),
]


@dataclass
class Response:
    url:        str
    method:     str
    status:     int            = 0
    headers:    Dict[str, str] = field(default_factory=dict)
    body:       str            = ""
    elapsed_ms: float          = 0.0
    error:      Optional[str]  = None

    @property
    def ok(self) -> bool:
        return self.error is None and 0 < self.status < 400

    @property
    def headers_lower(self) -> Dict[str, str]:
        return {k.lower(): v for k, v in self.headers.items()}

    def json(self) -> Any:
        import json
        try:
            return json.loads(self.body)
        except Exception:
            return None


class AsyncEngine:
    """
    Async HTTP engine using requests + ThreadPoolExecutor.
    API-compatible with the original httpx-based AsyncEngine.
    """

    def __init__(
        self,
        *,
        concurrency: int = 20,
        timeout: int = 10,
        max_retries: int = 3,
        delay: float = 0.0,
        stealth: bool = False,
        verify_ssl: bool = True,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        dry_run: bool = False,
        allow_internal: bool = False,
        on_security_event: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]] = None,
    ):
        self.concurrency      = min(concurrency, 50)
        self.timeout          = timeout
        self.max_retries      = max_retries
        self.base_delay       = delay
        self.stealth          = stealth
        self.verify_ssl       = verify_ssl
        self.base_headers     = headers or {}
        self.proxy            = proxy
        self.dry_run          = dry_run
        self.allow_internal   = allow_internal
        self.on_security_event = on_security_event
        self.rate_limit_per_minute = 1000

        self._semaphore       = asyncio.Semaphore(concurrency)
        self._executor        = ThreadPoolExecutor(max_workers=min(concurrency, 32))
        self._session         = _requests.Session()
        self._req_count       = 0
        self._err_count       = 0
        self._lock            = asyncio.Lock()
        self._host_requests: Dict[str, List[float]] = {}
        self._global_requests: List[float] = []
        self.consecutive_errors: Dict[str, int] = {}
        self.waf_name: Optional[str] = None
        self.waf_confidence: float = 0.0

        if proxy:
            self._session.proxies = {"http": proxy, "https": proxy}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        self._executor.shutdown(wait=False)

    def _get_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {"User-Agent": random.choice(_USER_AGENTS), "Accept": "*/*"}
        h.update(self.base_headers)
        if extra:
            h.update(extra)
        return h

    async def _is_ssrf_risk(self, url: str) -> bool:
        if self.allow_internal:
            return False
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return True
            # FIX #4: get_event_loop() is deprecated inside async context (raises RuntimeError in
            # Python 3.12+). Use get_running_loop() which always returns the active loop.
            loop = asyncio.get_running_loop()
            ip_addr = await loop.run_in_executor(None, socket.gethostbyname, hostname)
            ip = ipaddress.ip_address(ip_addr)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                if self.on_security_event:
                    await self.on_security_event({"url": url, "reason": f"{ip} is internal", "category": "ssrf_blocked"})
                return True
            return False
        except Exception:
            return True

    def _sync_request(self, method: str, url: str, headers: dict,
                      params=None, json=None, data=None) -> Response:
        t0 = time.perf_counter()
        try:
            r = self._session.request(
                method.upper(), url,
                headers=headers, params=params,
                json=json, data=data,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            elapsed = (time.perf_counter() - t0) * 1000
            return Response(
                url=url, method=method,
                status=r.status_code,
                headers=dict(r.headers),
                body=r.text,
                elapsed_ms=elapsed,
            )
        except _requests.Timeout:
            elapsed = (time.perf_counter() - t0) * 1000
            return Response(url=url, method=method, elapsed_ms=elapsed, error="Timeout")
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return Response(url=url, method=method, elapsed_ms=elapsed, error=str(e))

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params=None,
        json=None,
        data=None,
    ) -> Response:
        if await self._is_ssrf_risk(url):
            return Response(url=url, method=method, error="SSRF_PROTECTION_TRIGGERED")

        target_host = urlparse(url).hostname or "unknown"
        async with self._lock:
            now = time.time()
            self._host_requests.setdefault(target_host, [])
            self._host_requests[target_host] = [t for t in self._host_requests[target_host] if now - t < 1.0]
            if len(self._host_requests[target_host]) >= 10:
                RATE_LIMITED_REQS_TOTAL.labels(source="internal_host").inc()
                await asyncio.sleep(1.0)
                now = time.time()
            self._host_requests[target_host].append(now)
            if self.consecutive_errors.get(target_host, 0) >= 5:
                return Response(url=url, method=method, error="WAF_BLOCK_ESTABLISHED")

        async with self._semaphore:
            if self.base_delay > 0:
                await asyncio.sleep(self.base_delay)
            if self.dry_run:
                return Response(url=url, method=method, status=200, body="[DRY-RUN]")

            full_headers = self._get_headers(headers)
            loop = asyncio.get_running_loop()  # FIX #4: get_running_loop() safe in async context
            resp = await loop.run_in_executor(
                self._executor,
                lambda: self._sync_request(method, url, full_headers, params, json, data)
            )
            async with self._lock:
                self._req_count += 1
                if resp.status in (403, 429):
                    self.consecutive_errors[target_host] = self.consecutive_errors.get(target_host, 0) + 1
                    RATE_LIMITED_REQS_TOTAL.labels(source="external_waf").inc()
                elif resp.ok:
                    self.consecutive_errors[target_host] = 0
            self._detect_waf_passive(resp)
            return resp

    async def get(self, url: str, **kw) -> Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> Response:
        return await self.request("POST", url, **kw)

    _WAF_HEADER_SIGS = {
        "Cloudflare": ["cf-ray", "cloudflare"],
        "AWS WAF":    ["x-amzn-requestid", "awselb"],
        "Akamai":     ["x-akamai-request-id"],
    }

    def _detect_waf_passive(self, resp: Response) -> None:
        h = str(resp.headers_lower).lower()
        for waf, sigs in self._WAF_HEADER_SIGS.items():
            if any(s in h for s in sigs):
                self.waf_name = waf
                self.waf_confidence = 80.0

    async def fingerprint(self, base_url: str) -> List[str]:
        resp = await self.get(base_url)
        if not resp.ok:
            return []
        techs = []
        h = resp.headers_lower
        if "nginx" in h.get("server", "").lower():
            techs.append("Nginx")
        if "apache" in h.get("server", "").lower():
            techs.append("Apache")
        if "express" in h.get("x-powered-by", "").lower():
            techs.append("Express.js")
        return list(set(techs))

    @property
    def request_count(self) -> int:
        return self._req_count
