"""
core/metrics.py — Metrics stubs (prometheus_client not available).
Provides compatible Counter/Histogram/Gauge no-ops.
"""
from contextlib import contextmanager

class _Counter:
    def __init__(self, *a, **kw): pass
    def labels(self, **kw): return self
    def inc(self, n=1): pass

class _Gauge(_Counter):
    def dec(self, n=1): pass
    def set(self, v): pass

class _HistCtx:
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def observe(self, v): pass

class _Histogram:
    def __init__(self, *a, **kw): pass
    def labels(self, **kw): return self
    @contextmanager
    def time(self):
        yield
    def observe(self, v): pass

SCANNER_JOBS_TOTAL       = _Counter()
SCANNER_ACTIVE_JOBS      = _Gauge()
SCAN_PHASE_DURATION      = _Histogram()
SCANNER_FINDINGS_TOTAL   = _Counter()
RATE_LIMITED_REQS_TOTAL  = _Counter()
ACTIVE_SCANS_PER_TARGET  = _Gauge()
HTTP_REQUEST_DURATION    = _Histogram()

def generate_latest() -> bytes:
    return b"# metrics unavailable (prometheus_client not installed)\n"

CONTENT_TYPE_LATEST = "text/plain"
