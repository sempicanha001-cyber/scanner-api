"""
scanner_config.py — Configuration (pydantic-settings-free version).
Uses dataclass + os.getenv for full compatibility.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class ScannerConfig:
    # Network
    max_concurrency: int = 20
    request_timeout: int = 10
    delay_between_requests: float = 0.0

    # Security & Privacy
    verify_ssl: bool = True
    redact_secrets_in_logs: bool = True
    include_request_response_in_report: bool = True
    enable_hot_reload: bool = False

    # Shield / Engine Safeguards
    allow_private_targets: bool = False
    rate_limit_per_minute: int = 1000
    api_key_required: bool = False  # disabled by default for CLI

    # OAST Integration
    oast_provider: Optional[str] = "interact.sh"
    oast_timeout: int = 1

    # Reporting
    report_format: str = "html"
    include_cvss_vector: bool = True

    def __post_init__(self):
        """Load from environment variables if present."""
        self.max_concurrency     = int(os.getenv("MAX_CONCURRENCY", str(self.max_concurrency)))
        self.request_timeout     = int(os.getenv("SCAN_TIMEOUT", str(self.request_timeout)))
        self.verify_ssl          = os.getenv("VERIFY_SSL", "true").lower() != "false"
        self.allow_private_targets = os.getenv("ALLOW_PRIVATE", "false").lower() == "true"
        self.api_key_required    = os.getenv("API_KEY_REQUIRED", "false").lower() == "true"

    def dict(self) -> dict:
        return asdict(self)
