"""
ai/llm_client.py — Local LLM client for Ollama
Connects to a locally-running Ollama server (http://localhost:11434).
Zero cloud dependencies — 100% free and local.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

def _safe_int(value: Optional[str], default: int) -> int:
    """Parse int from env var safely — never crashes on bad input."""
    try:
        return int(value)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return default

OLLAMA_BASE_URL   = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL      = os.getenv("OLLAMA_MODEL",    "llama3")
OLLAMA_TIMEOUT    = _safe_int(os.getenv("OLLAMA_TIMEOUT"),    120)   # FIX 1: safe int
OLLAMA_MAX_TOKENS = _safe_int(os.getenv("OLLAMA_MAX_TOKENS"), 1024)  # FIX 1: safe int

_AVAILABILITY_CACHE_TTL = 60.0   # FIX 4: re-check availability every 60 seconds


class OllamaUnavailableError(Exception):
    """Raised when the Ollama server cannot be reached."""


class OllamaClient:
    """
    Thin HTTP client for the Ollama /api/generate endpoint.

    Usage:
        client = OllamaClient()
        if client.is_available():
            text = client.generate("Explain SQL injection")
    """

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        model: str    = OLLAMA_MODEL,
        timeout: int  = OLLAMA_TIMEOUT,
    ) -> None:
        self.base_url  = base_url.rstrip("/")
        self.model     = model
        self.timeout   = timeout
        self._available: Optional[bool] = None     # FIX 4: TTL-based cache
        self._available_checked_at: float = 0.0    # FIX 4: timestamp of last check

    # ── Health check ──────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """
        Returns True if the Ollama server is reachable and the configured
        model is loaded (or can be loaded).
        Result is cached for 60 seconds — re-checked after TTL expires (FIX 4).
        """
        now = time.monotonic()
        # FIX 4: return cached value only if within TTL window
        if (
            self._available is not None
            and (now - self._available_checked_at) < _AVAILABILITY_CACHE_TTL
        ):
            return self._available

        try:
            resp = requests.get(
                f"{self.base_url}/api/tags",
                timeout=5,
            )
            if resp.status_code != 200:
                logger.warning("Ollama /api/tags returned %d", resp.status_code)
                self._available = False
                self._available_checked_at = time.monotonic()
                return False

            tags = resp.json().get("models", [])
            model_names = [m.get("name", "").split(":")[0] for m in tags]
            configured_base = self.model.split(":")[0]

            if configured_base not in model_names:
                logger.warning(
                    "Ollama model '%s' not found. Available: %s. "
                    "Run: ollama pull %s",
                    self.model, model_names, self.model,
                )
                self._available = True
                self._available_checked_at = time.monotonic()
                return True

            self._available = True
            self._available_checked_at = time.monotonic()
            logger.info("Ollama ready — model: %s", self.model)
            return True

        except (requests.ConnectionError, requests.Timeout) as exc:
            logger.warning("Ollama not reachable at %s: %s", self.base_url, exc)
            self._available = False
            self._available_checked_at = time.monotonic()
            return False

    # ── Core generate ─────────────────────────────────────────────────────────

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Send a prompt to Ollama and return the generated text.

        Raises OllamaUnavailableError if the server is not reachable.
        Raises RuntimeError on non-200 responses.
        """
        if not self.is_available():
            raise OllamaUnavailableError(
                f"Ollama server not available at {self.base_url}. "
                "Install Ollama and run: ollama pull llama3"
            )

        payload: Dict[str, Any] = {
            "model":  self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict":  OLLAMA_MAX_TOKENS,
                "temperature":  0.3,   # low temp → more deterministic security advice
                "top_p":        0.9,
                **(options or {}),
            },
        }

        if system:
            payload["system"] = system

        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
        except (requests.ConnectionError, requests.Timeout) as exc:
            self._available = False   # reset cache so next call retries
            raise OllamaUnavailableError(str(exc)) from exc

        if resp.status_code != 200:
            raise RuntimeError(
                f"Ollama returned HTTP {resp.status_code}: {resp.text[:300]}"
            )

        data = resp.json()
        response_text = data.get("response", "").strip()

        if not response_text:
            raise RuntimeError("Ollama returned an empty response.")

        return response_text

    # ── Chat (multi-turn) ─────────────────────────────────────────────────────

    def chat(
        self,
        messages: list[Dict[str, str]],
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Multi-turn chat via /api/chat.
        messages = [{"role": "user"|"assistant"|"system", "content": "..."}]
        """
        if not self.is_available():
            raise OllamaUnavailableError(
                f"Ollama server not available at {self.base_url}."
            )

        payload: Dict[str, Any] = {
            "model":    self.model,
            "messages": messages,
            "stream":   False,
            "options":  {
                "num_predict": OLLAMA_MAX_TOKENS,
                "temperature": 0.3,
                **(options or {}),
            },
        }

        try:
            resp = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout,
            )
        except (requests.ConnectionError, requests.Timeout) as exc:
            self._available = False
            raise OllamaUnavailableError(str(exc)) from exc

        if resp.status_code != 200:
            raise RuntimeError(
                f"Ollama /api/chat returned HTTP {resp.status_code}: {resp.text[:300]}"
            )

        try:
            return resp.json().get("message", {}).get("content", "").strip()
        except (ValueError, KeyError) as exc:
            raise RuntimeError(f"Ollama /api/chat returned malformed JSON: {exc}") from exc


# ── Module-level singleton (lazy) ─────────────────────────────────────────────

_client: Optional[OllamaClient] = None


def get_client() -> OllamaClient:
    """Return the shared OllamaClient singleton."""
    global _client
    if _client is None:
        _client = OllamaClient()
    return _client
