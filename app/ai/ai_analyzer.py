"""
ai/ai_analyzer.py — AI-powered vulnerability analysis using local Ollama/Llama3.

This module is the main interface for AI analysis. It:
  1. Takes a Finding from the scanner
  2. Sends it to the local LLM via OllamaClient
  3. Parses the structured JSON response
  4. Attaches the analysis back to the Finding
  5. Degrades gracefully if Ollama is unavailable

100% local — zero cloud APIs — zero cost.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ai.llm_client import OllamaClient, OllamaUnavailableError, get_client
from ai.prompts import (
    SECURITY_EXPERT_SYSTEM,
    build_vuln_analysis_prompt,
    build_executive_summary_prompt,
    build_triage_prompt,
)

logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_status(val: Any) -> int:
    """Convert response_status to int safely — never crashes on bad input. (FIX 5)"""
    try:
        return int(val or 0)
    except (ValueError, TypeError):
        return 0


# ── AI Analysis result dataclass ──────────────────────────────────────────────

@dataclass
class AIAnalysis:
    """Structured result returned by the AI analyzer for a single finding."""

    # Core fields (populated from LLM JSON response)
    explanation:        str       = ""
    risk:               str       = ""
    exploit_example:    str       = ""
    remediation:        List[str] = field(default_factory=list)
    severity_assessment: str      = ""
    owasp_reference:    str       = ""

    # Meta
    model_used:         str       = ""
    analysis_time_ms:   float     = 0.0
    ai_available:       bool      = False
    error:              Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "explanation":         self.explanation,
            "risk":                self.risk,
            "exploit_example":     self.exploit_example,
            "remediation":         self.remediation,
            "severity_assessment": self.severity_assessment,
            "owasp_reference":     self.owasp_reference,
            "model_used":          self.model_used,
            "analysis_time_ms":    round(self.analysis_time_ms, 1),
            "ai_available":        self.ai_available,
            "error":               self.error,
        }

    @property
    def remediation_html(self) -> str:
        """Pre-rendered HTML list for embedding directly in HTML reports."""
        if not self.remediation:
            return "<em>No remediation steps available.</em>"
        items = "".join(f"<li>{step}</li>" for step in self.remediation)
        return f"<ol>{items}</ol>"

    @property
    def is_successful(self) -> bool:
        return self.ai_available and self.error is None and bool(self.explanation)


@dataclass
class AIExecutiveSummary:
    """AI-generated executive summary for the full scan result."""
    executive_summary:  str       = ""
    risk_headline:      str       = ""
    priority_actions:   List[str] = field(default_factory=list)
    overall_risk_rating: str      = ""
    model_used:         str       = ""
    ai_available:       bool      = False
    error:              Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "executive_summary":  self.executive_summary,
            "risk_headline":      self.risk_headline,
            "priority_actions":   self.priority_actions,
            "overall_risk_rating": self.overall_risk_rating,
            "model_used":         self.model_used,
            "ai_available":       self.ai_available,
            "error":              self.error,
        }


# ── JSON parser helper ────────────────────────────────────────────────────────

def _parse_json_response(raw: str) -> Dict[str, Any]:
    """
    Robustly extract a JSON object from LLM output.
    Handles markdown code fences and leading/trailing text.
    """
    # Strip markdown fences if present
    raw = re.sub(r"```(?:json)?", "", raw).strip()

    # Try direct parse first
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Try to find the first {...} block
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not parse JSON from LLM response:\n{raw[:500]}")


# ── Core Analyzer ─────────────────────────────────────────────────────────────

class VulnerabilityAnalyzer:
    """
    Wraps OllamaClient with vulnerability-specific analysis logic.

    Instantiate once and reuse — it caches the availability check.
    Degrades gracefully: if Ollama is down, returns an empty AIAnalysis
    with ai_available=False so callers can decide what to do.
    """

    def __init__(self, client: Optional[OllamaClient] = None) -> None:
        self._client = client or get_client()

    @property
    def available(self) -> bool:
        return self._client.is_available()

    @property
    def model_name(self) -> str:
        """Safe accessor for the model name — avoids exposing _client directly. (FIX 8)"""
        return getattr(self._client, "model", "unknown")

    # ── Single finding analysis ───────────────────────────────────────────────

    def analyze_finding(
        self,
        vuln_type:   str,
        endpoint:    str,
        method:      str          = "GET",
        payload:     str          = "",
        status_code: int          = 0,
        response_body: str        = "",
        severity:    str          = "MEDIUM",
        description: str          = "",
    ) -> AIAnalysis:
        """
        Analyze a single vulnerability finding.
        Always returns an AIAnalysis — never raises.
        """
        if not self.available:
            return AIAnalysis(
                ai_available=False,
                error="Ollama not available. Install Ollama and run: ollama pull llama3",
            )

        t0 = time.perf_counter()

        prompt = build_vuln_analysis_prompt(
            vuln_type=vuln_type,
            endpoint=endpoint,
            method=method,
            payload=payload,
            status_code=status_code,
            response_snippet=response_body,
            severity=severity,
            description=description,
        )

        try:
            raw = self._client.generate(prompt, system=SECURITY_EXPERT_SYSTEM)
            data = _parse_json_response(raw)

            return AIAnalysis(
                explanation        = data.get("explanation", ""),
                risk               = data.get("risk", ""),
                exploit_example    = data.get("exploit_example", ""),
                remediation        = data.get("remediation", []),
                severity_assessment= data.get("severity_assessment", ""),
                owasp_reference    = data.get("owasp_reference", ""),
                model_used         = self._client.model,
                analysis_time_ms   = (time.perf_counter() - t0) * 1000,
                ai_available       = True,
            )

        except OllamaUnavailableError as exc:
            logger.warning("Ollama unavailable during analysis: %s", exc)
            return AIAnalysis(
                ai_available=False,
                analysis_time_ms=(time.perf_counter() - t0) * 1000,
                error=str(exc),
            )
        except Exception as exc:
            logger.error("AI analysis failed for %s %s: %s", method, endpoint, exc)
            return AIAnalysis(
                ai_available=True,
                analysis_time_ms=(time.perf_counter() - t0) * 1000,
                error=f"Analysis error: {exc}",
            )

    # ── Executive summary ─────────────────────────────────────────────────────

    def generate_executive_summary(
        self,
        target: str,
        total_findings: int,
        critical: int,
        high: int,
        medium: int,
        low: int,
        security_score: int,
        top_vuln_types: List[str],
    ) -> AIExecutiveSummary:
        """
        Generate an AI executive summary for the full scan.
        Always returns an AIExecutiveSummary — never raises.
        """
        if not self.available:
            return AIExecutiveSummary(
                ai_available=False,
                error="Ollama not available.",
            )

        prompt = build_executive_summary_prompt(
            target=target,
            total_findings=total_findings,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            security_score=security_score,
            top_vulns=top_vuln_types,
        )

        try:
            raw = self._client.generate(prompt, system=SECURITY_EXPERT_SYSTEM)
            data = _parse_json_response(raw)

            return AIExecutiveSummary(
                executive_summary  = data.get("executive_summary", ""),
                risk_headline      = data.get("risk_headline", ""),
                priority_actions   = data.get("priority_actions", []),
                overall_risk_rating= data.get("overall_risk_rating", ""),
                model_used         = self._client.model,
                ai_available       = True,
            )

        except OllamaUnavailableError as exc:
            logger.warning("Ollama unavailable for executive summary: %s", exc)
            return AIExecutiveSummary(ai_available=False, error=str(exc))
        except Exception as exc:
            logger.error("Executive summary generation failed: %s", exc)
            return AIExecutiveSummary(ai_available=True, error=str(exc))

    # ── Batch analysis ────────────────────────────────────────────────────────

    def analyze_findings_batch(
        self,
        findings: List[Dict[str, Any]],
        max_findings: int = 10,
    ) -> Dict[str, AIAnalysis]:
        """
        Analyze multiple findings, up to max_findings (to control LLM costs/time).
        Returns a dict keyed by finding ID.

        Prioritises by severity: CRITICAL > HIGH > MEDIUM > LOW > INFO.
        """
        SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        sorted_findings = sorted(
            findings,
            key=lambda f: SEV_ORDER.get(str(f.get("severity", "INFO")).upper(), 5),
        )[:max_findings]

        results: Dict[str, AIAnalysis] = {}

        for finding in sorted_findings:
            fid = str(finding.get("id", "unknown"))
            logger.info("AI analyzing finding %s (%s)", fid, finding.get("vuln_type"))

            analysis = self.analyze_finding(
                vuln_type    = str(finding.get("vuln_type", "")),
                endpoint     = str(finding.get("endpoint", "")),
                method       = str(finding.get("method", "GET")),
                payload      = str(finding.get("payload", "")),
                status_code  = _safe_status(finding.get("response_status")),  # FIX 5
                response_body= str(finding.get("response_body", ""))[:600],
                severity     = str(finding.get("severity", "MEDIUM")),
                description  = str(finding.get("description", "")),
            )

            results[fid] = analysis

            # If Ollama became unavailable mid-batch, stop early
            if not analysis.ai_available:
                logger.warning("AI unavailable — stopping batch analysis at finding %s", fid)
                break

        return results


# ── Module-level singleton ────────────────────────────────────────────────────

_analyzer: Optional[VulnerabilityAnalyzer] = None
_analyzer_lock = threading.Lock()   # FIX 6: prevents race condition in multi-thread env


def get_analyzer() -> VulnerabilityAnalyzer:
    """Return the shared VulnerabilityAnalyzer singleton (thread-safe). (FIX 6)"""
    global _analyzer
    if _analyzer is None:
        with _analyzer_lock:
            if _analyzer is None:   # double-checked locking
                _analyzer = VulnerabilityAnalyzer()
    return _analyzer
