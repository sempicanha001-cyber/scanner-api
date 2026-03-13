"""
ai/prompts.py — Structured prompt templates for vulnerability analysis.

All prompts follow a strict output schema so the ai_analyzer can parse
them deterministically even when Llama3 is running locally.
"""
from __future__ import annotations

from typing import Any, Dict


# ── System persona ─────────────────────────────────────────────────────────────

SECURITY_EXPERT_SYSTEM = """\
You are a senior application security engineer with expertise in API security,
OWASP Top 10, and penetration testing. You provide clear, accurate, and
actionable security analysis. You always structure your responses in the exact
JSON format requested. You never add commentary outside the JSON block."""


# ── Vulnerability analysis prompt ──────────────────────────────────────────────

def build_vuln_analysis_prompt(
    vuln_type:   str,
    endpoint:    str,
    method:      str,
    payload:     str,
    status_code: int,
    response_snippet: str,
    severity:    str,
    description: str,
) -> str:
    """
    Build the main vulnerability analysis prompt.
    Returns a prompt that instructs the model to respond with a JSON object.
    """
    # Truncate large evidence blobs so the context window doesn't overflow
    resp_snippet = response_snippet[:800] if response_snippet else "(no response body)"
    payload_str  = payload[:300] if payload else "(none)"

    return f"""\
Analyze this API vulnerability finding and return a JSON object.

=== VULNERABILITY FINDING ===
Type        : {vuln_type}
Severity    : {severity}
Endpoint    : {method} {endpoint}
Payload used: {payload_str}
HTTP Status : {status_code}
Response    : {resp_snippet}
Description : {description}

=== REQUIRED JSON OUTPUT FORMAT ===
Return ONLY a valid JSON object with these exact keys:

{{
  "explanation": "2-4 sentence plain-English explanation of what this vulnerability is and why it exists in this endpoint.",
  "risk": "2-3 sentences describing the business/technical impact if exploited.",
  "exploit_example": "A concrete, realistic example of how an attacker would exploit this specific finding (1-3 sentences).",
  "remediation": [
    "Specific fix #1 (actionable, concrete)",
    "Specific fix #2",
    "Specific fix #3"
  ],
  "severity_assessment": "Your independent severity assessment: CRITICAL / HIGH / MEDIUM / LOW and one sentence justification.",
  "owasp_reference": "Relevant OWASP category, e.g. OWASP API Security Top 10 2023 - API1: Broken Object Level Authorization"
}}

Return ONLY the JSON. No markdown fences. No preamble. No commentary."""


# ── Batch summary prompt ────────────────────────────────────────────────────────

def build_executive_summary_prompt(
    target: str,
    total_findings: int,
    critical: int,
    high: int,
    medium: int,
    low: int,
    security_score: int,
    top_vulns: list[str],
) -> str:
    """Build a prompt for generating an AI-written executive summary."""
    vuln_list = "\n".join(f"- {v}" for v in top_vulns[:10])

    return f"""\
Write a professional executive summary for an API security audit report.

=== SCAN DATA ===
Target         : {target}
Security Score : {security_score}/100
Total Findings : {total_findings}
  Critical     : {critical}
  High         : {high}
  Medium       : {medium}
  Low          : {low}
Top Vulnerabilities Found:
{vuln_list}

=== REQUIRED JSON OUTPUT FORMAT ===
Return ONLY a valid JSON object:

{{
  "executive_summary": "3-5 sentence non-technical summary suitable for a CISO or CTO. Describe overall security posture, most critical risks, and urgency of remediation.",
  "risk_headline": "One punchy sentence describing the overall risk level.",
  "priority_actions": [
    "Immediate action #1 (most critical)",
    "Immediate action #2",
    "Immediate action #3"
  ],
  "overall_risk_rating": "CRITICAL / HIGH / MEDIUM / LOW"
}}

Return ONLY the JSON. No markdown fences. No preamble."""


# ── Quick triage prompt (fast, single-line) ────────────────────────────────────

def build_triage_prompt(vuln_type: str, endpoint: str, payload: str) -> str:
    """
    Lightweight prompt for quick triage — used when full analysis budget is
    exceeded. Returns a single sentence.
    """
    return f"""\
In one sentence, describe the security risk of a {vuln_type} vulnerability
found at endpoint '{endpoint}' with payload: {payload[:150]}.
Return ONLY the sentence, no JSON, no preamble."""


# ── Remediation deep-dive prompt ───────────────────────────────────────────────

def build_remediation_prompt(
    vuln_type: str,
    tech_stack: str,
    code_context: str = "",
) -> str:
    """Build a prompt for detailed remediation guidance."""
    code_block = f"\nCode context:\n{code_context[:600]}" if code_context else ""

    return f"""\
Provide detailed remediation guidance for a {vuln_type} vulnerability.
Technology stack: {tech_stack}{code_block}

Return ONLY a valid JSON object:
{{
  "short_fix": "One-line fix description",
  "code_example": "Pseudocode or framework-specific code showing the correct implementation",
  "references": [
    "OWASP link or RFC or CVE reference"
  ],
  "testing": "How to verify the fix worked"
}}

Return ONLY the JSON. No markdown fences."""
