"""
ai/ — Local AI vulnerability analysis module.

Powered by Ollama + Llama3 (100% free, local, no cloud APIs).

Quick start:
    from ai.ai_analyzer import get_analyzer
    analyzer = get_analyzer()
    if analyzer.available:
        analysis = analyzer.analyze_finding(vuln_type="SQLI", endpoint="/api/users", ...)
"""
from ai.ai_analyzer import AIAnalysis, AIExecutiveSummary, VulnerabilityAnalyzer, get_analyzer
from ai.llm_client import OllamaClient, OllamaUnavailableError, get_client

__all__ = [
    "AIAnalysis",
    "AIExecutiveSummary",
    "VulnerabilityAnalyzer",
    "get_analyzer",
    "OllamaClient",
    "OllamaUnavailableError",
    "get_client",
]
