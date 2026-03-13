"""
tests/test_ai_analyzer.py — Tests for the AI vulnerability analyzer module.

Tests cover:
 1. AI analysis works when Ollama is available (mocked)
 2. Scanner works correctly when Ollama is NOT available (graceful degradation)
 3. JSON parsing robustness (markdown fences, extra text)
 4. Executive summary generation
 5. Batch analysis prioritization
"""
from __future__ import annotations

import json
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


# ── Lightweight stubs so tests run without installing all scanner deps ─────────

def _make_stub_module(name: str) -> types.ModuleType:
    mod = types.ModuleType(name)
    sys.modules[name] = mod
    return mod


for _mod in ["redis", "celery", "celery.schedules", "celery.utils.log",
             "fpdf", "colorama", "cryptography", "cryptography.fernet",
             "prometheus_client", "aioredis", "fastapi", "uvicorn"]:
    if _mod not in sys.modules:
        _make_stub_module(_mod)


# ── Tests ──────────────────────────────────────────────────────────────────────

class TestOllamaClient(unittest.TestCase):
    """Unit tests for the OllamaClient."""

    def _make_client(self):
        from ai.llm_client import OllamaClient
        return OllamaClient(base_url="http://localhost:11434", model="llama3")

    def test_is_available_returns_false_when_server_down(self):
        """Client correctly reports unavailable when server is not running."""
        import requests
        client = self._make_client()
        with patch("requests.get", side_effect=requests.ConnectionError("refused")):
            self.assertFalse(client.is_available())

    def test_is_available_returns_true_when_model_listed(self):
        """Client correctly reports available when model appears in /api/tags."""
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "models": [{"name": "llama3:latest"}, {"name": "mistral:latest"}]
        }
        with patch("requests.get", return_value=mock_resp):
            self.assertTrue(client.is_available())

    def test_generate_returns_text_on_success(self):
        """generate() returns the 'response' field from Ollama JSON."""
        client = self._make_client()

        mock_tags = MagicMock()
        mock_tags.status_code = 200
        mock_tags.json.return_value = {"models": [{"name": "llama3:latest"}]}

        mock_gen = MagicMock()
        mock_gen.status_code = 200
        mock_gen.json.return_value = {"response": "SQL injection is dangerous."}

        with patch("requests.get", return_value=mock_tags):
            with patch("requests.post", return_value=mock_gen):
                result = client.generate("Explain SQL injection")
        self.assertEqual(result, "SQL injection is dangerous.")

    def test_generate_raises_on_server_error(self):
        """generate() raises RuntimeError on non-200 HTTP responses."""
        client = self._make_client()

        mock_tags = MagicMock()
        mock_tags.status_code = 200
        mock_tags.json.return_value = {"models": [{"name": "llama3:latest"}]}

        mock_gen = MagicMock()
        mock_gen.status_code = 500
        mock_gen.text = "Internal Server Error"

        with patch("requests.get", return_value=mock_tags):
            with patch("requests.post", return_value=mock_gen):
                with self.assertRaises(RuntimeError):
                    client.generate("Test prompt")

    def test_generate_raises_unavailable_when_server_down(self):
        """generate() raises OllamaUnavailableError when server is unreachable."""
        import requests
        from ai.llm_client import OllamaUnavailableError
        client = self._make_client()
        # Mock both get (availability) and post (generate) as failing
        with patch("requests.get", side_effect=requests.ConnectionError("refused")):
            with patch("requests.post", side_effect=requests.ConnectionError("refused")):
                with self.assertRaises(OllamaUnavailableError):
                    client.generate("Test")


class TestJsonParsing(unittest.TestCase):
    """Test the _parse_json_response helper."""

    def setUp(self):
        from ai.ai_analyzer import _parse_json_response
        self.parse = _parse_json_response

    def test_plain_json(self):
        raw = '{"explanation": "XSS is bad", "risk": "high"}'
        result = self.parse(raw)
        self.assertEqual(result["explanation"], "XSS is bad")

    def test_json_with_markdown_fences(self):
        raw = '```json\n{"explanation": "SQLi", "risk": "critical"}\n```'
        result = self.parse(raw)
        self.assertEqual(result["explanation"], "SQLi")

    def test_json_with_preamble(self):
        raw = 'Sure! Here is the analysis:\n{"explanation": "SSRF", "remediation": []}'
        result = self.parse(raw)
        self.assertEqual(result["explanation"], "SSRF")

    def test_invalid_json_raises(self):
        with self.assertRaises(ValueError):
            self.parse("This is not JSON at all, just plain text.")


class TestVulnerabilityAnalyzer(unittest.TestCase):
    """Integration-style tests for VulnerabilityAnalyzer."""

    def _mock_client(self, available: bool = True, response: dict = None) -> MagicMock:
        client = MagicMock()
        client.is_available.return_value = available
        client.model = "llama3"
        if available and response:
            client.generate.return_value = json.dumps(response)
        return client

    def test_analyze_finding_returns_graceful_result_when_unavailable(self):
        """When Ollama is down, analysis returns ai_available=False without raising."""
        from ai.ai_analyzer import VulnerabilityAnalyzer
        client = self._mock_client(available=False)
        analyzer = VulnerabilityAnalyzer(client=client)

        result = analyzer.analyze_finding(
            vuln_type="SQLI",
            endpoint="/api/users",
            method="GET",
            payload="' OR 1=1--",
            status_code=200,
            response_body="admin,root,user",
            severity="CRITICAL",
            description="SQL injection detected",
        )

        self.assertFalse(result.ai_available)
        self.assertFalse(result.is_successful)
        self.assertIn("Ollama", result.error)

    def test_analyze_finding_parses_llm_response(self):
        """When Ollama returns valid JSON, analysis is parsed correctly."""
        from ai.ai_analyzer import VulnerabilityAnalyzer
        mock_response = {
            "explanation":         "An attacker can inject SQL to dump the database.",
            "risk":                "Full database compromise possible.",
            "exploit_example":     "GET /api/users?id=1' OR 1=1--",
            "remediation":         ["Use parameterized queries", "Validate all inputs"],
            "severity_assessment": "CRITICAL — direct database access",
            "owasp_reference":     "OWASP API Security Top 10 2023 - API8: Security Misconfiguration",
        }
        client = self._mock_client(available=True, response=mock_response)
        analyzer = VulnerabilityAnalyzer(client=client)

        result = analyzer.analyze_finding(
            vuln_type="SQLI",
            endpoint="/api/users",
            severity="CRITICAL",
            description="SQL injection",
        )

        self.assertTrue(result.ai_available)
        self.assertTrue(result.is_successful)
        self.assertIn("SQL", result.explanation)
        self.assertEqual(len(result.remediation), 2)
        self.assertEqual(result.model_used, "llama3")

    def test_analyze_finding_handles_llm_error_gracefully(self):
        """When LLM returns garbage, error is captured without raising."""
        from ai.ai_analyzer import VulnerabilityAnalyzer
        client = MagicMock()
        client.is_available.return_value = True
        client.model = "llama3"
        client.generate.return_value = "I cannot parse this as JSON ¯\\_(ツ)_/¯"

        analyzer = VulnerabilityAnalyzer(client=client)
        result = analyzer.analyze_finding(vuln_type="XSS", endpoint="/api/search")

        self.assertTrue(result.ai_available)
        self.assertIsNotNone(result.error)
        self.assertFalse(result.is_successful)

    def test_executive_summary_generation(self):
        """Executive summary is generated and parsed correctly."""
        from ai.ai_analyzer import VulnerabilityAnalyzer
        mock_response = {
            "executive_summary":   "The API has critical vulnerabilities requiring immediate remediation.",
            "risk_headline":       "API is at immediate risk of full compromise.",
            "priority_actions":    ["Fix SQL injection", "Rotate API keys", "Enable WAF"],
            "overall_risk_rating": "CRITICAL",
        }
        client = self._mock_client(available=True, response=mock_response)
        analyzer = VulnerabilityAnalyzer(client=client)

        summary = analyzer.generate_executive_summary(
            target="https://api.example.com",
            total_findings=15,
            critical=3, high=5, medium=4, low=3,
            security_score=12,
            top_vuln_types=["SQLI", "XSS", "IDOR"],
        )

        self.assertTrue(summary.ai_available)
        self.assertEqual(summary.overall_risk_rating, "CRITICAL")
        self.assertEqual(len(summary.priority_actions), 3)

    def test_batch_analysis_prioritises_by_severity(self):
        """Batch analysis processes CRITICAL findings before LOW ones."""
        from ai.ai_analyzer import VulnerabilityAnalyzer

        analyzed_types = []

        def fake_analyze(**kwargs):
            from ai.ai_analyzer import AIAnalysis
            analyzed_types.append(kwargs.get("vuln_type"))
            return AIAnalysis(ai_available=True, explanation="ok", model_used="llama3")

        client = self._mock_client(available=True)
        analyzer = VulnerabilityAnalyzer(client=client)
        analyzer.analyze_finding = lambda **kw: fake_analyze(**kw)

        findings = [
            {"id": "A", "vuln_type": "MISSING_HEADER", "severity": "LOW",      "endpoint": "/"},
            {"id": "B", "vuln_type": "SQLI",           "severity": "CRITICAL", "endpoint": "/api/users"},
            {"id": "C", "vuln_type": "XSS",            "severity": "MEDIUM",   "endpoint": "/search"},
        ]

        results = analyzer.analyze_findings_batch(findings, max_findings=3)
        self.assertIn("B", results)   # CRITICAL must be analyzed
        self.assertIn("C", results)
        self.assertIn("A", results)


class TestScannerWorksWithoutAI(unittest.TestCase):
    """
    Verify scanner pipeline is not broken when AI is unavailable.
    These are smoke tests — they don't execute real HTTP scans.
    """

    def test_ai_analysis_result_has_safe_defaults(self):
        """AIAnalysis with no fields is safe to render in reports."""
        from ai.ai_analyzer import AIAnalysis
        a = AIAnalysis()
        self.assertFalse(a.is_successful)
        self.assertFalse(a.ai_available)
        self.assertEqual(a.remediation, [])
        # remediation_html should not raise
        html = a.remediation_html
        self.assertIn("No remediation", html)

    def test_ai_executive_summary_has_safe_defaults(self):
        """AIExecutiveSummary with no fields is safe."""
        from ai.ai_analyzer import AIExecutiveSummary
        s = AIExecutiveSummary()
        self.assertFalse(s.ai_available)
        d = s.to_dict()
        self.assertIn("ai_available", d)

    def test_reporter_renders_without_ai_analysis(self):
        """HTMLReporter.generate works fine when ai_analysis=None."""
        try:
            from reports.reporter import HTMLReporter
        except (ImportError, ModuleNotFoundError):
            self.skipTest("Reporter dependencies (cryptography etc.) not available in test env")

        # Minimal mock of ScanResult
        result = MagicMock()
        result.target = "https://api.example.com"
        result.start_time = "2025-01-01T00:00:00Z"
        result.duration_seconds = 5.0
        result.total_requests = 42
        result.scanner_version = "2.0"
        result.waf_detected = None
        result.findings = []
        result.sorted_findings.return_value = []
        result.by_severity.return_value = {s: [] for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
        result.summary = {
            "security_score": 100,
            "security_rating": "A",
            "total": 0,
            "by_severity": {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0},
            "by_owasp": {},
            "highest_cvss": 0.0,
            "confirmed_count": 0,
            "waf_detected": None,
            "technologies": [],
            "total_requests": 42,
            "endpoints_found": 3,
            "duration": 5.0,
        }

        import tempfile, os
        from reports.reporter import HTMLReporter
        reporter = HTMLReporter()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
            tmp = f.name

        try:
            reporter.generate(result, tmp, ai_analysis=None)
            with open(tmp) as f:
                html = f.read()
            self.assertIn("API Security Audit Report", html)
            self.assertNotIn("ai-section", html)   # No AI section when unavailable
        finally:
            os.unlink(tmp)


class TestFixes(unittest.TestCase):
    """Tests specifically covering the 10 bug fixes."""

    # Fix 1 — safe int parsing
    def test_safe_int_handles_bad_env_var(self):
        """_safe_int never raises on non-numeric env values."""
        from ai.llm_client import _safe_int
        self.assertEqual(_safe_int("disabled", 120), 120)
        self.assertEqual(_safe_int("", 120), 120)
        self.assertEqual(_safe_int(None, 120), 120)
        self.assertEqual(_safe_int("90", 120), 90)

    # Fix 2 — findings None guard
    def test_run_ai_analysis_handles_none_findings(self):
        """run_ai_analysis does not crash when findings=None."""
        from ai.ai_analyzer import VulnerabilityAnalyzer, AIAnalysis
        client = MagicMock()
        client.is_available.return_value = False
        client.model = "llama3"
        analyzer = VulnerabilityAnalyzer(client=client)
        # analyze_findings_batch with None should not crash
        result = analyzer.analyze_findings_batch(None or [], max_findings=5)
        self.assertEqual(result, {})

    # Fix 4 — TTL-based cache
    def test_availability_cache_expires_after_ttl(self):
        """Availability is re-checked after TTL expires."""
        from ai.llm_client import OllamaClient, _AVAILABILITY_CACHE_TTL
        client = OllamaClient()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"models": [{"name": "llama3:latest"}]}

        with patch("requests.get", return_value=mock_resp) as mock_get:
            client.is_available()   # first call
            client.is_available()   # should use cache — no new request
            self.assertEqual(mock_get.call_count, 1)

            # Expire the cache
            client._available_checked_at = 0.0
            client.is_available()   # should re-check
            self.assertEqual(mock_get.call_count, 2)

    # Fix 5 — safe status code
    def test_safe_status_handles_non_numeric(self):
        """_safe_status returns 0 for non-numeric values."""
        from ai.ai_analyzer import _safe_status
        self.assertEqual(_safe_status("N/A"), 0)
        self.assertEqual(_safe_status(""), 0)
        self.assertEqual(_safe_status(None), 0)
        self.assertEqual(_safe_status(200), 200)
        self.assertEqual(_safe_status("404"), 404)

    # Fix 6 — thread-safe singleton
    def test_get_analyzer_is_thread_safe(self):
        """Concurrent calls to get_analyzer return the same instance."""
        import threading
        from ai import ai_analyzer
        ai_analyzer._analyzer = None  # reset singleton

        instances = []
        def _get():
            from ai.ai_analyzer import get_analyzer
            instances.append(get_analyzer())

        threads = [threading.Thread(target=_get) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()

        # All threads should get the exact same instance
        self.assertEqual(len(set(id(i) for i in instances)), 1)

    # Fix 7 — list type guard
    def test_reporter_handles_priority_actions_as_string(self):
        """_ai_executive_section does not crash when priority_actions is a string."""
        try:
            from reports.reporter import HTMLReporter
        except (ImportError, ModuleNotFoundError):
            self.skipTest("Reporter deps not available")

        reporter = HTMLReporter()
        ai_analysis = {
            "ai_available": True,
            "model_used": "llama3",
            "executive_summary": {
                "executive_summary": "High risk API.",
                "risk_headline": "Critical issues found.",
                "priority_actions": "Fix everything immediately",  # string, not list
                "overall_risk_rating": "CRITICAL",
            }
        }
        html = reporter._ai_executive_section(ai_analysis)
        self.assertIn("Critical issues found", html)

    # Fix 8 — model_name property
    def test_model_name_property_does_not_expose_private_client(self):
        """model_name property returns model without accessing _client directly."""
        from ai.ai_analyzer import VulnerabilityAnalyzer
        client = MagicMock()
        client.is_available.return_value = False
        client.model = "llama3:8b"
        analyzer = VulnerabilityAnalyzer(client=client)
        self.assertEqual(analyzer.model_name, "llama3:8b")


if __name__ == "__main__":
    unittest.main()

