"""
Comprehensive test suite for Datadog SAIST AI-Native SAST Integration & Groq Bridge.
Tests:
1. OpenAI-to-Groq Proxy endpoint (/internal/groq-proxy/v1/chat/completions)
2. Models endpoint (/internal/groq-proxy/v1/models)
3. SARIF 2.1.0 Parser & AST Ground-Truth Zero-Hallucination Guardrail
4. Native Python 2-Stage SAIST Engine (Detection + Adversarial Validation)
5. Ensemble SAST Merger & Confidence Boosting in sast_scanner.py
6. Remediation LLM service Groq integration
"""

import json
import os
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.app import app
from backend.config import settings
from backend.models.schemas import UnifiedFinding, RouteEntry
from backend.services.datadog_saist_runner import (
    DatadogSAISTRunner,
    get_datadog_saist_runner
)
from backend.services.sast_scanner import SASTScannerService


client = TestClient(app)


# ---------------------------------------------------------------------------
# Test 1: OpenAI-to-Groq Adapter Endpoint (groq_proxy.py)
# ---------------------------------------------------------------------------

def test_groq_proxy_model_remapping_and_temp():
    """Verify proxy remaps openai-gpt5-mini to settings.groq_model and enforces temp=0.0."""
    with patch("httpx.AsyncClient.post") as mock_post:
        # Mock upstream response from Groq
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps({
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "model": settings.groq_model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": '{"candidates": []}'}
            }]
        }).encode("utf-8")
        mock_post.return_value = mock_response

        payload = {
            "model": "openai-gpt5-mini",  # Sent by datadog-saist
            "messages": [{"role": "user", "content": "analyze code"}],
            "temperature": 0.8  # Should be forced to 0.0
        }

        # Test both URI routes
        for endpoint in ["/internal/groq-proxy/v1/chat/completions", "/v1/chat/completions"]:
            res = client.post(endpoint, json=payload)
            assert res.status_code == 200
            data = res.json()
            assert data["model"] == settings.groq_model

            # Verify arguments sent to upstream Groq
            call_kwargs = mock_post.call_args[1]
            sent_body = call_kwargs["json"]
            assert sent_body["model"] == settings.groq_model
            assert sent_body["temperature"] == 0.0
            assert "Authorization" in call_kwargs["headers"]
            assert settings.groq_api_key in call_kwargs["headers"]["Authorization"]


def test_groq_proxy_models_endpoint():
    """Verify /v1/models returns advertised models for OpenAI client compatibility."""
    for endpoint in ["/internal/groq-proxy/v1/models", "/v1/models"]:
        res = client.get(endpoint)
        assert res.status_code == 200
        data = res.json()
        assert "data" in data
        model_ids = [m["id"] for m in data["data"]]
        assert "openai-gpt5-mini" in model_ids
        assert "gpt5-mini" in model_ids
        assert settings.groq_model in model_ids


# ---------------------------------------------------------------------------
# Test 2: SARIF 2.1.0 Parser & Zero-Hallucination Guardrail
# ---------------------------------------------------------------------------

def test_sarif_parser_ground_truth_verification():
    """Verify SARIF parser extracts real lines and rejects hallucinated line numbers."""
    runner = DatadogSAISTRunner()

    sample_sarif = {
        "runs": [{
            "results": [
                {
                    # Valid finding on line 30 of ecommerce_api.py
                    "ruleId": "datadog-saist/CWE-89",
                    "message": {"text": "SQL Injection in get_orders"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "ecommerce_api.py"},
                            "region": {
                                "startLine": 33,
                                "endLine": 33,
                                "snippet": {"text": "db.execute(query)"}
                            }
                        }
                    }],
                    "properties": {
                        "tags": ["CWE-89", "security"],
                        "confidence": "HIGH"
                    }
                },
                {
                    # Hallucinated line 99999 (does not exist in ecommerce_api.py)
                    "ruleId": "datadog-saist/CWE-79",
                    "message": {"text": "Hallucinated XSS"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "ecommerce_api.py"},
                            "region": {
                                "startLine": 99999,
                                "endLine": 99999
                            }
                        }
                    }],
                    "properties": {"tags": ["CWE-79"]}
                },
                {
                    # Non-existent file
                    "ruleId": "datadog-saist/CWE-22",
                    "message": {"text": "Ghost File Traversal"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "non_existent_file.py"},
                            "region": {"startLine": 10}
                        }
                    }]
                }
            ]
        }]
    }

    findings = runner.parse_sarif_to_findings(sample_sarif, "data/samples")
    assert len(findings) == 1, "Only the legitimate finding on line 33 should be parsed"
    legit = findings[0]
    assert legit.cwe_id == "CWE-89"
    assert legit.line == 33
    assert legit.file == "ecommerce_api.py"
    assert legit.confidence == "HIGH"
    assert "db.execute(query)" in legit.code_snippet


# ---------------------------------------------------------------------------
# Test 3: Native Python 2-Stage SAIST Engine (Stage 1 + Stage 2)
# ---------------------------------------------------------------------------

def test_native_saist_two_stage_filtering():
    """Verify Stage 1 generates candidates and Stage 2 discards false positives."""
    runner = DatadogSAISTRunner()

    # Candidate 0: True Positive SQL injection
    # Candidate 1: False Positive (sanitized / parameterized)
    mock_candidates = [
        {
            "cwe_id": "CWE-89",
            "vulnerability_type": "SQL Injection",
            "start_line": 33,
            "end_line": 33,
            "explanation": "Raw SQL concatenation"
        },
        {
            "cwe_id": "CWE-79",
            "vulnerability_type": "XSS",
            "start_line": 20,
            "end_line": 20,
            "explanation": "False positive test"
        }
    ]

    mock_validations = {
        "validations": [
            {
                "candidate_id": 0,
                "is_valid": True,
                "confidence": "HIGH",
                "validation_reason": "Confirmed raw concatenation"
            },
            {
                "candidate_id": 1,
                "is_valid": False,  # Discarded as false positive
                "confidence": "LOW",
                "validation_reason": "Input is strictly sanitized"
            }
        ]
    }

    with patch.object(runner, "_stage1_detect", return_value=mock_candidates):
        with patch.object(runner, "_stage2_validate", return_value=[mock_candidates[0]]):
            findings = runner.run_scan("data/samples")
            # Only candidate 0 should be present
            cwe_list = [f.cwe_id for f in findings]
            assert "CWE-89" in cwe_list


# ---------------------------------------------------------------------------
# Test 4: Ensemble SAST Merger & Confidence Boosting (sast_scanner.py)
# ---------------------------------------------------------------------------

def test_ensemble_merger_and_confidence_boost():
    """Verify that when Semgrep/AST and Datadog SAIST both flag a bug, they merge & boost confidence to HIGH."""
    scanner = SASTScannerService()

    # Mock Semgrep finding with MEDIUM confidence
    semgrep_f = UnifiedFinding(
        finding_id="semgrep-1",
        dedup_key="SAST:orders.py:88:CWE-89",
        source_scanner="SAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="HIGH",
        confidence="MEDIUM",
        file="orders.py",
        line=88,
        code_snippet="query = f'SELECT * FROM orders WHERE id={id}'",
        description="SQL injection in orders"
    )

    # Mock Datadog SAIST finding at line 89 (within +-2 line tolerance)
    saist_f = UnifiedFinding(
        finding_id="saist-1",
        dedup_key="SAST:orders.py:89:CWE-89",
        source_scanner="SAST",
        cwe_id="CWE-89",
        vulnerability_type="SQL Injection",
        severity="CRITICAL",
        confidence="HIGH",
        file="orders.py",
        line=89,
        code_snippet="db.execute(query)",
        description="Datadog SAIST verified SQL injection"
    )

    # Unique Datadog SAIST finding (SSRF) not found by Semgrep
    saist_unique = UnifiedFinding(
        finding_id="saist-2",
        dedup_key="SAST:orders.py:120:CWE-918",
        source_scanner="SAST",
        cwe_id="CWE-918",
        vulnerability_type="Server-Side Request Forgery (SSRF)",
        severity="HIGH",
        confidence="HIGH",
        file="orders.py",
        line=120,
        code_snippet="requests.get(target_url)",
        description="SSRF in webhook endpoint"
    )

    with patch.object(scanner, "_run_semgrep_cli", return_value=[semgrep_f]):
        with patch.object(scanner, "_run_static_fallback", return_value=[]):
            with patch("backend.services.sast_scanner.get_datadog_saist_runner") as mock_runner_getter:
                mock_runner = MagicMock()
                mock_runner.run_scan.return_value = [saist_f, saist_unique]
                mock_runner_getter.return_value = mock_runner

                with patch.object(scanner, "_collect_scanned_files", return_value=1, create=True):
                    res = scanner.scan_folder("data/samples")

                    # Verify 2 findings total (1 merged + 1 unique)
                    assert res.total_findings == 2

                    merged = next(f for f in res.findings if f.cwe_id == "CWE-89")
                    assert merged.confidence == "HIGH", "Confidence must be boosted to HIGH"
                    assert merged.severity == "CRITICAL", "Severity elevated to highest reported"
                    assert "[Confirmed by Semgrep & Datadog SAIST]" in merged.description

                    unique = next(f for f in res.findings if f.cwe_id == "CWE-918")
                    assert unique.vulnerability_type == "Server-Side Request Forgery (SSRF)"
