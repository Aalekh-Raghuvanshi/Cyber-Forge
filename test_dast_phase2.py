"""
Comprehensive Phase 2 Verification Tests.
Validates:
- FR-2: DAST Scan & OWASP ZAP Ingestion (Mode A and Mode B)
- FR-3: Common Finding Format, URL Path Normalization, and Canonical CWE Mapping (including CWE-693)
- FR-6: Idempotent Deduplication and Evidence Aggregation
- API: POST /api/dast/scan endpoint
"""

import hashlib
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.models.schemas import UnifiedFinding, DASTScanRequest, DASTScanResponse
from backend.services.cwe_normalizer import normalize_cwe, compute_dast_dedup_key
from backend.services.dast_scanner import DASTScanner, get_dast_scanner
from backend.app import app


# ---------------------------------------------------------------------------
# Test 1: FR-3 URL Path Normalization
# ---------------------------------------------------------------------------

def test_url_path_normalization():
    """Verify that full URLs with query parameters and schemes normalize to clean paths."""
    scanner = get_dast_scanner()

    assert scanner.normalize_url_path("http://localhost:5000/api/orders?id=1") == "/api/orders"
    assert scanner.normalize_url_path("http://localhost:5000/api/orders/") == "/api/orders"
    assert scanner.normalize_url_path("https://example.com/api/v1/users/profile?tab=info") == "/api/v1/users/profile"
    assert scanner.normalize_url_path("http://localhost:5000/") == "/"
    assert scanner.normalize_url_path("http://localhost:5000") == "/"
    assert scanner.normalize_url_path("/api/orders") == "/api/orders"
    assert scanner.normalize_url_path("api/orders") == "/api/orders"


# ---------------------------------------------------------------------------
# Test 2: FR-3 Canonical CWE Mapping for ZAP Plugins & Alert IDs
# ---------------------------------------------------------------------------

def test_zap_cwe_and_plugin_normalization():
    """Verify ZAP pluginId and cweid fields map to canonical CWEs with 'Runtime only' status."""
    scanner = get_dast_scanner()

    raw_alerts = [
        # SQL Injection
        {
            "pluginId": "40018",
            "cweid": "89",
            "alert": "SQL Injection",
            "url": "http://localhost:5000/api/orders?id=1",
            "method": "GET",
            "param": "id",
            "attack": "1' OR '1'='1",
            "evidence": "syntax error near 1'",
            "risk": "High"
        },
        # Reflected XSS
        {
            "pluginId": "40012",
            "cweid": "79",
            "alert": "Cross Site Scripting (Reflected)",
            "url": "http://localhost:5000/search?q=test",
            "method": "GET",
            "param": "q",
            "attack": "<script>alert(1)</script>",
            "evidence": "<script>alert(1)</script>",
            "risk": "High"
        },
        # Path Traversal
        {
            "pluginId": "6",
            "cweid": "22",
            "alert": "Path Traversal",
            "url": "http://localhost:5000/files?name=../../etc/passwd",
            "method": "GET",
            "param": "name",
            "attack": "../../etc/passwd",
            "evidence": "root:x:0:0",
            "risk": "High"
        },
        # Remote OS Command Injection
        {
            "pluginId": "90020",
            "cweid": "78",
            "alert": "Remote OS Command Injection",
            "url": "http://localhost:5000/api/ping",
            "method": "POST",
            "param": "host",
            "attack": "127.0.0.1; whoami",
            "evidence": "root",
            "risk": "High"
        },
        # SSRF
        {
            "pluginId": "40046",
            "cweid": "918",
            "alert": "Server Side Request Forgery (SSRF)",
            "url": "http://localhost:5000/fetch?url=http://169.254.169.254",
            "method": "GET",
            "param": "url",
            "attack": "http://169.254.169.254",
            "evidence": "instance-id",
            "risk": "High"
        },
        # Open Redirect
        {
            "pluginId": "40028",
            "cweid": "601",
            "alert": "Open Redirect",
            "url": "http://localhost:5000/redirect?target=https://evil.com",
            "method": "GET",
            "param": "target",
            "attack": "https://evil.com",
            "evidence": "Location: https://evil.com",
            "risk": "Medium"
        },
        # Missing Security Headers (CWE-693)
        {
            "pluginId": "10038",
            "cweid": "693",
            "alert": "Content Security Policy (CSP) Header Not Set",
            "url": "http://localhost:5000/",
            "method": "GET",
            "param": "",
            "attack": "",
            "evidence": "Header missing",
            "risk": "Medium"
        },
        {
            "pluginId": "10020",
            "cweid": "-1",  # Test when cweid is missing/-1, should map via pluginId 10020
            "alert": "X-Frame-Options Header Missing",
            "url": "http://localhost:5000/",
            "method": "GET",
            "evidence": "Header missing",
            "risk": "Medium"
        }
    ]

    findings = scanner.parse_zap_alerts(raw_alerts)
    cwe_map = {f.cwe_id: f for f in findings}

    assert "CWE-89" in cwe_map
    assert "CWE-79" in cwe_map
    assert "CWE-22" in cwe_map
    assert "CWE-78" in cwe_map
    assert "CWE-918" in cwe_map
    assert "CWE-601" in cwe_map
    assert "CWE-693" in cwe_map

    # Check finding attributes
    sql = cwe_map["CWE-89"]
    assert sql.source_scanner == "DAST"
    assert sql.status_label == "Runtime only"
    assert sql.url_path == "/api/orders"
    assert sql.http_method == "GET"
    assert sql.parameter == "id"
    assert sql.payload == "1' OR '1'='1"
    assert sql.evidence == "syntax error near 1'"
    assert sql.file is None
    assert sql.line is None


# ---------------------------------------------------------------------------
# Test 3: FR-6 Idempotent Deduplication and Evidence Aggregation
# ---------------------------------------------------------------------------

def test_dast_deduplication_and_evidence_aggregation():
    """
    Verify that multiple alerts for the same bug on the same endpoint & parameter
    merge into a single finding and aggregate evidence.
    """
    scanner = get_dast_scanner()

    duplicate_alerts = [
        {
            "pluginId": "40018",
            "cweid": "89",
            "alert": "SQL Injection - Error Based",
            "url": "http://localhost:5000/api/orders?id=1",
            "method": "GET",
            "param": "id",
            "attack": "1' OR '1'='1",
            "evidence": "syntax error at or near quote",
            "risk": "High"
        },
        {
            "pluginId": "40019",
            "cweid": "89",
            "alert": "SQL Injection - Boolean Based",
            "url": "http://localhost:5000/api/orders?id=2",
            "method": "GET",
            "param": "id",
            "attack": "1 AND 1=1",
            "evidence": "different response content length",
            "risk": "High"
        },
        {
            "pluginId": "40024",
            "cweid": "89",
            "alert": "SQL Injection - SQLite",
            "url": "http://localhost:5000/api/orders?id=3",
            "method": "GET",
            "param": "id",
            "attack": "1' UNION SELECT 1--",
            "evidence": "sqlite3 error",
            "risk": "High"
        }
    ]

    findings = scanner.parse_zap_alerts(duplicate_alerts)
    # Must merge into exactly 1 finding because method, url_path, param, and cwe are identical
    assert len(findings) == 1

    finding = findings[0]
    assert finding.cwe_id == "CWE-89"
    assert finding.url_path == "/api/orders"
    assert finding.parameter == "id"
    # Evidence must be aggregated
    assert "syntax error at or near quote" in finding.evidence
    assert "different response content length" in finding.evidence
    assert "sqlite3 error" in finding.evidence

    # Deduplication key must be deterministic
    expected_key = compute_dast_dedup_key("GET", "/api/orders", "id", "CWE-89")
    assert finding.dedup_key == expected_key

    # Running twice must produce identical results
    second_run = scanner.parse_zap_alerts(duplicate_alerts)
    assert len(second_run) == 1
    assert second_run[0].dedup_key == finding.dedup_key


# ---------------------------------------------------------------------------
# Test 4: FR-2 Mode A (Live OWASP ZAP API Mock)
# ---------------------------------------------------------------------------

def test_mode_a_live_zap_scan_mock():
    """Verify live ZAP REST API interaction with seed routes and alerts extraction."""
    scanner = get_dast_scanner()

    mock_client = MagicMock()

    # Mock responses for ZAP API endpoints
    mock_version = MagicMock()
    mock_version.json.return_value = {"version": "2.14.0"}
    mock_version.raise_for_status = MagicMock()

    mock_access = MagicMock()

    mock_spider = MagicMock()
    mock_spider.json.return_value = {"scan": "1"}

    mock_status = MagicMock()
    mock_status.json.return_value = {"status": "100"}

    mock_alerts = MagicMock()
    mock_alerts.json.return_value = {
        "alerts": [
            {
                "pluginId": "40018",
                "cweid": "89",
                "alert": "SQL Injection",
                "url": "http://localhost:5000/api/orders?id=1",
                "method": "GET",
                "param": "id",
                "attack": "1' OR '1'='1",
                "evidence": "SQL syntax error",
                "risk": "High"
            }
        ]
    }
    mock_alerts.raise_for_status = MagicMock()

    def get_side_effect(url, params=None):
        if "core/view/version" in url:
            return mock_version
        elif "core/action/accessUrl" in url:
            return mock_access
        elif "spider/action/scan" in url:
            return mock_spider
        elif "spider/view/status" in url:
            return mock_status
        elif "core/view/alerts" in url:
            return mock_alerts
        return MagicMock()

    mock_client.get.side_effect = get_side_effect
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None

    with patch("backend.services.dast_scanner.httpx.Client", return_value=mock_client):
        findings = scanner.run_zap_scan(
            target_url="http://localhost:5000",
            seed_routes=["/api/orders", "/api/users"],
            zap_api_url="http://localhost:8090"
        )

        assert len(findings) == 1
        assert findings[0].cwe_id == "CWE-89"
        assert findings[0].url_path == "/api/orders"
        assert findings[0].status_label == "Runtime only"


# ---------------------------------------------------------------------------
# Test 5: FR-2 Mode B Local Verification Mode
# ---------------------------------------------------------------------------

def test_mode_b_local_diagnostics():
    """Verify Mode B offline diagnostics against running server or mock headers."""
    scanner = get_dast_scanner()

    mock_res = MagicMock()
    # Missing CSP, X-Frame-Options; has Server banner
    mock_res.headers = {
        "Content-Type": "text/html",
        "Server": "uvicorn"
    }
    mock_res.text = "Hello world"

    mock_client = MagicMock()
    mock_client.get.return_value = mock_res
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None

    with patch("backend.services.dast_scanner.httpx.Client", return_value=mock_client):
        findings = scanner.run_local_diagnostics(
            target_url="http://localhost:8000",
            seed_routes=["/api/health"]
        )

        assert len(findings) >= 2
        cwe_ids = {f.cwe_id for f in findings}
        assert "CWE-693" in cwe_ids  # Missing headers
        assert "CWE-200" in cwe_ids  # Server banner leak


# ---------------------------------------------------------------------------
# Test 6: API Endpoint POST /api/dast/scan
# ---------------------------------------------------------------------------

def test_api_dast_scan_with_raw_alerts():
    """Verify POST /api/dast/scan correctly ingests raw ZAP reports."""
    client = TestClient(app)

    payload = {
        "target_url": "http://localhost:5000",
        "raw_zap_alerts": [
            {
                "pluginId": "40018",
                "cweid": "89",
                "alert": "SQL Injection",
                "url": "http://localhost:5000/api/orders?id=1",
                "method": "GET",
                "param": "id",
                "attack": "1' OR '1'='1",
                "evidence": "syntax error near 1'",
                "risk": "High"
            },
            {
                "pluginId": "10038",
                "cweid": "693",
                "alert": "Content Security Policy (CSP) Header Not Set",
                "url": "http://localhost:5000/",
                "method": "GET",
                "evidence": "Header missing",
                "risk": "Medium"
            }
        ]
    }

    res = client.post("/api/dast/scan", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["target_url"] == "http://localhost:5000"
    assert data["total_findings"] == 2

    findings = data["findings"]
    sql = next(f for f in findings if f["cwe_id"] == "CWE-89")
    assert sql["source_scanner"] == "DAST"
    assert sql["status_label"] == "Runtime only"
    assert sql["url_path"] == "/api/orders"
    assert sql["parameter"] == "id"
    assert sql["payload"] == "1' OR '1'='1"
    assert sql["evidence"] == "syntax error near 1'"
    assert "dedup_key" in sql

    csp = next(f for f in findings if f["cwe_id"] == "CWE-693")
    assert csp["url_path"] == "/"
    assert csp["status_label"] == "Runtime only"


def test_api_dast_scan_validation_error():
    """Verify endpoint rejects empty target_url."""
    client = TestClient(app)
    res = client.post("/api/dast/scan", json={"target_url": "   "})
    assert res.status_code == 400
